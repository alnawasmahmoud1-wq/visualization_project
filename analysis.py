"""
malware_analyzer.py
====================
Malware Sandbox Report Parser + IOC Extraction + Visualization + Dashboard Integration.

Covers all assigned tasks (Security & Visualization role):
  1. Parsing:        read report.json (Cuckoo/CAPE format) and extract the
                      process tree and network indicators.
  2. IOC Extraction:  extract IPs / domains / URLs from the report itself
                      and (optionally) from a real dump.pcap file, then
                      clean them from legitimate Windows/Microsoft traffic.
  3. Visualization:   render the process tree and network map as a static
                      PNG and as an interactive HTML (pan/zoom) file.
  4. Dashboard integration: a single function (`analyze_for_dashboard`)
                      that the Flask dashboard can import and call directly,
                      returning a JSON-serializable dict. No file is
                      hardcoded anywhere - any report path can be passed in.

CLI usage:
    # basic (report.json only)
    python3 malware_analyzer.py report.json --out output

    # with a real pcap file (requires: pip install scapy --break-system-packages)
    python3 malware_analyzer.py report.json --pcap dump.pcap --out output

Outputs (in the --out folder):
    - iocs_clean.json    : IOCs (IPs/Domains/URLs) after removing legitimate
                            traffic
    - process_tree.png   : process tree (static image)
    - process_tree.html  : process tree (interactive - zoom/pan)
    - network_map.png    : network map (static image)
    - network_map.html   : network map (interactive)
"""

import argparse
import ipaddress
import json
import os
import re
from pathlib import Path

import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

try:
    from scapy.all import rdpcap, IP, DNSQR, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# =============================================================================
# 1) Parsing: load report.json and extract the process tree + network IOCs
# =============================================================================

def load_report(report_path: str) -> dict:
    """Load a report.json file and return it as a dict. Works with any
    filename/path passed in - nothing is hardcoded."""
    path = Path(report_path)
    if not path.exists():
        raise FileNotFoundError(f"Report file not found: {report_path}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def extract_process_tree(report: dict):
    """
    Extract the process tree from report['behavior']['processtree'].
    Returns:
        nodes: dict {pid: {"name", "pid", "parent_id", "path"}}
        edges: list[(parent_pid, child_pid)]
    Supports more than one root process, since processtree can contain
    multiple top-level entries.
    """
    nodes = {}
    edges = []

    def walk(node, parent_pid=None):
        pid = node.get("pid")
        nodes[pid] = {
            "name": node.get("name", "unknown"),
            "pid": pid,
            "parent_id": node.get("parent_id", parent_pid),
            "path": node.get("module_path", ""),
        }
        if parent_pid is not None:
            edges.append((parent_pid, pid))
        for child in node.get("children", []) or []:
            walk(child, pid)

    roots = report.get("behavior", {}).get("processtree", []) or []
    for root in roots:
        walk(root, None)

    return nodes, edges


def extract_network_iocs(report: dict) -> dict:
    """
    Walk report['network'] and report['behavior']['network_map'] (standard
    Cuckoo/CAPE structure) and extract ips/domains/urls/dns_queries/http_hosts.
    If the report has no network activity (e.g. route=none in the sandbox
    config), the sets simply come back empty - that's expected, and in that
    case a real dump.pcap (see extract_iocs_from_pcap) is needed instead.
    """
    iocs = {"ips": set(), "domains": set(), "urls": set(), "dns_queries": set(), "http_hosts": set()}

    net = report.get("network", {}) or {}

    for host in net.get("hosts", []) or []:
        if isinstance(host, str):
            iocs["ips"].add(host)
        elif isinstance(host, dict) and host.get("ip"):
            iocs["ips"].add(host["ip"])

    for d in net.get("domains", []) or []:
        if isinstance(d, dict):
            if d.get("domain"):
                iocs["domains"].add(d["domain"])
            if d.get("ip"):
                iocs["ips"].add(d["ip"])

    for conn_type in ("tcp", "udp"):
        for conn in net.get(conn_type, []) or []:
            if isinstance(conn, dict):
                if conn.get("dst"):
                    iocs["ips"].add(conn["dst"])
                if conn.get("src"):
                    iocs["ips"].add(conn["src"])

    for req in net.get("http", []) or []:
        if isinstance(req, dict):
            if req.get("host"):
                iocs["http_hosts"].add(req["host"])
            if req.get("uri"):
                iocs["urls"].add(req.get("host", "") + req["uri"])

    for dns in net.get("dns", []) or []:
        if isinstance(dns, dict) and dns.get("request"):
            iocs["dns_queries"].add(dns["request"])
            for ans in dns.get("answers", []) or []:
                if isinstance(ans, dict) and ans.get("data"):
                    iocs["ips"].add(ans["data"])

    # behavior.network_map is an alternate location used by newer CAPE
    # versions to store the same kind of information
    nm = report.get("behavior", {}).get("network_map", {}) or {}
    for host in (nm.get("endpoint_map") or {}).keys():
        iocs["ips"].add(host)
    for host in (nm.get("http_host_map") or {}).keys():
        iocs["http_hosts"].add(host)
    for domain in (nm.get("dns_intents") or {}).keys():
        iocs["dns_queries"].add(domain)
    for req in nm.get("http_requests", []) or []:
        if isinstance(req, dict) and req.get("host"):
            iocs["http_hosts"].add(req["host"])
            if req.get("uri"):
                iocs["urls"].add(req["host"] + req["uri"])

    return iocs


def summarize(report: dict) -> dict:
    """Quick sample info (file name, hash, malscore) for display alongside
    the results."""
    target = report.get("target", {}).get("file", {}) or {}
    return {
        "file_name": target.get("name"),
        "sha256": target.get("sha256"),
        "malscore": report.get("malscore"),
        "malstatus": report.get("malstatus"),
        "analysis_id": report.get("info", {}).get("id"),
    }


# =============================================================================
# 2) IOC Extraction from a real dump.pcap file (Task 3)
# =============================================================================

def extract_iocs_from_pcap(pcap_path: str) -> dict:
    """
    Extract ips/dns_queries/http_hosts from a real pcap file via scapy.
    Requires: pip install scapy --break-system-packages
    """
    if not SCAPY_AVAILABLE:
        raise ImportError(
            "scapy is not installed. Install it with: pip install scapy --break-system-packages"
        )

    iocs = {"ips": set(), "dns_queries": set(), "http_hosts": set(), "domains": set(), "urls": set()}
    packets = rdpcap(pcap_path)

    for pkt in packets:
        if pkt.haslayer(IP):
            iocs["ips"].add(pkt[IP].src)
            iocs["ips"].add(pkt[IP].dst)

        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode(errors="ignore")
            iocs["dns_queries"].add(qname.rstrip("."))

        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load)
                if b"Host:" in payload:
                    for line in payload.split(b"\r\n"):
                        if line.lower().startswith(b"host:"):
                            host = line.split(b":", 1)[1].strip().decode(errors="ignore")
                            iocs["http_hosts"].add(host)
            except Exception:
                pass

    return iocs


def merge_iocs(a: dict, b: dict) -> dict:
    merged = {}
    for k in set(a) | set(b):
        merged[k] = set(a.get(k, set())) | set(b.get(k, set()))
    return merged


# =============================================================================
# 3) Clean IOCs from legitimate Windows/Microsoft traffic (Task 3)
# =============================================================================

LEGIT_DOMAIN_SUFFIXES = [
    "microsoft.com", "windowsupdate.com", "windows.com", "msftconnecttest.com",
    "msftncsi.com", "live.com", "office.com", "office365.com", "microsoftonline.com",
    "azure.com", "azureedge.net", "akamaiedge.net", "digicert.com", "sectigo.com",
    "verisign.com", "gstatic.com", "time.windows.com", "ntp.org",
]


def is_private_or_reserved_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified)


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_legit_domain(domain: str) -> bool:
    domain = domain.lower().strip(".")
    return any(domain == s or domain.endswith("." + s) for s in LEGIT_DOMAIN_SUFFIXES)


def clean_iocs(iocs: dict, extra_legit_domains=None, extra_legit_ips=None) -> dict:
    """Remove private/local IPs and domains belonging to known-legitimate
    Windows/Microsoft infrastructure."""
    extra_legit_domains = set(d.lower() for d in (extra_legit_domains or []))
    extra_legit_ips = set(extra_legit_ips or [])

    cleaned = {
        "ips": sorted(
            ip for ip in iocs.get("ips", [])
            if is_valid_ip(ip) and not is_private_or_reserved_ip(ip) and ip not in extra_legit_ips
        ),
        "domains": sorted(
            d for d in (iocs.get("domains", set()) | iocs.get("dns_queries", set()) | iocs.get("http_hosts", set()))
            if not is_legit_domain(d) and d.lower() not in extra_legit_domains
        ),
        "urls": sorted(
            u for u in iocs.get("urls", [])
            if not any(is_legit_domain(part) for part in re.split(r"[/:]", u) if part)
        ),
    }
    return cleaned


# =============================================================================
# 4) Visualization: process tree + network map (static PNG + interactive HTML)
# =============================================================================

def _hierarchical_layout(G: nx.DiGraph, roots):
    """Simple hierarchical layout for trees (no pygraphviz dependency)."""
    pos = {}
    depth_counts = {}

    def assign(node, depth, visited):
        if node in visited:
            return
        visited.add(node)
        x = depth_counts.get(depth, 0)
        pos[node] = (x, -depth)
        depth_counts[depth] = x + 1
        for child in G.successors(node):
            assign(child, depth + 1, visited)

    visited = set()
    for r in roots:
        assign(r, 0, visited)
    for node in G.nodes():
        if node not in pos:
            depth = max((d for _, d in pos.values()), default=0) + 1
            x = depth_counts.get(depth, 0)
            pos[node] = (x, -depth)
            depth_counts[depth] = x + 1
    return pos


def build_process_tree_graph(nodes: dict, edges: list) -> nx.DiGraph:
    G = nx.DiGraph()
    for pid, info in nodes.items():
        G.add_node(pid, label=f"{info['name']}\nPID {pid}", **info)
    for parent, child in edges:
        if parent in G and child in G:
            G.add_edge(parent, child)
    return G


def draw_process_tree_png(G: nx.DiGraph, out_path: str, title="Process Tree"):
    if G.number_of_nodes() == 0:
        print(f"[!] No process tree data to draw ({out_path} skipped)")
        return
    roots = [n for n in G.nodes() if G.in_degree(n) == 0]
    pos = _hierarchical_layout(G, roots)
    plt.figure(figsize=(max(10, G.number_of_nodes() * 1.2), 8))
    labels = nx.get_node_attributes(G, "label")
    nx.draw(G, pos, labels=labels, with_labels=True, node_color="#ffb3b3",
            node_size=2200, font_size=7, arrows=True, edge_color="#666666", arrowsize=15)
    plt.title(title)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {out_path}")


def build_network_graph(iocs: dict, root_label="Sandbox VM") -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node(root_label, label=root_label, kind="host")
    for ip in iocs.get("ips", []):
        G.add_node(ip, label=ip, kind="ip")
        G.add_edge(root_label, ip)
    for domain in iocs.get("domains", []):
        G.add_node(domain, label=domain, kind="domain")
        G.add_edge(root_label, domain)
    return G


def draw_network_graph_png(G: nx.DiGraph, out_path: str, title="Network Map"):
    if G.number_of_nodes() <= 1:
        print(f"[!] No network activity (IOCs) to draw ({out_path} skipped)")
        return
    pos = nx.spring_layout(G, seed=42, k=0.9)
    colors = ["#7fb3ff" if G.nodes[n].get("kind") == "host"
              else ("#ff9d9d" if G.nodes[n].get("kind") == "ip" else "#ffd97f")
              for n in G.nodes()]
    plt.figure(figsize=(10, 8))
    labels = nx.get_node_attributes(G, "label")
    nx.draw(G, pos, labels=labels, with_labels=True, node_color=colors,
            node_size=1800, font_size=7, arrows=True, edge_color="#999999")
    plt.title(title)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {out_path}")


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
  body {{ font-family: sans-serif; margin:0; background:#111; color:#eee; }}
  #header {{ padding: 10px 16px; background:#1c1c1c; border-bottom:1px solid #333; }}
  #network {{ width: 100vw; height: calc(100vh - 50px); }}
</style>
</head>
<body>
<div id="header"><b>{title}</b> &nbsp;|&nbsp; Drag / scroll to interact with the graph</div>
<div id="network"></div>
<script>
  const nodes = new vis.DataSet({nodes_json});
  const edges = new vis.DataSet({edges_json});
  const container = document.getElementById("network");
  const data = {{ nodes: nodes, edges: edges }};
  const options = {{
    layout: {{ hierarchical: {hierarchical} }},
    physics: {{ enabled: {physics} }},
    nodes: {{ shape: "box", font: {{ color: "#111" }} }},
    edges: {{ arrows: "to", color: "#888" }}
  }};
  new vis.Network(container, data, options);
</script>
</body>
</html>
"""


def _process_tree_color(n, G):
    return "#ffb3b3"


def _network_color(n, G):
    kind = G.nodes[n].get("kind")
    return "#7fb3ff" if kind == "host" else ("#ff9d9d" if kind == "ip" else "#ffd97f")


def export_interactive_html(G: nx.DiGraph, out_path: str, title="Graph", hierarchical=False, color_map=None):
    """Export the graph as an interactive HTML file (vis-network via CDN)
    that opens directly in any browser - no extra Python package required."""
    vis_nodes = [
        {"id": str(n), "label": G.nodes[n].get("label", str(n)),
         "color": color_map(n, G) if color_map else "#ffb3b3"}
        for n in G.nodes()
    ]
    vis_edges = [{"from": str(u), "to": str(v)} for u, v in G.edges()]
    html = _HTML_TEMPLATE.format(
        title=title,
        nodes_json=json.dumps(vis_nodes, ensure_ascii=False),
        edges_json=json.dumps(vis_edges, ensure_ascii=False),
        hierarchical=json.dumps(bool(hierarchical)),
        physics=json.dumps(not hierarchical),
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Saved (interactive): {out_path}")


# =============================================================================
# 5) Dashboard integration (import this function directly - do not merge code)
# =============================================================================
#
# Usage from the dashboard's Flask code:
#
#     from malware_analyzer import analyze_for_dashboard
#     result = analyze_for_dashboard("path/to/report.json", pcap_path="path/to/dump.pcap")
#
# The function does not save or draw anything (no matplotlib/HTML here) - it
# just returns a plain Python dict that is directly JSON-serializable
# (json.dumps(result)), ready to be sent from a Flask route to the frontend.
#
# Output schema (always this exact structure):
#
# {
#   "sample": {
#       "file_name": str, "sha256": str, "malscore": float,
#       "malstatus": str, "analysis_id": int
#   },
#   "process_tree": {
#       "nodes": [ {"id": int, "label": str, "name": str, "pid": int,
#                    "parent_id": int, "path": str} , ... ],
#       "edges": [ {"from": int, "to": int}, ... ]
#   },
#   "network_map": {
#       "nodes": [ {"id": str, "label": str, "kind": "host"|"ip"|"domain"}, ... ],
#       "edges": [ {"from": str, "to": str}, ... ]
#   },
#   "iocs": {
#       "ips": [str, ...], "domains": [str, ...], "urls": [str, ...]
#   }
# }
#
# "id" in process_tree is the PID (integer). "id" in network_map is a
# string (the IP, the domain, or "Sandbox VM" for the root node).
# If the frontend expects different key names, this function is the only
# place that needs to change - the rest of the code is unaffected.
#
# The report_path argument accepts ANY filename/path - nothing is hardcoded.


def analyze_for_dashboard(report_path: str, pcap_path: str = None) -> dict:
    """
    Official dashboard integration entry point. Do not edit this from the
    dashboard project - just import and call it. Any schema change needed
    happens here, in this file (the Security/Visualization file), not in
    the dashboard's code.
    """
    report = load_report(report_path)
    info = summarize(report)

    nodes, edges = extract_process_tree(report)
    process_tree = {
        "nodes": [
            {"id": pid, "label": f"{n['name']} (PID {pid})", **n}
            for pid, n in nodes.items()
        ],
        "edges": [{"from": p, "to": c} for p, c in edges],
    }

    iocs = extract_network_iocs(report)
    if pcap_path:
        iocs = merge_iocs(iocs, extract_iocs_from_pcap(pcap_path))
    clean = clean_iocs(iocs)

    net_g = build_network_graph(clean)
    network_map = {
        "nodes": [
            {"id": str(n), "label": net_g.nodes[n].get("label", str(n)),
             "kind": net_g.nodes[n].get("kind")}
            for n in net_g.nodes()
        ],
        "edges": [{"from": str(u), "to": str(v)} for u, v in net_g.edges()],
    }

    return {
        "sample": info,
        "process_tree": process_tree,
        "network_map": network_map,
        "iocs": clean,
    }


# =============================================================================
# 6) main: CLI entry point for direct/manual runs (not required by the
#    dashboard - useful for standalone testing on any report file)
# =============================================================================

def main():
    ap = argparse.ArgumentParser(description="Malware Sandbox Report Parser + IOC Extraction + Visualization")
    ap.add_argument("report", help="Path to the report.json file (any filename/path)")
    ap.add_argument("--pcap", help="Path to a dump.pcap file (optional)", default=None)
    ap.add_argument("--out", help="Output folder", default="output")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    print("== Loading report ==")
    report = load_report(args.report)
    info = summarize(report)
    print(json.dumps(info, ensure_ascii=False, indent=2))

    print("\n== Extracting process tree ==")
    nodes, edges = extract_process_tree(report)
    print(f"Process count: {len(nodes)}")

    print("\n== Extracting IOCs from report.json ==")
    iocs = extract_network_iocs(report)
    for k, v in iocs.items():
        print(f"  {k}: {len(v)}")

    if args.pcap:
        print(f"\n== Extracting IOCs from {args.pcap} ==")
        pcap_iocs = extract_iocs_from_pcap(args.pcap)
        iocs = merge_iocs(iocs, pcap_iocs)
        for k, v in iocs.items():
            print(f"  {k}: {len(v)}")

    print("\n== Cleaning IOCs (removing legitimate traffic) ==")
    clean = clean_iocs(iocs)
    print(json.dumps(clean, ensure_ascii=False, indent=2))

    iocs_out = os.path.join(args.out, "iocs_clean.json")
    with open(iocs_out, "w", encoding="utf-8") as f:
        json.dump({"sample": info, "iocs": clean}, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved: {iocs_out}")

    print("\n== Drawing process tree ==")
    tree_g = build_process_tree_graph(nodes, edges)
    draw_process_tree_png(tree_g, os.path.join(args.out, "process_tree.png"),
                           title=f"Process Tree - {info.get('file_name')}")
    export_interactive_html(tree_g, os.path.join(args.out, "process_tree.html"),
                             title=f"Process Tree - {info.get('file_name')}",
                             hierarchical=True, color_map=_process_tree_color)

    print("\n== Drawing network map ==")
    net_g = build_network_graph(clean)
    draw_network_graph_png(net_g, os.path.join(args.out, "network_map.png"),
                            title=f"Network Map - {info.get('file_name')}")
    export_interactive_html(net_g, os.path.join(args.out, "network_map.html"),
                             title=f"Network Map - {info.get('file_name')}",
                             hierarchical=False, color_map=_network_color)

    print("\n== Done ==")


if __name__ == "__main__":
    main()
