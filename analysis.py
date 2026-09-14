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


# =============================================================================
# 1b) Attempted Connections - detected from Windows API calls, NOT from
#     report['network'] (which stays empty in a Host-Only VM even when the
#     malware actively TRIED to reach a host). This is what the lead asked
#     for: not a map/drawing, just a plain list answering "did it try to
#     connect to some IP/domain, and which one".
# =============================================================================

_CONNECTION_ATTEMPT_APIS = {
    "InternetConnectA": "ServerName",
    "InternetConnectW": "ServerName",
    "WinHttpConnect": "ServerName",
    "ConnectEx": "ip",
    "WSAConnect": "ip",
    "connect": "ip",
    "GetAddrInfoExW": "Name",
    "getaddrinfo": "Name",
    "gethostbyname": "Name",
}


def extract_attempted_connections(report: dict) -> list:
    """
    Scan every process's API calls for connection-attempt functions
    (InternetConnect*, WinHttpConnect, ConnectEx/WSAConnect/connect,
    GetAddrInfoEx/getaddrinfo/gethostbyname) and return the list of
    hosts/IPs the sample TRIED to reach - even though the sandbox is
    Host-Only and no real traffic was captured in report['network'].

    Returns a flat, de-duplicated list (per process + target), sorted by
    process name:
        [{"pid": int, "process": str, "api": str, "target": str}, ...]
    `target` is either an IP (e.g. "185.156.73.98") or a domain
    (e.g. "tokjoza.shop").
    """
    seen = set()
    attempts = []
    for proc in report.get("behavior", {}).get("processes", []) or []:
        pid = proc.get("process_id")
        pname = proc.get("process_name", "unknown")
        for call in proc.get("calls", []) or []:
            api = call.get("api")
            arg_name = _CONNECTION_ATTEMPT_APIS.get(api)
            if not arg_name:
                continue
            args = {a.get("name"): a.get("value") for a in call.get("arguments", []) or []}
            target = args.get(arg_name)
            if not target:
                continue
            key = (pid, api, target)
            if key in seen:
                continue
            seen.add(key)
            attempts.append({"pid": pid, "process": pname, "api": api, "target": target})

    attempts.sort(key=lambda a: (a["process"], a["target"]))
    return attempts


def attempted_connections_to_iocs(attempts: list) -> dict:
    """Fold the raw attempted-connections list into the same {ips, domains}
    shape used elsewhere, so it can be cleaned with clean_iocs() and/or
    merged into the main IOC list (see ioc_blocklist_tool.py)."""
    iocs = {"ips": set(), "domains": set()}
    for a in attempts:
        target = a["target"]
        if is_valid_ip(target):
            iocs["ips"].add(target)
        else:
            iocs["domains"].add(target)
    return iocs



# =============================================================================
# 1b) Behavior events, Attack Flow, and Timeline
# =============================================================================
# NOTE: in a Host-Only VM (no outbound internet), the network graph is almost
# always empty or trivial - it provides little value. These three additions
# (behavior events -> attack flow, and the timeline) use CAPE's per-process
# `calls` data, which is captured locally inside the VM regardless of network
# access, and give a much richer picture of what the sample actually did.

# APIs that indicate the process wrote to the filesystem
_FILE_WRITE_APIS = {
    "NtWriteFile", "WriteFile", "CopyFileW", "CopyFileA",
    "MoveFileWithProgressW", "MoveFileWithProgressA",
}
_FILE_DELETE_APIS = {"DeleteFileW", "DeleteFileA", "NtDeleteFile"}

# Reads are only interesting (and reported) when the target path itself is
# sensitive (browser credential stores, SSH keys, wallets) - tracking every
# read would be extremely noisy since almost every process reads files.
_FILE_READ_APIS = {"NtReadFile", "ReadFile"}

# APIs that indicate a registry value/key was created or modified
_REGISTRY_WRITE_APIS = {
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
}
_REGISTRY_DELETE_APIS = {
    "RegDeleteValueA", "RegDeleteValueW", "RegDeleteKeyA", "RegDeleteKeyW",
}

# APIs commonly associated with process injection. This is a heuristic
# indicator, not a definitive verdict - legitimate installers/updaters can
# occasionally call some of these too, so treat it as "worth a closer look".
_INJECTION_APIS = {
    "CreateRemoteThread", "WriteProcessMemory", "NtWriteVirtualMemory",
}

# Privilege escalation: trying to acquire a sensitive Windows privilege
# (SeDebugPrivilege lets a process touch almost any other process/LSASS;
# SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeTakeOwnershipPrivilege
# are classic "act as Administrator/SYSTEM" indicators) or impersonate
# another logged-on user's token.
_PRIVILEGE_APIS = {
    "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    "AdjustTokenPrivileges", "ImpersonateLoggedOnUser", "SetThreadToken",
}

# Service creation/reconfiguration - a classic persistence + "run as SYSTEM"
# technique. Note: StartServiceA/W (starting an EXISTING service, e.g.
# svchost.exe managing normal Windows services) is intentionally NOT
# included here - that's routine OS behavior, not persistence. Only
# creating a new service or reconfiguring one is flagged.
_SERVICE_APIS = {
    "CreateServiceA", "CreateServiceW",
    "ChangeServiceConfigA", "ChangeServiceConfig2A", "ChangeServiceConfig2W",
}

# Anti-debug / anti-analysis checks
_ANTI_DEBUG_APIS = {
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtSetInformationThread", "OutputDebugStringA",
}

# Decrypting Windows-protected data (DPAPI) - commonly used by infostealers
# to decrypt saved browser passwords/cookies
_CREDENTIAL_APIS = {"CryptUnprotectData", "CryptUnprotectMemory"}

# Commands that spawn a shell/scripting interpreter - a common technique
# for living-off-the-land execution
_SHELL_PROCESS_NAMES = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}

# Command-line fragments (lowercased) indicating the sample tried to disable
# security tooling, wipe backups/shadow copies, or otherwise tamper with the
# system's defenses - detected inside executed_commands / CreateProcess args.
_EVASION_COMMAND_MARKERS = [
    "netsh advfirewall", "sc stop", "sc delete", "sc config",
    "bcdedit", "vssadmin delete shadows", "wbadmin delete",
    "reg delete", "taskkill /f", "-windowstyle hidden", "-enc ",
    "disableantispyware", "disablerealtimemonitoring", "set-mppreference",
]


def _first_arg(call: dict, *names) -> str:
    """Pull the value of the first matching named argument from a call, if any."""
    for arg in call.get("arguments", []) or []:
        if arg.get("name") in names:
            return arg.get("value", "")
    return ""


def _tag_sensitive_path(path: str) -> str:
    """Flag a file path if it touches a location an analyst would care
    about. Returns a short tag string, or None if the path is unremarkable
    (a normal Temp/AppData drop location, for example - too common to flag
    on its own)."""
    p = path.lower()
    if p.endswith("\\hosts") or "system32\\drivers\\etc\\hosts" in p:
        return "Hosts File (DNS Hijack)"
    if "\\system32\\" in p or "\\syswow64\\" in p:
        return "System32"
    if "\\drivers\\" in p:
        return "Driver Files"
    if "\\startup\\" in p:
        return "Startup Folder (Persistence)"
    if any(p.endswith(ext) for ext in (".ini", ".cfg", ".conf")):
        return "Config File"
    if "login data" in p or "\\cookies" in p or "cookies\\" in p:
        return "Browser Credentials/Cookies"
    if p.endswith("wallet.dat") or p.endswith(".kdbx") or "\\.ssh\\" in p:
        return "Credential/Wallet File"
    return None


def _tag_registry_key(key: str) -> str:
    """Flag a registry key if it matches a well-known persistence or
    security-tampering location."""
    k = key.lower()
    if "\\currentversion\\run" in k or k.endswith("runonce") or "\\runonce" in k:
        return "Persistence (Run Key)"
    if "\\winlogon" in k:
        return "Persistence (Winlogon)"
    if "image file execution options" in k:
        return "Persistence (IFEO/Debugger Hijack)"
    if "windows defender" in k or "microsoft antimalware" in k:
        return "Defender/Security Tampering"
    if "\\services\\" in k:
        return "Service Registry"
    return None


def _classify_call(call: dict):
    """
    Central classifier for one API call: decides which behavior category it
    belongs to (if any) and builds a ready-to-display detail string that
    already includes any sensitive-location tag. Returns (category, detail)
    or (None, None) if the call isn't interesting.

    Categories: file_write, file_delete, registry_write, registry_delete,
    injection, privilege_escalation, persistence, defense_evasion,
    credential_access.
    """
    api = call.get("api", "")
    args = {a.get("name"): a.get("value") for a in call.get("arguments", []) or []}

    if api in _FILE_WRITE_APIS:
        path = args.get("HandleName") or args.get("FileName") or args.get("FilePath") or args.get("lpFileName")
        if not path:
            return None, None
        tag = _tag_sensitive_path(path)
        return "file_write", (f"[{tag}] {path}" if tag else path)

    if api in _FILE_DELETE_APIS:
        path = args.get("HandleName") or args.get("FileName") or args.get("lpFileName")
        if not path:
            return None, None
        tag = _tag_sensitive_path(path)
        return "file_delete", (f"[{tag}] {path}" if tag else path)

    if api in _FILE_READ_APIS:
        path = args.get("HandleName") or args.get("FileName")
        if not path:
            return None, None
        tag = _tag_sensitive_path(path)
        # Reads are only reported when they hit something sensitive
        # (credential stores) - a generic read is too common to be useful.
        if tag not in ("Browser Credentials/Cookies", "Credential/Wallet File"):
            return None, None
        return "credential_access", f"[{tag}] {path}"

    if api in _REGISTRY_WRITE_APIS:
        key = args.get("FullName") or args.get("Registry") or args.get("SubKey")
        if not key:
            return None, None
        tag = _tag_registry_key(key)
        if tag in ("Persistence (Run Key)", "Persistence (Winlogon)", "Persistence (IFEO/Debugger Hijack)"):
            return "persistence", f"[{tag}] {key}"
        if tag == "Defender/Security Tampering":
            return "defense_evasion", f"[{tag}] {key}"
        return "registry_write", (f"[{tag}] {key}" if tag else key)

    if api in _REGISTRY_DELETE_APIS:
        key = args.get("FullName") or args.get("Registry") or args.get("SubKey")
        if not key:
            return None, None
        tag = _tag_registry_key(key)
        return "registry_delete", (f"[{tag}] {key}" if tag else key)

    if api in _INJECTION_APIS:
        return "injection", api

    if api in _SERVICE_APIS:
        name = args.get("ServiceName") or args.get("ServiceStartName") or ""
        return "persistence", (f"[Service] {name}" if name else f"[Service] {api}")

    if api in _PRIVILEGE_APIS:
        if api.startswith("LookupPrivilegeValue"):
            priv = args.get("Name") or args.get("PrivilegeName") or ""
            return "privilege_escalation", (f"Requests {priv}" if priv else "Looks up a privilege")
        if api == "ImpersonateLoggedOnUser":
            return "privilege_escalation", "Impersonates a logged-on user's token"
        return "privilege_escalation", "Adjusts token privileges"

    if api in _ANTI_DEBUG_APIS:
        return "defense_evasion", f"Anti-analysis check ({api})"

    if api in _CREDENTIAL_APIS:
        return "credential_access", f"Decrypts protected data ({api})"

    return None, None


def extract_suspicious_commands(report: dict) -> list:
    """
    Scan behavior.summary.executed_commands for command-line fragments that
    indicate the sample tried to disable security tooling, wipe backups, or
    otherwise tamper with system defenses (netsh firewall rules, `sc stop`/
    `sc delete` on a security service, vssadmin/wbadmin backup deletion,
    disabling Windows Defender via PowerShell, hidden/encoded PowerShell,
    etc.). Returns the list of matching commands as-is (empty if none found -
    which is expected/normal for most samples).
    """
    commands = report.get("behavior", {}).get("summary", {}).get("executed_commands", []) or []
    return [cmd for cmd in commands if any(marker in cmd.lower() for marker in _EVASION_COMMAND_MARKERS)]


def extract_behavior_events(report: dict, max_per_category: int = 6) -> dict:
    """
    Scan each process's `calls` list and extract notable behavior events
    using the shared classifier `_classify_call` (see above). Returns:
        { pid: {"file_write": [...], "file_delete": [...],
                "registry_write": [...], "registry_delete": [...],
                "injection": [...], "privilege_escalation": [...],
                "persistence": [...], "defense_evasion": [...],
                "credential_access": [...]} }
    Each list holds de-duplicated, human-readable strings (already tagged
    with any sensitive location, e.g. "[System32] C:\\Windows\\System32\\..."),
    capped at `max_per_category` entries per process to keep the flow readable.
    """
    categories = ["file_write", "file_delete", "registry_write", "registry_delete",
                  "injection", "privilege_escalation", "persistence",
                  "defense_evasion", "credential_access"]
    events_by_pid = {}

    for proc in report.get("behavior", {}).get("processes", []) or []:
        pid = proc.get("process_id")
        seen = {cat: set() for cat in categories}

        for call in proc.get("calls", []) or []:
            cat, detail = _classify_call(call)
            if cat and detail:
                seen[cat].add(detail)

        events_by_pid[pid] = {k: sorted(v)[:max_per_category] for k, v in seen.items()}

    return events_by_pid


def build_attack_flow_graph(nodes: dict, edges: list, behavior_events: dict) -> nx.DiGraph:
    """
    Build the Attack Flow graph: the process tree (process -> process, labeled
    "Creates Process") plus, hanging off each process node, leaf action nodes
    for its notable behavior (file writes/deletes, registry changes, possible
    injection). This mirrors: malware.exe -> Creates Process -> cmd.exe ->
    Creates File / Modifies Registry / Suspicious Activity.
    """
    G = nx.DiGraph()

    for pid, info in nodes.items():
        G.add_node(("proc", pid), label=f"{info['name']}\nPID {pid}", kind="process")

    for parent, child in edges:
        if ("proc", parent) in G and ("proc", child) in G:
            G.add_edge(("proc", parent), ("proc", child), label="Creates Process")

    action_labels = {
        "file_write": "Creates/Modifies File",
        "file_delete": "Deletes File",
        "registry_write": "Modifies Registry",
        "registry_delete": "Deletes Registry Key",
        "injection": "Suspicious Activity (possible injection)",
        "privilege_escalation": "Privilege Escalation Attempt",
        "persistence": "Adds Persistence",
        "defense_evasion": "Defense Evasion",
        "credential_access": "Credential Access Attempt",
    }
    _SUSPICIOUS_CATEGORIES = {"injection", "privilege_escalation", "persistence",
                               "defense_evasion", "credential_access"}

    for pid, events in behavior_events.items():
        if ("proc", pid) not in G:
            continue
        for category, items in events.items():
            if not items:
                continue
            action_id = ("action", pid, category)
            label = f"{action_labels[category]}\n({len(items)} item{'s' if len(items) != 1 else ''})"
            kind = "suspicious" if category in _SUSPICIOUS_CATEGORIES else "action"
            G.add_node(action_id, label=label, kind=kind, details=items)
            G.add_edge(("proc", pid), action_id, label=action_labels[category])

    return G


def _attack_flow_color(n, G):
    kind = G.nodes[n].get("kind")
    if kind == "process":
        return "#ffb3b3"
    if kind == "suspicious":
        return "#ff4d4d"
    return "#ffe08a"


# --- Malware Timeline ---------------------------------------------------

def extract_timeline(report: dict) -> list:
    """
    Build a chronological timeline of key events: each process's start time
    (first_seen) plus the first occurrence of each notable behavior category
    for that process. Returns a list of dicts sorted by timestamp:
        [{"timestamp": str, "seconds_offset": float, "process": str,
          "pid": int, "event": str}, ...]
    `seconds_offset` is relative to the earliest event, ready for display as
    a running clock (00:00, 00:05, ...).
    """
    import datetime as _dt

    def parse_ts(ts):
        # CAPE timestamps look like "2026-08-14 08:16:28,839"
        try:
            return _dt.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S,%f")
        except (ValueError, TypeError):
            return None

    behavior_events = extract_behavior_events(report)
    events = []

    for proc in report.get("behavior", {}).get("processes", []) or []:
        pid = proc.get("process_id")
        name = proc.get("process_name", "unknown")
        start = parse_ts(proc.get("first_seen"))
        if start:
            events.append({"dt": start, "process": name, "pid": pid, "event": "Process Started"})

        proc_events = behavior_events.get(pid, {})
        labels = {
            "file_write": "File Created/Modified",
            "file_delete": "File Deleted",
            "registry_write": "Registry Modified",
            "registry_delete": "Registry Key Deleted",
            "injection": "Suspicious Activity Detected",
            "privilege_escalation": "Privilege Escalation Attempt",
            "persistence": "Persistence Mechanism Added",
            "defense_evasion": "Defense Evasion Attempt",
            "credential_access": "Credential Access Attempt",
        }
        # Find the timestamp of the first call in each category, for ordering
        first_ts_by_category = {}
        for call in proc.get("calls", []) or []:
            cat, _detail = _classify_call(call)
            if cat and cat not in first_ts_by_category and proc_events.get(cat):
                ts = parse_ts(call.get("timestamp"))
                if ts:
                    first_ts_by_category[cat] = ts

        for cat, ts in first_ts_by_category.items():
            events.append({"dt": ts, "process": name, "pid": pid, "event": labels[cat]})

    events.sort(key=lambda e: e["dt"])
    if not events:
        return []

    t0 = events[0]["dt"]
    timeline = []
    for e in events:
        offset = (e["dt"] - t0).total_seconds()
        timeline.append({
            "timestamp": e["dt"].strftime("%Y-%m-%d %H:%M:%S"),
            "seconds_offset": offset,
            "process": e["process"],
            "pid": e["pid"],
            "event": e["event"],
        })
    return timeline


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
    "verisign.com", "gstatic.com", "time.windows.com", "ntp.org", "msn.com",
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


def classify_process_severity(behavior_events: dict) -> dict:
    """
    Classify each process's danger level using the same behavior events
    already extracted by extract_behavior_events() (file/registry writes
    or deletes, injection, privilege escalation, persistence, defense
    evasion, credential access). Returns {pid: "high"|"medium"|"low"}.

    - "high"   : injection, privilege escalation, persistence, defense
                 evasion, or credential-access indicators - the strongest
                 signals that a process is actively doing something malicious
    - "medium" : deletes a file/registry key, or writes/creates several
                 files or registry values (tampering, but not one of the
                 stronger signals above)
    - "low"    : process exists but shows no notable suspicious behavior
    """
    high_categories = {"injection", "privilege_escalation", "persistence",
                        "defense_evasion", "credential_access"}
    severity = {}
    for pid, events in behavior_events.items():
        if any(events.get(cat) for cat in high_categories):
            severity[pid] = "high"
        elif events.get("file_delete") or events.get("registry_delete") or events.get("file_write") or events.get("registry_write"):
            severity[pid] = "medium"
        else:
            severity[pid] = "low"
    return severity


_SEVERITY_COLORS = {
    "high": "#ff4d4d",    # red   - possible injection
    "medium": "#ffb84d",  # orange - writes/deletes files or registry
    "low": "#8fd18f",     # green - no notable suspicious behavior observed
}


def build_process_tree_graph(nodes: dict, edges: list, severity: dict = None) -> nx.DiGraph:
    """Build the process tree graph. If `severity` (from
    classify_process_severity) is given, each node gets a "severity"
    attribute so it can be colored by danger level."""
    G = nx.DiGraph()
    for pid, info in nodes.items():
        sev = (severity or {}).get(pid, "low")
        G.add_node(pid, label=f"{info['name']}\nPID {pid}", severity=sev, **info)
    for parent, child in edges:
        if parent in G and child in G:
            G.add_edge(parent, child)
    return G


def _process_tree_severity_color(n, G):
    """color_map function: colors each process node red/orange/green
    according to its "severity" attribute (see classify_process_severity)."""
    sev = G.nodes[n].get("severity", "low")
    return _SEVERITY_COLORS.get(sev, "#8fd18f")


def draw_process_tree_png(G: nx.DiGraph, out_path: str, title="Process Tree", color_map=None):
    if G.number_of_nodes() == 0:
        print(f"[!] No process tree data to draw ({out_path} skipped)")
        return
    roots = [n for n in G.nodes() if G.in_degree(n) == 0]
    pos = _hierarchical_layout(G, roots)
    colors = [color_map(n, G) for n in G.nodes()] if color_map else "#ffb3b3"
    plt.figure(figsize=(max(10, G.number_of_nodes() * 1.2), 8))
    labels = nx.get_node_attributes(G, "label")
    nx.draw(G, pos, labels=labels, with_labels=True, node_color=colors,
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
#                    "parent_id": int, "path": str,
#                    "severity": "high"|"medium"|"low",
#                    "color": str (hex, e.g. "#ff4d4d")} , ... ],
#       "edges": [ {"from": int, "to": int}, ... ]
#   },
#   "attempted_connections": [
#       {"pid": int, "process": str, "api": str, "target": str}, ...
#   ],  # raw list - "did it try to reach X", regardless of whether report['network'] captured real traffic
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

    Primary visuals (recommended - always meaningful, work regardless of
    network configuration):
        process_tree, attack_flow, timeline

    Secondary (network_map): kept for completeness, but in a Host-Only VM
    with no outbound internet it will typically be empty or near-empty,
    since there is no real network traffic to capture. Only rely on it once
    a real dump.pcap from an internet-enabled run is available.
    """
    report = load_report(report_path)
    info = summarize(report)

    nodes, edges = extract_process_tree(report)
    behavior_events = extract_behavior_events(report)
    severity = classify_process_severity(behavior_events)
    process_tree = {
        "nodes": [
            {"id": pid, "label": f"{n['name']} (PID {pid})",
             "severity": severity.get(pid, "low"),  # "high" | "medium" | "low"
             "color": _SEVERITY_COLORS[severity.get(pid, "low")],
             **n}
            for pid, n in nodes.items()
        ],
        "edges": [{"from": p, "to": c} for p, c in edges],
    }

    flow_g = build_attack_flow_graph(nodes, edges, behavior_events)
    attack_flow = {
        "nodes": [
            {"id": "|".join(str(x) for x in n), "label": flow_g.nodes[n].get("label", str(n)),
             "kind": flow_g.nodes[n].get("kind"), "details": flow_g.nodes[n].get("details")}
            for n in flow_g.nodes()
        ],
        "edges": [
            {"from": "|".join(str(x) for x in u), "to": "|".join(str(x) for x in v),
             "label": flow_g.edges[u, v].get("label")}
            for u, v in flow_g.edges()
        ],
    }

    timeline = extract_timeline(report)
    suspicious_commands = extract_suspicious_commands(report)

    iocs = extract_network_iocs(report)
    attempts = extract_attempted_connections(report)
    iocs = merge_iocs(iocs, attempted_connections_to_iocs(attempts))
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
        "attack_flow": attack_flow,
        "timeline": timeline,
        "suspicious_commands": suspicious_commands,  # command-lines that tried to disable security tooling / wipe backups (usually empty - that's normal)
        "attempted_connections": attempts,  # [{"pid","process","api","target"}, ...] - "did it try to reach X" as plain info, not a map
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

    print("\n== Extracting ATTEMPTED connections from API calls (works even with report['network'] empty) ==")
    attempts = extract_attempted_connections(report)
    for a in attempts:
        print(f"  {a['process']} (PID {a['pid']}) tried {a['api']} -> {a['target']}")
    iocs = merge_iocs(iocs, attempted_connections_to_iocs(attempts))

    attempts_out = os.path.join(args.out, "attempted_connections.json")
    with open(attempts_out, "w", encoding="utf-8") as f:
        json.dump(attempts, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved: {attempts_out} ({len(attempts)} attempts)")

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

    print("\n== Extracting behavior events (used for severity coloring + Attack Flow) ==")
    behavior_events = extract_behavior_events(report)
    severity = classify_process_severity(behavior_events)
    print(f"Severity by PID: {severity}")

    print("\n== Drawing process tree (colored by danger level: red=high, orange=medium, green=low) ==")
    tree_g = build_process_tree_graph(nodes, edges, severity=severity)
    draw_process_tree_png(tree_g, os.path.join(args.out, "process_tree.png"),
                           title=f"Process Tree - {info.get('file_name')}",
                           color_map=_process_tree_severity_color)
    export_interactive_html(tree_g, os.path.join(args.out, "process_tree.html"),
                             title=f"Process Tree - {info.get('file_name')}",
                             hierarchical=True, color_map=_process_tree_severity_color)

    print("\n== Building Attack Flow ==")
    flow_g = build_attack_flow_graph(nodes, edges, behavior_events)
    draw_process_tree_png(flow_g, os.path.join(args.out, "attack_flow.png"),
                           title=f"Attack Flow - {info.get('file_name')}",
                           color_map=_attack_flow_color)
    export_interactive_html(flow_g, os.path.join(args.out, "attack_flow.html"),
                             title=f"Attack Flow - {info.get('file_name')}",
                             hierarchical=True, color_map=_attack_flow_color)

    print("\n== Building Malware Timeline ==")
    timeline = extract_timeline(report)
    timeline_out = os.path.join(args.out, "timeline.json")
    with open(timeline_out, "w", encoding="utf-8") as f:
        json.dump(timeline, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved: {timeline_out} ({len(timeline)} events)")

    print("\n== Checking for security-tampering commands (netsh/sc/vssadmin/etc.) ==")
    suspicious_commands = extract_suspicious_commands(report)
    if suspicious_commands:
        for cmd in suspicious_commands:
            print(f"  [!] {cmd}")
    else:
        print("  (none found - normal for most samples)")

    print("\n== Drawing network map (secondary - may be empty in a Host-Only VM) ==")
    net_g = build_network_graph(clean)
    draw_network_graph_png(net_g, os.path.join(args.out, "network_map.png"),
                            title=f"Network Map - {info.get('file_name')}")
    export_interactive_html(net_g, os.path.join(args.out, "network_map.html"),
                             title=f"Network Map - {info.get('file_name')}",
                             hierarchical=False, color_map=_network_color)

    print("\n== Done ==")


if __name__ == "__main__":
    main()
