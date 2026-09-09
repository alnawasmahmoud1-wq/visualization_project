"""
ioc_blocklist_tool.py
======================
IOC Installation Tool (Task: "Person 4 - Security & Visualization").

Purpose (per team lead's spec):
    Take the malicious IPs / Domains extracted from a sandbox report
    (and optionally a real dump.pcap), clean/filter out legitimate
    Windows/Microsoft traffic and invalid data, then produce a neatly
    organized list under the name "Indicators of Compromise (IOCs)"
    that a security analyst can immediately use to block on a real
    firewall.

This tool does NOT duplicate any logic - it imports the extraction and
cleaning functions directly from malware_analyzer.py (load_report,
extract_network_iocs, extract_iocs_from_pcap, merge_iocs, clean_iocs).
If that file's logic changes, this tool automatically benefits.

Usage:
    # From a sandbox report.json only
    python3 ioc_blocklist_tool.py report.json --out iocs_output

    # With a real pcap file too (requires: pip install scapy --break-system-packages)
    python3 ioc_blocklist_tool.py report.json --pcap dump.pcap --out iocs_output

    # From a manual list instead of / in addition to a report
    # (one IP or domain per line in a text file)
    python3 ioc_blocklist_tool.py report.json --manual extra_iocs.txt --out iocs_output

Outputs (in the --out folder):
    - IOCs.txt   : human-readable blocklist under "Indicators of Compromise (IOCs)",
                   one IP/domain per line, ready to paste into a firewall block list.
    - IOCs.json  : the same data structured for the dashboard / automation
                   (analyst tooling, SIEM import, etc.)
"""

import argparse
import json
import os
from datetime import datetime, timezone

from analysis import (
    load_report,
    extract_network_iocs,
    extract_iocs_from_pcap,
    merge_iocs,
    clean_iocs,
    summarize,
)


def load_manual_iocs(path: str) -> dict:
    """Read a plain text file with one IP or domain per line and return it
    in the same {ips, domains, ...} shape used by the rest of the pipeline.
    Blank lines and lines starting with '#' are ignored."""
    manual = {"ips": set(), "domains": set(), "urls": set(), "dns_queries": set(), "http_hosts": set()}
    if not path:
        return manual
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            # crude but reliable: an IPv4/IPv6-looking value goes to ips,
            # anything else (has a letter) is treated as a domain
            if all(c.isdigit() or c in ".:" for c in value):
                manual["ips"].add(value)
            else:
                manual["domains"].add(value)
    return manual


def format_ioc_text(clean: dict, sample_info: dict) -> str:
    """Build the human-readable IOC blocklist text, ready for an analyst
    to paste directly into a firewall block list."""
    lines = []
    lines.append("=" * 60)
    lines.append("INDICATORS OF COMPROMISE (IOCs)")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    if sample_info.get("file_name"):
        lines.append(f"Sample: {sample_info['file_name']}")
    if sample_info.get("sha256"):
        lines.append(f"SHA256: {sample_info['sha256']}")
    if sample_info.get("malstatus"):
        lines.append(f"Verdict: {sample_info['malstatus']} (score {sample_info.get('malscore')})")
    lines.append("")

    lines.append(f"--- Malicious IPs ({len(clean.get('ips', []))}) ---")
    if clean.get("ips"):
        lines.extend(clean["ips"])
    else:
        lines.append("(none found - no IOC to block)")
    lines.append("")

    lines.append(f"--- Malicious Domains ({len(clean.get('domains', []))}) ---")
    if clean.get("domains"):
        lines.extend(clean["domains"])
    else:
        lines.append("(none found - no IOC to block)")
    lines.append("")

    if clean.get("urls"):
        lines.append(f"--- Malicious URLs ({len(clean['urls'])}) ---")
        lines.extend(clean["urls"])
        lines.append("")

    lines.append("=" * 60)
    lines.append("Legitimate Windows/Microsoft traffic has already been filtered out.")
    lines.append("Analyst: these entries are safe to add to the firewall block list.")
    lines.append("=" * 60)
    return "\n".join(lines)


def build_iocs(report_path: str, pcap_path: str = None, manual_path: str = None) -> tuple:
    """Runs the full pipeline (report -> +pcap -> +manual -> clean) and
    returns (clean_iocs_dict, sample_info_dict)."""
    report = load_report(report_path)
    sample_info = summarize(report)

    iocs = extract_network_iocs(report)

    if pcap_path:
        iocs = merge_iocs(iocs, extract_iocs_from_pcap(pcap_path))

    if manual_path:
        iocs = merge_iocs(iocs, load_manual_iocs(manual_path))

    clean = clean_iocs(iocs)
    return clean, sample_info


def main():
    ap = argparse.ArgumentParser(
        description="IOC cleaning/filtering tool - produces a ready-to-block IOC list"
    )
    ap.add_argument("report", help="Path to the sandbox report.json")
    ap.add_argument("--pcap", help="Path to a real dump.pcap file (optional)", default=None)
    ap.add_argument(
        "--manual",
        help="Path to a text file with extra IPs/domains, one per line (optional)",
        default=None,
    )
    ap.add_argument("--out", help="Output folder", default="iocs_output")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    clean, sample_info = build_iocs(args.report, args.pcap, args.manual)

    # --- Text output (for the analyst) ---
    text_out = format_ioc_text(clean, sample_info)
    txt_path = os.path.join(args.out, "IOCs.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(text_out)
    print(text_out)
    print(f"\n[+] Saved: {txt_path}")

    # --- JSON output (for the dashboard / automation) ---
    json_path = os.path.join(args.out, "IOCs.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"sample": sample_info, "iocs": clean}, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved: {json_path}")


if __name__ == "__main__":
    main()
