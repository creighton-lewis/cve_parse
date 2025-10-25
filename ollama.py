#!/usr/bin/env python3
"""
nmap_cve_report.py

Run:

    python nmap_cve_report.py  -i scan.xml  -o report.yaml  -f yaml

Options
*  -i / --input   : Nmap XML file (mandatory)
*  -o / --output  : Output file (default: report.json)
*  -f / --format  : json / yaml / txt (default: json)
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import requests
import xmltodict
import yaml

# --------------------------------------------------------------------
# Helper classes (already provided, we just keep them and add docstrings)
# --------------------------------------------------------------------
class NvdDB:
    """Query the NVD REST API for a CVE and return the raw JSON dict (or None)."""

    def __init__(self) -> None:
        self.base = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def find(self, keyword: str = "", version: str = "") -> Optional[Dict[str, Any]]:
        keyword = f"{keyword} {version}".strip()
        keyword = keyword.replace(" ", "%20")
        resp = requests.get(f"{self.base}?keywordSearch={keyword}")
        return resp.json() if resp.status_code == 200 else None


class CVESearch:
    """Pull the Markdown POC file from Trick‑E‑ST's GitHub repo."""
    def __init__(self) -> None:
        self.base = "https://raw.githubusercontent.com/trickest/cve/refs/heads/main"

    def find(self, keyword: str) -> Optional[str]:
        if "CVE-" not in keyword:
            return None
        year = keyword.split("-", 1)[1]
        url = f"{self.base}/{year}/{keyword}.md"
        resp = requests.get(url)
        return resp.text if resp.status_code == 200 else None


# --------------------------------------------------------------------
# Core functions
# --------------------------------------------------------------------
def parse_nmap_xml(xml_path: Path) -> List[Dict[str, Any]]:
    """
    Parse an Nmap XML scan and return a list of host‑dicts.
    Each host‑dict contains:
        'host'  : str
        'ports' : List[Dict[str, Any]]
    """
    with xml_path.open("r", encoding="utf-8") as fh:
        data = xmltodict.parse(fh.read())

    result: List[Dict[str, Any]] = []

    hosts = data.get("nmaprun", {}).get("host", [])
    if isinstance(hosts, dict):
        hosts = [hosts]                    # single host → list[dict]

    for h in hosts:
        # Resolve the host: ipaddr or hostname
        hostnames = h.get("hostnames", {}).get("hostname", {})
        if isinstance(hostnames, dict):      # single hostname
            hostname = hostnames.get("@name", "")
        else:
            # list of hostnames – take the first one (if any)
            hostname = hostnames[0].get("@name", "") if hostnames else ""

        # Grab any IPv4/IPv6 addresses that are up
        addresses = h.get("address", [])
        if isinstance(addresses, dict):
            addresses = [addresses]

        ip = next(
            (a["@addr"] for a in addresses if a.get("@addrtype") == "ipv4"),
            None,
        )

        host_id = hostname or ip or "unknown"

        # ----- Ports -----------------------------------------------------------------
        ports_info = h.get("ports", {}).get("port", [])
        if isinstance(ports_info, dict):
            ports_info = [ports_info]

        ports: List[Dict[str, Any]] = []

        for p in ports_info:
            portid = p.get("@portid", "")
            protocol = p.get("@protocol", "")
            service_elem = p.get("service", {})
            service_name = service_elem.get("@name", "") if service_elem else ""
            version = service_elem.get("@version") if service_elem else None

            # Extract CVEs from the vulners script (if present)
            cves: List[str] = []

            script_elem = p.get("script")
            if script_elem:
                scripts = (
                    script_elem if isinstance(script_elem, list) else [script_elem]
                )
                for s in scripts:
                    if s.get("@id") == "vulners":
                        # The script's output is a big block of text – each line a CVE
                        for line in s.get("@output", "").splitlines():
                            if "CVE-" in line:
                                cves.append(line.strip().split()[0])

            ports.append(
                {
                    "portid": portid,
                    "protocol": protocol,
                    "service": service_name,
                    "version": version,
                    "cves": cves,
                }
            )

        result.append(
            {
                "host": host_id,
                "ports": ports,
            }
        )

    return result


def enrich_cve_info(cve_list: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    For every CVE in *cve_list* pull:
        * the JSON from NVD
        * the Markdown POC (if exists)
    Returns a dict keyed by CVE.
    """
    nvd = NvdDB()
    poc = CVESearch()

    enriched: Dict[str, Dict[str, Any]] = {}
    for cve in cve_list:
        cve_detail = {"cve": cve}
        # NVD entry
        nvd_res = nvd.find(cve)
        cve_detail["nvd"] = nvd_res if nvd_res else {}

        # POC (Trick‑E‑ST markdown)
        poc_txt = poc.find(cve)
        cve_detail["poc"] = poc_txt if poc_txt else None

        enriched[cve] = cve_detail
    return enriched


def assemble_report(nmap_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Combine the parsed Nmap data with the enriched CVE information."""
    all_cve_ids = {cve for host in nmap_results for p in host["ports"] for cve in p["cves"]}
    cve_data = enrich_cve_info(list(all_cve_ids))

    report: List[Dict[str, Any]] = []

    for host in nmap_results:
        host_entry: Dict[str, Any] = {"host": host["host"], "ports": []}
        for p in host["ports"]:
            port_entry = {
                "portid": p["portid"],
                "service": f"{p['service']} ({p['version']})" if p["version"] else p["service"],
                "cves": [],
            }
            for cve in p["cves"]:
                port_entry["cves"].append(cve_data[cve])
            host_entry["ports"].append(port_entry)
        report.append(host_entry)

    return {"scan_date": nmap_results[0]["host"] + " scan", "hosts": report}


def write_report(report: Dict[str, Any], output_path: Path, fmt: str) -> None:
    """Write to JSON, YAML or plain‑text."""
    if fmt == "json":
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    elif fmt == "yaml":
        output_path.write_text(
            yaml.dump(report, sort_keys=False, default_flow_style=False), encoding="utf-8"
        )

    elif fmt == "txt":
        lines = []
        for h in report["hosts"]:
            lines.append(f"Host: {h['host']}")
            for p in h["ports"]:
                lines.append(f"  Port {p['portid']} – {p['service']}")
                for cve in p["cves"]:
                    nvd = cve.get("nvd", {})
                    if nvd:
                        desc = nvd.get("summary", {}).replace("\n", " ")
                        lines.append(f"    CVE: {cve['cve']} - {desc[:80]}…")
            lines.append("")
        output_path.write_text("\n".join(lines), encoding="utf-8")

    else:
        raise ValueError(f"Unsupported format: {fmt}")


# --------------------------------------------------------------------
# CLI part
# --------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Nmap → CVE report generator")
    parser.add_argument("-i", "--input", required=True, type=Path, help="Nmap XML file")
    parser.add_argument("-o", "--output", type=Path, help="Output file")
    parser.add_argument(
        "-f", "--format",
        choices=["json", "yaml", "txt"],
        default="json",
        help="Output format",
    )

    args = parser.parse_args()

    if not args.input.is_file():
        print(f"❌  Input file {args.input!s} does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"📥  Reading Nmap scan from {args.input!s} …")
    nmap_results = parse_nmap_xml(args.input)

    print(
        f"🔍  Found {len(nmap_results)} host(s) with "
        f"{sum(len(h["ports"]) for h in nmap_results)} open port(s)."
    )
    report = assemble_report(nmap_results)

    print(f"💾  Writing report to {args.output!s} [{args.format.upper()}] …")
    write_report(report, args.output, args.format)

    print("✅  Done!")


if __name__ == "__main__":
    main()
