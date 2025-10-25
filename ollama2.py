#!/usr/bin/env python3
#  ────────────────────────────────────────────────────────────────────────────────
#  vuln_report.py – scan Nmap XML, auto‑lookup CVEs, and export results
#                                                                              ▼
#  1.  Imports
#  2.  API wrappers – MsfModule, ExploitDB, NvdDB, CVESearch
#  3.  Nmap helper – parse + CVE extraction
#  4.  Output collector – JSON / YAML / HTML
#  5.  Main workflow
#  6.  CLI plumbing
#  ────────────────────────────────────────────────────────────────────────────────

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests      # type‑ignore
import xmltodict     # type‑ignore
import yaml          # type‑ignore

# ---------------------------------------------------------------------# MSF -------------------------------------------------
class MsfModule:
    def __init__(self, json_path: str | Path = "files/msf_copy.json"):
        self.json_path = Path(json_path)

    def find(self, keyword: str = "", version: str = "") -> List[Dict[str, Any]] | None:
        try:
            full = f"{keyword.lower()} {version.lower()}".strip()
            data = json.loads(self.json_path.read_text(encoding="utf-8"))
            return [m for m in data if full in m.get("title", "").lower()]
        except Exception:
            return None

# ---------------------------------------------------------------------# ExploitDB -----------------------------------------------
class ExploitDB:
    @staticmethod
    def find(keyword: str = "", version: str = "") -> List[Dict[str, Any]] | None:
        try:
            kw = f"{keyword} {version}".strip()
            h = {"X-Requested-With": "XMLHttpRequest"}
            q = (
                f"https://www.exploit-db.com/?search%5Bvalue%5D={kw}"
                "&draw=5&columns%5B0%5D%5Bdata%5D=date_published"
            )
            r = requests.get(q, headers=h, timeout=10)
            return r.json() if r.ok else None
        except Exception:
            return None

# ---------------------------------------------------------------------# NVD -------------------------------------------------
class NvdDB:
    @staticmethod
    def find(keyword: str = "", version: str = "") -> Dict[str, Any] | None:
        try:
            kw = f"{keyword} {version}".strip().replace(" ", "%20")
            r = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}",
                timeout=10,
            )
            return r.json() if r.ok else None
        except Exception:
            return None

# ---------------------------------------------------------------------# Trick‑E‑ST -------------------------------------------
class CVESearch:
    @staticmethod
    def find(keyword: str = "") -> str | None:
        try:
            if "CVE-" not in keyword:
                return None
            yr = keyword.split("-", 1)[1]
            r = requests.get(
                f"https://raw.githubusercontent.com/trickest/cve/refs/heads/main/{yr}/{keyword}.md",
                timeout=10,
            )
            return r.text if r.ok else None
        except Exception:
            return None

# ---------------------------------------------------------------------# Nmap Helpers -----------------------------------------
class NmapParse:
    @staticmethod
    def parse(path: str | Path) -> List[Dict[str, Any]]:
        """Return a list of {'service':…, 'version':…} tuples."""
        data = xmltodict.parse(Path(path).read_text(encoding="utf-8"))
        out: List[Dict[str, Any]] = []

        hosts = data.get("nmaprun", {}).get("host", [])
        if isinstance(hosts, dict):
            hosts = [hosts]
        for h in hosts:
            pths = h.get("ports", {}).get("port", [])
            if isinstance(pths, dict):
                pths = [pths]
            for p in pths:
                svc = p.get("service")
                if svc:
                    out.append(
                        {
                            "service": svc.get("@product", ""),
                            "version": svc.get("@version", ""),
                        }
                    )
        return out

    @staticmethod
    def extract_cve_ids(xml_path: str | Path) -> List[str]:
        """Return a flat list of CVE identifiers found in a Nmap XML."""
        data = xmltodict.parse(Path(xml_path).read_text(encoding="utf-8"))
        ids: List[str] = []

        hosts = data.get("nmaprun", {}).get("host", [])
        if isinstance(hosts, dict):
            hosts = [hosts]
        for h in hosts:
            for p in h.get("ports", {}).get("port", []):
                if isinstance(p, dict):
                    scts = p.get("script")
                    if not scts:
                        continue
                    if isinstance(scts, dict):
                        scts = [scts]
                    for s in scts:
                        if s.get("@id") == "vulners":
                            for line in s.get("@output", "").splitlines():
                                if line.startswith("CVE-"):
                                    ids.append(line.split()[0])
        return ids

# ---------------------------------------------------------------------# Output -------------------------------------------------
class Output:
    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._banner()

    def _banner(self) -> None:
        print("=== Vulnerability Search ===")

    def _store(self, key: str, value: Any) -> None:
        self._data[key] = value

    def exploitdb(self, data: Any) -> None:
        self._store("exploitdb", data)

    def msfmodule(self, data: Any) -> None:
        self._store("msfmodule", data)

    def nvd(self, data: Any) -> None:
        self._store("nvd", data)

    def cve_search(self, data: Any) -> None:
        self._store("cvesearch", data)

    def outJson(self, out_path: str | Path) -> None:
        out_path = Path(out_path)
        out_path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        print(f"✓ JSON written to {out_path}")

    def outYaml(self, out_path: str | Path) -> None:
        out_path = Path(out_path)
        out_path.write_text(
            yaml.dump(self._data, sort_keys=False, default_flow_style=False), encoding="utf-8"
        )
        print(f"✓ YAML written to {out_path}")

    def outHtml(self, out_path: str | Path) -> None:
        out_path = Path(out_path)
        html = "<html><body><pre>" + json.dumps(self._data, indent=2) + "</pre></body></html>"
        out_path.write_text(html, encoding="utf-8")
        print(f"✓ HTML written to {out_path}")

# ---------------------------------------------------------------------# Main ---------------------------------------------------
def main(
    args: argparse.Namespace,
    keyword: str = "",
    keyword_version: str = "",
    *extra: Any,
) -> None:
    if args.all:
        args.exploitdb = args.msfmodule = args.cvesearch = args.nvd = True

    # ------------------------------------------------------------------
    #  Auto‑lookup CVEs that appear in the XML
    # ------------------------------------------------------------------
    if args.nmap:
        cve_ids = NmapParse.extract_cve_ids(args.nmap)
        for cve in cve_ids:
            if args.nvd:
                output.nvd(NvdDB.find(cve))
            if args.cvesearch:
                output.cve_search(CVESearch.find(cve))

    # ------------------------------------------------------------------
    #  Keyword‑based searches (superseded when an XML was used)
    # ------------------------------------------------------------------
    if args.exploitdb:
        output.exploitdb(ExploitDB.find(keyword, keyword_version))
    if args.msfmodule:
        output.msfmodule(MsfModule().find(keyword, keyword_version))
    if args.nvd and not args.nmap:
        output.nvd(NvdDB.find(keyword, keyword_version))
    if args.cvesearch and not args.nmap:
        output.cve_search(CVESearch.find(keyword))

    # ------------------------------------------------------------------
    #  Persist the aggregated result
    # ------------------------------------------------------------------
    if args.output:
        if args.output_type == "yaml":
            output.outYaml(args.output)
        elif args.output_type == "html":
            output.outHtml(args.output)
        else:
            output.outJson(args.output)

# ---------------------------------------------------------------------# CLI -------------------------------------------------
parser = argparse.ArgumentParser(
    description="Scan an Nmap XML or keyword and aggregate vulnerability info."
)
parser.add_argument("-k", "--keyword", help="search keyword")
parser.add_argument("-kv", "--keyword_version", help="additional version string")
parser.add_argument("-nm", "--nmap", help="path to an Nmap XML file")
parser.add_argument("--nvd", action="store_true", help="query NVD")
parser.add_argument("--cvesearch", action="store_true", help="query Trick‑E‑ST POCs")
parser.add_argument("--exploitdb", action="store_true", help="query Exploit‑DB")
parser.add_argument("--msfmodule", action="store_true", help="query MSF modules")
parser.add_argument("--all", action="store_true", help="enable all sources")
parser.add_argument("-o", "--output", help="output file path")
parser.add_argument(
    "-ot",
    "--output_type",
    choices=["json", "yaml", "html"],
    default="json",
    help="output format",
)
args = parser.parse_args()

# Global collector
output = Output()

# ------------------------------------------------------------------
#  Decide which mode we are in
# ------------------------------------------------------------------
if args.nmap:
    # We rely on the XML – no separate keyword search needed
    main(args)
else:
    if not args.keyword:
        parser.error("Either --keyword or --nmap must be supplied.")
    main(args, args.keyword, args.keyword_version)
