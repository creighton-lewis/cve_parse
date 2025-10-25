import xmltodict
from typing import List, Dict, Any


class NmapParse:
    """Parse an Nmap XML file and return structured data."""
    file_name = input("Enter file_name")
    def __init__(self):
        # No state needed at this point
        pass

        def parse(self, file_name: str) -> Dict[str, List[Dict[str, Any]]]:
            """
            Read *file_name* (XML output from Nmap) and return a dict with two keys:

                services : list of {"portid": ..., "protocol": ..., "service": ..., "version": ...}
                vulners  : list of {"portid": ..., "output": ...}

            If anything goes wrong an empty dict is returned (you can change this behaviour
            if you want exception handling).
            """
            try:
                with open(file_name, "r", encoding="utf-8") as fh:
                    data = xmltodict.parse(fh.read())
            except Exception as exc:
                # Handle file‑reading/parsing errors gracefully
                print(f"Error reading/parsing {file_name!r}: {exc}")
                return {"services": [], "vulners": []}

            services: List[Dict[str, Any]] = []
            vulners: List[Dict[str, Any]] = []

            # The root element is <nmaprun>, inside it there may be one or many <host> elements.
            hosts = data["nmaprun"].get("host", [])
            if isinstance(hosts, dict):
                hosts = [hosts]          # normalise to a list

            for host in hosts:
                # Same normalisation trick for <port>
                ports = host.get("ports", {}).get("port", [])
                if isinstance(ports, dict):
                    ports = [ports]

                for port in ports:
                    # ---------- Service / version ---------------------------------
                    service_elem = port.get("service")
                    if service_elem:
                        services.append({
                            "portid":    port.get("@portid"),
                            "protocol":  port.get("@protocol"),
                            "service":   service_elem.get("@product", ""),
                            "version":   service_elem.get("@version", ""),
                        })

                    # ---------- Vulnerabilities (vulners script) -----------------
                    script_elem = port.get("script")
                    if not script_elem:
                        continue

                    scripts = script_elem if isinstance(script_elem, list) else [script_elem]
                    for script in scripts:
                        if script.get("@id") == "vulners":
                            vulners.append({
                                "portid": port.get("@portid"),
                                "output": script.get("@output", "").strip(),
                            })

            return {"services": services, "vulners": vulners}
        NmapParse()
