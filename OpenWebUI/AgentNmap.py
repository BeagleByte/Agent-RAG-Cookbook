"""
title: Nmap Network Scanner - Complete XML Parser
author: BeagleByteI
author_url: https://github.com/BeagleByteI
version: 2.1.0
license: MIT
description: Performs comprehensive network scanning using nmap with complete XML detail extraction.  WARNING: Full port scans (-p-) can take 10-60 minutes.
requirements: python-nmap
"""

import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Optional, List
from pydantic import BaseModel, Field
import time


class Tools:
    def __init__(self):
        pass

    def run_nmap_scan(
        self,
        target: str = Field(..., description="Target IP address, hostname, or CIDR range (e.g., 10.10.11.98)"),
        scan_type: str = Field(
            default="full",
            description="""Type of scan with estimated duration: 
            - 'full' (-Pn -sCV -p- -T3): Scans all 65535 ports.  Takes 15-60 minutes.
            - 'full_aggressive' (-Pn -sCV -p- -T4 -A): Faster with OS detection. Takes 10-30 minutes.
            - 'quick' (top 1000 ports): Fast scan.  Takes 1-5 minutes.
            - 'custom':  Use custom_flags parameter."""
        ),
        custom_flags: Optional[str] = Field(
            default=None,
            description="Custom nmap flags (only used when scan_type='custom'). Example: '-Pn -sS -p 1-1000 -T4'"
        )
    ) -> str:
        """
        Execute comprehensive nmap network scan with full detail extraction.

        ⚠️ IMPORTANT: Full port scans take 15-60 minutes to complete.
        Always inform the user that the scan is starting and will take several minutes.
        """

        # Define scan options
        scan_options = {
            "full": ["-Pn", "-sCV", "-p-", "-T3"],
            "full_aggressive":  ["-Pn", "-sCV", "-p-", "-T4", "-A"],
            "full_slow": ["-Pn", "-sCV", "-p-", "-T2"],
            "quick": ["-Pn", "-sCV", "-T4", "--top-ports", "1000"],
            "version": ["-Pn", "-sV", "-sC", "-T3"],
            "vuln": ["-Pn", "-sV", "--script", "vuln", "-T3"],
            "udp": ["-Pn", "-sU", "-sV", "--top-ports", "100", "-T3"],
        }

        duration_estimates = {
            "full": "15-60 minutes",
            "full_aggressive": "10-30 minutes",
            "full_slow": "30-120 minutes",
            "quick":  "1-5 minutes",
            "version": "2-10 minutes",
            "vuln": "5-15 minutes",
            "udp": "10-30 minutes",
        }

        estimated_time = duration_estimates.get(scan_type, "several minutes")

        # Build nmap command
        if scan_type == "custom" and custom_flags:
            flags = custom_flags.split()
            cmd = ["nmap", "-oX", "-"] + flags + [target]
        else:
            cmd = ["nmap", "-oX", "-"] + scan_options. get(scan_type, scan_options["full"]) + [target]

        cmd_string = " ".join(cmd)

        # Initial status message
        initial_message = f"""🔄 **Nmap Scan Started**

**Target:** {target}
**Scan Type:** {scan_type}
**Command:** `{cmd_string}`
**Estimated Duration:** {estimated_time}

⏳ Please wait while the scan completes... 

---

"""

        try:
            timeout = 3600 if scan_type in ["full", "full_aggressive", "full_slow"] else 600
            start_time = time.time()

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            elapsed_time = time.time() - start_time
            elapsed_formatted = f"{int(elapsed_time // 60)}m {int(elapsed_time % 60)}s"

            if result.returncode != 0:
                return f"{initial_message}❌ **Scan Failed** (after {elapsed_formatted})\n\n**Error:** {result.stderr}"

            # Parse and format results
            parsed = self._parse_nmap_xml(result.stdout)
            parsed["command"] = cmd_string
            parsed["scan_type"] = scan_type
            parsed["actual_duration"] = elapsed_formatted

            report = self._format_report(parsed)

            completion_notice = f"""✅ **Scan Completed Successfully**
**Actual Duration:** {elapsed_formatted}

"""

            return initial_message + completion_notice + report

        except subprocess.TimeoutExpired:
            return f"{initial_message}⏱️ **Scan Timeout:** Exceeded {timeout} seconds ({timeout//60} minutes)"
        except Exception as e:
            return f"{initial_message}❌ **Error:** {str(e)}"

    def _parse_nmap_xml(self, xml_output:  str) -> Dict:
        """Parse nmap XML output with complete detail extraction."""
        try:
            root = ET.fromstring(xml_output)
            results = {
                "error": False,
                "scan_info": {},
                "hosts": []
            }

            # ===== NMAPRUN (root attributes) =====
            results["scan_info"] = {
                "scanner": root.attrib.get("scanner", "nmap"),
                "version": root.attrib.get("version", "unknown"),
                "args": root.attrib.get("args", "unknown"),
                "start":  root.attrib.get("start", ""),
                "startstr": root. attrib.get("startstr", "unknown"),
                "xmloutputversion": root.attrib.get("xmloutputversion", "")
            }

            # ===== SCANINFO =====
            scaninfo = root. find("scaninfo")
            if scaninfo is not None:
                results["scan_info"]["scaninfo"] = {
                    "type": scaninfo.attrib.get("type", ""),
                    "protocol": scaninfo.attrib.get("protocol", ""),
                    "numservices": scaninfo.attrib. get("numservices", ""),
                    "services": scaninfo.attrib.get("services", "")
                }

            # ===== VERBOSE =====
            verbose = root. find("verbose")
            if verbose is not None:
                results["scan_info"]["verbose"] = verbose.attrib.get("level", "0")

            # ===== DEBUGGING =====
            debugging = root.find("debugging")
            if debugging is not None:
                results["scan_info"]["debugging"] = debugging.attrib.get("level", "0")

            # ===== RUNSTATS =====
            runstats = root.find("runstats")
            if runstats is not None:
                finished = runstats.find("finished")
                if finished is not None:
                    results["scan_info"]["finished"] = {
                        "time": finished. attrib.get("time", ""),
                        "timestr":  finished.attrib.get("timestr", ""),
                        "summary": finished. attrib.get("summary", ""),
                        "elapsed": finished. attrib.get("elapsed", ""),
                        "exit": finished.attrib.get("exit", "")
                    }

                hosts = runstats.find("hosts")
                if hosts is not None:
                    results["scan_info"]["hosts"] = {
                        "up": hosts. attrib.get("up", "0"),
                        "down": hosts.attrib.get("down", "0"),
                        "total": hosts.attrib.get("total", "0")
                    }

            # ===== PARSE HOSTS =====
            for host in root.findall("host"):
                host_data = self._parse_host(host)
                results["hosts"].append(host_data)

            return results

        except Exception as e:
            import traceback
            return {
                "error": True,
                "message": f"XML parsing error: {str(e)}",
                "traceback": traceback.format_exc()
            }

    def _parse_host(self, host) -> Dict:
        """Parse a single host element."""
        host_data = {
            "starttime": host.attrib.get("starttime", ""),
            "endtime": host.attrib.get("endtime", ""),
            "status": {},
            "addresses": [],
            "hostnames": [],
            "ports": [],
            "extraports": [],
            "times": {}
        }

        # ===== STATUS =====
        status = host.find("status")
        if status is not None:
            host_data["status"] = {
                "state": status.attrib.get("state", ""),
                "reason": status.attrib.get("reason", ""),
                "reason_ttl": status.attrib.get("reason_ttl", "")
            }

        # ===== ADDRESSES =====
        for address in host.findall("address"):
            host_data["addresses"].append({
                "addr": address.attrib.get("addr", ""),
                "addrtype": address. attrib.get("addrtype", ""),
                "vendor": address.attrib.get("vendor", "")
            })

        # ===== HOSTNAMES =====
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hostname in hostnames.findall("hostname"):
                host_data["hostnames"].append({
                    "name": hostname. attrib.get("name", ""),
                    "type": hostname.attrib.get("type", "")
                })

        # ===== PORTS =====
        ports_elem = host.find("ports")
        if ports_elem is not None:
            # EXTRAPORTS
            for extraports in ports_elem.findall("extraports"):
                ep_data = {
                    "state": extraports.attrib.get("state", ""),
                    "count": extraports.attrib.get("count", ""),
                    "reasons": []
                }

                for extrareasons in extraports.findall("extrareasons"):
                    ep_data["reasons"].append({
                        "reason": extrareasons.attrib.get("reason", ""),
                        "count": extrareasons.attrib. get("count", ""),
                        "proto": extrareasons.attrib.get("proto", ""),
                        "ports": extrareasons.attrib.get("ports", "")
                    })

                host_data["extraports"].append(ep_data)

            # INDIVIDUAL PORTS
            for port in ports_elem.findall("port"):
                port_data = self._parse_port(port)
                host_data["ports"].append(port_data)

        # ===== TIMES =====
        times = host.find("times")
        if times is not None:
            host_data["times"] = {
                "srtt": times. attrib.get("srtt", ""),
                "rttvar": times.attrib.get("rttvar", ""),
                "to": times.attrib. get("to", "")
            }

        return host_data

    def _parse_port(self, port) -> Dict:
        """Parse a single port element."""
        port_data = {
            "protocol": port.attrib.get("protocol", ""),
            "portid":  port.attrib.get("portid", ""),
            "state": {},
            "service": {},
            "scripts": []
        }

        # ===== STATE =====
        state = port. find("state")
        if state is not None:
            port_data["state"] = {
                "state": state.attrib. get("state", ""),
                "reason": state.attrib. get("reason", ""),
                "reason_ttl": state. attrib.get("reason_ttl", ""),
                "reason_ip": state.attrib.get("reason_ip", "")
            }

        # ===== SERVICE =====
        service = port.find("service")
        if service is not None:
            port_data["service"] = {
                "name": service.attrib.get("name", ""),
                "product": service.attrib.get("product", ""),
                "version": service.attrib.get("version", ""),
                "extrainfo": service. attrib.get("extrainfo", ""),
                "ostype":  service.attrib.get("ostype", ""),
                "method": service.attrib.get("method", ""),
                "conf": service.attrib.get("conf", ""),
                "cpe": []
            }

            # CPE elements
            for cpe in service. findall("cpe"):
                if cpe.text:
                    port_data["service"]["cpe"].append(cpe.text)

        # ===== SCRIPTS =====
        for script in port.findall("script"):
            script_data = self._parse_script(script)
            port_data["scripts"].append(script_data)

        return port_data

    def _parse_script(self, script) -> Dict:
        """
        Parse NSE script output with complete element extraction.

        Extracts:
        - Script ID (from 'id' attribute)
        - Script output (from 'output' attribute)
        - All <elem> subnodes (with or without 'key' attribute)
        - All <table> subnodes (nested structures)
        """
        script_data = {
            "id": script.attrib.get("id", ""),
            "output": script.attrib.get("output", ""),
            "elements": [],
            "tables": []
        }

        # ===== ELEM tags (key-value pairs or standalone values) =====
        # This extracts ALL <elem> subnodes, including:
        # - <elem key="somekey">somevalue</elem>  (keyed element)
        # - <elem>somevalue</elem>                (non-keyed element)
        for elem in script.findall("elem"):
            key = elem.attrib.get("key", "")  # Empty string if no key attribute
            value = elem.text if elem.text else ""  # Text content of elem

            script_data["elements"].append({
                "key": key,
                "value": value
            })

        # ===== TABLE tags (nested structures) =====
        for table in script.findall("table"):
            table_data = self._parse_script_table(table)
            script_data["tables"].append(table_data)

        return script_data

    def _parse_script_table(self, table, depth=0) -> Dict:
        """Recursively parse script tables."""
        if depth > 10:  # Prevent infinite recursion
            return {}

        table_data = {
            "key": table.attrib.get("key", ""),
            "elements": [],
            "tables": []
        }

        # Parse elements in this table
        for elem in table.findall("elem"):
            key = elem.attrib.get("key", "")
            value = elem.text if elem.text else ""

            table_data["elements"].append({
                "key": key,
                "value": value
            })

        # Parse nested tables
        for nested_table in table.findall("table"):
            nested_data = self._parse_script_table(nested_table, depth + 1)
            table_data["tables"].append(nested_data)

        return table_data

    def _format_report(self, scan_results: Dict) -> str:
        """Format comprehensive scan results into detailed markdown report."""
        if scan_results. get("error"):
            error_msg = f"⚠️ **Scan Error:** {scan_results.get('message')}"
            if scan_results.get('traceback'):
                error_msg += f"\n\n**Debug Info:**\n```\n{scan_results['traceback']}\n```"
            return error_msg

        report = []
        report.append("# 🔍 Nmap Scan Report\n")

        # ===== SCAN INFORMATION =====
        info = scan_results.get("scan_info", {})

        report.append(f"**Command:** `{info.get('args', 'N/A')}`")
        report.append(f"**Scanner:** {info.get('scanner', 'nmap')} v{info.get('version', 'unknown')}")
        report.append(f"**Scan Type:** {scan_results.get('scan_type', 'unknown')}")

        # Timing information
        if info.get('startstr'):
            report.append(f"**Start Time:** {info['startstr']}")

        if info.get('finished') and info['finished'].get('timestr'):
            report.append(f"**End Time:** {info['finished']['timestr']}")

        if info.get('finished') and info['finished'].get('elapsed'):
            report.append(f"**Duration:** {info['finished']['elapsed']} seconds")
        elif scan_results.get('actual_duration'):
            report.append(f"**Duration:** {scan_results['actual_duration']}")

        # Scan type details
        if info.get('scaninfo'):
            si = info['scaninfo']
            report.append(f"**Scan Method:** {si.get('type', 'N/A')} scan on {si.get('protocol', 'N/A')}")
            if si.get('numservices'):
                report.append(f"**Ports Scanned:** {si['numservices']}")

        # Host statistics
        if info.get('hosts'):
            h = info['hosts']
            report.append(f"**Hosts:** {h.get('up', '0')} up, {h.get('down', '0')} down, {h.get('total', '0')} total")

        # Summary
        if info.get('finished') and info['finished'].get('summary'):
            report.append(f"\n_{info['finished']['summary']}_")

        report.append("\n---\n")

        # ===== HOSTS =====
        for host_idx, host in enumerate(scan_results.get("hosts", []), 1):
            self._format_host(report, host, host_idx)

        return "\n".join(report)

    def _format_host(self, report: List[str], host: Dict, host_idx: int):
        """Format a single host's complete information."""

        # ===== HOST HEADER =====
        ip = "unknown"
        if host.get("addresses"):
            for addr in host["addresses"]:
                if addr.get("addrtype") == "ipv4":
                    ip = addr. get("addr", "unknown")
                    break

        report.append(f"## 🖥️ Host {host_idx}:  {ip}\n")

        # ===== STATUS =====
        status = host.get("status", {})
        status_line = f"**Status:** {status.get('state', 'unknown').upper()}"

        # Add latency if available
        if host.get("times") and host["times"].get("srtt"):
            try:
                latency_ms = float(host["times"]["srtt"]) / 1000
                status_line += f" ({latency_ms:.3f}s latency)"
            except:
                pass

        report.append(status_line)

        if status.get("reason"):
            reason_line = f"**Reason:** {status['reason']}"
            if status.get("reason_ttl"):
                reason_line += f" (TTL: {status['reason_ttl']})"
            report.append(reason_line)

        report.append("")

        # ===== ADDRESSES =====
        if host.get("addresses") and len(host["addresses"]) > 0:
            report.append("**Addresses:**")
            for addr in host["addresses"]:
                addr_line = f"- {addr. get('addr', 'N/A')} ({addr.get('addrtype', 'N/A')})"
                if addr.get("vendor"):
                    addr_line += f" - {addr['vendor']}"
                report.append(addr_line)
            report.append("")

        # ===== HOSTNAMES =====
        if host.get("hostnames") and len(host["hostnames"]) > 0:
            report.append("**Hostnames:**")
            for hostname in host["hostnames"]:
                report.append(f"- {hostname.get('name', 'N/A')} (type: {hostname.get('type', 'N/A')})")
            report.append("")

        # ===== TIMING DETAILS =====
        if host.get("times"):
            times = host["times"]
            if times.get("srtt") or times.get("rttvar"):
                report.append("**Network Timing:**")
                if times. get("srtt"):
                    try:
                        srtt_ms = float(times["srtt"]) / 1000
                        report.append(f"- Smoothed RTT: {srtt_ms:. 3f}s")
                    except:
                        report.append(f"- Smoothed RTT: {times['srtt']} μs")
                if times.get("rttvar"):
                    report.append(f"- RTT Variance: {times['rttvar']} μs")
                if times.get("to"):
                    try:
                        to_ms = float(times["to"]) / 1000
                        report. append(f"- Timeout:  {to_ms:.3f}s")
                    except:
                        report.append(f"- Timeout: {times['to']} μs")
                report.append("")

        # ===== EXTRAPORTS (Filtered/Closed Summary) =====
        if host. get("extraports"):
            for ep in host["extraports"]:
                state = ep.get("state", "unknown")
                count = ep. get("count", "0")
                report.append(f"**Not shown:** {count} {state} ports")

                if ep.get("reasons"):
                    for reason in ep["reasons"]:
                        reason_text = f"- {reason.get('count', '0')} ports {state} due to **{reason.get('reason', 'unknown')}**"
                        if reason.get("ports"):
                            # Truncate if port list is too long
                            ports = reason['ports']
                            if len(ports) > 100:
                                ports = ports[: 100] + "..."
                            reason_text += f" (ports: {ports})"
                        report.append(reason_text)
            report.append("")

        # ===== PORT SUMMARY =====
        ports = host.get("ports", [])
        if ports:
            open_ports = [p for p in ports if p. get("state", {}).get("state") == "open"]
            closed_ports = [p for p in ports if p.get("state", {}).get("state") == "closed"]
            filtered_ports = [p for p in ports if p.get("state", {}).get("state") == "filtered"]

            report.append("### 📊 Port Summary\n")
            if open_ports:
                report. append(f"- **Open:** {len(open_ports)}")
            if closed_ports:
                report.append(f"- **Closed:** {len(closed_ports)}")
            if filtered_ports:
                report.append(f"- **Filtered:** {len(filtered_ports)}")
            report.append("")

            # ===== OPEN PORTS TABLE =====
            if open_ports:
                report.append("### 🔓 Open Ports\n")
                report.append("| Port | State | Service | Version |")
                report.append("|------|-------|---------|---------|")

                for port in open_ports:
                    portid = port.get("portid", "? ")
                    protocol = port.get("protocol", "?")
                    state = port.get("state", {}).get("state", "?")
                    svc = port.get("service", {})

                    service_name = svc.get("name", "unknown")

                    # Build version string
                    version_parts = []
                    if svc.get("product"):
                        version_parts. append(svc["product"])
                    if svc.get("version"):
                        version_parts.append(svc["version"])
                    if svc.get("extrainfo"):
                        version_parts. append(f"({svc['extrainfo']})")

                    version_str = " ".join(version_parts) if version_parts else "-"

                    report.append(f"| **{portid}/{protocol}** | {state} | {service_name} | {version_str} |")

                report.append("")

                # ===== DETAILED PORT INFORMATION =====
                report.append("### 📋 Detailed Port Information\n")

                for port in open_ports:
                    self._format_port_detailed(report, port)

    def _format_port_detailed(self, report: List[str], port: Dict):
        """Format detailed information for a single port."""
        portid = port.get("portid", "? ")
        protocol = port.get("protocol", "?")
        state_info = port.get("state", {})
        svc = port.get("service", {})

        # Port header
        service_name = svc.get("name", "unknown")
        report.append(f"#### Port {portid}/{protocol} - {service_name}\n")

        # State information
        state = state_info.get("state", "unknown")
        reason = state_info.get("reason", "")
        reason_ttl = state_info.get("reason_ttl", "")

        state_line = f"**State:** {state}"
        if reason:
            state_line += f" (reason: {reason}"
            if reason_ttl:
                state_line += f", TTL: {reason_ttl}"
            state_line += ")"
        report.append(state_line)

        # Service details
        if svc.get("product"):
            report.append(f"**Product:** {svc['product']}")

        if svc.get("version"):
            report.append(f"**Version:** {svc['version']}")

        if svc.get("extrainfo"):
            report.append(f"**Extra Info:** {svc['extrainfo']}")

        if svc.get("ostype"):
            report.append(f"**OS Type:** {svc['ostype']}")

        if svc.get("method"):
            method_line = f"**Detection Method:** {svc['method']}"
            if svc.get("conf"):
                method_line += f" (confidence: {svc['conf']})"
            report.append(method_line)

        # CPE identifiers
        if svc.get("cpe") and len(svc["cpe"]) > 0:
            report. append(f"**CPE:**")
            for cpe in svc["cpe"]:
                report.append(f"  - `{cpe}`")

        # Script results
        if port.get("scripts") and len(port["scripts"]) > 0:
            report. append("\n**🔧 NSE Script Results:**\n")

            for script in port["scripts"]:
                self._format_script_output(report, script)

        report.append("")

    def _format_script_output(self, report: List[str], script: Dict):
        """
        Format NSE script output with complete detail extraction.

        Displays:
        - Script ID as header
        - Script output attribute (main text)
        - All elem subnodes (both keyed and non-keyed)
        - All nested table structures
        """
        script_id = script.get("id", "unknown")
        output = script.get("output", "").strip()

        # Script header
        report.append(f"##### 📜 {script_id}\n")

        # Main output text (from 'output' attribute)
        if output:
            # For single-line output, use italics
            if "\n" not in output and len(output) < 150:
                report.append(f"_{output}_\n")
            else:
                # Multi-line or long output in code block
                report.append("```")
                report.append(output)
                report.append("```\n")

        # Structured elements (from <elem> subnodes)
        # This section displays ALL elem elements, including:
        # - Elements with keys: <elem key="redirect_url">http://...</elem>
        # - Elements without keys: <elem>Microsoft-HTTPAPI/2.0</elem>
        elements = script.get("elements", [])
        if elements and len(elements) > 0:
            report.append("**Details:**\n")

            for elem in elements:
                key = elem.get("key", "")
                value = elem.get("value", "")

                if key:
                    # Element with key attribute - format as key: value
                    # Special formatting for specific keys
                    if "redirect" in key.lower() or "url" in key.lower():
                        report.append(f"- 🔗 **{key.replace('_', ' ').title()}:** `{value}`")
                    elif key in ["title", "server", "header"]:
                        report.append(f"- **{key.title()}:** {value}")
                    elif "cve" in key.lower():
                        report.append(f"- 🚨 **{key.upper()}:** {value}")
                    else:
                        report.append(f"- **{key.replace('_', ' ').title()}:** {value}")
                else:
                    # Element without key attribute - just display the value
                    report.append(f"- {value}")

            report.append("")

        # Tables (nested structures from <table> subnodes)
        tables = script.get("tables", [])
        if tables and len(tables) > 0:
            for table in tables:
                self._format_script_table(report, table, indent=0)

    def _format_script_table(self, report: List[str], table: Dict, indent:  int = 0):
        """Format script tables recursively."""
        indent_str = "  " * indent

        # Table header
        table_key = table.get("key", "")
        if table_key:
            report.append(f"\n{indent_str}**{table_key. replace('_', ' ').title()}:**\n")

        # Table elements
        for elem in table.get("elements", []):
            key = elem.get("key", "")
            value = elem.get("value", "")

            if key:
                report.append(f"{indent_str}  - **{key}:** {value}")
            else:
                report.append(f"{indent_str}  - {value}")

        # Nested tables
        for nested_table in table.get("tables", []):
            self._format_script_table(report, nested_table, indent + 1)