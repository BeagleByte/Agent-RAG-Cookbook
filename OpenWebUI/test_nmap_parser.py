#!/usr/bin/env python3
"""
Test script to verify nmap XML parsing with script elements
"""

import xml.etree.ElementTree as ET

# Your sample XML
xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.94SVN scan initiated Sun Dec 14 03:23:21 2025 as: nmap -nP -sCV -p- -T3 -oX 10.10.11.98.xml 10.10.11.98 -->
<nmaprun scanner="nmap" args="nmap -nP -sCV -p- -T3 -oX 10.10.11.98.xml 10.10.11.98" start="1765679001" startstr="Sun Dec 14 03:23:21 2025" version="7.94SVN" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="65535" services="1-65535"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="10.10.11.98" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1765679002" endtime="1765679293"><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="10.10.11.98" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><extraports state="filtered" count="65533">
<extrareasons reason="no-response" count="65533" proto="tcp" ports="1-79,81-5984,5986-65535"/>
</extraports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="nginx" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx</cpe></service><script id="http-title" output="Did not follow redirect to http://monitorsfour.htb/"><elem key="redirect_url">http://monitorsfour.htb/</elem>
</script></port>
<port protocol="tcp" portid="5985"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="Microsoft HTTPAPI httpd" version="2.0" extrainfo="SSDP/UPnP" ostype="Windows" method="probed" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service><script id="http-title" output="Not Found"><elem key="title">Not Found</elem>
</script><script id="http-server-header" output="Microsoft-HTTPAPI/2.0"><elem>Microsoft-HTTPAPI/2.0</elem>
</script></port>
</ports>
<times srtt="31150" rttvar="3176" to="100000"/>
</host>
<runstats><finished time="1765679293" timestr="Sun Dec 14 03:28:13 2025" summary="Nmap done at Sun Dec 14 03:28:13 2025; 1 IP address (1 host up) scanned in 292.08 seconds" elapsed="292.08" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""

def parse_script(script):
    """Parse NSE script output."""
    script_data = {
        "id": script.attrib.get("id", ""),
        "output": script.attrib.get("output", ""),
        "elements": [],
        "tables": []
    }

    # ===== ELEM tags (key-value pairs or standalone values) =====
    for elem in script.findall("elem"):
        key = elem.attrib.get("key", "")
        value = elem.text if elem.text else ""

        script_data["elements"].append({
            "key": key,
            "value": value
        })

    return script_data

# Parse XML
root = ET.fromstring(xml_data)

# Find all ports
for host in root.findall("host"):
    ports_elem = host.find("ports")
    if ports_elem:
        for port in ports_elem.findall("port"):
            portid = port.attrib.get("portid")
            print(f"\n=== Port {portid} ===")

            # Find all scripts
            scripts = port.findall("script")
            print(f"Found {len(scripts)} script(s)")

            for script in scripts:
                script_data = parse_script(script)
                print(f"\nScript ID: {script_data['id']}")
                print(f"Output: {script_data['output']}")
                print(f"Elements: {script_data['elements']}")

