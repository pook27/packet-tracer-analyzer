import sys
import os
import subprocess
import xml.etree.ElementTree as ET
import json
import urllib.parse
import webbrowser
import http.server
import socketserver

# --- CONFIGURATION ---
def get_pka2xml_path():
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(application_path, "pka2xml")

PKA2XML_BIN = get_pka2xml_path()
TEMP_XML_FILE = "temp_analysis.xml"
JSON_OUTPUT_FILE = "analysis_output.json"
DEFAULT_PORT = 8000

def decrypt_pkt(pkt_path):
    if not os.path.exists(pkt_path):
        print(f"[!] Error: Input file {pkt_path} not found.")
        return False
    if not os.path.exists(PKA2XML_BIN):
        print(f"[!] Error: {PKA2XML_BIN} tool not found.")
        return False
    try: os.chmod(PKA2XML_BIN, 0o755)
    except: pass 
    print(f"[*] Decrypting {pkt_path}...")
    result = subprocess.run([PKA2XML_BIN, "-d", pkt_path, TEMP_XML_FILE], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] pka2xml failed:\n{result.stderr}")
        return False
    return True

def clean_line(text):
    if not text: return ""
    try: text = urllib.parse.unquote(text)
    except: pass
    text = text.replace('\\n', '').replace('\r', '').rstrip()
    if text.startswith(" "): return "    " + text.lstrip()
    return text

def parse_cisco_config(config_node):
    if config_node is None: return []
    lines = []
    line_nodes = config_node.findall("LINE")
    if line_nodes:
        for line in line_nodes:
            if line.text: 
                val = clean_line(line.text)
                if val.strip() != "!": lines.append(val)
        return lines
    if config_node.text:
        raw_text = config_node.text
        temp_lines = []
        if "\\n" in raw_text: temp_lines = [clean_line(l) for l in raw_text.split('\\n')]
        else: temp_lines = [clean_line(l) for l in raw_text.splitlines()]
        return [l for l in temp_lines if l.strip() != "!"]
    return []

def extract_config_lines(device_node):
    config_lines = []
    engine = device_node.find("ENGINE")
    if engine is not None:
        run_conf = engine.find("RUNNINGCONFIG")
        if run_conf is not None: config_lines = parse_cisco_config(run_conf)
        if not config_lines:
            start_conf = engine.find("STARTUPCONFIG")
            if start_conf is not None: config_lines = parse_cisco_config(start_conf)
    return config_lines

def extract_pc_settings(device_node):
    settings = {}
    engine = device_node.find("ENGINE")
    if engine is None: return settings
    gw = engine.find("GATEWAY")
    if gw is not None and gw.text: settings["Gateway"] = gw.text
    dns = engine.find("DNS_CLIENT/SERVER_IP")
    if dns is not None and dns.text: settings["DNS Server"] = dns.text
    return settings

def parse_topology(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] XML Parsing Error: {e}")
        return None

    network_data = {"meta": {}, "devices": [], "links": []}
    version = root.find("VERSION")
    if version is not None: network_data["meta"]["pt_version"] = version.text

    print(f"[*] Scanning XML for devices...")
    
    # Map SAVE_REF_ID to internal Index
    ref_to_id = {}
    # Map internal Index to Device Name (for readable links)
    id_to_name = {}
    
    for i, device in enumerate(root.findall(".//DEVICE")):
        engine = device.find("ENGINE")
        if engine is None: continue

        name = engine.find("NAME").text if engine.find("NAME") is not None else "Unnamed"
        type_str = engine.find("TYPE").text if engine.find("TYPE") is not None else "Unknown"
        
        save_ref = engine.find("SAVE_REF_ID")
        if save_ref is not None:
            ref_to_id[save_ref.text] = i
        
        id_to_name[i] = name

        # Extract VLANs
        device_vlans = []
        vlans_node = engine.find("VLANS")
        if vlans_node is not None:
            for v_node in vlans_node.findall("VLAN"):
                v_num = v_node.attrib.get("number")
                v_name = v_node.attrib.get("name")
                if v_num:
                    device_vlans.append({"number": v_num, "name": v_name if v_name else f"VLAN{v_num}"})

        dev_info = {
            "id": i,
            "name": name,
            "type": type_str,
            "ports": [],
            "vlans": device_vlans,
            "config": None,
            "pc_settings": {}
        }

        for port in device.findall(".//PORT"):
            p_data = {}
            ip = port.find("IP")
            mask = port.find("SUBNET")
            name_node = port.find("NAME")
            if ip is not None and ip.text:
                p_data["ip"] = ip.text
                p_data["mask"] = mask.text if mask is not None else "/24"
            if name_node is not None:
                p_data["name"] = name_node.text
            dev_info["ports"].append(p_data)

        if any(x in type_str for x in ["Pc", "Server", "Printer", "Laptop"]):
            dev_info["pc_settings"] = extract_pc_settings(device)
            dev_info["config"] = "PC_MODE"
        else:
            dev_info["config"] = extract_config_lines(device)
        network_data["devices"].append(dev_info)

    # 2. Parse Links
    print(f"[*] Scanning XML for connections...")
    links_node = root.find("LINKS")
    if links_node is not None:
        for link in links_node.findall("LINK"):
            cable = link.find("CABLE")
            if cable is not None:
                l_type = link.find("TYPE").text if link.find("TYPE") is not None else "eCopper"
                c_type = cable.find("TYPE").text if cable.find("TYPE") is not None else "eStraightThrough"
                src_ref = cable.find("FROM").text
                dst_ref = cable.find("TO").text
                ports = cable.findall("PORT")
                src_port = ports[0].text if len(ports) > 0 else "Unknown"
                dst_port = ports[1].text if len(ports) > 1 else "Unknown"

                if src_ref in ref_to_id and dst_ref in ref_to_id:
                    src_id = ref_to_id[src_ref]
                    dst_id = ref_to_id[dst_ref]
                    
                    network_data["links"].append({
                        "from_device": id_to_name.get(src_id, "Unknown"), # Readable Name
                        "from_port": src_port,
                        "to_device": id_to_name.get(dst_id, "Unknown"),   # Readable Name
                        "to_port": dst_port,
                        "link_type": l_type,
                        "cable_type": c_type,
                        # We keep IDs just in case, but user doesn't need to look at them
                        "_debug_from_id": src_id,
                        "_debug_to_id": dst_id
                    })

    return network_data

def generate_report(data):
    with open(JSON_OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[*] Analysis complete. Data saved to '{JSON_OUTPUT_FILE}'")

def start_web_server():
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args): pass

    port = DEFAULT_PORT
    httpd = None
    retries = 20
    while retries > 0:
        try:
            httpd = socketserver.TCPServer(("", port), QuietHandler)
            break
        except OSError:
            port += 1
            retries -= 1
    
    if httpd is None: return

    url = f"http://localhost:{port}/{JSON_OUTPUT_FILE}"
    print(f"[+] Server running at: http://localhost:{port}")
    print(f"[+] Opening browser to: {url}")
    
    is_wsl = False
    if hasattr(os, 'uname') and "microsoft" in os.uname().release.lower():
        is_wsl = True
            
    if is_wsl:
        try:
            subprocess.run(["powershell.exe", "-c", f"Start-Process '{url}'"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (FileNotFoundError, OSError):
            webbrowser.open(url)
    else:
        webbrowser.open(url)
    
    try: httpd.serve_forever()
    except KeyboardInterrupt: httpd.server_close()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py <input_file.pkt>")
        return

    pkt_file = sys.argv[1]
    if decrypt_pkt(pkt_file):
        data = parse_topology(TEMP_XML_FILE)
        if data:
            generate_report(data)
            #start_web_server()

if __name__ == "__main__":
    main()