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
    """Finds pka2xml binary dynamically (Script vs Compiled Exe)."""
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
    
    try:
        os.chmod(PKA2XML_BIN, 0o755)
    except:
        pass 

    print(f"[*] Decrypting {pkt_path}...")
    result = subprocess.run([PKA2XML_BIN, "-d", pkt_path, TEMP_XML_FILE], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[!] pka2xml failed:\n{result.stderr}")
        return False
    return True

def clean_line(text):
    """
    Cleans text and converts spaces to tabs for indentation.
    """
    if not text: return ""
    try: text = urllib.parse.unquote(text)
    except: pass
    
    text = text.replace('\\n', '') 
    text = text.replace('\r', '')
    text = text.rstrip() # Remove trailing whitespace
    
    # NEW: Replace leading space with a tab for JSON legibility
    if text.startswith(" "):
        return "    " + text.lstrip()
        
    return text

def parse_cisco_config(config_node):
    if config_node is None: return []
    lines = []
    
    # Method A: Structured <LINE> tags
    line_nodes = config_node.findall("LINE")
    if line_nodes:
        for line in line_nodes:
            if line.text: 
                val = clean_line(line.text)
                # Filter out lines that are strictly "!" (comments/spacers)
                if val.strip() != "!":
                    lines.append(val)
        return lines
    
    # Method B: Flat Text
    if config_node.text:
        raw_text = config_node.text
        temp_lines = []
        if "\\n" in raw_text:
            temp_lines = [clean_line(l) for l in raw_text.split('\\n')]
        else:
            temp_lines = [clean_line(l) for l in raw_text.splitlines()]
            
        # Filter '!' lines here as well
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

    if not config_lines:
        for file_node in device_node.findall(".//FILE"):
            name = file_node.attrib.get("name", "").lower()
            if "startup-config" in name or "running-config" in name:
                content = file_node.find("CONTENT") or file_node.find("FILE_CONTENT/CONFIG")
                if content is not None:
                    if content.find("LINE") is not None:
                         config_lines = parse_cisco_config(content)
                    elif content.text:
                         raw = content.text
                         try: raw = urllib.parse.unquote(raw)
                         except: pass
                         
                         temp_lines = []
                         if "\\n" in raw: temp_lines = [l.strip() for l in raw.split('\\n')]
                         else: temp_lines = [l.strip() for l in raw.splitlines()]
                         
                         # Apply cleaning and filtering
                         config_lines = []
                         for l in temp_lines:
                             cleaned = clean_line(l)
                             if cleaned.strip() != "!":
                                 config_lines.append(cleaned)
                         
                if config_lines: break
    return config_lines

def extract_pc_settings(device_node):
    settings = {}
    engine = device_node.find("ENGINE")
    if engine is None: return settings
    gw = engine.find("GATEWAY")
    if gw is not None and gw.text: settings["Gateway"] = gw.text
    dns = engine.find("DNS_CLIENT/SERVER_IP")
    if dns is not None and dns.text: settings["DNS Server"] = dns.text
    ipv6_gw = engine.find("GATEWAYV6")
    if ipv6_gw is not None and ipv6_gw.text: settings["IPv6 Gateway"] = ipv6_gw.text
    return settings

def parse_topology(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] XML Parsing Error: {e}")
        return None

    network_data = {"meta": {}, "devices": []}
    version = root.find("VERSION")
    if version is not None: network_data["meta"]["pt_version"] = version.text

    print(f"[*] Scanning XML for devices...")
    for device in root.findall(".//DEVICE"):
        engine = device.find("ENGINE")
        if engine is None: continue

        name = engine.find("NAME").text if engine.find("NAME") is not None else "Unnamed"
        model = engine.find("TYPE").attrib.get("model", "Unknown") if engine.find("TYPE") is not None else "Unknown"
        type_str = engine.find("TYPE").text if engine.find("TYPE") is not None else "Unknown"

        dev_info = {
            "name": name,
            "type": type_str,
            "model": model,
            "ports": [],
            "config": None,
            "pc_settings": {}
        }

        for port in device.findall(".//PORT"):
            p_data = {}
            mac = port.find("MACADDRESS")
            ip = port.find("IP")
            mask = port.find("SUBNET")
            name_node = port.find("NAME")
            if mac is not None:
                p_data["mac"] = mac.text
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
    return network_data

def generate_report(data):
    with open(JSON_OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[*] Analysis complete. Data saved to '{JSON_OUTPUT_FILE}'")

def start_web_server():
    """Starts a simple HTTP server with Port Conflicts + WSL support."""
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

    print(f"\n" + "="*50)
    print(f" STARTING LOCAL WEB SERVER")
    print(f"="*50)
    
    # 1. Find an Open Port
    port = DEFAULT_PORT
    httpd = None
    retries = 20
    
    while retries > 0:
        try:
            httpd = socketserver.TCPServer(("", port), QuietHandler)
            break
        except OSError as e:
            if e.errno == 98 or e.errno == 10048: # Address in use (Linux/Win)
                port += 1
                retries -= 1
            else:
                raise e
    
    if httpd is None:
        print(f"[!] Could not find an open port after 20 tries.")
        return

    url = f"http://localhost:{port}/{JSON_OUTPUT_FILE}"
    print(f"[+] Server running at: http://localhost:{port}")
    print(f"[+] Opening browser to: {url}")
    print(f"[*] Press CTRL+C to stop the server and exit.")
    
    # 2. Open Browser (WSL Safe Mode)
    is_wsl = False
    if hasattr(os, 'uname'):
        if "microsoft" in os.uname().release.lower():
            is_wsl = True
            
    if is_wsl:
        try:
            subprocess.run(["powershell.exe", "-c", f"Start-Process '{url}'"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            webbrowser.open(url)
    else:
        webbrowser.open(url)
    
    # 3. Start Server Loop
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping server. Goodbye!")
        httpd.server_close()

def main():
    if len(sys.argv) < 2:
        print("Usage: ./net-analyzer <input_file.pkt>")
        if len(sys.argv) < 2:
            input("\nPress Enter to exit...") 
            return

    pkt_file = sys.argv[1]
    
    if decrypt_pkt(pkt_file):
        data = parse_topology(TEMP_XML_FILE)
        if data:
            generate_report(data)
            if os.path.exists(TEMP_XML_FILE):
                os.remove(TEMP_XML_FILE)
            start_web_server()

if __name__ == "__main__":
    main()