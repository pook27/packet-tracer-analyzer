import sys
import os
import subprocess
import xml.etree.ElementTree as ET
import json

# --- CONFIGURATION ---
def get_pka2xml_path():
    if getattr(sys, 'frozen', False):
        path = os.path.dirname(sys.executable)
    else:
        path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(path, "pka2xml")

PKA2XML_BIN = get_pka2xml_path()
TEMP_XML_FILE = "temp_analysis.xml"
INPUT_JSON = "analysis_output.json"

def update_vlan_database(engine, vlan_list):
    """Directly updates the <VLANS> XML tag, bypassing CLI/vlan.dat issues."""
    if not vlan_list:
        return

    # Find or create the <VLANS> tag
    vlans_node = engine.find("VLANS")
    if vlans_node is None:
        vlans_node = ET.SubElement(engine, "VLANS")
    
    # 1. Clear existing VLANs (optional: you could choose to append instead)
    # Clearing ensures the JSON is the "source of truth"
    for child in list(vlans_node):
        vlans_node.remove(child)

    # 2. Add Default VLANs (Good practice to keep these)
    # If your JSON doesn't include them, we re-add them to prevent errors
    defaults = {1, 1002, 1003, 1004, 1005}
    user_defined_ids = {int(v['number']) for v in vlan_list}
    
    # Add user VLANs
    for vlan in vlan_list:
        v_elem = ET.SubElement(vlans_node, "VLAN")
        v_elem.set("number", str(vlan["number"]))
        v_elem.set("name", vlan["name"])
        v_elem.set("rspan", "0") # Default value

    # Add back missing defaults if the user forgot them
    if 1 not in user_defined_ids:
        ET.SubElement(vlans_node, "VLAN", number="1", name="default", rspan="0")
    if 1002 not in user_defined_ids:
        ET.SubElement(vlans_node, "VLAN", number="1002", name="fddi-default", rspan="0")
    if 1003 not in user_defined_ids:
        ET.SubElement(vlans_node, "VLAN", number="1003", name="token-ring-default", rspan="0")
    if 1004 not in user_defined_ids:
        ET.SubElement(vlans_node, "VLAN", number="1004", name="fddinet-default", rspan="0")
    if 1005 not in user_defined_ids:
        ET.SubElement(vlans_node, "VLAN", number="1005", name="trnet-default", rspan="0")

def update_config_block(engine, tag_name, config_lines):
    config_node = engine.find(tag_name)
    if config_node is None:
        config_node = ET.SubElement(engine, tag_name)
    
    config_node.text = None
    for child in list(config_node):
        config_node.remove(child)
        
    for line_text in config_lines:
        line_elem = ET.SubElement(config_node, "LINE")
        if line_text:
            # URL Encode to fix "vlan 999" spaces
            line_elem.text = line_text
        else:
            line_elem.text = ""

def update_xml(xml_file, json_data, output_xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"[!] Error reading XML: {e}")
        return False

    devices_xml = root.findall(".//DEVICE")
    devices_json = json_data.get("devices", [])

    print(f"[*] Patching {len(devices_json)} devices...")

    for i, dev_json in enumerate(devices_json):
        if i >= len(devices_xml): break
        xml_device = devices_xml[i]
        engine = xml_device.find("ENGINE")
        if engine is None: continue

        # --- 1. Update Hostname ---
        if "name" in dev_json:
            name_node = engine.find("NAME")
            if name_node is not None: name_node.text = dev_json["name"]

        # --- 2. Update PC Settings ---
        pc_settings = dev_json.get("pc_settings", {})
        if pc_settings:
            gw = engine.find("GATEWAY")
            if gw is not None and "Gateway" in pc_settings: gw.text = pc_settings["Gateway"]
            dns = engine.find("DNS_CLIENT/SERVER_IP")
            if dns is not None and "DNS Server" in pc_settings: dns.text = pc_settings["DNS Server"]

        # --- 3. Update Ports ---
        xml_ports = xml_device.findall(".//PORT")
        json_ports = dev_json.get("ports", [])
        for j, p_json in enumerate(json_ports):
            if j < len(xml_ports):
                p_xml = xml_ports[j]
                if "ip" in p_json:
                    ip_node = p_xml.find("IP")
                    if ip_node is not None: ip_node.text = p_json["ip"]
                if "mask" in p_json:
                    mask_node = p_xml.find("SUBNET")
                    if mask_node is not None: mask_node.text = p_json["mask"]

        # --- 4. Update VLAN Database (NEW!) ---
        if "vlans" in dev_json:
            update_vlan_database(engine, dev_json["vlans"])

        # --- 5. Update Config ---
        if "config" in dev_json and isinstance(dev_json["config"], list):
            update_config_block(engine, "RUNNINGCONFIG", dev_json["config"])
            update_config_block(engine, "STARTUPCONFIG", dev_json["config"])

    tree.write(output_xml_file)
    print(f"[*] XML patched successfully: {output_xml_file}")
    return True

def encrypt_pkt(xml_input, pkt_output):
    if not os.path.exists(PKA2XML_BIN):
        print(f"[!] Error: {PKA2XML_BIN} not found.")
        return False
    print(f"[*] Encrypting to {pkt_output}...")
    result = subprocess.run([PKA2XML_BIN, "-e", xml_input, pkt_output], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] pka2xml failed:\n{result.stderr}")
        return False
    print(f"[+] Success! Created {pkt_output}")
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 builder.py <output_file.pkt>")
        return
    output_pkt = sys.argv[1]
    mod_xml = "modified_analysis.xml"
    if not os.path.exists(TEMP_XML_FILE):
        print(f"[!] Error: {TEMP_XML_FILE} not found. Run analyzer.py first.")
        return
    if not os.path.exists(INPUT_JSON):
        print(f"[!] Error: {INPUT_JSON} not found.")
        return

    if update_xml(TEMP_XML_FILE, json.load(open(INPUT_JSON)), mod_xml):
        encrypt_pkt(mod_xml, output_pkt)
        if os.path.exists(mod_xml): os.remove(mod_xml)

if __name__ == "__main__":
    main()