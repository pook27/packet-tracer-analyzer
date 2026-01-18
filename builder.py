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
    if not vlan_list: return
    vlans_node = engine.find("VLANS")
    if vlans_node is None: vlans_node = ET.SubElement(engine, "VLANS")
    
    for child in list(vlans_node): vlans_node.remove(child)

    user_defined_ids = {int(v['number']) for v in vlan_list}
    
    for vlan in vlan_list:
        v_elem = ET.SubElement(vlans_node, "VLAN")
        v_elem.set("number", str(vlan["number"]))
        v_elem.set("name", vlan["name"])
        v_elem.set("rspan", "0") 

    # Restore defaults
    defaults = {1: "default", 1002: "fddi-default", 1003: "token-ring-default", 1004: "fddinet-default", 1005: "trnet-default"}
    for num, name in defaults.items():
        if num not in user_defined_ids:
            ET.SubElement(vlans_node, "VLAN", number=str(num), name=name, rspan="0")

def update_config_block(engine, tag_name, config_lines):
    config_node = engine.find(tag_name)
    if config_node is None: config_node = ET.SubElement(engine, tag_name)
    config_node.text = None
    for child in list(config_node): config_node.remove(child)
    for line_text in config_lines:
        line_elem = ET.SubElement(config_node, "LINE")
        line_elem.text = line_text if line_text else ""

def update_xml(xml_file, json_data, output_xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"[!] Error reading XML: {e}")
        return False

    # --- FIX: Locate the NETWORK node first ---
    network_node = root.find("NETWORK")
    if network_node is None:
        print("[!] Error: Could not find <NETWORK> tag in XML.")
        return False

    devices_xml = network_node.findall(".//DEVICE")
    devices_json = json_data.get("devices", [])
    
    # --- BUILD NAME MAP (Name -> Index) ---
    name_to_index = {}
    for idx, dev_xml in enumerate(devices_xml):
        eng = dev_xml.find("ENGINE")
        if eng is not None:
            name_node = eng.find("NAME")
            if name_node is not None and name_node.text:
                name_to_index[name_node.text] = idx

    print(f"[*] Patching {len(devices_json)} devices...")

    for i, dev_json in enumerate(devices_json):
        if i >= len(devices_xml): break
        xml_device = devices_xml[i]
        engine = xml_device.find("ENGINE")
        if engine is None: continue

        if "name" in dev_json:
            name_node = engine.find("NAME")
            if name_node is not None: name_node.text = dev_json["name"]

        pc_settings = dev_json.get("pc_settings", {})
        if pc_settings:
            gw = engine.find("GATEWAY")
            if gw is not None and "Gateway" in pc_settings: gw.text = pc_settings["Gateway"]
            dns = engine.find("DNS_CLIENT/SERVER_IP")
            if dns is not None and "DNS Server" in pc_settings: dns.text = pc_settings["DNS Server"]

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

        if "vlans" in dev_json: update_vlan_database(engine, dev_json["vlans"])
        if "config" in dev_json and isinstance(dev_json["config"], list):
            update_config_block(engine, "RUNNINGCONFIG", dev_json["config"])
            update_config_block(engine, "STARTUPCONFIG", dev_json["config"])

    # --- REBUILD LINKS (Correct Hierarchy) ---
    print(f"[*] Rebuilding links...")
    
    # FIX: Find LINKS inside NETWORK, not ROOT
    links_xml = network_node.find("LINKS")
    if links_xml is None:
        links_xml = ET.SubElement(network_node, "LINKS")
    
    # Clear existing links to rebuild from JSON
    for l in list(links_xml): links_xml.remove(l)

    for link in json_data.get("links", []):
        try:
            # Resolve Source
            src_idx = -1
            if "from_device" in link:
                if link["from_device"] in name_to_index:
                    src_idx = name_to_index[link["from_device"]]
            elif "from_device_id" in link:
                src_idx = link["from_device_id"]

            # Resolve Dest
            dst_idx = -1
            if "to_device" in link:
                if link["to_device"] in name_to_index:
                    dst_idx = name_to_index[link["to_device"]]
            elif "to_device_id" in link:
                dst_idx = link["to_device_id"]
            
            if src_idx == -1 or dst_idx == -1:
                print(f"[!] Warning: Device not found for link. Skipping.")
                continue

            src_dev_xml = devices_xml[src_idx]
            dst_dev_xml = devices_xml[dst_idx]
            
            src_ref = src_dev_xml.find("ENGINE/SAVE_REF_ID").text
            dst_ref = dst_dev_xml.find("ENGINE/SAVE_REF_ID").text
            
            # Create Link Node
            l_node = ET.SubElement(links_xml, "LINK")
            ET.SubElement(l_node, "TYPE").text = link.get("link_type", "eCopper")
            
            c_node = ET.SubElement(l_node, "CABLE")
            ET.SubElement(c_node, "LENGTH").text = "50.0"
            ET.SubElement(c_node, "FUNCTIONAL").text = "true"
            ET.SubElement(c_node, "FROM").text = src_ref
            ET.SubElement(c_node, "PORT").text = link['from_port']
            ET.SubElement(c_node, "TO").text = dst_ref
            ET.SubElement(c_node, "PORT").text = link['to_port']
            ET.SubElement(c_node, "TYPE").text = link.get("cable_type", "eStraightThrough")
            
        except Exception as e:
            print(f"[!] Link Error: {e}")

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