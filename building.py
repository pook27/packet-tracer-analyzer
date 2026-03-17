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

def update_xml(xml_file, json_data, output_xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"[!] Error reading XML: {e}")
        return False

    network = root.find("NETWORK")
    if network is None: return False

    # 1. MAP NAMES TO REF IDs
    name_to_ref = {}
    name_to_xml = {}
    for dev in network.findall(".//DEVICE"):
        eng = dev.find("ENGINE")
        name = eng.find("NAME").text
        ref = eng.find("SAVE_REF_ID").text
        name_to_ref[name] = ref
        name_to_xml[name] = dev

    # 2. SYNC CONFIGURATIONS (Restore this feature safely)
    for dev_json in json_data.get("devices", []):
        name = dev_json.get("name")
        config_lines = dev_json.get("config", [])
        
        if name in name_to_xml and config_lines:
            print(f"[*] Syncing Config: {name}")
            engine = name_to_xml[name].find("ENGINE")
            
            # Update Running Config
            rc = engine.find("RUNNINGCONFIG")
            if rc is None: rc = ET.SubElement(engine, "RUNNINGCONFIG")
            for child in list(rc): rc.remove(child) # Clear old
            for line in config_lines:
                ET.SubElement(rc, "LINE").text = line
            
            # Update Startup Config (Best practice to sync both)
            sc = engine.find("STARTUPCONFIG")
            if sc is None: sc = ET.SubElement(engine, "STARTUPCONFIG")
            for child in list(sc): sc.remove(child)
            for line in config_lines:
                ET.SubElement(sc, "LINE").text = line

    # 3. REBUILD LINKS
    links_node = network.find("LINKS")
    if links_node is None: links_node = ET.SubElement(network, "LINKS")
    for child in list(links_node): links_node.remove(child)

    for link in json_data.get("links", []):
        src = link["from_device"]
        dst = link["to_device"]
        
        if src not in name_to_ref or dst not in name_to_ref:
            continue

        print(f"[*] Wiring {src} <---> {dst}")
        l_node = ET.SubElement(links_node, "LINK")
        ET.SubElement(l_node, "TYPE").text = "eCopper"
        c_node = ET.SubElement(l_node, "CABLE")
        ET.SubElement(c_node, "LENGTH").text = "10"
        ET.SubElement(c_node, "FUNCTIONAL").text = "true"
        ET.SubElement(c_node, "FROM").text = name_to_ref[src]
        ET.SubElement(c_node, "PORT").text = link["from_port"]
        ET.SubElement(c_node, "TO").text = name_to_ref[dst]
        ET.SubElement(c_node, "PORT").text = link["to_port"]
        ET.SubElement(c_node, "TYPE").text = link.get("cable_type", "eCrossOver")

    # 4. REMOVE GEOVIEW (Prevention)
    geoview = root.find("GEOVIEW_GRAPHICSITEMS")
    if geoview is not None:
        for child in list(geoview): geoview.remove(child)

    # 5. WRITE WITHOUT HEADER (Packet Tracer preference)
    tree.write(output_xml_file, encoding="utf-8", xml_declaration=False)
    return True

def encrypt_pkt(xml_input, pkt_output):
    print(f"[*] Encrypting to {pkt_output}...")
    subprocess.run([PKA2XML_BIN, "-e", xml_input, pkt_output], capture_output=True)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 builder.py <output_file.pkt>")
        return
    
    if not os.path.exists(TEMP_XML_FILE) or not os.path.exists(INPUT_JSON):
        print("[!] Missing input files.")
        return

    mod_xml = "modified_analysis.xml"
    data = json.load(open(INPUT_JSON))
    
    if update_xml(TEMP_XML_FILE, data, mod_xml):
        encrypt_pkt(mod_xml, sys.argv[1])
        if os.path.exists(mod_xml): os.remove(mod_xml)

if __name__ == "__main__":
    main()