import json
import os
import sys

INPUT_JSON = "analysis_output.json"

class NetworkAgent:
    def __init__(self):
        if not os.path.exists(INPUT_JSON):
            print(f"[!] Error: {INPUT_JSON} not found. Run analyzer.py first.")
            sys.exit(1)
            
        with open(INPUT_JSON, "r") as f:
            self.data = json.load(f)
            
        if "links" not in self.data: self.data["links"] = []
        
        # Map device names to data
        self.devices = {d["name"]: d for d in self.data.get("devices", [])}
        print(f"[*] Agent loaded {len(self.devices)} devices.")

    def save(self):
        with open(INPUT_JSON, "w") as f:
            json.dump(self.data, f, indent=2)
        print(f"[*] Saved blueprint to {INPUT_JSON}")

    def get_device(self, name):
        return self.devices.get(name)

    # --- PORT MANAGEMENT ---

    def _get_used_ports(self, dev_name):
        used = set()
        for link in self.data["links"]:
            if link["from_device"] == dev_name: used.add(link["from_port"])
            if link["to_device"] == dev_name: used.add(link["to_port"])
        return used

    def get_free_port(self, dev_name):
        dev = self.get_device(dev_name)
        if not dev: return None
        
        used = self._get_used_ports(dev_name)
        
        # Priority: Gig -> Fast -> Serial
        candidates = []
        for i in range(0, 4): candidates.append(f"GigabitEthernet0/{i}")
        for i in range(1, 25): candidates.append(f"FastEthernet0/{i}")
        for i in range(0, 2): candidates.append(f"Serial0/{i}/{i}")
        
        for p in candidates:
            if p not in used: return p
        return None

    # --- CONFIGURATION HELPERS ---

    def add_config(self, dev_name, lines):
        dev = self.get_device(dev_name)
        # Safety: Only add config to IOS devices (Routers/Switches)
        # PCs typically have type "Pc" or "Server"
        dtype = dev.get("type", "").upper()
        if "PC" in dtype or "COMPUTER" in dtype or "SERVER" in dtype:
            print(f"[!] Skipping IOS config for non-IOS device: {dev_name}")
            return

        if "config" not in dev: dev["config"] = []
        dev["config"].extend(lines)

    # --- CORE ACTIONS ---

    def connect(self, dev1, dev2):
        p1 = self.get_free_port(dev1)
        p2 = self.get_free_port(dev2)
        
        if not p1 or not p2:
            print(f"[!] Error: No free ports on {dev1} or {dev2}")
            return None, None

        # Auto-Crossover Logic
        d1 = self.get_device(dev1)
        d2 = self.get_device(dev2)
        t1 = d1.get("type", "").upper()
        t2 = d2.get("type", "").upper()
        
        cable = "eStraightThrough"
        # Router-Router or Switch-Switch needs CrossOver
        if t1 == t2 or ("ROUTER" in t1 and "ROUTER" in t2): cable = "eCrossOver"

        self.data["links"].append({
            "from_device": dev1, "from_port": p1,
            "to_device": dev2, "to_port": p2,
            "link_type": "eCopper", "cable_type": cable
        })
        print(f"[*] Wired {dev1}:{p1} <---> {dev2}:{p2} ({cable})")

        # Wake up ports
        self.add_config(dev1, [f"interface {p1}", "no shutdown", "exit"])
        self.add_config(dev2, [f"interface {p2}", "no shutdown", "exit"])
        return p1, p2

    def set_ip(self, dev_name, port, ip, mask):
        print(f"[*] Setting IP on {dev_name} {port}: {ip}")
        self.add_config(dev_name, [
            f"interface {port}",
            f" ip address {ip} {mask}",
            " no shutdown",
            " exit"
        ])

    def enable_ospf(self, dev_name, process_id=1, area=0):
        print(f"[*] Enabling OSPF on {dev_name}")
        # Router ID generation logic
        try: rid = int(''.join(filter(str.isdigit, dev_name)))
        except: rid = 1
        router_id = f"{rid}.{rid}.{rid}.{rid}"
        
        self.add_config(dev_name, [
            f"router ospf {process_id}",
            f" router-id {router_id}",
            f" network 0.0.0.0 255.255.255.255 area {area}",
            " exit"
        ])

    # --- NEW SWITCHING METHODS ---

    def create_vlan(self, dev_name, vlan_id, name):
        print(f"[*] Creating VLAN {vlan_id} on {dev_name}")
        self.add_config(dev_name, [
            f"vlan {vlan_id}",
            f" name {name}",
            " exit"
        ])

    def config_trunk(self, dev_name, port):
        print(f"[*] Configuring Trunk on {dev_name}:{port}")
        # Generic trunk config safe for most PT switches
        self.add_config(dev_name, [
            f"interface {port}",
            " switchport mode trunk",
            " no shutdown",
            " exit"
        ])

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    agent = NetworkAgent()
    
    # SETUP: R1 <-> R2 (OSPF Backbone)
    #        R2 <-> S1 (Switched Network)
    
    # 1. Connect Devices
    p_r1_r2, p_r2_r1 = agent.connect("R1", "R2")
    p_r2_s1, p_s1_r2 = agent.connect("R2", "S1")

    # 2. Configure OSPF between Routers
    if p_r1_r2 and p_r2_r1:
        agent.set_ip("R1", p_r1_r2, "10.0.0.1", "255.255.255.252")
        agent.set_ip("R2", p_r2_r1, "10.0.0.2", "255.255.255.252")
        agent.enable_ospf("R1")
        agent.enable_ospf("R2")

    # 3. Configure Switch (THE TEST)
    # If this causes a crash, we know Switching logic is the culprit.
    if p_s1_r2:
        agent.create_vlan("S1", 10, "TEST_VLAN")
        agent.create_vlan("S1", 20, "GUEST_VLAN")
        agent.config_trunk("S1", p_s1_r2)

    agent.save()