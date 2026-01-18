import json
import os
import subprocess

INPUT_FILE = "analysis_output.json"

class NetworkArchitect:
    def __init__(self):
        self.data = self.load_data()
        self.inventory = {"Router": [], "Switch": [], "PC": []}
        self.ip_cursor = 10 # Start PC IPs at .10

    def load_data(self):
        if not os.path.exists(INPUT_FILE):
            print(f"[!] Error: {INPUT_FILE} not found. Run analyzer first.")
            exit()
        with open(INPUT_FILE, "r") as f:
            return json.load(f)

    def discover_hardware(self):
        """Scans the JSON to categorize devices by type."""
        print("[*] Scanning hardware inventory...")
        # Reset inventory to ensure clean state
        self.inventory = {"Router": [], "Switch": [], "PC": []}
        
        for device in self.data.get("devices", []):
            name = device.get("name", "Unknown")
            dtype = device.get("type", "Unknown")
            
            # Convert to upper case for robust matching
            n_up = name.upper()
            t_up = dtype.upper()
            
            if "ROUTER" in t_up or "ROUTER" in n_up:
                self.inventory["Router"].append(name)
            elif "SWITCH" in t_up or "SWITCH" in n_up:
                self.inventory["Switch"].append(name)
            # FIX: Check NAME for PC, and also include Laptop/Server
            elif "PC" in t_up or "COMPUTER" in t_up or "PC" in n_up or "LAPTOP" in t_up:
                self.inventory["PC"].append(name)
        
        print(f"    Found: {len(self.inventory['Router'])} Routers, "
              f"{len(self.inventory['Switch'])} Switches, "
              f"{len(self.inventory['PC'])} PCs.")

    def plan_network(self):
        """The AI Logic: Decides how to wire and config everything."""
        if not self.inventory["Router"] or not self.inventory["Switch"]:
            print("[!] Error: Need at least 1 Router and 1 Switch.")
            return

        router_name = self.inventory["Router"][0]
        switch_name = self.inventory["Switch"][0]
        
        print(f"[*] Designating {router_name} as Gateway (192.168.1.1)")
        
        # 1. Configure Router (Gateway)
        self.configure_device(router_name, [
            "hostname Gateway_R1",
            "interface GigabitEthernet0/0",
            " ip address 192.168.1.1 255.255.255.0",
            " no shutdown",
            " exit"
        ])

        # 2. Connect Router <-> Switch
        self.add_link(router_name, "GigabitEthernet0/0", 
                      switch_name, "GigabitEthernet0/1")

        # 3. Configure Switch
        self.configure_device(switch_name, [
            "hostname Core_SW1",
            "vlan 10",
            " name STAFF",
            " exit"
        ])

        # 4. Connect & Config ALL PCs found
        port_cursor = 1
        for pc_name in self.inventory["PC"]:
            pc_ip = f"192.168.1.{self.ip_cursor}"
            print(f"[*] Provisioning {pc_name} with IP {pc_ip}")
            
            # Link PC <-> Switch
            sw_port = f"FastEthernet0/{port_cursor}"
            self.add_link(pc_name, "FastEthernet0", switch_name, sw_port)
            
            # Config PC (Gateway + IP)
            self.configure_pc(pc_name, pc_ip, "192.168.1.1")
            
            # Increment counters
            self.ip_cursor += 1
            port_cursor += 1

    def configure_device(self, device_name, config_lines):
        # Find device in data list
        for dev in self.data["devices"]:
            if dev["name"] == device_name:
                dev["config"] = config_lines
                return

    def configure_pc(self, device_name, ip, gateway):
        for dev in self.data["devices"]:
            if dev["name"] == device_name:
                dev["pc_settings"] = {
                    "Gateway": gateway,
                    "DNS Server": "8.8.8.8"
                }
                # Set Interface IP (Port 0 is usually FastEthernet on PCs)
                if not dev.get("ports"): dev["ports"] = [{}]
                dev["ports"][0]["ip"] = ip
                dev["ports"][0]["mask"] = "255.255.255.0"

    def add_link(self, dev1, port1, dev2, port2):
        # Determine Cable Type (Router-Switch = Straight, PC-Switch = Straight)
        # Simplified: Just assume Straight for these standard connections
        self.data["links"].append({
            "from_device": dev1,
            "from_port": port1,
            "to_device": dev2,
            "to_port": port2,
            "link_type": "eCopper",
            "cable_type": "eStraightThrough"
        })

    def save_blueprint(self):
        with open(INPUT_FILE, "w") as f:
            json.dump(self.data, f, indent=2)
        print(f"[*] Blueprint updated. Ready for Builder.")

def main():
    agent = NetworkArchitect()
    agent.discover_hardware()
    agent.plan_network()
    agent.save_blueprint()
    
    # Auto-run builder?
    print("\n[?] Running Builder...")
    subprocess.run(["python3", "builder.py", "AI_Configured.pkt"])

if __name__ == "__main__":
    main()