import json
import os
import sys
import subprocess
import ipaddress

# --- CONFIGURATION ---
INPUT_INVENTORY = "analysis_output.json"
OUTPUT_PKT = "OSPF_Ring.pkt"
MISSION_FILE = "mission.json"

class UniversalAgent:
    def __init__(self):
        self.data = self.load_json(INPUT_INVENTORY)
        self.devices = self.data.get("devices", [])
        self.links = [] 
        self.data["links"] = self.links 
        self.used_ports = {d["name"]: [] for d in self.devices}

    def load_json(self, path):
        if not os.path.exists(path):
            print(f"[!] Error: {path} not found.")
            sys.exit(1)
        with open(path, "r") as f: return json.load(f)

    def save_blueprint(self):
        with open(INPUT_INVENTORY, "w") as f: json.dump(self.data, f, indent=2)
        print(f"[*] Blueprint saved to {INPUT_INVENTORY}")

    def get_devices_by_type(self, type_filter):
        matches = []
        for d in self.devices:
            t_str = d.get("type", "").upper()
            n_str = d.get("name", "").upper()
            filter_up = type_filter.upper()
            if filter_up in t_str or filter_up in n_str:
                matches.append(d)
        return matches

    def wipe_config(self, target_type):
        targets = self.get_devices_by_type(target_type)
        print(f"[*] Wiping config for {len(targets)} {target_type}s...")
        for dev in targets:
            dev["config"] = [
                "version 15.1",
                "no service password-encryption",
                f"hostname {dev['name']}"
            ]

    def add_config_line(self, device, line):
        if "config" not in device: device["config"] = []
        device["config"].append(line)

    def get_next_port(self, device, port_prefix="GigabitEthernet0/"):
        for i in range(0, 5): 
            pname = f"{port_prefix}{i}"
            if pname not in self.used_ports[device["name"]]:
                self.used_ports[device["name"]].append(pname)
                return pname
        return f"{port_prefix}X"

    def build_ring(self, device_type, subnet_cidr):
        targets = self.get_devices_by_type(device_type)
        if len(targets) < 2:
            print("[!] Need at least 2 devices for a ring.")
            return

        print(f"[*] Building Ring Topology for {len(targets)} devices...")
        
        # Subnet Calculator (Using /30s from the base CIDR)
        base_net = ipaddress.IPv4Network(subnet_cidr)
        subnets = list(base_net.subnets(new_prefix=30))
        
        count = len(targets)
        for i in range(count):
            dev_a = targets[i]
            dev_b = targets[(i + 1) % count] # Wrap around
            
            if i >= len(subnets):
                print("[!] Error: Not enough subnets!")
                break

            current_subnet = subnets[i]
            ip_a = str(current_subnet.network_address + 1)
            ip_b = str(current_subnet.network_address + 2)
            mask = str(current_subnet.netmask)
            
            port_a = self.get_next_port(dev_a)
            port_b = self.get_next_port(dev_b)
            
            print(f"    Link: {dev_a['name']}({port_a}) <--> {dev_b['name']}({port_b}) [{current_subnet}]")
            
            self.data["links"].append({
                "from_device": dev_a["name"],
                "from_port": port_a,
                "to_device": dev_b["name"],
                "to_port": port_b,
                "link_type": "eCopper",
                "cable_type": "eCrossOver"
            })
            
            self.add_config_line(dev_a, f"interface {port_a}")
            self.add_config_line(dev_a, f" ip address {ip_a} {mask}")
            self.add_config_line(dev_a, " no shutdown")
            self.add_config_line(dev_a, " exit")

            self.add_config_line(dev_b, f"interface {port_b}")
            self.add_config_line(dev_b, f" ip address {ip_b} {mask}")
            self.add_config_line(dev_b, " no shutdown")
            self.add_config_line(dev_b, " exit")

    def configure_ospf(self, device_type, area_id):
        targets = self.get_devices_by_type(device_type)
        print(f"[*] configuring OSPF Area {area_id} on {len(targets)} devices...")
        for dev in targets:
            try:
                rid_num = int(''.join(filter(str.isdigit, dev['name'])))
            except:
                rid_num = self.devices.index(dev) + 1
            
            router_id = f"{rid_num}.{rid_num}.{rid_num}.{rid_num}"
            self.add_config_line(dev, "router ospf 1")
            self.add_config_line(dev, f" router-id {router_id}")
            self.add_config_line(dev, f" network 0.0.0.0 255.255.255.255 area {area_id}")
            self.add_config_line(dev, " exit")

    def run_mission(self, mission_path):
        mission = self.load_json(mission_path)
        print(f"--- STARTING MISSION: {mission.get('comment', 'Unknown')} ---")
        
        for task in mission.get("tasks", []):
            action = task.get("action")
            if action == "clear_config":
                self.wipe_config(task["target_type"])
            elif action == "topology_ring":
                self.build_ring(task["target_type"], task.get("subnet_base", "10.0.0.0/24"))
            elif action == "enable_ospf":
                self.configure_ospf(task["target_type"], task.get("area", 0))
            
        self.save_blueprint()
        print("\n[Agent] Calling Builder...")
        if os.path.exists("builder.py"):
            subprocess.run(["python3", "builder.py", OUTPUT_PKT])

if __name__ == "__main__":
    agent = UniversalAgent()
    agent.run_mission(MISSION_FILE)