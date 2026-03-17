import json
import os
import sys

INPUT_JSON = "analysis_output.json"

class NetworkAgent:
    def __init__(self):
        if not os.path.exists(INPUT_JSON):
            print("[!] Run analyzer.py first.")
            sys.exit(1)
        with open(INPUT_JSON, "r") as f: self.data = json.load(f)
        if "links" not in self.data: self.data["links"] = []
        self.devices = {d["name"]: d for d in self.data["devices"]}

    def save(self):
        with open(INPUT_JSON, "w") as f: json.dump(self.data, f, indent=2)
        print("[*] Blueprint ready.")

    def add_config(self, dev_name, lines):
        if dev_name in self.devices:
            if "config" not in self.devices[dev_name]: self.devices[dev_name]["config"] = []
            self.devices[dev_name]["config"].extend(lines)

    def connect_routers(self):
        print("[*] Connecting R1 <-> R2")
        self.data["links"].append({
            "from_device": "R1", "from_port": "GigabitEthernet0/0",
            "to_device": "R2", "to_port": "GigabitEthernet0/0",
            "link_type": "eCopper", "cable_type": "eCrossOver"
        })
        
        # R1 Config
        self.add_config("R1", [
            "interface GigabitEthernet0/0",
            " ip address 10.0.0.1 255.255.255.252",
            " no shutdown", # Packet Tracer should read this and turn on power
            " exit"
        ])
        
        # R2 Config
        self.add_config("R2", [
            "interface GigabitEthernet0/0",
            " ip address 10.0.0.2 255.255.255.252",
            " no shutdown",
            " exit"
        ])

if __name__ == "__main__":
    agent = NetworkAgent()
    agent.connect_routers()
    agent.save()