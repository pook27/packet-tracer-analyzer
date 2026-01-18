import json
import sys

INPUT_TXT = "mission.txt"
OUTPUT_JSON = "mission.json"

def parse_script():
    tasks = []
    print(f"[*] Parsing {INPUT_TXT}...")
    
    if not try_read(INPUT_TXT): return

    with open(INPUT_TXT, "r") as f:
        for line_num, line in enumerate(f):
            parts = line.strip().split()
            # Skip empty lines or comments
            if not parts or parts[0].startswith("#"): continue
            
            cmd = parts[0].upper()
            
            try:
                # --- COMMAND MAPPING ---
                
                # Syntax: RESET [DeviceType]
                if cmd == "RESET":
                    tasks.append({
                        "action": "clear_config", 
                        "target_type": parts[1]
                    })
                    print(f"    Line {line_num+1}: Reset Config for {parts[1]}")
                    
                # Syntax: RING [DeviceType] [Subnet]
                elif cmd == "RING":
                    tasks.append({
                        "action": "topology_ring", 
                        "target_type": parts[1],
                        "subnet_base": parts[2]
                    })
                    print(f"    Line {line_num+1}: Build Ring for {parts[1]}")
                    
                # Syntax: OSPF [DeviceType] [AreaID]
                elif cmd == "OSPF":
                    tasks.append({
                        "action": "enable_ospf",
                        "target_type": parts[1],
                        "area": parts[2]
                    })
                    print(f"    Line {line_num+1}: Enable OSPF Area {parts[2]} for {parts[1]}")

                else:
                    print(f"[!] Warning Line {line_num+1}: Unknown command '{cmd}'")

            except IndexError:
                print(f"[!] Error Line {line_num+1}: Missing arguments for '{cmd}'")

    data = {"comment": "Generated from Text Script", "tasks": tasks}
    with open(OUTPUT_JSON, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[*] Success! Compiled instructions to {OUTPUT_JSON}")

def try_read(path):
    try:
        open(path, "r").close()
        return True
    except FileNotFoundError:
        print(f"[!] Error: {path} not found.")
        return False

if __name__ == "__main__":
    parse_script()