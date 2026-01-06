# Packet Tracer Network Analyzer

A Python tool that reverse-engineers Cisco Packet Tracer (`.pkt`) files to extract network topology, configurations, and IP addresses into a readable JSON format.

## Features
- **Decrypts** `.pkt` files using `pka2xml`.
- **Analyzes** network topology (Routers, Switches, PCs).
- **Extracts** Running and Startup configurations.
- **Web View:** Launches a local web server to view the analysis in your browser.
- **WSL Support:** Works seamlessly in Windows Subsystem for Linux.

## Usage
1. Place your `.pkt` file in the `inputs/` folder.
2. Run the analyzer:
   ```bash
   python3 analyzer.py inputs/lab1.pkt
