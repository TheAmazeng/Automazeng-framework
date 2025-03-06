import argparse
import subprocess
import os
import socket
import time
import random

class SubdomainVulnScanner:
    def __init__(self, file_path, output_file):
        self.file_path = file_path
        self.output_file = output_file

    def resolve_subdomain(self, subdomain):
        """Resolve subdomain to IP address."""
        try:
            ip = socket.gethostbyname(subdomain)
            return subdomain, ip
        except:
            return subdomain, None

    def scan_ports_and_vulns(self, subdomain, ip):
        """Run Nmap port scan and vulnerability scan on an IP stealthily."""
        if not ip:
            return
        
        print(f"[*] Scanning {subdomain} ({ip})...")
        
        # Randomly choose stealth techniques
        source_port = random.choice([53, 123, 443, 8080])  # Common ports
        decoy_count = random.randint(3, 6)  # Random decoys
        data_length = random.choice([16, 32, 64])
        
        nmap_command = [
            "nmap", "-sS", "-p-", "-T2", "-Pn", "--open", "-sV", "--script=vuln",
            "--source-port", str(source_port), "-D", f"RND:{decoy_count}", "--data-length", str(data_length),
            "--disable-arp-ping", "-oN", "-", ip
        ]

        try:
            result = subprocess.run(nmap_command, text=True, capture_output=True)

            if result.returncode != 0:
                return

            # Save results
            with open(self.output_file, "a") as f:
                f.write(f"\n\n[SCAN RESULTS FOR {subdomain} ({ip})]\n")
                f.write(result.stdout)
                f.write("\n" + "=" * 80 + "\n")

            print(f"[+] Scan complete for {subdomain}. Results saved.")

        except:
            return

    def process_subdomains(self):
        """Read subdomains, resolve them, and scan for vulnerabilities sequentially."""
        if not os.path.exists(self.file_path):
            return

        with open(self.file_path, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]

        if not subdomains:
            return

        print(f"[*] Resolving and scanning {len(subdomains)} subdomains stealthily...")
        
        for subdomain in subdomains:
            sub, ip = self.resolve_subdomain(subdomain)
            self.scan_ports_and_vulns(sub, ip)
            time.sleep(random.randint(5, 15))  # Random delay for stealth

        print("[+] Scanning complete. Results saved in", self.output_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stealthy Subdomain Vulnerability Scanner")
    parser.add_argument("-f", "--file", required=True, help="File containing subdomains (one per line)")
    parser.add_argument("-o", "--output", required=True, help="Output file for scan results")
    args = parser.parse_args()

    scanner = SubdomainVulnScanner(args.file, args.output)
    scanner.process_subdomains()

