import asyncio
import aiodns
import aiohttp
import socket
import os
import subprocess  # For fast file line counting in Termux
from tqdm.asyncio import tqdm

class SubdomainBruteForce:
    """Optimized Brute-force subdomain enumeration for Termux (low RAM usage & instant file writes)."""

    def __init__(self, domain, wordlist_path, max_concurrent_tasks=5):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.output_dns_only = f"output/{self.domain}_dns_only.txt"
        self.output_dns_and_http = f"output/{self.domain}_dns_and_http.txt"
        self.total_processed = 0
        self.dns_queries = 0
        self.http_queries = 0
        self.max_concurrent_tasks = max_concurrent_tasks
        self.lock = asyncio.Lock()  
        os.makedirs("output", exist_ok=True)  

    async def initialize_resolver(self):
        """Initialize DNS resolver."""
        loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=loop)

    async def resolve_subdomain(self, subdomain):
        """Resolve DNS for a subdomain with retries (ensuring counter correctness)."""
        for _ in range(2):  
            try:
                await self.resolver.gethostbyname(subdomain, socket.AF_INET)

                async with self.lock:  
                    self.dns_queries += 1

                return subdomain  
            except (aiodns.error.DNSError, asyncio.TimeoutError):
                await asyncio.sleep(0.5)  # Reduce delay to save time
        return None  

    async def check_http_live(self, subdomain):
        """Check if the subdomain has an active HTTP server."""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"http://{subdomain}", timeout=4) as response:
                    if response.status in [200, 301, 302]:  
                        async with self.lock:
                            self.http_queries += 1 
                        return subdomain
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return None  

    async def process_subdomain(self, subdomain, progress_bar):
        """Process a single subdomain: DNS check + HTTP check (counts from output files)."""
        resolved_subdomain = await self.resolve_subdomain(subdomain)
        if resolved_subdomain:
            await self.save_to_file(self.output_dns_only, resolved_subdomain)  

            live_http_subdomain = await self.check_http_live(resolved_subdomain)
            if live_http_subdomain:
                await self.save_to_file(self.output_dns_and_http, live_http_subdomain)  

        # Update counters every 10 subdomains (based on actual file contents)
        if self.total_processed % 10 == 0:
            self.dns_queries = self.count_lines(self.output_dns_only)
            self.http_queries = self.count_lines(self.output_dns_and_http)

        async with self.lock:  # Ensure safe update of progress tracking
            self.total_processed += 1
            progress_bar.update(1)
            progress_bar.set_postfix(dns=self.dns_queries, http=self.http_queries)

    async def run_bruteforce(self):
        """Run the brute-force process efficiently (low RAM usage)."""
        await self.initialize_resolver()

        # Clear previous output files
        open(self.output_dns_only, 'w').close()
        open(self.output_dns_and_http, 'w').close()

        try:
            with open(self.wordlist_path, 'r') as f:
                total_lines = sum(1 for _ in f)  # Get total line count
                f.seek(0)  # Reset file pointer

                with tqdm(total=total_lines, desc="Brute-forcing", ncols=80) as progress_bar:
                    batch = []  # Minimize memory by using a batch
                    for line in f:
                        subdomain = f"{line.strip()}.{self.domain}"
                        batch.append(subdomain)

                        if len(batch) >= self.max_concurrent_tasks:  # Process small batches
                            await asyncio.gather(*(self.process_subdomain(sub, progress_bar) for sub in batch))
                            batch.clear()  # Free memory immediately

                    if batch:  # Process remaining batch
                        await asyncio.gather(*(self.process_subdomain(sub, progress_bar) for sub in batch))

        except Exception as e:
            print(f"[ERROR] Failed to read wordlist: {e}")
            return

        print(f"\n✅ Scan complete! Results saved in the 'output/' folder.")

    async def save_to_file(self, filename, data):
        """Save a single subdomain to an output file asynchronously."""
        try:
            async with self.lock:  
                with open(filename, 'a', buffering=1) as f:
                    f.write(f"{data}\n")
                    f.flush()  
                    os.fsync(f.fileno())  
        except Exception as e:
            print(f"[ERROR] Unable to save {data}: {e}")

    def count_lines(self, filename):
        """Count the number of lines in a file (efficiently for Termux)."""
        try:
            result = subprocess.run(["wc", "-l", filename], capture_output=True, text=True)
            return int(result.stdout.split()[0])  # Extract the line count
        except Exception:
            return 0  # Return 0 if there's an error (file missing, etc.)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Subdomain Brute-force Tool (Optimized for Termux)")
    parser.add_argument("domain", help="Target domain for brute force")
    parser.add_argument("wordlist", help="Path to subdomain wordlist")
    parser.add_argument("--batch", type=int, default=5, help="Batch size for concurrency (default: 5 for Termux)")
    args = parser.parse_args()

    brute_forcer = SubdomainBruteForce(args.domain, args.wordlist, args.batch)
    asyncio.run(brute_forcer.run_bruteforce())

if __name__ == "__main__":
    main()
