import asyncio
import aiodns
import aiohttp
import socket
import os
from tqdm.asyncio import tqdm

class SubdomainBruteForce:
    """Handles Brute-force subdomain enumeration efficiently using a wordlist."""

    def __init__(self, domain, wordlist_path, max_concurrent_tasks=10):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.output_dns_only = f"output/{self.domain}_dns_only.txt"
        self.output_dns_and_http = f"output/{self.domain}_dns_and_http.txt"
        self.found_dns_only = set()
        self.found_dns_and_http = set()
        self.total_processed = 0
        self.dns_queries = 0
        self.http_queries = 0
        self.max_concurrent_tasks = max_concurrent_tasks
        self.lock = asyncio.Lock()  # Lock for counter safety
        os.makedirs("output", exist_ok=True)  # Ensure output directory exists

    async def initialize_resolver(self):
        """Initialize DNS resolver."""
        loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=loop)

    async def resolve_subdomain(self, subdomain):
        """Resolve DNS for a subdomain with retries."""
        for _ in range(3):  # 3 retries
            try:
                async with self.lock:
                    self.dns_queries += 1  # Safe counter increment
                await self.resolver.gethostbyname(subdomain, socket.AF_INET)
                return subdomain
            except (aiodns.error.DNSError, asyncio.TimeoutError):
                await asyncio.sleep(1)  # Retry delay
        return None  # ❌ DNS resolution failed

    async def check_http_live(self, subdomain):
        """Check if the subdomain has an active HTTP server."""
        for _ in range(2):  # 2 retries
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{subdomain}", timeout=5) as response:
                        if response.status in [200, 301, 302]:
                            async with self.lock:
                                self.http_queries += 1  # Safe counter increment
                            return subdomain
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(1)
        return None

    async def process_subdomain(self, subdomain, progress_bar):
        """Process a single subdomain: DNS check + HTTP check."""
        resolved_subdomain = await self.resolve_subdomain(subdomain)
        if resolved_subdomain:
            self.found_dns_only.add(resolved_subdomain)
            self.save_to_file(self.output_dns_only, resolved_subdomain)  # 🔥 Use synchronous writing

            live_http_subdomain = await self.check_http_live(resolved_subdomain)
            if live_http_subdomain:
                self.found_dns_and_http.add(live_http_subdomain)
                self.save_to_file(self.output_dns_and_http, live_http_subdomain)  # 🔥 Use synchronous writing

        async with self.lock:
            self.total_processed += 1  # Ensure safe increment

        progress_bar.update(1)
        progress_bar.set_postfix(dns=self.dns_queries, http=self.http_queries)

    async def run_bruteforce(self):
        """Run the brute-force process efficiently (streaming wordlist)."""
        await self.initialize_resolver()

        # Clear previous output files
        open(self.output_dns_only, 'w').close()
        open(self.output_dns_and_http, 'w').close()

        # Process the wordlist in **chunks** (streaming mode)
        batch = []
        batch_size = self.max_concurrent_tasks  # Small batch size for Termux stability

        try:
            with open(self.wordlist_path, 'r') as f:
                total_lines = sum(1 for _ in f)  # Get total line count efficiently
                f.seek(0)  # Reset file pointer

                with tqdm(total=total_lines, desc="Brute-forcing subdomains", ncols=100) as progress_bar:
                    for line in f:
                        subdomain = f"{line.strip()}.{self.domain}"
                        batch.append(subdomain)

                        if len(batch) >= batch_size:  # Process in small chunks
                            await asyncio.gather(*(self.process_subdomain(sub, progress_bar) for sub in batch))
                            batch.clear()  # Clear batch for next cycle

                    if batch:  # Process any remaining batch
                        await asyncio.gather(*(self.process_subdomain(sub, progress_bar) for sub in batch))

        except Exception as e:
            print(f"[ERROR] Failed to read wordlist: {e}")
            return

        print(f"\n✅ Scan complete! Found {len(self.found_dns_only)} DNS records and {len(self.found_dns_and_http)} active HTTP servers.")

    def save_to_file(self, filename, data):
        """Save a single subdomain to an output file (fixed for Termux)."""
        try:
            with open(filename, 'a') as f:  # 🔥 Use **synchronous** file writing
                f.write(f"{data}\n")
        except Exception as e:
            print(f"[ERROR] Unable to save {data} to {filename}: {e}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Subdomain Brute-force Tool (Optimized for Termux)")
    parser.add_argument("domain", help="Target domain for brute force")
    parser.add_argument("wordlist", help="Path to subdomain wordlist")
    parser.add_argument("--batch", type=int, default=10, help="Batch size for concurrency (default: 10 for Termux)")
    args = parser.parse_args()

    brute_forcer = SubdomainBruteForce(args.domain, args.wordlist, args.batch)
    asyncio.run(brute_forcer.run_bruteforce())

if __name__ == "__main__":
    main()
