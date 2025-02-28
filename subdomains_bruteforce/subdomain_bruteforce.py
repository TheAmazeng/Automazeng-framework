import asyncio
import aiodns
import aiohttp
import aiofiles
import socket
import os
import time

class SubdomainBruteForce:
    """Handles Brute-force subdomain enumeration using a wordlist."""

    def __init__(self, domain, wordlist_path, max_concurrent_tasks=20):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.output_dns_only = f"output/{self.domain}_dns_only.txt"
        self.output_dns_and_http = f"output/{self.domain}_dns_and_http.txt"
        self.found_dns_only = set()
        self.found_dns_and_http = set()
        self.total_processed = 0
        self.total_words = 0
        self.start_time = time.time()
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)

        os.makedirs("output", exist_ok=True)  # Ensure output directory exists

    async def initialize_resolver(self):
        """Initialize DNS resolver."""
        self.resolver = aiodns.DNSResolver(loop=asyncio.get_running_loop())

    async def resolve_subdomain(self, subdomain, retries=3):
        """Resolve DNS for a subdomain with retries."""
        for attempt in range(retries):
            try:
                await self.resolver.gethostbyname(subdomain, socket.AF_INET)
                return subdomain
            except (aiodns.error.DNSError, asyncio.TimeoutError):
                if attempt < retries - 1:
                    await asyncio.sleep(1)
        return None

    async def check_http_live(self, subdomain, retries=3):
        """Check if the subdomain has an active HTTP server with retries."""
        for attempt in range(retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{subdomain}", timeout=5) as response:
                        if response.status in [200, 301, 302]:
                            return subdomain
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < retries - 1:
                    await asyncio.sleep(1)
        return None

    async def process_subdomain(self, word):
        """Process a single subdomain: DNS check + HTTP check."""
        subdomain = f"{word}.{self.domain}"

        async with self.semaphore:
            resolved_subdomain = await self.resolve_subdomain(subdomain)
            if resolved_subdomain:
                self.found_dns_only.add(resolved_subdomain)
                await self.save_to_file(self.output_dns_only, resolved_subdomain)

                live_http_subdomain = await self.check_http_live(resolved_subdomain)
                if live_http_subdomain:
                    self.found_dns_and_http.add(live_http_subdomain)
                    await self.save_to_file(self.output_dns_and_http, live_http_subdomain)

            self.total_processed += 1

    async def run_bruteforce(self):
        """Run the brute-force process with a wordlist."""
        await self.initialize_resolver()

        # Clear previous output files
        open(self.output_dns_only, 'w').close()
        open(self.output_dns_and_http, 'w').close()

        # Load wordlist
        try:
            with open(self.wordlist_path, 'r') as f:
                words = [line.strip() for line in f.readlines()]
                self.total_words = len(words)
        except Exception as e:
            print(f"[ERROR] Failed to load wordlist: {e}")
            return

        # Start brute force
        last_update = time.time()
        tasks = []
        for word in words:
            tasks.append(self.process_subdomain(word))
            
            # Run in batches to avoid memory overuse
            if len(tasks) >= 20:
                await asyncio.gather(*tasks)
                tasks = []

            # Print progress update every 5 minutes
            if time.time() - last_update >= 300:
                self.print_progress()
                last_update = time.time()
        
        # Final batch
        if tasks:
            await asyncio.gather(*tasks)

        self.print_progress(final=True)
        print(f"\n✅ Scan complete! Found {len(self.found_dns_only)} DNS records and {len(self.found_dns_and_http)} active HTTP servers.")

    def print_progress(self, final=False):
        """Prints progress update every 5 minutes."""
        elapsed_time = int(time.time() - self.start_time)
        percentage = (self.total_processed / self.total_words) * 100 if self.total_words else 0
        status = "Final Report:" if final else "Progress Update:"  
        print(f"\n[{status}] {self.total_processed}/{self.total_words} ({percentage:.2f}%) completed | DNS: {len(self.found_dns_only)} | HTTP: {len(self.found_dns_and_http)} | Time: {elapsed_time}s")

    async def save_to_file(self, filename, data):
        """Save a single subdomain to an output file asynchronously."""
        try:
            async with aiofiles.open(filename, 'a') as f:
                await f.write(f"{data}\n")
        except Exception as e:
            print(f"[ERROR] Unable to save {data} to {filename}: {e}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Subdomain Brute-force Tool")
    parser.add_argument("domain", help="Target domain for brute force")
    parser.add_argument("wordlist", help="Path to subdomain wordlist")
    args = parser.parse_args()

    brute_forcer = SubdomainBruteForce(args.domain, args.wordlist)
    asyncio.run(brute_forcer.run_bruteforce())

if __name__ == "__main__":
    main()
