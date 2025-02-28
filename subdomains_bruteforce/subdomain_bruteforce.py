import asyncio
import aiodns
import aiohttp
import aiofiles
import socket
import os
from tqdm.asyncio import tqdm

class SubdomainBruteForce:
    """Handles Brute-force subdomain enumeration using a wordlist."""

    def __init__(self, domain, wordlist_path, max_concurrent_tasks=50):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.output_dns_only = f"output/{self.domain}_dns_only.txt"
        self.output_dns_and_http = f"output/{self.domain}_dns_and_http.txt"
        self.found_dns_only = set()
        self.found_dns_and_http = set()
        self.total_processed = 0
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

    async def process_subdomain(self, word, progress_bar):
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
            progress_bar.update(1)
            progress_bar.set_postfix(dns=len(self.found_dns_only), http=len(self.found_dns_and_http))

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
        except Exception as e:
            print(f"[ERROR] Failed to load wordlist: {e}")
            return

        # Start brute force
        with tqdm(total=len(words), desc="Brute-forcing subdomains", ncols=100) as progress_bar:
            tasks = [self.process_subdomain(word, progress_bar) for word in words]
            await asyncio.gather(*tasks)

        print(f"\n✅ Scan complete! Found {len(self.found_dns_only)} DNS records and {len(self.found_dns_and_http)} active HTTP servers.")

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
