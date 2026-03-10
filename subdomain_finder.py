#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║           SUBDOMAIN FINDER - DNS Reconnaissance Tool     ║
║                   Author: Security Toolkit               ║
╚══════════════════════════════════════════════════════════╝

Definition:
    A Subdomain Finder discovers subdomains of a target domain
    using a wordlist and DNS resolution. It helps security
    professionals map the attack surface of a target domain.

Learning Procedure:
    1. Load a wordlist of common subdomain prefixes
    2. For each word, construct a candidate: word.domain.com
    3. Perform DNS resolution (A, AAAA, CNAME records)
    4. If it resolves → subdomain exists → record it
    5. Output all discovered subdomains with their IPs
"""

import dns.resolver
import dns.exception
import concurrent.futures
import argparse
import sys
import os
import json
import csv
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)


# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║     🔎  SUBDOMAIN FINDER  - DNS Reconnaissance Tool      ║
║         Discover hidden subdomains via DNS lookup         ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


# ─────────────────────────────────────────────
#  DEFINITIONS / GLOSSARY
# ─────────────────────────────────────────────
DEFINITIONS = {
    "Subdomain": (
        "A subdomain is a prefix added to a domain name to separate and organize "
        "content or services. E.g., 'mail' in mail.example.com."
    ),
    "DNS (Domain Name System)": (
        "DNS is the internet's phonebook. It translates human-readable domain names "
        "(example.com) into IP addresses (93.184.216.34) that computers use."
    ),
    "A Record": (
        "An 'A' DNS record maps a hostname to an IPv4 address. "
        "E.g., api.example.com → 192.168.1.10"
    ),
    "AAAA Record": (
        "An 'AAAA' DNS record maps a hostname to an IPv6 address. "
        "E.g., api.example.com → 2001:db8::1"
    ),
    "CNAME Record": (
        "A CNAME (Canonical Name) record is an alias for another domain name. "
        "E.g., www.example.com → example.com"
    ),
    "Wordlist": (
        "A wordlist (dictionary) is a text file containing common subdomain prefixes "
        "like 'www', 'mail', 'api', 'dev', 'staging', etc. used for brute-force enumeration."
    ),
    "DNS Resolution": (
        "The process of converting a domain name into its IP address by querying DNS servers. "
        "If a subdomain resolves, it exists and is active."
    ),
    "Brute-force Enumeration": (
        "Testing every possible prefix from a wordlist against the target domain "
        "to discover hidden or undocumented subdomains."
    ),
    "Wildcard DNS": (
        "A wildcard DNS entry (*.example.com) matches ALL subdomains. "
        "This can cause false positives in subdomain enumeration."
    ),
    "Concurrency / Threading": (
        "Running multiple DNS queries simultaneously using threads to dramatically "
        "speed up the enumeration process."
    ),
    "Reconnaissance (Recon)": (
        "The first phase of penetration testing: gathering information about a target "
        "to identify potential attack vectors."
    ),
    "Attack Surface": (
        "The total number of possible entry points (subdomains, services, ports) "
        "where an attacker could try to enter or extract data."
    ),
}


# ─────────────────────────────────────────────
#  DNS RESOLVER CLASS
# ─────────────────────────────────────────────
class SubdomainFinder:
    """
    Core engine that performs DNS-based subdomain enumeration.

    FLOW:
      __init__  → configure resolver & settings
      load_wordlist → read prefixes from file
      check_wildcard → detect wildcard DNS (avoid false positives)
      resolve_subdomain → query DNS for one candidate
      run → orchestrate threading + collect results
      save_results → export to txt / json / csv
      print_definitions → display all learning definitions
    """

    def __init__(self, domain: str, wordlist_path: str,
                 threads: int = 50, timeout: float = 2.0,
                 record_types: list = None):
        self.domain = domain.lower().strip()
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.timeout = timeout
        self.record_types = record_types or ["A", "AAAA", "CNAME"]
        self.found_subdomains = []
        self.total_checked = 0
        self.wildcard_ips = set()

        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    # ── STEP 1: Load Wordlist ──────────────────
    def load_wordlist(self) -> list:
        """
        Definition: Reads the wordlist file and returns a list of subdomain prefixes.

        Learning:
          - Each line in the file is a potential subdomain prefix.
          - Lines starting with '#' are comments (skipped).
          - Empty lines are skipped.
        """
        if not os.path.exists(self.wordlist_path):
            print(f"{Fore.RED}[ERROR] Wordlist not found: {self.wordlist_path}")
            sys.exit(1)

        with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            ]

        print(f"{Fore.YELLOW}[*] Loaded {len(words)} words from wordlist.")
        return words

    # ── STEP 2: Check Wildcard DNS ─────────────
    def check_wildcard(self):
        """
        Definition: Wildcard DNS (*) means ANY subdomain resolves — even fake ones.

        Learning:
          - We test a random, impossible subdomain.
          - If it resolves, the domain has wildcard DNS.
          - We record the wildcard IPs to filter false positives later.
        """
        test_sub = f"wildcard-test-xyz123456.{self.domain}"
        try:
            answers = self.resolver.resolve(test_sub, "A")
            for rdata in answers:
                self.wildcard_ips.add(str(rdata))
            print(f"{Fore.YELLOW}[!] Wildcard DNS detected! IPs: {self.wildcard_ips}")
            print(f"{Fore.YELLOW}[!] These IPs will be filtered from results.")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            print(f"{Fore.GREEN}[✓] No wildcard DNS detected. Clean enumeration.")

    # ── STEP 3: Resolve a Single Subdomain ─────
    def resolve_subdomain(self, word: str) -> dict | None:
        """
        Definition: Performs DNS resolution for one candidate subdomain.

        Learning:
          - Construct: prefix + "." + domain  →  e.g. "api.example.com"
          - Query DNS for A, AAAA, and CNAME records
          - If ANY record exists → subdomain is live
          - Filter out wildcard matches (false positives)

        Returns:
          dict with subdomain info if found, else None
        """
        candidate = f"{word}.{self.domain}"
        result = {
            "subdomain": candidate,
            "records": {},
            "ips": []
        }
        found = False

        for record_type in self.record_types:
            try:
                answers = self.resolver.resolve(candidate, record_type)
                values = [str(r) for r in answers]

                # Filter wildcard IPs
                if record_type == "A":
                    values = [ip for ip in values if ip not in self.wildcard_ips]
                    if not values:
                        continue
                    result["ips"].extend(values)

                result["records"][record_type] = values
                found = True

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.exception.Timeout, dns.resolver.NoNameservers,
                    dns.resolver.LifetimeTimeout):
                pass  # Subdomain doesn't exist for this record type

        return result if found else None

    # ── STEP 4: Run Enumeration ─────────────────
    def run(self) -> list:
        """
        Definition: Orchestrates the full subdomain enumeration workflow.

        Learning Flow:
          1. Load wordlist → get list of prefixes
          2. Check wildcard → avoid false positives
          3. Use ThreadPoolExecutor → concurrent DNS queries
          4. Collect & display results in real-time
          5. Return sorted list of all found subdomains
        """
        print(BANNER)
        print(f"{Fore.CYAN}[*] Target Domain : {Fore.WHITE}{self.domain}")
        print(f"{Fore.CYAN}[*] Wordlist       : {Fore.WHITE}{self.wordlist_path}")
        print(f"{Fore.CYAN}[*] Threads        : {Fore.WHITE}{self.threads}")
        print(f"{Fore.CYAN}[*] Timeout        : {Fore.WHITE}{self.timeout}s")
        print(f"{Fore.CYAN}[*] Record Types   : {Fore.WHITE}{', '.join(self.record_types)}")
        print(f"{Fore.CYAN}{'─'*58}")

        words = self.load_wordlist()
        self.check_wildcard()

        print(f"\n{Fore.YELLOW}[*] Starting enumeration... Press Ctrl+C to stop.\n")
        start_time = datetime.now()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.resolve_subdomain, word): word
                           for word in words}

                for future in concurrent.futures.as_completed(futures):
                    self.total_checked += 1
                    result = future.result()

                    # Progress indicator every 100 checks
                    if self.total_checked % 100 == 0:
                        pct = (self.total_checked / len(words)) * 100
                        print(f"{Fore.BLUE}[~] Progress: {self.total_checked}/{len(words)} "
                              f"({pct:.1f}%) | Found: {len(self.found_subdomains)}",
                              end="\r")

                    if result:
                        self.found_subdomains.append(result)
                        ip_str = ", ".join(result["ips"]) if result["ips"] else "N/A"
                        records_str = " | ".join(
                            f"{k}: {', '.join(v)}"
                            for k, v in result["records"].items()
                        )
                        print(f"\n{Fore.GREEN}[+] FOUND ➜ {Fore.WHITE}{result['subdomain']:<40} "
                              f"{Fore.CYAN}IP: {ip_str}")
                        print(f"    {Fore.YELLOW}Records: {records_str}")

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.")

        duration = datetime.now() - start_time
        print(f"\n\n{Fore.CYAN}{'═'*58}")
        print(f"{Fore.GREEN}[✓] Scan Complete!")
        print(f"{Fore.CYAN}[*] Duration       : {duration}")
        print(f"{Fore.CYAN}[*] Total Checked  : {self.total_checked}")
        print(f"{Fore.CYAN}[*] Subdomains Found: {Fore.GREEN}{len(self.found_subdomains)}")
        print(f"{Fore.CYAN}{'═'*58}\n")

        return self.found_subdomains

    # ── STEP 5: Save Results ────────────────────
    def save_results(self, output_dir: str = "."):
        """
        Definition: Exports found subdomains to multiple formats.

        Formats:
          - .txt  → plain list of subdomains
          - .json → full structured data with records/IPs
          - .csv  → spreadsheet-friendly format
        """
        if not self.found_subdomains:
            print(f"{Fore.YELLOW}[!] No subdomains found. Nothing to save.")
            return

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{output_dir}/{self.domain.replace('.', '_')}_{timestamp}"

        # TXT
        txt_path = f"{base}_subdomains.txt"
        with open(txt_path, "w") as f:
            f.write(f"# Subdomain Finder Results\n")
            f.write(f"# Target: {self.domain}\n")
            f.write(f"# Date: {datetime.now()}\n")
            f.write(f"# Total Found: {len(self.found_subdomains)}\n\n")
            for item in sorted(self.found_subdomains, key=lambda x: x["subdomain"]):
                f.write(f"{item['subdomain']}\n")
        print(f"{Fore.GREEN}[✓] TXT saved  → {txt_path}")

        # JSON
        json_path = f"{base}_subdomains.json"
        with open(json_path, "w") as f:
            json.dump({
                "target": self.domain,
                "scan_date": str(datetime.now()),
                "total_found": len(self.found_subdomains),
                "subdomains": sorted(self.found_subdomains, key=lambda x: x["subdomain"])
            }, f, indent=2)
        print(f"{Fore.GREEN}[✓] JSON saved → {json_path}")

        # CSV
        csv_path = f"{base}_subdomains.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Subdomain", "IP Addresses", "A Records",
                             "AAAA Records", "CNAME Records"])
            for item in sorted(self.found_subdomains, key=lambda x: x["subdomain"]):
                writer.writerow([
                    item["subdomain"],
                    ", ".join(item["ips"]),
                    ", ".join(item["records"].get("A", [])),
                    ", ".join(item["records"].get("AAAA", [])),
                    ", ".join(item["records"].get("CNAME", [])),
                ])
        print(f"{Fore.GREEN}[✓] CSV saved  → {csv_path}")

    # ── BONUS: Print Definitions ─────────────────
    @staticmethod
    def print_definitions():
        """Prints all key definitions for educational purposes."""
        print(f"\n{Fore.CYAN}{'═'*58}")
        print(f"{Fore.CYAN}  📚  KEY DEFINITIONS & LEARNING GUIDE")
        print(f"{Fore.CYAN}{'═'*58}\n")
        for term, definition in DEFINITIONS.items():
            print(f"{Fore.YELLOW}▸ {term}")
            print(f"  {Fore.WHITE}{definition}\n")
        print(f"{Fore.CYAN}{'═'*58}\n")


# ─────────────────────────────────────────────
#  ARGUMENT PARSER & MAIN ENTRY POINT
# ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="🔎 Subdomain Finder - DNS Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomain_finder.py -d example.com -w wordlists/common.txt
  python subdomain_finder.py -d example.com -w wordlists/large.txt -t 100
  python subdomain_finder.py -d example.com -w wordlists/common.txt --output results/
  python subdomain_finder.py --definitions
        """
    )
    parser.add_argument("-d", "--domain",   help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-t", "--threads",  type=int, default=50,
                        help="Number of concurrent threads (default: 50)")
    parser.add_argument("--timeout",        type=float, default=2.0,
                        help="DNS query timeout in seconds (default: 2.0)")
    parser.add_argument("--output",         default="results",
                        help="Output directory for results (default: results/)")
    parser.add_argument("--no-save",        action="store_true",
                        help="Don't save results to files")
    parser.add_argument("--definitions",    action="store_true",
                        help="Show all key definitions and exit")
    return parser.parse_args()


def main():
    args = parse_args()

    # Show definitions mode
    if args.definitions:
        SubdomainFinder.print_definitions()
        sys.exit(0)

    # Validate required args
    if not args.domain or not args.wordlist:
        print(f"{Fore.RED}[ERROR] --domain and --wordlist are required.")
        print(f"        Run with --help for usage. Or --definitions for learning guide.")
        sys.exit(1)

    # Run the finder
    finder = SubdomainFinder(
        domain=args.domain,
        wordlist_path=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
    )

    finder.run()

    if not args.no_save:
        finder.save_results(output_dir=args.output)

    # Always print definitions at end for learning
    print(f"\n{Fore.CYAN}[📚] Run with --definitions to see the full learning guide.\n")


if __name__ == "__main__":
    main()
