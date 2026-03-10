#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║      SUBDOMAIN FINDER — Definitions & Learning Guide     ║
╚══════════════════════════════════════════════════════════╝

Run this file directly to print all definitions:
    python definitions.py
"""

DEFINITIONS = {
    # ── Core Networking ──────────────────────────────────────
    "Subdomain": {
        "definition": (
            "A subdomain is a prefix added to a root domain to separate and organize "
            "content or services. It appears BEFORE the main domain, separated by a dot."
        ),
        "example": "mail.example.com  →  'mail' is the subdomain of 'example.com'",
        "category": "Core Networking",
    },
    "Domain Name": {
        "definition": (
            "A human-readable address used to identify a website or service on the internet. "
            "It maps to an underlying IP address via DNS."
        ),
        "example": "example.com, google.com, github.com",
        "category": "Core Networking",
    },
    "IP Address": {
        "definition": (
            "A numerical label assigned to a device connected to a computer network. "
            "IPv4 uses 4 octets (192.168.1.1), IPv6 uses 128-bit hex (2001:db8::1)."
        ),
        "example": "93.184.216.34 (IPv4)  |  2606:2800:220:1:248:1893:25c8:1946 (IPv6)",
        "category": "Core Networking",
    },

    # ── DNS Records ──────────────────────────────────────────
    "DNS (Domain Name System)": {
        "definition": (
            "The internet's phonebook. DNS translates human-readable domain names into "
            "machine-readable IP addresses. Without DNS, you'd need to remember IPs for every site."
        ),
        "example": "example.com  →  DNS lookup  →  93.184.216.34",
        "category": "DNS Records",
    },
    "A Record": {
        "definition": (
            "The most fundamental DNS record type. Maps a hostname directly to an IPv4 address. "
            "Used for most standard web and service lookups."
        ),
        "example": "api.example.com  IN  A  93.184.216.34",
        "category": "DNS Records",
    },
    "AAAA Record": {
        "definition": (
            "The IPv6 equivalent of an A record. Maps a hostname to a 128-bit IPv6 address. "
            "As IPv6 adoption grows, more services use AAAA records alongside A records."
        ),
        "example": "api.example.com  IN  AAAA  2606:2800:220:1:248:1893:25c8:1946",
        "category": "DNS Records",
    },
    "CNAME Record": {
        "definition": (
            "Canonical Name record — creates an alias from one domain name to another. "
            "CNAME records point to a domain (not an IP), which is then resolved separately. "
            "Cannot coexist with other records on the same name."
        ),
        "example": "www.example.com  IN  CNAME  example.com",
        "category": "DNS Records",
    },
    "MX Record": {
        "definition": (
            "Mail Exchanger record — specifies the mail server responsible for accepting "
            "email messages for a domain. Has a priority value (lower = higher priority)."
        ),
        "example": "example.com  IN  MX  10  mail.example.com",
        "category": "DNS Records",
    },
    "NS Record": {
        "definition": (
            "Name Server record — specifies which DNS servers are authoritative for a domain. "
            "These are the servers that hold the actual DNS zone records."
        ),
        "example": "example.com  IN  NS  ns1.exampledns.com",
        "category": "DNS Records",
    },

    # ── Enumeration Concepts ──────────────────────────────────
    "Wordlist (Dictionary)": {
        "definition": (
            "A text file containing common or probable values used for brute-force attacks. "
            "In subdomain enumeration, it contains common subdomain prefixes like 'www', "
            "'mail', 'api', 'dev', 'staging', 'admin', etc."
        ),
        "example": "wordlist.txt:  www\\n mail\\n api\\n admin\\n dev\\n staging",
        "category": "Enumeration Concepts",
    },
    "Brute-force Enumeration": {
        "definition": (
            "A technique that systematically tests every possible value from a predefined list. "
            "For subdomains: test 'www.domain.com', then 'mail.domain.com', then 'api.domain.com' etc., "
            "resolving each via DNS to see which ones exist."
        ),
        "example": "Test: www → 200 OK | Test: xyz → NXDOMAIN | Test: api → 200 OK",
        "category": "Enumeration Concepts",
    },
    "DNS Resolution": {
        "definition": (
            "The process of converting a domain name or hostname into its corresponding IP address "
            "by querying DNS servers. Returns NXDOMAIN if the name doesn't exist."
        ),
        "example": "resolve('api.example.com') → 93.184.216.34  OR  NXDOMAIN",
        "category": "Enumeration Concepts",
    },
    "Wildcard DNS (* Record)": {
        "definition": (
            "A wildcard entry (*.example.com) in DNS that matches ALL possible subdomains, "
            "even ones that don't really exist. This causes false positives in enumeration "
            "— every tested subdomain 'resolves', making results meaningless without filtering."
        ),
        "example": "*.example.com → 1.2.3.4  means  anything.example.com → 1.2.3.4",
        "category": "Enumeration Concepts",
    },
    "NXDOMAIN": {
        "definition": (
            "Non-Existent Domain — the DNS response returned when a queried domain or subdomain "
            "does not exist in the DNS system. This is the expected response for non-existent subdomains."
        ),
        "example": "resolve('fake123abc.example.com') → NXDOMAIN",
        "category": "Enumeration Concepts",
    },

    # ── Performance ───────────────────────────────────────────
    "Concurrency / Threading": {
        "definition": (
            "Running multiple tasks simultaneously. In Python, ThreadPoolExecutor launches N worker "
            "threads, each performing DNS queries independently. This reduces total scan time from "
            "hours to minutes by parallelizing I/O-bound DNS operations."
        ),
        "example": "50 threads → 50 DNS queries fire simultaneously → 50x speedup",
        "category": "Performance",
    },
    "DNS Timeout": {
        "definition": (
            "The maximum time (in seconds) to wait for a DNS server to respond before "
            "giving up and moving to the next query. Shorter = faster scans but may miss "
            "slow servers. Longer = more accurate but slower."
        ),
        "example": "timeout=2.0 → wait max 2 seconds per DNS query",
        "category": "Performance",
    },

    # ── Security / Pentesting ─────────────────────────────────
    "Reconnaissance (Recon)": {
        "definition": (
            "The first and most critical phase of ethical hacking/penetration testing. "
            "Involves gathering as much information as possible about a target system "
            "before attempting any exploitation. Subdomain enumeration is a key recon technique."
        ),
        "example": "Find all subdomains → map services → identify potential vulnerabilities",
        "category": "Security",
    },
    "Attack Surface": {
        "definition": (
            "The total number of different points (subdomains, ports, services, APIs) "
            "where an attacker could try to enter or extract data from a system. "
            "More subdomains = larger attack surface."
        ),
        "example": "admin.example.com, api.example.com, dev.example.com all expand the attack surface",
        "category": "Security",
    },
    "Passive vs Active Recon": {
        "definition": (
            "Passive recon gathers info without directly touching the target (WHOIS, certificates). "
            "Active recon interacts with target systems directly (DNS queries, port scanning). "
            "This tool performs ACTIVE reconnaissance via direct DNS resolution."
        ),
        "example": "Passive: check crt.sh  |  Active: DNS query api.example.com",
        "category": "Security",
    },
    "False Positive": {
        "definition": (
            "A result that appears valid but is actually incorrect. In subdomain enumeration, "
            "wildcard DNS causes false positives — every subdomain 'resolves' even if it "
            "doesn't exist as a real service."
        ),
        "example": "fake999xyz.example.com resolves due to wildcard → false positive",
        "category": "Security",
    },
}


def print_all_definitions():
    """Print all definitions organized by category."""
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        C = Fore.CYAN
        Y = Fore.YELLOW
        W = Fore.WHITE
        G = Fore.GREEN
        R = Style.RESET_ALL
    except ImportError:
        C = Y = W = G = R = ""

    categories = {}
    for term, info in DEFINITIONS.items():
        cat = info["category"]
        categories.setdefault(cat, []).append((term, info))

    print(f"\n{C}{'═'*65}")
    print(f"{C}  📚  SUBDOMAIN FINDER — COMPLETE DEFINITIONS & LEARNING GUIDE")
    print(f"{C}{'═'*65}\n")

    for cat, items in categories.items():
        print(f"{G}┌─ {cat.upper()} {'─'*(55-len(cat))}┐{R}")
        for term, info in items:
            print(f"\n{Y}  ▸ {term}{R}")
            print(f"  {W}Definition: {info['definition']}{R}")
            print(f"  {C}Example:    {info['example']}{R}")
        print()

    print(f"{C}{'═'*65}")
    print(f"{C}  Total definitions: {len(DEFINITIONS)}")
    print(f"{C}{'═'*65}\n")


if __name__ == "__main__":
    print_all_definitions()
