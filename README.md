# 🔎 Subdomain Finder — DNS Reconnaissance Tool

> **A Python-based tool that discovers subdomains of a given domain using a wordlist and DNS resolution.**

---

## 📖 Table of Contents

1. [Definition & Purpose](#-definition--purpose)
2. [Key Definitions (Glossary)](#-key-definitions-glossary)
3. [Full Program Flow](#-full-program-flow)
4. [Learning Procedure](#-learning-procedure)
5. [Output Explained](#-output-explained)
6. [Installation](#-installation)
7. [Usage Examples](#-usage-examples)
8. [Project Structure](#-project-structure)
9. [Ethical Use Disclaimer](#-ethical-use-disclaimer)

---

## 🧠 Definition & Purpose

A **Subdomain Finder** is a security reconnaissance tool used to **discover subdomains** of a target domain. Subdomains can reveal hidden services, development environments, admin panels, APIs, and more that aren't publicly advertised — potentially exposing an organization's attack surface.

**How it works:**
1. Takes a **wordlist** (dictionary) of common subdomain prefixes
2. Constructs candidate subdomains: `word + "." + domain`
3. Queries **DNS servers** to check if each candidate resolves
4. Records and reports all **live subdomains** with their IP addresses

---

## 📚 Key Definitions (Glossary)

| Term | Definition |
|------|-----------|
| **Subdomain** | A prefix added before the main domain. Example: `mail` in `mail.example.com` |
| **DNS (Domain Name System)** | The internet's phonebook — translates domain names into IP addresses |
| **A Record** | DNS record mapping a hostname → IPv4 address (e.g., `api.example.com → 93.184.1.1`) |
| **AAAA Record** | DNS record mapping a hostname → IPv6 address |
| **CNAME Record** | An alias DNS record — points one domain name to another |
| **Wordlist** | A text file of common subdomain prefixes used for brute-force enumeration |
| **DNS Resolution** | The process of converting a domain/hostname into an IP address via DNS servers |
| **Brute-force Enumeration** | Testing every word in a wordlist against the target domain |
| **Wildcard DNS** | A DNS entry (`*.example.com`) that matches ALL subdomains — causes false positives |
| **Concurrency / Threading** | Running multiple DNS queries simultaneously to speed up the scan |
| **Reconnaissance** | Phase 1 of penetration testing — gathering info about a target |
| **Attack Surface** | All the possible entry points an attacker could exploit on a target |

---

## 🔄 Full Program Flow

```
                    ┌─────────────────────────────────┐
                    │       START: User provides       │
                    │  --domain example.com            │
                    │  --wordlist wordlists/common.txt │
                    └─────────────┬───────────────────┘
                                  │
                    ┌─────────────▼───────────────────┐
                    │   STEP 1: Load Wordlist          │
                    │   Read all prefixes from file    │
                    │   Filter comments & empty lines  │
                    │   → ["www","api","mail","dev"…]  │
                    └─────────────┬───────────────────┘
                                  │
                    ┌─────────────▼───────────────────┐
                    │   STEP 2: Check Wildcard DNS     │
                    │   Query: xyz999abc.example.com   │
                    │   If resolves → Wildcard active  │
                    │   Record wildcard IPs to filter  │
                    └─────────────┬───────────────────┘
                                  │
                    ┌─────────────▼───────────────────┐
                    │   STEP 3: Thread Pool Executor   │
                    │   Launch N threads concurrently  │
                    │   Each thread handles one word   │
                    └─────────────┬───────────────────┘
                                  │
               ┌──────────────────▼──────────────────────┐
               │  For each word in wordlist (threaded):   │
               │                                          │
               │  Construct: word + "." + domain          │
               │     e.g. "api" + "." + "example.com"    │
               │         = "api.example.com"              │
               │                                          │
               │  Query DNS for:                          │
               │    ├─ A Record    (IPv4 address)         │
               │    ├─ AAAA Record (IPv6 address)         │
               │    └─ CNAME Record (alias)               │
               │                                          │
               │  ┌──────────────────────────────────┐   │
               │  │  Did it resolve?                  │   │
               │  │  YES → Is it wildcard IP?         │   │
               │  │    NO  → 🟢 FOUND! Add to list   │   │
               │  │    YES → ❌ Skip (false positive) │   │
               │  │  NO  → ❌ Skip (not found)        │   │
               │  └──────────────────────────────────┘   │
               └──────────────────┬──────────────────────┘
                                  │
                    ┌─────────────▼───────────────────┐
                    │   STEP 4: Collect & Display      │
                    │   Print found subdomains live    │
                    │   Show IP addresses & records    │
                    │   Show progress counter          │
                    └─────────────┬───────────────────┘
                                  │
                    ┌─────────────▼───────────────────┐
                    │   STEP 5: Save Results           │
                    │   → results/domain_TXT.txt       │
                    │   → results/domain_JSON.json     │
                    │   → results/domain_CSV.csv       │
                    └─────────────┬───────────────────┘
                                  │
                    ┌─────────────▼───────────────────┐
                    │          END / SUMMARY           │
                    │   Total checked | Total found    │
                    │   Duration of scan               │
                    └─────────────────────────────────┘
```

---

## 🎓 Learning Procedure

### How DNS Resolution Works (Step-by-Step)

```
You → resolver.resolve("api.example.com", "A")
         │
         ▼
   [1] Check local cache
         │
         ▼
   [2] Ask Root DNS Server → "Where is .com?"
         │
         ▼
   [3] Ask TLD Server (.com) → "Where is example.com?"
         │
         ▼
   [4] Ask Authoritative DNS → "Where is api.example.com?"
         │
         ▼
   Response: 93.184.1.55   ← IP Address!
         │
   OR: NXDOMAIN            ← Does not exist
```

### Why Threading Matters

| Mode | Time for 1000 words | How |
|------|--------------------|----|
| Sequential | ~16 minutes | 1 query at a time, 1s each |
| 50 Threads | ~20 seconds | 50 queries simultaneously |
| 100 Threads | ~10 seconds | 100 queries simultaneously |

### Wildcard DNS Problem & Solution

```
Without wildcard check:
  xyz123-fake.example.com → 1.2.3.4  ← WILDCARD!
  apple-fake.example.com  → 1.2.3.4  ← WILDCARD!
  api.example.com         → 1.2.3.4  ← Looks found, but is it real?

Our solution:
  1. Query a random impossible subdomain first
  2. If it resolves → record the wildcard IP(s)
  3. During scan → if result IP == wildcard IP → SKIP IT
```

---

## 📊 Output Explained

### Terminal Output
```
[+] FOUND ➜ api.example.com              IP: 93.184.216.34
    Records: A: 93.184.216.34 | CNAME: example.com

[+] FOUND ➜ mail.example.com             IP: 93.184.1.10
    Records: A: 93.184.1.10

[~] Progress: 200/500 (40.0%) | Found: 12
```

### File Outputs (saved to `results/` directory)

**`domain_subdomains.txt`** — Simple list:
```
api.example.com
mail.example.com
www.example.com
```

**`domain_subdomains.json`** — Full structured data:
```json
{
  "target": "example.com",
  "total_found": 3,
  "subdomains": [
    {
      "subdomain": "api.example.com",
      "records": { "A": ["93.184.216.34"] },
      "ips": ["93.184.216.34"]
    }
  ]
}
```

**`domain_subdomains.csv`** — Spreadsheet format:
```
Subdomain,IP Addresses,A Records,AAAA Records,CNAME Records
api.example.com,93.184.216.34,93.184.216.34,,
```

---

## ⚙️ Installation

```bash
# 1. Clone or download the project
cd subdomain_finder

# 2. Install dependencies
pip install -r requirements.txt

# 3. Verify installation
python subdomain_finder.py --help
```

**Dependencies:**
- `dnspython` — DNS query library
- `colorama` — Cross-platform colored terminal output

---

## 💻 Usage Examples

```bash
# Basic scan
python subdomain_finder.py -d example.com -w wordlists/common.txt

# Faster scan with more threads
python subdomain_finder.py -d example.com -w wordlists/common.txt -t 100

# Custom output directory
python subdomain_finder.py -d example.com -w wordlists/common.txt --output /tmp/scan/

# Just print results, don't save files
python subdomain_finder.py -d example.com -w wordlists/common.txt --no-save

# Show all definitions & learning guide
python subdomain_finder.py --definitions
```

### All Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-d`, `--domain` | required | Target domain to enumerate |
| `-w`, `--wordlist` | required | Path to wordlist file |
| `-t`, `--threads` | 50 | Number of concurrent DNS threads |
| `--timeout` | 2.0 | DNS query timeout (seconds) |
| `--output` | `results/` | Output directory for saved files |
| `--no-save` | False | Skip saving results to disk |
| `--definitions` | False | Print full definitions & exit |

---

## 📁 Project Structure

```
subdomain_finder/
│
├── subdomain_finder.py     ← Main tool (core logic)
├── requirements.txt        ← Python dependencies
├── README.md               ← This file
│
├── wordlists/
│   └── common.txt          ← ~200 common subdomain prefixes
│
└── results/                ← Auto-created when results are saved
    ├── example_com_*.txt   ← Plain text results
    ├── example_com_*.json  ← JSON structured results
    └── example_com_*.csv   ← CSV spreadsheet results
```

---

## ⚠️ Ethical Use Disclaimer

> **This tool is intended for educational purposes and authorized security testing only.**

- ✅ Use on domains you **own** or have **written permission** to test
- ✅ Use in **CTF (Capture the Flag)** competitions
- ✅ Use in **bug bounty programs** where subdomain enumeration is in scope
- ❌ **Never** run against domains without authorization
- ❌ Unauthorized scanning may violate the **Computer Fraud and Abuse Act (CFAA)** and similar laws

---

## 🧪 Testing Without a Real Target

Use safe, permissioned targets:
- `scanme.nmap.org` — officially allowed for testing
- Your own domains
- Local test DNS servers

---

*Built for learning DNS, networking, and cybersecurity fundamentals.* 🔐
