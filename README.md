# TryRecon 🔍

> Free OSINT. Real data. No paid APIs required.

TryRecon is an OSINT reconnaissance framework for **authorized penetration tests and bug bounty engagements**. It combines modules across subdomain enumeration, port scanning, technology detection, email harvesting, phone number analysis, breach lookup, and attack-surface mapping — using only **free, no-key APIs** where possible.
Target ──► TryRecon ──► recon.db + report.html
│
├── Subdomain enumeration (crt.sh, HackerTarget, DNS brute)
├── Port scanning (async TCP + Shodan InternetDB)
├── Technology fingerprinting (headers + HTML)
├── Favicon correlation (Censys free tier, optional)
├── Email harvesting (scraping + optional Tomba)
├── Phone number OSINT (libphonenumber + optional APIs)
├── Breach lookup (XposedOrNot, free)
├── WHOIS + ASN/BGP expansion (BGPView, free)
├── Cloud bucket enumeration (S3/Azure/GCS)
├── Subdomain takeover detection (CNAME check)
└── HTML report + SQLite storage

---

## ⚠️ Legal Disclaimer

TryRecon is provided **for authorized security testing only**.

- Only scan domains and analyze data you **own** or have **written permission** to test.
- Unauthorized port scanning, email harvesting, and phone number lookups are illegal in most jurisdictions.
- The authors assume **no liability** for misuse.

---

## Features

| Module | Source | API Key? | Rate Limit |
|---|---|---|---|
| Subdomain enum (CT logs) | crt.sh | ❌ | None |
| Subdomain enum (passive) | HackerTarget | ❌ | 100/day |
| Subdomain enum (passive) | CyberAtlas | ❌ | 2000/day |
| DNS brute force | local wordlist | ❌ | N/A |
| Async port scanner | local asyncio | ❌ | N/A |
| IP enrichment | Shodan InternetDB | ❌ | Unlimited |
| Service fingerprint | banner grab | ❌ | N/A |
| Technology detection | headers + HTML | ❌ | N/A |
| Favicon correlation | local MMH3 + Censys free | ✅ optional | 250/mo |
| Email scraping | local crawler | ❌ | N/A |
| Email discovery | Tomba free tier | ✅ optional | 25/mo |
| **Phone OSINT** | **libphonenumber** | **❌** | **Unlimited** |
| **Phone enrichment** | **NumVerify / Veriphone** | **✅ optional** | **100–1000/mo** |
| Breach lookup | XposedOrNot | ❌ | Fair use |
| WHOIS | python-whois | ❌ | N/A |
| ASN / BGP expansion | BGPView | ❌ | Fair use |
| GitHub secret scan | GitHub API | ✅ optional | 10/min |
| Cloud bucket enum | S3/Azure/GCS HTTP | ❌ | N/A |
| Subdomain takeover | CNAME check | ❌ | N/A |
| Wayback Machine | archive.org | ❌ | Fair use |

---

## 📱 Phone Number OSINT Module

The phone module analyzes a phone number offline using **Google's libphonenumber** database, and optionally enriches it with free online APIs.

### What it extracts (offline, no key, unlimited):

| Field | Example |
|---|---|
| **Country** | United States |
| **Country code** | US (+1) |
| **Region** | California |
| **Carrier** | T-Mobile USA (for mobile numbers) |
| **Line type** | Mobile / Landline / VoIP / Toll-free |
| **Timezone(s)** | America/Los_Angeles |
| **E.164 format** | +14155552671 |
| **International format** | +1 415-555-2671 |
| **National format** | (415) 555-2671 |
| **Valid?** | Yes / No |
| **Possible?** | Yes / No |

### What it can detect (high-value findings):

- **Disposable / VoIP numbers** — flagged as high-risk
- **Toll-free numbers** — often used by scam centers
- **Premium-rate numbers** — red flag
- **Invalid length** — not a real number
- **Mismatched country** — number claims US but has European format
- **Carrier vs. expected region mismatch** — suggests porting / spoofing

### Optional online enrichment (with free keys):

- **NumVerify** — carrier + line type + portability (100/month free)
- **Veriphone** — same features (1000/month free)

### Usage

```bash
# Analyze a single number
python -m tryrecon.cli phone "+14155552671"

# Analyze a list of numbers from a file
python -m tryrecon.cli phone --file numbers.txt

# Specify a fallback region for national format
python -m tryrecon.cli phone "4155552671" --region US
Sample output
[*] Analyzing +14155552671

    Valid:            ✓ Yes
    Possible:         ✓ Yes
    Country:          United States (+1)
    Region:           California
    Carrier:          T-Mobile USA
    Line type:        Mobile
    Timezone:         America/Los_Angeles
    E.164:            +14155552671
    International:    +1 415-555-2671
    National:         (415) 555-2671

    Flags:
    ✓ Not a VoIP number
    ✓ Not toll-free
    ✓ Not premium-rate
    ✓ Length valid for region
Installation
git clone https://github.com/7r13x3/tryrecon.git
cd tryrecon
pip install -r requirements.txt
Requires Python 3.10+.
Usage
# Full domain recon
python -m tryrecon.cli scan example.com --full

# Subdomains only
python -m tryrecon.cli scan example.com --subdomains

# Port scan only
python -m tryrecon.cli scan example.com --ports

# Phone number OSINT
python -m tryrecon.cli phone "+14155552671"

# Regenerate HTML report from saved DB
python -m tryrecon.cli report --db recon.db --out report.html

# Validate config
python -m tryrecon.cli check --config configs/example.toml
License
MIT
