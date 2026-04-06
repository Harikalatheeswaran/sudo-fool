<div align=center>

---
# Advanced `Su`b`do`main `F`inder T`ool`

---
</div>

- A powerful, fast, and beautiful **subdomain enumeration tool** built with Python and Rich.

- It combines multiple passive sources + intelligent DNS brute-forcing + automatic `robots.txt` checking — all with graceful error handling and a stunning terminal UI.

---

## ✨ Features

- **Multi-source discovery** (independent & fail-safe):
  - crt.sh (Certificate Transparency Logs)
  - VirusTotal (Passive DNS)
  - DNS Dumpster
  - DNS Brute-force with **110+ realistic prefixes**
- **Smart SSL handling** — tries secure mode first (`certifi`), auto-falls back to insecure if needed
- **robots.txt Checker** — automatically detects and prints full contents if found
- **Optional Live HTTP check** — marks which subdomains are actually responding
- **Beautiful Rich UI** — panels, tables, progress bars, and colored output
- **Graceful degradation** — one source failing doesn’t stop the others
- **Interactive prompt** — just run and type your domain
- Works on macOS, Linux, and Windows

---

## 📦 Installation

1. Clone or download the script (`sudo_fool.py`)

2. Install required packages:

```bash
pip install rich requests dnspython
```

3. **Recommended** (fixes most SSL certificate errors):

```bash
pip install certifi
```

---

## 🚀 Usage

```bash
python sudo_fool.py
```

- You will be prompted to enter the target domain (example: `grok.com`)
- Press Enter and the scan starts automatically

### Options (edit inside the script)

At the bottom of the file you can change:

```python
main(
    domain=domain,
    enable_bruteforce=True,   # Set to False to skip brute-force
    check_live=False          # Set to True to enable live HTTP check (slower)
)
```

---

## 🛠 How It Works

| Source              | Type          | Speed | Notes |
|---------------------|---------------|-------|-------|
| crt.sh              | Passive       | Fast  | Certificate logs |
| VirusTotal          | Passive       | Fast  | Observed subdomains |
| DNS Dumpster        | Passive       | Fast  | Public database |
| Brute-force         | Active        | Medium| 110+ smart prefixes + wildcard detection |
| robots.txt Checker  | Active        | Fast  | Shows full content if exists |

---

## 📋 Example Output

```
Advanced Subdomain Scanner
grok.com

🔍 Fetching from crt.sh for grok.com...          [crt.sh Panel]
🔍 Fetching from VirusTotal for grok.com...      [VirusTotal Panel]
🔍 Fetching from DNS Dumpster for grok.com...    [DNS Dumpster Panel]

✓ crt.sh: 27 subdomains
✓ VirusTotal: 12 subdomains
✓ DNS Dumpster: 8 subdomains

🔍 Starting DNS brute-force (112 prefixes) for grok.com...   [Brute-Force Panel]

🔍 Checking robots.txt for grok.com...           [robots.txt Checker]
✅ robots.txt FOUND!  ← full contents shown in panel

✅ Final Unique Subdomain List
────────────────────────────────────
api.grok.com
dev.grok.com
blog.grok.com
...
Total unique subdomains: 89
```

---

## ⚠️ Troubleshooting

**SSL Certificate Error?**  
- The script automatically detects it and shows a clear message.  
- Just run `pip install certifi` for the best experience.

**No subdomains found?**  
Try enabling `check_live=True` or increase the wordlist (you can keep adding more prefixes).

---

## 🔧 Customization

- Want **more subdomains** in brute-force? Just edit the `wordlist` inside `brute_force_subdomains()` function.

---

## 📝 License

Free to use for personal and educational purposes.

Made with ❤️ for the bug bounty / recon community.

---

## Concetpts

Here’s the **proper, safe, and complete** way to fetch *all* subdomains of a website — with techniques confirmed by reliable sources.  
(Subdomain discovery is legal when done on domains you **own** or have **permission** to test.)

***

### ✅ **How to Fetch All Subdomains of a Website**

Subdomain enumeration is the process of discovering every subdomain linked to a root domain. It is used in security audits, SEO research, and asset inventory. [\[w3tutorials.net\]](https://www.w3tutorials.net/blog/how-do-i-get-a-list-of-all-subdomains-of-a-domain/), [\[ceeyu.io\]](https://www.ceeyu.io/resources/blog/subdomain-enumeration-tools-and-techniques)

There is **no single method** that returns *every* subdomain, but combining multiple techniques gives the best results. [\[w3tutorials.net\]](https://www.w3tutorials.net/blog/how-do-i-get-a-list-of-all-subdomains-of-a-domain/)

***

### ✅ **1. Certificate Transparency Logs (Most Reliable Passive Method)**

CT logs record every SSL/TLS certificate ever issued.  
Looking up a domain on CT log services (like **crt.sh**) reveals many subdomains.    [\[whoisxmlapi.com\]](https://www.whoisxmlapi.com/blog/subdomain-enumeration-tools-and-techniques)

#### Tools / Services:

*   **crt.sh**
*   **Censys**
*   **Google CT Search**

Example query:

    https://crt.sh/?q=%25.example.com

***

### ✅ **2. Passive Enumeration Using Public Data Sources**

These do not interact with the target and are completely safe.

Common passive sources include:

*   **Search engines (Google/Bing dorking)**  
    Using `site:example.com` often reveals indexed subdomains. [\[vaadata.com\]](https://www.vaadata.com/blog/subdomain-enumeration-techniques-and-tools/)

*   **DNS Aggregators (e.g., WhoisXML API)**  
    They store huge DNS datasets, including historical DNS records. [\[whoisxmlapi.com\]](https://www.whoisxmlapi.com/blog/subdomain-enumeration-tools-and-techniques)

*   **Security databases (Shodan, Censys, Virustotal)**  
    These collect open DNS and certificate data. [\[pentestguy.com\]](https://pentestguy.com/subdomain-enumeration-a-complete-guide/)

***

### ✅ **3. Active Methods (Direct Interaction with Target)**

These methods query DNS servers directly; use these **only with permission**.

### ✅ **Brute‑forcing DNS**

Try a list of common prefixes:

    www, api, dev, staging, mail, portal, test, blog

Tools generate DNS requests to check which ones resolve. [\[whoisxmlapi.com\]](https://www.whoisxmlapi.com/blog/subdomain-enumeration-tools-and-techniques)

### ✅ **Zone Transfer (AXFR) — Rarely Works**

This attempts to download the whole DNS zone containing every subdomain.  
However, most DNS servers **block AXFR** for security reasons.    [\[w3tutorials.net\]](https://www.w3tutorials.net/blog/how-do-i-get-a-list-of-all-subdomains-of-a-domain/)

***

### ✅ **4. OSINT Tools That Automate Subdomain Discovery**

Many modern tools combine the techniques above:

#### ✅ **Amass** (most comprehensive)

Uses passive + active + scraping + brute-force.    [\[pentestguy.com\]](https://pentestguy.com/subdomain-enumeration-a-complete-guide/), [\[golinuxcloud.com\]](https://www.golinuxcloud.com/subdomain-enumeration-tools/)

#### ✅ **Subfinder**

Fast passive enumerator using external data sources. [\[pentestguy.com\]](https://pentestguy.com/subdomain-enumeration-a-complete-guide/)

#### ✅ **Sublist3r**

Simple brute-force + OSINT enumerator. [\[golinuxcloud.com\]](https://www.golinuxcloud.com/subdomain-enumeration-tools/)

#### ✅ **Findomain**

Very fast passive subdomain finder. [\[pentestguy.com\]](https://pentestguy.com/subdomain-enumeration-a-complete-guide/)

#### ✅ **PureDNS / dnsx**

Great for brute-forcing with massive DNS resolution. [\[whoisxmlapi.com\]](https://www.whoisxmlapi.com/blog/subdomain-enumeration-tools-and-techniques)

***

### ✅ **5. Search Engine Dorking**

Useful for quick checks:

Examples:

    site:example.com -www
    site:*.example.com
    inurl:example.com

Search engines like Google and Bing can reveal indexed subdomains. [\[vaadata.com\]](https://www.vaadata.com/blog/subdomain-enumeration-techniques-and-tools/)

***

### ✅ **Best Complete Approach (Recommended)**

To reliably fetch the largest number of subdomains:

##### ✅ Step 1 — Query CT logs

(crt.sh, Censys)

##### ✅ Step 2 — Use passive OSINT

(Subfinder, Shodan, Virustotal, DNS history)

##### ✅ Step 3 — Run Amass to combine all techniques [\[pentestguy.com\]](https://pentestguy.com/subdomain-enumeration-a-complete-guide/)

##### ✅ Step 4 — Run DNS brute force

(PureDNS or Sublist3r)

This multi-step workflow is the industry standard. [\[w3tutorials.net\]](https://www.w3tutorials.net/blog/how-do-i-get-a-list-of-all-subdomains-of-a-domain/), [\[golinuxcloud.com\]](https://www.golinuxcloud.com/subdomain-enumeration-tools/)

***


## *__Enjoy Hunting SubDomains!__*
