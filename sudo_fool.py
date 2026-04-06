"""
Advanced Subdomain Finder Tool
------------------------------

A robust, multi-source subdomain discovery tool with graceful degradation.

Sources:
- crt.sh (Certificate Transparency)
- VirusTotal
- DNS Dumpster
- Google Dorking (4 advanced techniques)
- Wayback Machine (historical subdomains)
- DNS Brute-force (110+ realistic prefixes)
- robots.txt checker

Beautiful Rich terminal UI with panels and tables.
"""

import requests
import dns.resolver
import time
import sys
import re
import html
from urllib.parse import parse_qs, quote_plus, unquote, urlparse
from typing import Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress
from rich.prompt import Prompt

console = Console()


#-----------------------------------------------------------------------
# Helper: Colorful printing
#-----------------------------------------------------------------------
def gen(text: str, style: str = 'bold'):
    """Generate Rich-styled string to eliminate repetitive console.print code."""
    return f"[{style}]{text}[/{style}]"


def normalize_results(results: Any) -> set:
    """Ensure source results are always a set for downstream set operations."""
    if results is None:
        return set()
    if isinstance(results, set):
        return results
    return set(results)


def extract_google_targets_from_html(domain: str, html_text: str) -> tuple[set, set]:
    """Extract in-scope hosts and page URLs from raw Google result HTML."""
    hosts = set()
    page_urls = set()

    # Normalize common HTML escaping so query params like &amp;url= can be parsed.
    normalized_html = html.unescape(html_text).replace("\\/", "/")

    # Capture both absolute links and Google's relative redirect links.
    raw_links = set(re.findall(r'https?://[^"\'<>\s]+', normalized_html, re.IGNORECASE))
    relative_redirects = set(re.findall(r'/url\?[^"\'<>\s]+', normalized_html, re.IGNORECASE))
    raw_links.update([f"https://www.google.com{item}" for item in relative_redirects])

    def add_if_in_scope(candidate_url: str):
        try:
            parsed = urlparse(candidate_url)
            if not parsed.scheme or not parsed.netloc:
                return
            host = parsed.netloc.lower().strip()
            if ":" in host:
                host = host.split(":", 1)[0]
            if not (host == domain or host.endswith(f".{domain}")):
                return

            hosts.add(host)
            path = parsed.path or "/"
            normalized_url = f"{parsed.scheme.lower()}://{host}{path}"
            page_urls.add(normalized_url)
        except Exception:
            return

    for link in raw_links:
        parsed_link = urlparse(link)

        # Handle Google wrapper links that keep the real target in query params.
        if parsed_link.netloc.lower().endswith("google.com") and parsed_link.path == "/url":
            params = parse_qs(parsed_link.query)
            for key, values in params.items():
                key_name = key.lower()
                if key_name not in {"url", "q"} and not key_name.endswith("url") and not key_name.endswith("q"):
                    continue
                for value in values:
                    decoded = unquote(value)
                    if decoded.startswith("http://") or decoded.startswith("https://"):
                        add_if_in_scope(decoded)
            continue

        add_if_in_scope(link)

    # Fallback: some Google pages expose encoded targets only as query fragments in HTML.
    encoded_targets = re.findall(r'(?:[?&](?:amp;)?(?:url|q)=)(https?%3A%2F%2F[^&"\'<>\s]+)', normalized_html, re.IGNORECASE)
    for encoded in encoded_targets:
        decoded = unquote(encoded)
        if decoded.startswith("http://") or decoded.startswith("https://"):
            add_if_in_scope(decoded)

    return hosts, page_urls


# ====================== SMART SSL HANDLER ======================
VERIFY_SSL = True
SSL_FALLBACK_USED = False

def init_ssl():
    global VERIFY_SSL, SSL_FALLBACK_USED
    try:
        import certifi
        VERIFY_SSL = certifi.where()
        console.print(gen("✅ SSL verification enabled via certifi (secure mode)", "green"))
    except ImportError:
        VERIFY_SSL = False
        SSL_FALLBACK_USED = True
        console.print(gen("⚠️  certifi not found - starting in insecure mode", "bold yellow"))
        _disable_insecure_warnings()


def _disable_insecure_warnings():
    try:
        import urllib3
        from urllib3.exceptions import InsecureRequestWarning
        urllib3.disable_warnings(InsecureRequestWarning)
    except Exception:
        pass


def safe_get(url, **kwargs):
    global VERIFY_SSL, SSL_FALLBACK_USED
    try:
        return requests.get(url, verify=VERIFY_SSL, **kwargs)
    except requests.exceptions.SSLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e) and not SSL_FALLBACK_USED:
            SSL_FALLBACK_USED = True
            VERIFY_SSL = False
            _disable_insecure_warnings()
            console.print(Panel(
                gen("⚠️  SSL certificate verification failed!\n"
                    "→ Switching to insecure fallback mode (verify=False)\n"
                    "💡 Recommendation: pip install certifi", "bold yellow"),
                title="SSL Fallback Activated",
                border_style="yellow"
            ))
            return requests.get(url, verify=False, **kwargs)
        raise


def safe_post(url, **kwargs):
    global VERIFY_SSL, SSL_FALLBACK_USED
    try:
        return requests.post(url, verify=VERIFY_SSL, **kwargs)
    except requests.exceptions.SSLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e) and not SSL_FALLBACK_USED:
            SSL_FALLBACK_USED = True
            VERIFY_SSL = False
            _disable_insecure_warnings()
            console.print(Panel(
                gen("⚠️  SSL certificate verification failed!\n"
                    "→ Switching to insecure fallback mode (verify=False)\n"
                    "💡 Recommendation: pip install certifi", "bold yellow"),
                title="SSL Fallback Activated",
                border_style="yellow"
            ))
            return requests.post(url, verify=False, **kwargs)
        raise
# =============================================================================


#-----------------------------------------------------------------------
# 1-3. Existing passive sources (crt.sh, VirusTotal, DNS Dumpster)
#-----------------------------------------------------------------------
def fetch_from_crtsh(domain: str) -> set:
    console.print(Panel(gen(f"🔍 Fetching from crt.sh for {domain}...", "cyan"), title="crt.sh", border_style="blue"))
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()
    try:
        response = safe_get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subs.add(sub)
    except Exception as e:
        console.print(gen("crt.sh failed: ", "red") + str(e))
    return subs


def fetch_from_virustotal(domain: str) -> set:
    console.print(Panel(gen(f"🔍 Fetching from VirusTotal for {domain}...", "cyan"), title="VirusTotal", border_style="blue"))
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    subs = set()
    try:
        response = safe_get(url, timeout=12)
        if response.status_code == 200:
            data = response.json()
            for item in data.get("data", []):
                sub = item.get("id", "")
                if sub.endswith(f".{domain}") or sub == domain:
                    subs.add(sub.lower())
        else:
            console.print(gen(f"VirusTotal returned status {response.status_code}", "yellow"))
    except Exception as e:
        console.print(gen("VirusTotal failed: ", "red") + str(e))
    return subs


def fetch_from_dnsdumpster(domain: str) -> set:
    console.print(Panel(gen(f"🔍 Fetching from DNS Dumpster for {domain}...", "cyan"), title="DNS Dumpster", border_style="blue"))
    subs = set()
    try:
        session = requests.Session()
        session.verify = VERIFY_SSL
        session.get("https://dnsdumpster.com", timeout=10)
        csrf = session.cookies.get("csrftoken")
        headers = {"Referer": "https://dnsdumpster.com", "X-CSRFToken": csrf or ""}
        data = {"csrfmiddlewaretoken": csrf, "targetip": domain}
        response = safe_post("https://dnsdumpster.com/", data=data, headers=headers, timeout=15)
        if response.status_code == 200:
            import re
            found = re.findall(r'([a-zA-Z0-9-]+\.' + re.escape(domain) + r')', response.text, re.IGNORECASE)
            for sub in found:
                subs.add(sub.lower().strip())
    except Exception as e:
        console.print(gen("DNS Dumpster failed: ", "red") + str(e))
    return subs


#-----------------------------------------------------------------------
# 4. GOOGLE DORKING - 6 Advanced Techniques (separate panel)
#-----------------------------------------------------------------------
def fetch_from_google_dorking(domain: str) -> tuple[set, set, list[tuple[str, str]]]:
    console.print(Panel(
        gen(f"🔍 Running advanced Google Dorking techniques for {domain}...", "cyan"),
        title="Google Dorking (Advanced)",
        border_style="blue"
    ))
    subs = set()
    page_urls = set()
    dork_links: list[tuple[str, str]] = []
    blocked_techniques = 0
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }

    dorks = [
        f"site:*.{domain}",
        f"site:*.{domain} -site:www.{domain}",
        f"site:*.*.{domain}",
        f'site:*.{domain} (inurl:dev OR inurl:stage OR inurl:staging OR inurl:test OR inurl:uat OR inurl:preprod OR inurl:beta)',
        f'inurl:{domain}/',
        f'site:{domain} (inurl:/api/ OR inurl:/admin/ OR inurl:/login/ OR inurl:/docs/)',
        f'site:{domain} (inurl:index.html OR inurl:php OR inurl:aspx OR inurl:jsp)'
    ]

    for i, dork in enumerate(dorks, 1):
        query_url = f"https://www.google.com/search?q={quote_plus(dork)}"
        dork_links.append((f"Technique {i}", query_url))
        try:
            console.print(gen(f"   → Technique {i}/{len(dorks)}: {dork}", "dim"))
            url = f"{query_url}&num=30"
            response = safe_get(url, headers=headers, timeout=12)
            response.raise_for_status()

            # printing the response text to debug and see if Google is blocking us
            # console.print(response.text)

            lower_html = response.text.lower()
            anti_bot_signals = [
                "httpservice/retry/enablejs",
                "detected unusual traffic",
                "sorry/index",
                "captcha"
            ]
            if any(signal in lower_html for signal in anti_bot_signals):
                blocked_techniques += 1

            found_hosts, found_page_urls = extract_google_targets_from_html(domain, response.text)
            subs.update(found_hosts)
            page_urls.update(found_page_urls)
            time.sleep(1.8)  # Be gentle with Google
        except Exception:
            console.print(gen(f"   Technique {i} failed (normal - Google blocks often)", "yellow"))

    if blocked_techniques > 0 and not page_urls:
        console.print(Panel(
            gen(
                "Google returned anti-bot/JavaScript-only pages for one or more techniques.\n"
                "Dorking output may be incomplete in scripted mode.",
                "bold yellow"
            ),
            title="Google Dorking Notice",
            border_style="yellow"
        ))

    return subs, page_urls, dork_links, #type: ignore


#-----------------------------------------------------------------------
# 5. WAYBACK MACHINE (Historical Subdomains) - separate panel
#-----------------------------------------------------------------------
def fetch_from_wayback(domain: str) -> set:
    console.print(Panel(
        gen(f"🔍 Fetching historical subdomains from Wayback Machine for {domain}...", "cyan"),
        title="Wayback Machine",
        border_style="blue"
    ))
    subs = set()
    try:
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&limit=2000&collapse=urlkey"
        response = safe_get(cdx_url, timeout=20)
        response.raise_for_status()
        data = response.json()

        if isinstance(data, list) and len(data) > 1:
            for entry in data[1:]:
                if len(entry) > 2:
                    original_url = entry[2]
                    parsed = urlparse(original_url)
                    if parsed.netloc:
                        sub = parsed.netloc.lower().strip()
                        if sub.endswith(f".{domain}") or sub == domain:
                            subs.add(sub)
    except Exception as e:
        console.print(gen("Wayback Machine failed: ", "red") + str(e))

    return subs


#-----------------------------------------------------------------------
# 6. BRUTE FORCE (unchanged - massive wordlist)
#-----------------------------------------------------------------------
def brute_force_subdomains(domain: str, wordlist: Optional[list[str]] = None) -> set:
    if wordlist is None:
        # wordlist : 100+ more realistic & modern prefixes
        wordlist = [
            "www", "mail", "api", "dev", "test", "stage", "staging", "prod", "admin",
            "portal", "app", "apps", "beta", "demo", "login", "auth", "secure",
            "cdn", "static", "assets", "media", "images", "files", "backup",
            "blog", "shop", "store", "pay", "payment", "api-v1", "v2", "v3", "internal",
            "dashboard", "console", "ftp", "smtp", "pop3", "ns1", "ns2", "ns3",
            "support", "help", "status", "monitor", "metrics", "logs", "data",
            "mobile", "m", "webmail", "imap", "news", "forum", "community", "wiki",
            "api-docs", "swagger", "graphql", "oauth", "sso", "ldap", "vpn", "remote",
            "jenkins", "gitlab", "jira", "confluence", "bitbucket", "git", "svn",
            "db", "database", "sql", "mongo", "redis", "cache", "elastic", "kibana",
            "aws", "azure", "gcp", "cloud", "s3", "storage", "video", "media-cdn",
            "uat", "qa", "preprod", "sandbox", "sandbox1", "test1", "dev1", "prod1",
            "old", "new", "legacy", "archive", "temp", "tmp", "bak", "backup2",
            "calendar", "events", "crm", "erp", "hr", "finance", "accounting",
            "api1", "api2", "rest", "ws", "websocket", "socket", "chat", "live",
            "origin", "edge", "www2", "www3", "devops", "ci", "cd", "build",
            "test-api", "staging-api", "prod-api", "internal-api", "private",
            "extranet", "intranet", "corp", "corporate", "partner", "partners",
            "client", "clients", "user", "users", "account", "accounts",
            "download", "uploads", "upload", "cdn2", "assets2", "static2",
            "docs", "documentation", "knowledgebase", "kb", "faq", "helpdesk",
            "ticket", "tickets", "service", "services", "billing", "invoice"
        ]

    console.print(Panel(
        gen(f"🔍 Starting DNS brute-force ({len(wordlist)} prefixes) for {domain}...", "yellow"),
        title="Brute-Force",
        border_style="yellow"
    ))

    found = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    wildcard_ips = set()
    for test in ["random123xyz", "test123abc", "garbage987"]:
        try:
            answers = resolver.resolve(f"{test}.{domain}", "A")
            wildcard_ips.update([str(rdata) for rdata in answers])
        except Exception:
            pass

    with Progress() as progress:
        task = progress.add_task("[yellow]Brute-forcing...", total=len(wordlist))

        for prefix in wordlist:
            sub = f"{prefix}.{domain}"
            try:
                answers = resolver.resolve(sub, "A")
                ips = [str(rdata) for rdata in answers]
                if wildcard_ips and set(ips).issubset(wildcard_ips):
                    progress.update(task, advance=1)
                    continue
                found.add(sub)
            except Exception:
                pass
            progress.update(task, advance=1)

    return found


#-----------------------------------------------------------------------
# 7. ROBOTS.TXT CHECKER (unchanged)
#-----------------------------------------------------------------------
def check_robots_txt(domain: str):
    """Check if /robots.txt exists and print its full contents if found."""
    console.print(Panel(
        gen(f"🔍 Checking robots.txt for {domain}...", "cyan"),
        title="robots.txt Checker",
        border_style="green"
    ))

    content = None
    for proto in ["https", "http"]:
        try:
            r = safe_get(f"{proto}://{domain}/robots.txt", timeout=8)
            if r.status_code == 200 and len(r.text.strip()) > 20:
                # Quick validation that it actually looks like a robots.txt file
                if any(keyword in r.text for keyword in ["User-agent:", "Disallow:", "Allow:", "Sitemap:"]):
                    content = r.text.strip()
                    break
        except Exception:
            continue

    if content:
        console.print(Panel(
            f"[bold green]✅ robots.txt FOUND![/bold green]\n\n"
            f"[white]{content}[/white]",
            title=f"robots.txt — {domain}",
            border_style="green"
        ))
    else:
        console.print(gen("❌ No robots.txt found or it returned empty/404", "yellow"))



#-----------------------------------------------------------------------
# 8. LIVE HTTP CHECK (unchanged)
#-----------------------------------------------------------------------
def check_live_subdomains(subdomains: set, timeout: int = 5) -> dict[str, str]:
    console.print(Panel(
        gen("🔍 Checking live status for discovered subdomains...", "magenta"),
        title="Live Check",
        border_style="magenta"
    ))
    live_status = {}

    for sub in sorted(subdomains):
        status = "[red]down[/red]"
        for proto in ["https", "http"]:
            try:
                r = requests.get(
                    f"{proto}://{sub}",
                    timeout=timeout,
                    allow_redirects=True,
                    verify=VERIFY_SSL
                )
                if r.status_code < 500:
                    status = f"[green]live ({r.status_code})[/green]"
                    break
            except Exception:
                continue
        live_status[sub] = status
        time.sleep(0.1)

    return live_status



#-----------------------------------------------------------------------
# 9. DISPLAY RESULTS (unchanged)
#-----------------------------------------------------------------------
def display_results(title: str, items: set, live_status: Optional[dict[str, str]] = None):
    if not items:
        panel = Panel("[red]No results found[/red]", title=title, border_style="red")
        console.print(panel)
        return

    table = Table(show_lines=False, box=box.SIMPLE_HEAVY, title=title)
    table.add_column("Subdomain", style="green")
    if live_status:
        table.add_column("Status", style="cyan")

    for item in sorted(items):
        row = [item]
        if live_status:
            row.append(live_status.get(item, "[yellow]unknown[/yellow]"))
        table.add_row(*row)

    panel = Panel(table, border_style="cyan")
    console.print(panel)


def display_url_results(title: str, items: set):
    """Display full URLs in a dedicated panel."""
    if not items:
        panel = Panel("[red]No URL results found[/red]", title=title, border_style="red")
        console.print(panel)
        return

    table = Table(show_lines=False, box=box.SIMPLE_HEAVY, title=title)
    table.add_column("URL", style="green")

    for item in sorted(items):
        table.add_row(item)

    panel = Panel(table, border_style="cyan")
    console.print(panel)


def display_dork_query_links(title: str, links: list[tuple[str, str]]):
    """Display Google manual query links for each dorking technique."""
    if not links:
        panel = Panel("[red]No dork query links available[/red]", title=title, border_style="red")
        console.print(panel)
        return

    table = Table(show_lines=False, box=box.SIMPLE_HEAVY, title=title)
    table.add_column("Method", style="cyan", no_wrap=True)
    table.add_column("Google Link", style="green")

    for method, link in links:
        table.add_row(method, link)

    panel = Panel(table, border_style="cyan")
    console.print(panel)

#-----------------------------------------------------------------------
# MAIN WORKFLOW
#-----------------------------------------------------------------------
def main(domain: str, enable_bruteforce: bool = True, check_live: bool = False):
    console.print(Panel(
        f"[bold white]Advanced Subdomain Scanner[/bold white]\n[bold cyan]{domain}[/bold cyan]",
        style="blue"
    ))

    all_subs = set()

    # === Passive sources (no Google/Wayback) ===
    methods = [
        ("crt.sh", fetch_from_crtsh),
        ("VirusTotal", fetch_from_virustotal),
        ("DNS Dumpster", fetch_from_dnsdumpster),
    ]

    for name, func in methods:
        try:
            results = normalize_results(func(domain))
            console.print(gen("✓", "green") + gen(f" {name}: {len(results)} subdomains", "bold"))
            all_subs.update(results)
        except Exception as e:
            console.print(gen(f"✗ {name} failed: ", "red") + str(e))

    # === Google Dorking (separate panel) ===
    google_results = set()
    google_page_urls = set()
    google_dork_links: list[tuple[str, str]] = []
    try:
        google_results, google_page_urls, google_dork_links = fetch_from_google_dorking(domain)  # type: ignore
        google_results = normalize_results(google_results)
        google_page_urls = normalize_results(google_page_urls)

        console.print(
            gen("✓", "green") +
            gen(f" Google Dorking: {len(google_results)} hosts, {len(google_page_urls)} URLs", "bold")
        )
        all_subs.update(google_results)
    except Exception as e:
        console.print(gen("Google Dorking failed: ", "red") + str(e))

    # === Wayback Machine (separate panel) ===
    wayback_results = set()
    try:
        wayback_results = normalize_results(fetch_from_wayback(domain))
        console.print(gen("✓", "green") + gen(f" Wayback Machine: {len(wayback_results)} subdomains", "bold"))
        all_subs.update(wayback_results)
    except Exception as e:
        console.print(gen("Wayback Machine failed: ", "red") + str(e))

    # Brute-force
    brute_results = set()
    if enable_bruteforce:
        try:
            brute_results = normalize_results(brute_force_subdomains(domain))
            console.print(gen("✓", "green") + gen(f" Brute-force: {len(brute_results)} subdomains", "bold"))
            all_subs.update(brute_results)
        except Exception as e:
            console.print(gen("Brute-force failed: ", "red") + str(e))

    # robots.txt
    check_robots_txt(domain)

    # Live check
    live_status = check_live_subdomains(all_subs) if check_live and all_subs else None

    # === Separate Panels ===
    display_results("Passive Sources (crt.sh + VirusTotal + DNS Dumpster)",
                    all_subs - brute_results - google_results - wayback_results, live_status)

    display_results("🔎 Google Dorking Results", google_results, live_status)
    display_url_results("🌐 Google Dorking Page URLs", google_page_urls)
    display_dork_query_links("Google Dorking Manual Query Links", google_dork_links)

    display_results("📜 Wayback Machine Historical Subdomains", wayback_results, live_status)

    if enable_bruteforce and brute_results:
        display_results("DNS Brute-Force Results", brute_results, live_status)

    display_results("✅ Final Unique Subdomain List", all_subs, live_status)

    console.print(Panel(
        f"[bold green]Total unique subdomains:[/bold green] {len(all_subs)}\n"
        f"Methods completed successfully.",
        title="Scan Summary", border_style="green"
    ))


#-----------------------------------------------------------------------
# ENTRY POINT
#-----------------------------------------------------------------------
if __name__ == "__main__":
    init_ssl()
    console.print(Panel("[bold white]Advanced Subdomain Scanner[/bold white]", style="blue"))

    domain = Prompt.ask(gen("Enter the target domain (e.g. grok.com)", "bold cyan"))
    domain = domain.strip()

    if not domain:
        console.print(gen("❌ Error: Domain cannot be empty!", "bold red"))
        sys.exit(1)

    main(
        domain=domain,
        enable_bruteforce=True,
        check_live=False
    )