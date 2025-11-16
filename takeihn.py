#!/usr/bin/env python3
"""
takeihn.py — v1.0.0

Enhancements implemented (per request):
 - NS & MX takeover detection branches
 - Eliminated reliance on external subprocess tools where possible (dig/curl)
 - Uses dnspython for DNS queries, requests for HTTP, python-whois for WHOIS
 - Fingerprints may be loaded from an external JSON file `fingerprints.json`; built-in fallback provided
 - CLI: -l/--list for list mode, -d/--domain for single-host verbose mode
 - Optional output file (-o) that records vulnerable findings in one-line format
 - One-line httpx-like summaries in list mode; detailed report in domain mode
 - Uses rich for colored/professional terminal UI

Dependencies:
    pip install requests dnspython python-whois rich

Notes:
 - WHOIS results vary by registrar and TLD. Detection uses heuristic keywords; manual verification always recommended.
 - Public suffix edge-cases (e.g., co.uk) are handled best-effort by tldextract if installed; otherwise fallback to last-2-label heuristic.

"""
from __future__ import annotations
import re
import os
import sys
import time
import socket
import argparse
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from shutil import which
from typing import Optional, Tuple, List

# third-party libs
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except Exception:
    print("Please install requests: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    import dns.resolver
    DNSPYTHON = True
except Exception:
    DNSPYTHON = False

# whois (python-whois). optional fallback to subprocess if not present
try:
    import whois as pywhois
    WHOIS_PY = True
except Exception:
    WHOIS_PY = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH = True
    console = Console()
except Exception:
    RICH = False
    print("Please install rich: pip install rich", file=sys.stderr)
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------- fingerprints (externalizable) ----------------
# Default built-in fingerprints (fallback if no external file provided)
DEFAULT_FINGERPRINTS = {
    "providers": {
        "Fastly": ["fastly error", "error from fastly", "fastly", "no such domain for service"],
        "Amazon S3": ["nosuchbucket", "the specified bucket does not exist", "<code>nosuchbucket</code>", "no such bucket", "s3.amazonaws.com"],
        "CloudFront": ["cloudfront", "request could not be satisfied", "the request could not be satisfied"],
        "Netlify": ["there isn't a site here", "no such site", "netlify", "site could not be found"],
        "Vercel": ["there’s nothing here", "cannot get /", "vercel", "the requested resource was not found"],
        "GitHub Pages": ["there isn't a github pages site here", "project not found", "repository not found", "github.io"],
        "Heroku": ["no such app", "heroku", "application error", "h14", "herokuapp.com"],
        "SendGrid": ["sendgrid", "domain is not verified", "sendgrid.net", "sendgrid.com"],
        "Mailgun": ["mailgun", "domain not found", "mailgun verification", "mailgun.org"],
        "Shopify": ["sorry, this shop is currently unavailable", "shopify"],
        "Azure Blob": ["resourcenotfound", "the specified resource does not exist", "blob.core.windows.net"],
        "Google Cloud Storage": ["google cloud storage", "bucket does not exist", "no such object", "storage.googleapis.com"],
        "Generic": ["there isn't a site here", "no such app", "no such domain", "not found", "resource not found", "404", "not found"]
    },
    "domain_keywords": {
        "mailgun.org": "Mailgun",
        "sendgrid.com": "SendGrid",
        "sendgrid.net": "SendGrid",
        "vercel.app": "Vercel",
        "netlify.app": "Netlify",
        "github.io": "GitHub Pages",
        "githubusercontent.com": "GitHub Pages",
        "s3.amazonaws.com": "Amazon S3",
        "amazonaws.com": "Amazon S3",
        "cloudfront.net": "CloudFront",
        "fastly": "Fastly",
        "herokuapp.com": "Heroku",
        "blob.core.windows.net": "Azure Blob",
        "storage.googleapis.com": "Google Cloud Storage",
        "shopify": "Shopify",
        "cargocollective.com": "Cargo Collective",
        "uptimerobot": "UptimeRobot"
    }
}

FINGERPRINTS_PATHS = ["fingerprints.json", "./fingerprints.json"]

def load_fingerprints() -> dict:
    for p in FINGERPRINTS_PATHS:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    # normalize to lowercase patterns
                    for k in list(data.get("providers", {}).keys()):
                        data["providers"][k] = [x.lower() for x in data["providers"][k]]
                    return data
            except Exception:
                # fall through to default
                break
    # normalize default
    for k in list(DEFAULT_FINGERPRINTS["providers"].keys()):
        DEFAULT_FINGERPRINTS["providers"][k] = [x.lower() for x in DEFAULT_FINGERPRINTS["providers"][k]]
    return DEFAULT_FINGERPRINTS

FP = load_fingerprints()
PROVIDERS = FP.get("providers", {})
DOMAIN_KEYWORD_TO_PROVIDER = FP.get("domain_keywords", {})

# ---------------- regex & helpers ----------------
SUBDOMAIN_RE = re.compile(r"([a-z0-9][a-z0-9\-\_\.]{1,}\.[a-z]{2,})", re.IGNORECASE)

def sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)

def setup_requests_session(retries=1, backoff=0.2):
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff,
                  status_forcelist=[429,500,502,503,504],
                  allowed_methods=["HEAD","GET","OPTIONS","GET"])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": "takeihn/1.2"})
    return s

# ---------------- DNS helpers (dnspython-based) ----------------

def dns_query_records(name: str, rdtype: str) -> List[str]:
    if not DNSPYTHON:
        return []
    try:
        answers = dns.resolver.resolve(name, rdtype, raise_on_no_answer=False)
        vals = []
        for r in answers:
            # r can be different types
            if rdtype in ("A", "AAAA"):
                vals.append(str(r))
            elif rdtype == "CNAME":
                # r.target for CNAME RDATA
                try:
                    vals.append(str(r.target).rstrip('.'))
                except Exception:
                    vals.append(str(r))
            elif rdtype == "MX":
                try:
                    vals.append(str(r.exchange).rstrip('.'))
                except Exception:
                    vals.append(str(r))
            elif rdtype == "NS":
                try:
                    vals.append(str(r.target).rstrip('.'))
                except Exception:
                    vals.append(str(r))
            else:
                vals.append(str(r))
        return vals
    except Exception:
        return []

def dns_cname(host: str) -> Optional[str]:
    vals = dns_query_records(host, "CNAME")
    return vals[0] if vals else None

def resolve_a(host: str) -> List[str]:
    return dns_query_records(host, "A")

def resolve_aaaa(host: str) -> List[str]:
    return dns_query_records(host, "AAAA")

def lookup_ns(host: str) -> List[str]:
    return dns_query_records(host, "NS")

def lookup_mx(host: str) -> List[str]:
    return dns_query_records(host, "MX")

# ---------------- helper: extract root domain (best-effort) ----------------
# Use tldextract if present for accurate public suffix handling; fallback to last-2-label heuristic.
try:
    import tldextract
    TLD_EXT = True
except Exception:
    TLD_EXT = False

def get_domain_root(hostname: str) -> str:
    if TLD_EXT:
        ext = tldextract.extract(hostname)
        if ext.domain and ext.suffix:
            return ext.domain + "." + ext.suffix
    # fallback: last two labels
    parts = hostname.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return hostname

# ---------------- HTTP probe (requests-based) ----------------

def http_probe(session: requests.Session, host: str, timeout: int = 8) -> Tuple[Optional[int], dict, str, str]:
    headers = {"Host": host}
    for scheme in ("https://", "http://"):
        url = f"{scheme}{host}"
        try:
            r = session.head(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
            body = ""
            if r.status_code in (404, 403, 502, 503, 400):
                try:
                    r2 = session.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
                    body = (r2.text or "")[:16000]
                    return r2.status_code, r2.headers, body, r2.url
                except Exception:
                    body = ""
            return r.status_code, r.headers, body, r.url
        except requests.exceptions.SSLError:
            continue
        except requests.RequestException:
            try:
                r = session.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
                return r.status_code, r.headers, (r.text or "")[:16000], r.url
            except Exception:
                continue
    return None, {}, "", f"http://{host}"

# ---------------- provider matching ----------------

def match_provider_from_text_with_context(text: str):
    hay = (text or "").lower()
    for provider, patterns in PROVIDERS.items():
        for p in patterns:
            if p and p in hay:
                return provider, p, "body/header"
    return None, None, None


def disambiguate_provider(res_cname: str, hay_text: str):
    cname_low = (res_cname or "").lower()
    hay_low = (hay_text or "").lower()
    for keyword, provider in DOMAIN_KEYWORD_TO_PROVIDER.items():
        if keyword in hay_low:
            return provider, f"body-domain:{keyword}"
    for keyword, provider in DOMAIN_KEYWORD_TO_PROVIDER.items():
        if keyword in cname_low:
            return provider, f"cname-key:{keyword}"
    for token, provider in DOMAIN_KEYWORD_TO_PROVIDER.items():
        t = token.split('.')[0]
        if t and t in cname_low:
            return provider, f"cname-token:{t}"
    return None, None

# ---------------- dangling detection ----------------

def detect_dangling_type(host: str) -> Tuple[Optional[str], str]:
    # order: CNAME -> A/AAAA -> NS -> MX
    cname = dns_cname(host)
    if cname:
        return 'CNAME', cname
    a = resolve_a(host)
    if a:
        return 'A', ';'.join(a)
    aaaa = resolve_aaaa(host)
    if aaaa:
        return 'AAAA', ';'.join(aaaa)
    ns = lookup_ns(host)
    if ns:
        return 'NS', ns[0]
    mx = lookup_mx(host)
    if mx:
        return 'MX', mx[0]
    return None, ''

# ---------------- NS takeover check ----------------
NS_WHOIS_KEYWORDS = ["no match", "not found", "no entries found", "available", "no data found", "not registered", "status: free"]

def check_ns_takeover(ns_target: str) -> Tuple[bool, str]:
    """Check if an NS target's registered domain appears available/expired (best-effort).
    ns_target typically like 'ns1.expired-domain.com' so check root domain registration."""
    root = get_domain_root(ns_target)
    whois_text = ""
    # try python-whois if available
    if WHOIS_PY:
        try:
            info = pywhois.whois(root)
            # pywhois returns dict-like; if domain_name empty -> not registered
            if not info or not info.get('domain_name'):
                return True, f"whois-empty:{root}"
            # otherwise check raw text if present
            whois_text = str(info)
        except Exception as e:
            whois_text = str(e)
    else:
        # fallback to subprocess whois if present
        if which('whois'):
            try:
                import subprocess
                out = subprocess.check_output(['whois', root], text=True, stderr=subprocess.DEVNULL, timeout=12)
                whois_text = out.lower()
            except Exception:
                whois_text = ''
    low = (whois_text or '').lower()
    for k in NS_WHOIS_KEYWORDS:
        if k in low:
            return True, f"whois-keyword:{k}"
    # no clear evidence
    return False, whois_text[:1000]

# ---------------- MX takeover check ----------------
MX_PROVIDER_KEYWORDS = DOMAIN_KEYWORD_TO_PROVIDER

def check_mx_takeover(mx_target: str) -> Tuple[bool, str]:
    """Detect likely MX takeover based on DNS existence and provider fingerprinting.
    mx_target usually like 'mailgun.org' or 'mx1.sendgrid.net'"""
    # check if MX target resolves to any A/AAAA/CNAME
    # strip trailing dot
    target = mx_target.rstrip('.')
    a = resolve_a(target)
    aaaa = resolve_aaaa(target)
    cname = dns_cname(target)
    if not a and not aaaa and not cname:
        # provider likely not configured or target missing
        return True, f"mx-target-no-dns:{target}"
    # if target contains provider keyword that's known and we can detect unverified state via body headers
    # attempt HTTP probe on target (best-effort) to find provider-specific messages
    session = setup_requests_session()
    status, headers, body, final = http_probe(session, target, timeout=6)
    prov, pat, where = match_provider_from_text_with_context((headers and ' '.join([f"{k}:{v}" for k,v in headers.items()])) + ' ' + (body or ''))
    if prov:
        # basic heuristic: if provider found but body contains 'domain not verified' etc
        low = (body or '').lower()
        if any(x in low for x in ['domain is not verified', 'domain is not verified', 'not verified', 'domain not found', 'no such domain']):
            return True, f"provider-unverified:{prov}"
    # otherwise not clearly vulnerable
    return False, f"dns-exists:{','.join(a or aaaa or [cname or 'none'])}"

# ---------------- worker for list mode ----------------

def check_host_for_list(host: str, session: requests.Session, timeout: int, aggressive: bool) -> dict:
    host = host.strip()
    res = {"host": host, "cname": "", "a": "", "status": None, "provider": "", "evidence": "", "final_url": "", "dang_type": None, "resolver_val": ""}
    try:
        # detect dangling type early
        dang_type, resolver_val = detect_dangling_type(host)
        res['dang_type'] = dang_type
        res['resolver_val'] = resolver_val

        if dang_type in ('CNAME', 'A', 'AAAA'):
            # do HTTP fingerprinting
            status_code, headers, body, final = http_probe(session, host, timeout=timeout)
            res['status'] = status_code
            res['final_url'] = final
            headers_text = ' '.join([f"{k}:{v}" for k,v in (headers or {}).items()]) if headers else ''
            body_text = body or ''
            provider, matched_pattern, where = match_provider_from_text_with_context(headers_text + ' ' + body_text)
            if provider:
                res['provider'] = provider
                res['evidence'] = matched_pattern
            else:
                if aggressive and resolver_val:
                    # try cname heuristics
                    prov2, ev2 = disambiguate_provider(resolver_val, headers_text + ' ' + body_text)
                    if prov2:
                        res['provider'] = prov2
                        res['evidence'] = ev2
        elif dang_type == 'NS' and resolver_val:
            is_vuln, evidence = check_ns_takeover(resolver_val)
            if is_vuln:
                res['provider'] = 'NS-Takeover'
                res['evidence'] = evidence
        elif dang_type == 'MX' and resolver_val:
            is_vuln, evidence = check_mx_takeover(resolver_val)
            if is_vuln:
                res['provider'] = 'MX-Takeover'
                res['evidence'] = evidence
        else:
            # no DNS records found — leave as safe/unknown
            pass
    except Exception as e:
        res.setdefault('err', str(e))
    return res

# ---------------- single-host verbose ----------------

def verbose_single_host(host: str, session: requests.Session, timeout: int, aggressive: bool):
    console.rule(f"Detailed check: {host}")
    lines = []
    # DNS
    cname = dns_cname(host) or '<none>'
    lines.append(f"CNAME: {cname}")
    a = resolve_a(host)
    lines.append(f"A: {','.join(a) or '<none>'}")
    aaaa = resolve_aaaa(host)
    lines.append(f"AAAA: {','.join(aaaa) or '<none>'}")
    ns = lookup_ns(host)
    lines.append(f"NS: {','.join(ns) or '<none>'}")
    mx = lookup_mx(host)
    lines.append(f"MX: {','.join(mx) or '<none>'}")

    # WHOIS (for NS/MX root domains)
    if ns:
        ns_root = get_domain_root(ns[0])
        whois_text = '<whois-not-available>'
        if WHOIS_PY:
            try:
                info = pywhois.whois(ns_root)
                whois_text = str(info)[:2000]
            except Exception as e:
                whois_text = str(e)
        elif which('whois'):
            try:
                import subprocess
                out = subprocess.check_output(['whois', ns_root], text=True, stderr=subprocess.DEVNULL, timeout=12)
                whois_text = out[:2000]
            except Exception as e:
                whois_text = str(e)
        lines.append('WHOIS (NS root truncated): ')
        lines.append(whois_text)

    # HTTP
    lines.append('HTTP probes (HEAD + body snippet): ')
    status, headers, body, final = http_probe(session, host, timeout=timeout)
    lines.append(f"Status: {status}  Final URL: {final}")
    if headers:
        h_lines = ' '.join([f"{k}: {v}" for k, v in headers.items()][:200])
        lines.append(h_lines)
    lines.append('Body snippet (first 1200 chars):')
    lines.append((body or '')[:1200])

    # provider detection
    provider, pat, where = match_provider_from_text_with_context((headers and ' '.join([f"{k}:{v}" for k,v in headers.items()])) + ' ' + (body or ''))
    if not provider and aggressive and cname:
        prov2, ev2 = disambiguate_provider(cname, (headers and ' '.join([f"{k}:{v}" for k,v in headers.items()])) + ' ' + (body or ''))
        if prov2:
            provider = prov2
            pat = ev2
    lines.append('Provider detection:')
    lines.append(f"Provider: {provider or '<none>'}")
    lines.append(f"Evidence: {pat or '<none>'}")

    console.print(Panel('\n'.join(lines), title=f"Report: {host}", expand=True))

# ---------------- CLI & formatting ----------------

def parse_args():
    p = argparse.ArgumentParser(prog="takeihn.py",
        description="Subdomain Takeover detector — improved; includes NS/MX checks and fingerprint externalization.")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("-l", "--list", help="Input file containing hosts (one per line or mixed text)")
    group.add_argument("-d", "--domain", help="Single domain/host to run verbose checks against")
    p.add_argument("-o", "--output", help="Optional output file. If omitted, no file is written.")
    p.add_argument("--threads", type=int, default=16, help="Parallel threads (default: 16)")
    p.add_argument("--timeout", type=int, default=8, help="HTTP timeout seconds (default: 8)")
    p.add_argument("--aggressive", action="store_true", help="Aggressive heuristics (may increase false positives)")
    p.add_argument("--rate", type=float, default=0.0, help="Delay (s) between launching tasks to avoid bursts")
    p.add_argument("--quiet", action="store_true", help="Quiet terminal (only summary + final file)")
    # output column toggles for list mode
    p.add_argument("--show-type", action="store_true", help="Include dangling DNS type column in one-line output/file")
    p.add_argument("--show-resolver", action="store_true", help="Include resolver value column in one-line output/file")
    p.add_argument("--show-provider", action="store_true", help="Include provider column in one-line output/file")
    p.add_argument("--show-status", action="store_true", help="Include HTTP status column in one-line output/file")
    return p.parse_args()

BANNER = r'''
  __          __          .__.__            
_/  |______  |  | __ ____ |__|  |__   ____  
\   __\__  \ |  |/ // __ \|  |  |  \ /    \ 
 |  |  / __ \|    <\  ___/|  |   Y  \   |  \
 |__| (____  /__|_ \\___  >__|___|  /___|  /
           \/     \/    \/        \/     \/ 
   Subdomain Takeover Detector — iihhn. v1.0.0
'''


def extract_hosts_from_file(path: str) -> List[str]:
    txt = ""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        txt = fh.read()
    found = SUBDOMAIN_RE.findall(txt)
    cleaned = []
    for f in found:
        f = f.strip().strip(".,;:()[]{}<>\"'")
        if len(f) > 3 and f.count(".") >= 1:
            cleaned.append(f.lower())
    seen = set()
    unique = []
    for h in cleaned:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


def one_line_format(host: str, dang_type: Optional[str], resolver_val: str, provider: str, status: Optional[int], args) -> str:
    parts = [f"{host}"]
    any_flag = args.show_type or args.show_resolver or args.show_provider or args.show_status
    if any_flag:
        if args.show_type:
            parts.append(f"[{dang_type or '-'}]")
        if args.show_resolver:
            parts.append(f"[{resolver_val or '-'}]")
        if args.show_provider:
            parts.append(f"[{provider or '-'}]")
        if args.show_status:
            parts.append(f"[{status or '-'}]")
    else:
        parts.append(f"[{dang_type or '-'}]")
        parts.append(f"[{resolver_val or '-'}]")
        parts.append(f"[{provider or '-'}]")
        parts.append(f"[{status or '-'}]")
    return ' '.join(parts)


def main():
    args = parse_args()
    console.print(Panel(Text(BANNER), title="takeihn", expand=False))

    session = setup_requests_session(retries=1, backoff=0.2)

    if args.list:
        if not os.path.exists(args.list):
            console.print(f"[red]Input file not found: {args.list}[/red]")
            sys.exit(1)
        hosts = extract_hosts_from_file(args.list)
        total = len(hosts)
        if total == 0:
            console.print("[yellow]No hosts found in input. Exiting.[/yellow]")
            sys.exit(0)

        if not args.quiet:
            console.print(f"[cyan]Targets extracted: {total}  — threads={args.threads} timeout={args.timeout}s aggressive={args.aggressive}[/cyan]")

        start = time.time()
        results = []
        vulnerable = []

        with ThreadPoolExecutor(max_workers=max(2, args.threads)) as ex:
            futures = {}
            for h in hosts:
                futures[ex.submit(check_host_for_list, h, session, args.timeout, args.aggressive)] = h
                if args.rate and args.rate > 0:
                    time.sleep(args.rate)

            for fut in as_completed(futures):
                try:
                    r = fut.result()
                except Exception as e:
                    console.print(f"[yellow][ERROR] {futures[fut]}: {e}[/yellow]")
                    continue
                dang_type = r.get('dang_type')
                resolver_val = r.get('resolver_val','')
                line = one_line_format(r['host'], dang_type, resolver_val, r.get('provider',''), r.get('status'), args)
                if r.get('provider'):
                    vulnerable.append((r, dang_type, resolver_val))
                    console.print(f"[red]🔥 {line}[/red]")
                else:
                    console.print(f"[green]{line}[/green]")
                results.append((r, dang_type, resolver_val))

        duration = time.time() - start

        if args.output:
            os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
            with open(args.output, 'w', encoding='utf-8') as fh:
                fh.write(f"# takeihn scan results Generated: {datetime.now(timezone.utc).isoformat().replace('+00:00','Z')} Scanned: {total} targets Found: {len(vulnerable)} potential takeovers ")
                for r, dang_type, resolver_val in results:
                    if not r.get('provider'):
                        continue
                    fh.write(one_line_format(r['host'], dang_type, resolver_val, r.get('provider',''), r.get('status'), args) + ' ')
            console.print(f"[magenta]Results saved to: {args.output}[/magenta]")

        console.print(f"[cyan]Scan finished in {duration:.1f}s — scanned {total}, potential takeovers: {len(vulnerable)}[/cyan]")

    elif args.domain:
        verbose_single_host(args.domain, session, args.timeout, args.aggressive)
        # summary table
        status_code, headers, body, final = http_probe(session, args.domain, timeout=args.timeout)
        provider, pat, where = match_provider_from_text_with_context(( ' '.join([f"{k}:{v}" for k,v in (headers or {}).items()]) ) + ' ' + (body or ''))
        if not provider and args.aggressive:
            prov2, ev2 = disambiguate_provider(dns_cname(args.domain) or '', (body or ''))
            if prov2:
                provider = prov2
                pat = ev2
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("Host", args.domain)
        table.add_row("CNAME", dns_cname(args.domain) or '-')
        table.add_row("Resolved A", ','.join(resolve_a(args.domain)) or '-')
        table.add_row("Provider (heuristic)", provider or '-')
        table.add_row("Evidence", pat or '-')
        table.add_row("HTTP status/final-url", str(status_code or '-') + '  ' + (final or ''))
        console.print(table)

        if args.output:
            with open(args.output, 'a', encoding='utf-8') as fh:
                fh.write(f"# Detailed report for {args.domain} Generated: {datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}")
                fh.write(f"Host: {args.domain} CNAME: {dns_cname(args.domain) or '-'} Resolved A: {','.join(resolve_a(args.domain)) or '-'} Provider: {provider or '-'} Evidence: {pat or '-'} HTTP status/final-url: {status_code or '-'} {final or ''} ")

    else:
        console.print('[red]Either --list or --domain must be provided.[/red]')
        sys.exit(1)

if __name__ == '__main__':
    main()
