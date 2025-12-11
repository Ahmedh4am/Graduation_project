import os
import time
import json
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

USER_AGENT = "passive-enum-module/1.0"
SLEEP_BETWEEN_REQUESTS = 1.0

# -------------------------------
# Helper functions
# -------------------------------
def _normalize_hostname(h):
    if not h:
        return None
    h = h.strip().lower()
    if "://" in h:
        h = urlparse(h).hostname or h
    return h.rstrip(".")

def _is_valid_sub(s, domain):
    if not s or domain not in s:
        return False
    # reject IPs
    import re
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
        return False
    return True

# -------------------------------
# Passive sources
# -------------------------------
def _query_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": USER_AGENT}
    results = set()

    try:
        r = requests.get(url, headers=headers, timeout=30)
        time.sleep(SLEEP_BETWEEN_REQUESTS)

        # sometimes JSON is valid
        try:
            entries = r.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for part in name.split("\n"):
                    if part:
                        results.add(part.strip())
            return list(results)
        except:
            # fallback: HTML
            soup = BeautifulSoup(r.text, "html.parser")
            tds = soup.find_all("td")
            for td in tds:
                txt = td.get_text(strip=True)
                if domain in txt:
                    results.add(txt)
            return list(results)

    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return []

def _query_wayback(domain):
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&filter=statuscode:200&limit=2000"
    )
    headers = {"User-Agent": USER_AGENT}
    results = set()

    try:
        r = requests.get(url, headers=headers, timeout=30)
        time.sleep(SLEEP_BETWEEN_REQUESTS)

        data = r.json()
        for row in data[1:]:
            url = row[2] if len(row) > 2 else None
            if not url:
                continue
            host = urlparse(url).hostname
            if host:
                results.add(host)
        return list(results)
    except Exception as e:
        print(f"[!] Wayback error: {e}")
        return []

# -------------------------------
# MAIN FUNCTION TO USE
# -------------------------------
def passive_enumerate_subdomains(domain):
    print(f"[+] Passive enumeration for: {domain}")

    all_raw = []

    # crt.sh
    crt = _query_crtsh(domain)
    print(f"    crt.sh returned {len(crt)} candidates")
    all_raw.extend(crt)

    # Wayback
    wb = _query_wayback(domain)
    print(f"    Wayback returned {len(wb)} candidates")
    all_raw.extend(wb)

    # Normalize + filter
    filtered = []
    seen = set()

    for s in all_raw:
        s = _normalize_hostname(s)
        if not s:
            continue
        s = s.replace("*.", "")
        if s not in seen and _is_valid_sub(s, domain):
            filtered.append(s)
            seen.add(s)

    print(f"[+] Final cleaned subdomains: {len(filtered)}")

    # Save to Results folder
    base_dir = "Results"
    domain_dir = os.path.join(base_dir, f"{domain}_results")
    os.makedirs(domain_dir, exist_ok=True)

    output_file = os.path.join(domain_dir, f"{domain}_Passive_Enum_subdomains.txt")

    with open(output_file, "w") as f:
        for sub in filtered:
            f.write(sub + "\n")

    return filtered
