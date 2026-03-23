import requests
import argparse
import difflib
import random
import string
from urllib.parse import urlparse
import os
import re

# Static files to skip
SKIP_EXTENSIONS = {
    ".png",".jpg",".jpeg",".gif",".svg",".webp",
    ".pdf",".css",".js",".woff",".woff2",".ttf",
    ".ico",".mp4",".mp3",".avi",".zip",".tar",".gz"
}

# Debug pages that reflect query strings
SKIP_FILES = {
    "phpinfo.php",
    "server-status",
    "server-info"
}


def rand():
    return ''.join(random.choice(string.ascii_letters) for _ in range(6))


def similarity(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()


def normalize(text):
    """
    Remove noisy parts of response that cause false positives
    """
    text = re.sub(r'QUERY_STRING.*', '', text)
    text = re.sub(r'\?.*?=', '', text)
    return text


def should_skip(url):

    parsed = urlparse(url)
    path = parsed.path
    ext = os.path.splitext(path)[1].lower()

    if ext in SKIP_EXTENSIONS:
        return True

    if os.path.basename(path) in SKIP_FILES:
        return True

    return False


def test_param(url, param, headers):

    v1 = rand()
    v2 = rand()

    try:
        # baseline request
        r0 = requests.get(url, headers=headers, timeout=10)

        # requests with parameter
        r1 = requests.get(url, params={param: v1}, headers=headers, timeout=10)
        r2 = requests.get(url, params={param: v2}, headers=headers, timeout=10)

    except requests.RequestException:
        return False

    base = normalize(r0.text)
    t1 = normalize(r1.text)
    t2 = normalize(r2.text)

    sim1 = similarity(base, t1)
    sim2 = similarity(base, t2)
    sim12 = similarity(t1, t2)

    len_diff1 = abs(len(base) - len(t1))
    len_diff2 = abs(len(base) - len(t2))

    # reflection detection
    if v1 in r1.text or v2 in r2.text:
        return True

    # page changed from baseline
    if sim1 < 0.97 or sim2 < 0.97:
        return True

    # content length difference
    if len_diff1 > 20 or len_diff2 > 20:
        return True

    # different parameter values change output
    if sim12 < 0.97:
        return True

    return False


def main():

    parser = argparse.ArgumentParser(description="Hidden Parameter Finder")

    parser.add_argument("-u", required=True, help="URLs file")
    parser.add_argument("-p", required=True, help="Parameter wordlist")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--cookie", help="Cookie header")

    args = parser.parse_args()

    headers = {}

    if args.cookie:
        headers["Cookie"] = args.cookie

    with open(args.u) as f:
        urls = [i.strip() for i in f if i.strip()]

    with open(args.p) as f:
        params = [i.strip() for i in f if i.strip()]

    outfile = open(args.output, "w", buffering=1) if args.output else None

    for url in urls:

        if should_skip(url):
            print(f"[!] Skipping static/debug file: {url}", flush=True)
            continue

        print(f"\n[*] Testing {url}", flush=True)

        for param in params:

            if test_param(url, param, headers):

                result = f"{url}?{param}=VALUE"

                print(f"[+] Possible parameter: {result}", flush=True)

                if outfile:
                    outfile.write(result + "\n")
                    outfile.flush()

    if outfile:
        outfile.close()


if __name__ == "__main__":
    main()