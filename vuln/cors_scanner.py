import requests
from urllib.parse import urlparse

DEFAULT_TIMEOUT = 6

EXTENSIONS_TO_SKIP = [
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg",
    ".css", ".js",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".rar", ".exe", ".mp4", ".mp3"
]


def generate_smart_origins(target_url, listener_domain=None):
    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc
        scheme = parsed.scheme or "https"

        origins = {
            f"{scheme}://{domain}.attacker.com",
            f"{scheme}://attacker-{domain}",
            f"{scheme}://attacker{domain}",
            f"{scheme}://{domain}@attacker.com",
            f"{scheme}://attacker.com#{domain}",
            f"{scheme}://{domain}%00.attacker.com",
            "null",
            "https://evil.com"
        }

        # Add ngrok / listener domain if provided
        if listener_domain:
            origins.add(listener_domain)

            # add some trick variants based on ngrok
            parsed_listener = urlparse(listener_domain)
            listener_host = parsed_listener.netloc

            origins.add(f"https://{listener_host}.evil.com")
            origins.add(f"https://evil-{listener_host}")

        return list(origins)

    except Exception:
        origins = ["https://evil.com", "null"]

        if listener_domain:
            origins.append(listener_domain)

        return origins


def analyze_cors_response(method, origin, headers, credentialed=False):
    findings = []

    h = {k.lower(): v for k, v in headers.items()}

    acao = h.get("access-control-allow-origin")
    acac = h.get("access-control-allow-credentials", "").lower()

    if acao == origin:
        if credentialed and acac == "true":
            findings.append({
                "type": "CORS Origin Reflection with Credentials",
                "severity": "High",
                "details": f"{method} reflects {origin} with credentials"
            })
        else:
            findings.append({
                "type": "CORS Origin Reflection",
                "severity": "Medium",
                "details": f"{method} reflects {origin}"
            })

    elif acao == "*" and acac == "true":
        findings.append({
            "type": "Wildcard with Credentials",
            "severity": "Low",
            "details": "ACAO=* with ACAC=true"
        })

    elif acao == "null" and origin == "null":
        findings.append({
            "type": "Null Origin Allowed",
            "severity": "Medium",
            "details": "null origin trusted"
        })

    return findings


def build_headers(origin, credentialed=False, cookie=None, auth=None):
    headers = {"Origin": origin}

    if credentialed:
        if cookie:
            headers["Cookie"] = cookie
        if auth:
            headers["Authorization"] = auth

    return headers


def scan_cors_single(
    url,
    timeout=DEFAULT_TIMEOUT,
    verify=True,
    cookie_header=None,
    auth_header=None,
    with_credentials=False,
    listener_domain=None
):
    findings = []

    origins = generate_smart_origins(url, listener_domain)

    methods = ["GET", "POST", "HEAD"]

    session = requests.Session()

    modes = [{"name": "no_credentials", "cred": False}]
    if with_credentials:
        modes.append({"name": "with_credentials", "cred": True})

    for mode in modes:
        for origin in origins:

            for method in methods:
                try:
                    headers = build_headers(
                        origin,
                        mode["cred"],
                        cookie_header,
                        auth_header
                    )

                    r = session.request(
                        method,
                        url,
                        headers=headers,
                        timeout=timeout,
                        verify=verify
                    )

                    res = analyze_cors_response(
                        method,
                        origin,
                        r.headers,
                        mode["cred"]
                    )

                    for f in res:
                        f["mode"] = mode["name"]

                    findings.extend(res)

                except Exception:
                    continue

            # preflight
            try:
                opt = session.options(
                    url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "POST"
                    },
                    timeout=timeout,
                    verify=verify
                )

                res = analyze_cors_response(
                    "OPTIONS",
                    origin,
                    opt.headers,
                    mode["cred"]
                )

                for f in res:
                    f["mode"] = mode["name"] + "_preflight"

                findings.extend(res)

            except Exception:
                continue

    return findings


def run_cors_scan_file(
    input_file,
    cookie_header=None,
    auth_header=None,
    timeout=DEFAULT_TIMEOUT,
    verify=True,
    with_credentials=False,
    listener_domain=None
):
    try:
        with open(input_file) as f:
            urls = [u.strip() for u in f if u.strip()]

        for url in urls:
            if any(url.lower().endswith(ext) for ext in EXTENSIONS_TO_SKIP):
                continue

            print(f"\n[*] Testing: {url}")

            results = scan_cors_single(
                url,
                timeout,
                verify,
                cookie_header,
                auth_header,
                with_credentials,
                listener_domain
            )

            if results:
                for r in results:
                    print(f"  [!] {r['severity']} | {r['type']} | {r['mode']}")
                    print(f"      {r['details']}")
            else:
                print("  [-] No issues")

    except Exception as e:
        print(f"[!] Error: {e}")