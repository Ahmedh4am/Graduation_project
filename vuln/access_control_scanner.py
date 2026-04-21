import requests


# ============================================================
# HELPERS
# ============================================================

def make_request(url, method="GET", headers=None):
    try:
        return requests.request(
            method,
            url,
            headers=headers,
            timeout=6,
            verify=False
        )
    except:
        return None


def compare_responses(base, other):
    if not base or not other:
        return False

    if base.status_code != other.status_code:
        return False

    # simple similarity check
    return base.text[:300] == other.text[:300]


# ============================================================
# MAIN ACCESS CONTROL TEST
# ============================================================

def run_access_control_test(
    url,
    method="GET",
    session_main=None,
    session_low=None,
    session_alt=None
):
    print("\n===== ACCESS CONTROL TEST =====")

    headers_main = {"Cookie": session_main} if session_main else {}
    headers_low = {"Cookie": session_low} if session_low else {}
    headers_alt = {"Cookie": session_alt} if session_alt else {}

    # ------------------------------------------------
    # BASELINE
    # ------------------------------------------------
    print("[*] Sending baseline request (authenticated)")
    base = make_request(url, method, headers_main)

    if not base:
        print("[!] Baseline request failed")
        return

    print(f"[+] Status: {base.status_code}")

    # ------------------------------------------------
    # NO AUTH
    # ------------------------------------------------
    print("\n[*] Testing WITHOUT authentication")
    no_auth = make_request(url, method, {})

    if no_auth:
        if compare_responses(base, no_auth):
            print("[!] Potential UNAUTHENTICATED ACCESS (same response)")
        else:
            print("[OK] Unauthenticated access blocked")

    # ------------------------------------------------
    # SECOND SESSION (IDOR)
    # ------------------------------------------------
    if session_alt:
        print("\n[*] Testing with SECOND SESSION (IDOR check)")
        alt = make_request(url, method, headers_alt)

        if alt:
            if compare_responses(base, alt):
                print("[!] Potential IDOR (same data across users)")
            else:
                print("[OK] Data properly restricted")

    # ------------------------------------------------
    # LOW PRIV SESSION
    # ------------------------------------------------
    if session_low:
        print("\n[*] Testing LOW PRIVILEGE session")
        low = make_request(url, method, headers_low)

        if low:
            if compare_responses(base, low):
                print("[!] Potential PRIVILEGE ESCALATION")
            else:
                print("[OK] Privileges enforced correctly")

    print("\n===== TEST COMPLETE =====")

