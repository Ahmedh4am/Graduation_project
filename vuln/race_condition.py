import requests
import threading
import subprocess
import sys
import urllib.parse


# ============================================================
# RAW REQUEST PARSER
# ============================================================

def parse_raw_request(raw):
    lines = raw.strip().split("\n")

    method, path, _ = lines[0].split()

    headers = {}
    body = ""
    is_body = False

    for line in lines[1:]:
        if line.strip() == "":
            is_body = True
            continue

        if not is_body:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()
        else:
            body += line

    host = headers.get("Host")
    url = f"https://{host}{path}"

    return method, url, headers, body


# ============================================================
# PARAM MODIFIER
# ============================================================

def modify_param(body, param, index):
    parsed = urllib.parse.parse_qs(body)

    if param not in parsed:
        return body

    original = parsed[param][0]

    if "@" in original:
        name, domain = original.split("@")
        new_val = f"{name}+{index}@{domain}"
    else:
        new_val = f"{original}{index}"

    parsed[param] = new_val

    return urllib.parse.urlencode(parsed, doseq=True)


# ============================================================
# WORKER
# ============================================================

def send_request(method, url, headers, body):
    try:
        r = requests.request(
            method,
            url,
            headers=headers,
            data=body,
            timeout=5,
            verify=False
        )
        print(f"[{r.status_code}] {len(r.text)} bytes")
    except:
        print("[ERROR]")


# ============================================================
# RACE ENGINE
# ============================================================

def run_race_condition(raw_request, target_param, threads=10):

    print("\n===== RACE CONDITION ENGINE =====")

    method, url, headers, body = parse_raw_request(raw_request)

    thread_list = []

    for i in range(threads):
        modified_body = modify_param(body, target_param, i)

        t = threading.Thread(
            target=send_request,
            args=(method, url, headers, modified_body)
        )

        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    print("===== DONE =====")