#!/usr/bin/env python3

import os
import subprocess
import time
import requests
import sys
import tempfile

from colorama import Fore, Style, init
from pyfiglet import Figlet

from subdomain_enumeration.subdomain_active_enumeration import enumerate_subdomains
from subdomain_enumeration.subdomain_passive_enumeration import passive_enumerate_subdomains
from Proping.prope import probe_subdomains_from_file
from Proping.filter_probe import filter_probe_results_sync
from Crawler.async_crawler import run_crawler

from vuln.xss_scanner import run_xss_scan_single, run_xss_scan_file
from vuln.ssrf_scanner import run_ssrf_scan_single, run_ssrf_scan_file
from vuln.cors_scanner import run_cors_scan_file, scan_cors_single
from vuln.access_control_scanner import run_access_control_test
from vuln.sqli_scanner import run_sqli_scan_single, run_sqli_scan_file
from vuln.graphql_scanner import run_graphql_scan_file, scan_graphql_single
from vuln.csrf_scanner import run_csrf_scan_file, scan_csrf_single

from vuln.race_condition import run_race_condition


# ============================================================
# INIT + COLORS
# ============================================================

init(autoreset=True)

CRIMSON = Fore.RED + Style.DIM
ACCENT = Fore.RED + Style.NORMAL
RESET = Style.RESET_ALL


def cprint(text, accent=False):
    print((ACCENT if accent else CRIMSON) + text + RESET)


# ============================================================
# UI
# ============================================================

def banner():
    f = Figlet(font="slant")
    print(ACCENT + f.renderText("Crimson"))
    cprint("=" * 60)


def section(title):
    cprint("\n" + "=" * 60)
    cprint(f"[ {title} ]", True)
    cprint("=" * 60)


# ============================================================
# NGROK
# ============================================================

def start_ngrok(port=80):
    cprint("[+] Launching ngrok...", True)

    try:
        if os.name == "nt":
            subprocess.Popen(
                ["start", "cmd", "/k", f"ngrok http {port}"],
                shell=True
            )
        else:
            subprocess.Popen(
                ["x-terminal-emulator", "-e", "ngrok", "http", str(port)]
            )

        time.sleep(4)

        data = requests.get(
            "http://127.0.0.1:4040/api/tunnels",
            timeout=5
        ).json()

        for tunnel in data.get("tunnels", []):
            if "public_url" in tunnel:
                return tunnel["public_url"]

    except Exception as e:
        cprint(f"[!] Ngrok failed: {e}")

    return None


# ============================================================
# RECON
# ============================================================

def run_recon(domain, results_dir):
    section("ENUMERATION")

    subs = set()

    try:
        subs.update(passive_enumerate_subdomains(domain))
    except Exception as e:
        cprint(f"[!] Passive enum failed: {e}")

    try:
        subs.update(enumerate_subdomains(domain, 100))
    except Exception as e:
        cprint(f"[!] Active enum failed: {e}")

    enum_file = f"{results_dir}/{domain}_subs.txt"

    with open(enum_file, "w") as f:
        for s in sorted(subs):
            f.write(s + "\n")

    cprint(f"[+] Saved {len(subs)} subdomains")

    section("PROBING")

    probe_results = probe_subdomains_from_file(enum_file, domain)

    if not probe_results:
        cprint("[!] No live subdomains")
        return None

    section("FILTERING")

    filtered_file = f"{results_dir}/{domain}_filtered.txt"

    filtered = filter_probe_results_sync(
        input_file=f"{results_dir}/{domain}_probe_results.txt",
        status_filter="20*",
        output_file=filtered_file,
        follow_redirects_30x=True
    )

    if not filtered:
        cprint("[!] No filtered URLs")
        return None

    section("CRAWLING")

    try:
        run_crawler(
            input_file=filtered_file,
            domain=domain,
            output_prefix=f"{results_dir}/crawl"
        )
    except Exception as e:
        cprint(f"[!] Crawling failed: {e}")

    return filtered_file


# ============================================================
# MANUAL TOOLS
# ============================================================

def launch_race_terminal():
    section("RACE CONDITION")

    print("Paste RAW HTTP request")
    print("Finish with an empty line\n")

    raw_lines = []

    while True:
        line = input()

        if line == "":
            break

        raw_lines.append(line)

    raw_request = "\n".join(raw_lines)

    param = input("Target parameter: ").strip()
    threads = int(input("Threads: ") or "10")

    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        mode="w",
        suffix=".txt"
    )

    temp_file.write(raw_request)
    temp_file.close()

    cmd = [
        sys.executable,
        "-c",
        f"""
from vuln.race_condition import run_race_condition
raw = open(r'{temp_file.name}').read()
run_race_condition(raw, '{param}', {threads})
"""
    ]

    if os.name == "nt":
        subprocess.Popen(
            ["start", "cmd", "/k"] + cmd,
            shell=True
        )
    else:
        subprocess.Popen(
            ["x-terminal-emulator", "-e"] + cmd
        )


def run_manual_tools():
    section("MANUAL TOOLS")

    print("1) Race Condition Tester")

    choice = input("Select tool: ").strip()

    if choice == "1":
        launch_race_terminal()


# ============================================================
# VULNERABILITY MENU
# ============================================================

def run_vuln_menu(listener_server, filtered_file=None):
    section("VULNERABILITY SCANNING")

    print("1) XSS")
    print("2) SSRF")
    print("3) CORS")
    print("4) Access Control")
    print("5) SQL Injection")
    print("6) GraphQL")
    print("7) CSRF")
    print("8) Run ALL")

    try:
        vuln_choice = int(input("Select: "))
    except:
        vuln_choice = 8

    print("\n1) From recon results")
    print("2) Single endpoint")

    try:
        sub_choice = int(input("Choice: "))
    except:
        sub_choice = 2

    # ============================================================
    # SINGLE ENDPOINT
    # ============================================================

    if sub_choice == 2:

        url = input("Enter URL: ").strip()

        # ========================================================
        # XSS
        # ========================================================

        if vuln_choice in (1, 8):
            section("XSS")
            run_xss_scan_single(url, listener_server)

        # ========================================================
        # SSRF
        # ========================================================

        if vuln_choice in (2, 8):
            section("SSRF")
            run_ssrf_scan_single(url, listener_server)

        # ========================================================
        # CORS
        # ========================================================

        if vuln_choice in (3, 8):
            section("CORS")

            findings = scan_cors_single(
                url,
                with_credentials=True,
                listener_domain=listener_server
            )

            if findings:
                for f in findings:
                    cprint(
                        f"[!] {f['severity']} | {f['type']}",
                        True
                    )
            else:
                cprint("[-] No issues")

        # ========================================================
        # ACCESS CONTROL
        # ========================================================

        if vuln_choice in (4, 8):
            section("ACCESS CONTROL")

            print("\n[ Sessions ]")

            main_cookie = input("Main session: ").strip()
            low_cookie = input("Low privilege session: ").strip()
            alt_cookie = input("Second user session: ").strip()

            run_access_control_test(
                url,
                session_main=main_cookie,
                session_low=low_cookie,
                session_alt=alt_cookie
            )

        # ========================================================
        # SQLI
        # ========================================================

        if vuln_choice in (5, 8):
            section("SQL INJECTION")
            run_sqli_scan_single(url)

        # ========================================================
        # GRAPHQL
        # ========================================================

        if vuln_choice in (6, 8):
            section("GRAPHQL")

            findings = scan_graphql_single(url)

            if findings:
                for f in findings:
                    cprint(
                        f"[!] {f['severity']} | {f['type']}",
                        True
                    )
            else:
                cprint("[-] No GraphQL endpoints or issues found")

        # ========================================================
        # CSRF
        # ========================================================

        if vuln_choice in (7, 8):
            section("CSRF")

            cookie = input("Cookie (optional): ").strip() or None

            findings = scan_csrf_single(url, cookie_header=cookie)

            if findings:
                for f in findings:
                    cprint(
                        f"[!] {f['severity']} | {f['type']}",
                        True
                    )
            else:
                cprint("[-] No CSRF issues found")

        return

    # ============================================================
    # FILE MODE
    # ============================================================

    if not filtered_file or not os.path.exists(filtered_file):
        cprint("[!] Recon results missing")
        return

    # ============================================================
    # XSS
    # ============================================================

    if vuln_choice in (1, 8):
        section("XSS")
        run_xss_scan_file(filtered_file, listener_server)

    # ============================================================
    # SSRF
    # ============================================================

    if vuln_choice in (2, 8):
        section("SSRF")
        run_ssrf_scan_file(filtered_file, listener_server)

    # ============================================================
    # CORS
    # ============================================================

    if vuln_choice in (3, 8):
        section("CORS")

        run_cors_scan_file(
            filtered_file,
            with_credentials=True,
            listener_domain=listener_server
        )

    # ============================================================
    # SQLI
    # ============================================================

    if vuln_choice in (5, 8):
        section("SQL INJECTION")
        run_sqli_scan_file(filtered_file)

    # ============================================================
    # GRAPHQL
    # ============================================================

    if vuln_choice in (6, 8):
        section("GRAPHQL")
        run_graphql_scan_file(filtered_file)

    # ============================================================
    # CSRF
    # ============================================================

    if vuln_choice in (7, 8):
        section("CSRF")
        run_csrf_scan_file(filtered_file)


# ============================================================
# MAIN
# ============================================================

def main():
    banner()

    listener_server = start_ngrok()

    cprint(f"[+] Listener: {listener_server}", True)

    print("\n1) Full Recon + Vulnerability Scan")
    print("2) Recon Only")
    print("3) Vulnerability Scan Only")
    print("4) Scan Single Endpoint")
    print("5) Manual Tools")

    try:
        mode = int(input("Choice: "))
    except:
        mode = 1

    # ============================================================
    # MANUAL TOOLS
    # ============================================================

    if mode == 5:
        run_manual_tools()
        return

    # ============================================================
    # SINGLE ENDPOINT
    # ============================================================

    if mode == 4:
        run_vuln_menu(listener_server)
        return

    # ============================================================
    # DOMAIN INPUT
    # ============================================================

    domain = input("\nEnter domain: ").strip()

    results_dir = f"Results/{domain}_results"

    os.makedirs(results_dir, exist_ok=True)

    filtered_file = None

    # ============================================================
    # RECON
    # ============================================================

    if mode in (1, 2):
        filtered_file = run_recon(domain, results_dir)

    # ============================================================
    # RECON ONLY
    # ============================================================

    if mode == 2:
        section("DONE")
        cprint(f"Results saved in {results_dir}", True)
        return

    # ============================================================
    # VULN SCAN
    # ============================================================

    run_vuln_menu(listener_server, filtered_file)

    # ============================================================
    # DONE
    # ============================================================

    section("DONE")

    cprint(f"Results directory: {results_dir}", True)
    cprint(f"Listener server: {listener_server}", True)


if __name__ == "__main__":
    main()