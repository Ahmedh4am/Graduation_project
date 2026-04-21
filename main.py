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
            subprocess.Popen(["start", "cmd", "/k", f"ngrok http {port}"], shell=True)
        else:
            subprocess.Popen(["x-terminal-emulator", "-e", "ngrok", "http", str(port)])

        time.sleep(4)

        data = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=5).json()

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
    subs.update(passive_enumerate_subdomains(domain))
    subs.update(enumerate_subdomains(domain, 100))

    enum_file = f"{results_dir}/{domain}_subs.txt"

    with open(enum_file, "w") as f:
        for s in sorted(subs):
            f.write(s + "\n")

    section("PROBING")

    probe_results = probe_subdomains_from_file(enum_file, domain)
    if not probe_results:
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
        return None

    section("CRAWLING")

    run_crawler(
        input_file=filtered_file,
        domain=domain,
        output_prefix=f"{results_dir}/crawl"
    )

    return filtered_file


# ============================================================
# RACE CONDITION (MANUAL TOOL)
# ============================================================

def launch_race_terminal():
    print("\nPaste RAW HTTP request (end with empty line):")

    raw_lines = []
    while True:
        line = input()
        if line == "":
            break
        raw_lines.append(line)

    raw_request = "\n".join(raw_lines)

    param = input("Target parameter (e.g. email): ")
    threads = int(input("Threads: ") or "10")

    # Run directly instead of in subprocess to keep program running
    run_race_condition(raw_request, param, threads)


# ============================================================
# MANUAL TOOLS MENU
# ============================================================

def run_manual_tools():
    section("MANUAL TOOLS")

    print("1) Race Condition Tester")

    choice = input("Select tool: ")

    if choice == "1":
        launch_race_terminal()


# ============================================================
# VULN MENU
# ============================================================

def run_vuln_menu(listener_server, filtered_file=None):
    section("VULNERABILITY SCANNING")

    print("1) XSS")
    print("2) SSRF")
    print("3) CORS")
    print("4) Access Control")
    print("5) Run ALL")

    try:
        vuln_choice = int(input("Select: "))
    except:
        vuln_choice = 5

    print("\n1) From recon results")
    print("2) Single endpoint")

    sub_choice = int(input("Choice: ") or "2")

    if sub_choice == 2:
        url = input("Enter URL: ").strip()

        if vuln_choice in (1, 5):
            run_xss_scan_single(url, listener_server)

        if vuln_choice in (2, 5):
            run_ssrf_scan_single(url, listener_server)

        if vuln_choice in (3, 5):
            findings = scan_cors_single(
                url,
                with_credentials=True,
                listener_domain=listener_server
            )
            for f in findings:
                cprint(f"[!] {f['type']}", True)

        if vuln_choice in (4, 5):
            main_cookie = input("Main session: ")
            low_cookie = input("Low priv: ")
            alt_cookie = input("Second user: ")

            run_access_control_test(
                url,
                session_main=main_cookie,
                session_low=low_cookie,
                session_alt=alt_cookie
            )

        return

    # FILE MODE
    if not filtered_file:
        cprint("[!] No recon data")
        return

    if vuln_choice in (1, 5):
        run_xss_scan_file(filtered_file, listener_server)

    if vuln_choice in (2, 5):
        run_ssrf_scan_file(filtered_file, listener_server)

    if vuln_choice in (3, 5):
        run_cors_scan_file(
            filtered_file,
            with_credentials=True,
            listener_domain=listener_server
        )


# ============================================================
# MAIN
# ============================================================

def main():
    banner()

    listener_server = start_ngrok()
    cprint(f"[+] Listener: {listener_server}", True)

    while True:
        print("\n1) Full Recon + Vulnerability Scan")
        print("2) Recon Only")
        print("3) Vulnerability Scan Only")
        print("4) Scan Single Endpoint")
        print("5) Manual Tools")
        print("6) Exit")

        try:
            mode = int(input("Choice: ") or "1")
        except ValueError:
            mode = 1

        if mode == 6:
            break

        if mode == 5:
            run_manual_tools()
            continue

        if mode == 4:
            run_vuln_menu(listener_server)
            continue

        domain = input("Enter domain: ").strip()

        results_dir = f"Results/{domain}_results"
        os.makedirs(results_dir, exist_ok=True)

        filtered_file = None

        if mode in (1, 2):
            filtered_file = run_recon(domain, results_dir)

        if mode == 2:
            section("DONE")
            continue

        run_vuln_menu(listener_server, filtered_file)

        section("DONE")
        cprint(f"Results: {results_dir}", True)
        cprint(f"Listener: {listener_server}", True)


if __name__ == "__main__":
    main()