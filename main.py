#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import requests

from colorama import Fore, Style, init
from pyfiglet import Figlet

from subdomain_enumeration.subdomain_active_enumeration import enumerate_subdomains
from subdomain_enumeration.subdomain_passive_enumeration import passive_enumerate_subdomains
from Proping.prope import probe_subdomains_from_file
from Proping.filter_probe import filter_probe_results_sync
from Crawler.async_crawler import run_crawler

from vuln.xss_scanner import run_xss_scan_single, run_xss_scan_file


# ============================================================
# INIT
# ============================================================

init(autoreset=True)

CRIMSON = Fore.RED + Style.DIM
ACCENT = Fore.RED + Style.NORMAL
RESET = Style.RESET_ALL


def cprint(text, accent=False):
    print((ACCENT if accent else CRIMSON) + text + RESET)


# ============================================================
# NGROK (NEW TERMINAL)
# ============================================================

def start_ngrok(port=80):
    cprint("[+] Launching ngrok in new terminal...", True)

    try:
        if os.name == "nt":
            subprocess.Popen(["start", "cmd", "/k", f"ngrok http {port}"], shell=True)
        else:
            subprocess.Popen(["gnome-terminal", "--", "ngrok", "http", str(port)])

        time.sleep(3)

        data = requests.get("http://127.0.0.1:4040/api/tunnels").json()

        for t in data.get("tunnels", []):
            return t["public_url"]

    except Exception as e:
        cprint(f"[!] Ngrok failed: {e}")

    return None


# ============================================================
# UI
# ============================================================

def banner():
    f = Figlet(font="slant")
    print(ACCENT + f.renderText("Crimson"))


def section(title):
    cprint("\n" + "=" * 60)
    cprint(f"[ {title} ]", True)
    cprint("=" * 60)


# ============================================================
# MAIN
# ============================================================

def main():
    banner()

    listener_server = start_ngrok()

    cprint(f"[+] Listener: {listener_server}", True)

    print("\n1) Full Recon + Scan")
    print("2) Vulnerability Scan Only")
    print("3) Scan Single Endpoint")

    try:
        mode = int(input("Choice: "))
    except:
        mode = 1

    # ============================================================
    # SINGLE TARGET MODE
    # ============================================================

    if mode == 3:

        url = input("\nEnter full URL: ").strip()

        section("XSS SCAN")

        run_xss_scan_single(url, listener_server)

        return

    # ============================================================
    # NORMAL FLOW
    # ============================================================

    domain = input("\nEnter domain: ").strip()
    results_dir = f"Results/{domain}_results"
    os.makedirs(results_dir, exist_ok=True)

    filtered_file = f"{results_dir}/{domain}_filtered.txt"

    # ============================================================
    # RECON
    # ============================================================

    if mode == 1:

        section("ENUMERATION")

        subs = set()
        subs.update(passive_enumerate_subdomains(domain))
        subs.update(enumerate_subdomains(domain, 100))

        enum_file = f"{results_dir}/{domain}_subs.txt"

        with open(enum_file, "w") as f:
            for s in subs:
                f.write(s + "\n")

        section("PROBING")

        probe_subdomains_from_file(enum_file, domain)

        section("FILTERING")

        filter_probe_results_sync(
            input_file=f"{results_dir}/{domain}_probe_results.txt",
            status_filter="20*",
            output_file=filtered_file,
            follow_redirects_30x=True
        )

        section("CRAWLING")

        run_crawler(
            input_file=filtered_file,
            domain=domain,
            output_prefix=f"{results_dir}/crawl"
        )

    # ============================================================
    # VULN SCAN
    # ============================================================

    if mode in (1, 2):

        section("VULNERABILITY SCANNING")

        print("1) XSS Scanner")

        try:
            vuln_choice = int(input("Select module: "))
        except:
            vuln_choice = 1

        if vuln_choice == 1:

            print("\n1) Scan from recon results")
            print("2) Scan single endpoint")

            try:
                sub_choice = int(input("Choice: "))
            except:
                sub_choice = 1

            if sub_choice == 1:
                run_xss_scan_file(filtered_file, listener_server)
            else:
                url = input("Enter URL: ")
                run_xss_scan_single(url, listener_server)

    section("DONE")
    cprint(f"Listener: {listener_server}", True)


if __name__ == "__main__":
    main()