#!/usr/bin/env python3

import os
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
from vuln.ssrf_scanner import run_ssrf_scan_single, run_ssrf_scan_file
from vuln.cors_scanner import run_cors_scan_file, scan_cors_single

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
    cprint("[+] Launching ngrok in new terminal...", True)

    try:
        if os.name == "nt":
            subprocess.Popen(
                ["start", "cmd", "/k", f"ngrok http {port}"],
                shell=True
            )
        else:
            launched = False
            for cmd in [
                ["gnome-terminal", "--", "ngrok", "http", str(port)],
                ["x-terminal-emulator", "-e", "ngrok", "http", str(port)],
                ["xterm", "-e", "ngrok", "http", str(port)],
            ]:
                try:
                    subprocess.Popen(cmd)
                    launched = True
                    break
                except FileNotFoundError:
                    continue

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
# VULN MENU
# ============================================================

def run_vuln_menu(listener_server, filtered_file=None):
    section("VULNERABILITY SCANNING")

    print("1) XSS Scanner")
    print("2) SSRF Scanner")
    print("3) CORS Scanner")

    try:
        vuln_choice = int(input("Select module: "))
    except:
        vuln_choice = 1

    print("\n1) Scan from recon results")
    print("2) Scan single endpoint")

    try:
        sub_choice = int(input("Choice: "))
    except:
        sub_choice = 2

    # SINGLE ENDPOINT
    if sub_choice == 2:
        url = input("Enter full URL: ").strip()

        if vuln_choice == 1:
            run_xss_scan_single(url, listener_server)

        elif vuln_choice == 2:
            run_ssrf_scan_single(url, listener_server)

        elif vuln_choice == 3:
            findings = scan_cors_single(
                url,
                with_credentials=True,
                listener_domain=listener_server
            )

            if findings:
                for f in findings:
                    cprint(
                        f"[!] {f['severity']} | {f['type']} | {f['mode']}",
                        True
                    )
                    cprint(f"    {f['details']}")
            else:
                cprint("[-] No CORS issues found")

        return

    # FILE MODE
    if not filtered_file or not os.path.exists(filtered_file):
        cprint("[!] Recon results missing")
        return

    if vuln_choice == 1:
        run_xss_scan_file(filtered_file, listener_server)

    elif vuln_choice == 2:
        run_ssrf_scan_file(filtered_file, listener_server)

    elif vuln_choice == 3:
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

    print("\n1) Full Recon + Vulnerability Scan")
    print("2) Vulnerability Scan Only")
    print("3) Scan Single Endpoint")

    try:
        mode = int(input("Choice: "))
    except:
        mode = 1

    if mode == 3:
        run_vuln_menu(listener_server)
        return

    domain = input("\nEnter domain: ").strip()

    results_dir = f"Results/{domain}_results"
    os.makedirs(results_dir, exist_ok=True)

    filtered_file = None

    if mode == 1:
        filtered_file = run_recon(domain, results_dir)

    run_vuln_menu(listener_server, filtered_file)

    section("DONE")
    cprint(f"Results: {results_dir}", True)
    cprint(f"Listener: {listener_server}", True)


if __name__ == "__main__":
    main()