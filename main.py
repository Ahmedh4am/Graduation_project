#!/usr/bin/env python3
from subdomain_enumeration.subdomain_active_enumeration import enumerate_subdomains, subdomain_printer
from subdomain_enumeration.subdomain_passive_enumeration import passive_enumerate_subdomains
from Proping.prope import probe_subdomains_from_file
from Proping.filter_probe import filter_probe_results_sync
from Crawler.async_crawler import run_crawler
import os

def print_banner():
    """Print a formatted banner for better visual appearance"""
    print("============================================================")
    print("               SUBDOMAIN RECONNAISSANCE TOOL               ")
    print("            Enumeration -> Probing -> Crawling             ")
    print("============================================================")

def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'='*60}")
    print(f"[ {title} ]")
    print(f"{'='*60}")

def print_step(step_number, description):
    """Print a formatted step"""
    print(f"\n[STEP {step_number}] {description}")

def main():
    print_banner()
    wordlist_file = "Word_lists/active_subdomian_enumeration_word_list.txt"
    domain = input("\nEnter domain to scan: ").strip()
    print(f"Results will be saved in: Results/{domain}_results/")

    # =========================================================================
    # STEP 1: Subdomain Enumeration
    # =========================================================================

    print_section("PHASE 1: SUBDOMAIN ENUMERATION")
    print_step(1, "Enumerating subdomains")

    print("Choose enumeration method:")
    print("  1) Active (wordlist brute-force)")
    print("  2) Passive (crt.sh, Wayback, etc.)")
    print("  3) Both (passive first → active)")
    try:
        method = int(input("Enter choice (1, 2, or 3): "))
    except ValueError:
        method = 1

    print("\n[+] Selected mode:", 
        "Active" if method == 1 else 
        "Passive" if method == 2 else 
        "Both")

    # -----------------------------
    # Wordlist loading (only needed for active or both)
    # -----------------------------
    if method in (1, 3):
        with open(wordlist_file, "r", encoding="utf-8") as current_file:
            content = current_file.read()
            words = content.split()

        total_words = len(words)
        print(f"[+] Wordlist contains {total_words} entries.")

        try:
            word_list_filter = int(input("Select the number of entries: "))
        except ValueError:
            word_list_filter = 10
            print("[!] Invalid input, using default value: 10")

        if word_list_filter > total_words:
            word_list_filter = total_words
        elif word_list_filter <= 0:
            word_list_filter = 10

    # -----------------------------
    # RUN PASSIVE ENUM (if chosen)
    # -----------------------------
    all_subdomains = set()

    if method in (2, 3):
        print("\n[*] Running PASSIVE enumeration...")
        passive_subs = passive_enumerate_subdomains(domain)
        all_subdomains.update(passive_subs)
        print(f"[+] Passive found: {len(passive_subs)} subdomains")

    # -----------------------------
    # RUN ACTIVE ENUM (if chosen)
    # -----------------------------
    if method in (1, 3):
        print("\n[*] Running ACTIVE enumeration...")
        active_subs = enumerate_subdomains(domain, word_list_filter)
        all_subdomains.update(active_subs)
        print(f"[+] Active found: {len(active_subs)} subdomains")

    # -----------------------------
    # FINAL MERGED RESULTS
    # -----------------------------
    print("\n[+] FINAL MERGED RESULTS")
    print(f"[+] Total unique subdomains: {len(all_subdomains)}")

    # Save merged results to the SAME file ALWAYS
    results_dir = f"Results/{domain}_results"
    os.makedirs(results_dir, exist_ok=True)

    enum_file_path = os.path.join(results_dir, f"{domain}_Enum_subdomains.txt")

    with open(enum_file_path, "w") as f:
        for sub in sorted(all_subdomains):
            f.write(sub + "\n")

    print(f"[+] Saved results to: {enum_file_path}")

    # Print them
    print("\nFound Subdomains:\n---------------------------")
    for s in sorted(all_subdomains):
        print(s)



    # =========================================================================
    # STEP 2: Subdomain Probing
    # =========================================================================
    print_section("PHASE 2: SUBDOMAIN PROBING")

    print_step(2, "Probing subdomains for HTTP responses")

    # Build the path to the Active Enumeration file that was just created
    enum_file_path = f"Results/{domain}_results/{domain}_Enum_subdomains.txt"
    # active_enum_file_path = f"Results/tests/probe_test.txt"  # TEST PATH

    print(f"Reading subdomains from: {enum_file_path}")
    print("Probing subdomains (HTTP/HTTPS)...")

    probe_results = probe_subdomains_from_file(enum_file_path, domain)

    if probe_results:
        print(f"SUCCESS: Successfully probed {len(probe_results)} responsive subdomains")
    else:
        print("ERROR: No responsive subdomains found")
        return

    # =========================================================================
    # STEP 3: Filtering Probe Results
    # =========================================================================
    print_section("PHASE 3: FILTERING RESULTS")

    print_step(3, "Filtering responsive subdomains")

    probe_results_file = f"Results/{domain}_results/{domain}_probe_results.txt"
    filtered_results_file = f"Results/{domain}_results/{domain}_probe_filter_results.txt"

    print(f"Input file: {probe_results_file}")
    print(f"Output file: {filtered_results_file}")
    print("Filter: 20* status codes (successful responses)")
    print("Redirect following: Enabled for 30* status codes")

    filtered_urls = filter_probe_results_sync(
        input_file=probe_results_file,
        status_filter="20*",  # Change to "30*", "40*", etc. as needed
        output_file=filtered_results_file,
        follow_redirects_30x=True  # Automatically follow redirects for 30* codes
    )

    if filtered_urls:
        print(f"SUCCESS: Filtered to {len(filtered_urls)} URLs with successful responses")
    else:
        print("ERROR: No URLs passed the filter")
        return

    # =========================================================================
    # STEP 4: Web Crawling
    # =========================================================================
    print_section("PHASE 4: WEB CRAWLING")

    print_step(4, "Crawling filtered URLs for content discovery")

    # Use the filtered results file as input for crawling
    crawl_input_file = f"Results/{domain}_results/{domain}_probe_filter_results.txt"
    # crawl_input_file = f"Results/tests/crawl_test.txt"  # TEST PATH
    crawl_output_dir = f"Results/{domain}_results/crawl_results"

    print(f"Crawl input: {crawl_input_file}")
    print(f"Output directory: {crawl_output_dir}")
    print("Starting async crawler with real-time streaming...")
    print("Note: Results are saved immediately as they're discovered")

    # Run the crawler
    crawl_results = run_crawler(
        input_file=crawl_input_file,
        domain=domain,
        output_prefix=crawl_output_dir
    )

    # =========================================================================
    # FINAL SUMMARY
    # =========================================================================
    print_section("SCAN COMPLETE")

    print("All phases completed successfully!")
    print("\nFINAL RESULTS:")
    print(f"  - Subdomains enumerated: {len(activeEnum_subdomains)}")
    print(f"  - Responsive subdomains: {len(probe_results)}")
    print(f"  - Filtered URLs (20*): {len(filtered_urls)}")

    if crawl_results:
        print(f"  - Pages crawled: {len(crawl_results.visited_pages)}")
        print(f"  - URLs discovered: {len(crawl_results.discovered_urls)}")
        print(f"  - Files found: {len(crawl_results.discovered_files)}")
        print(f"  - Errors encountered: {len(crawl_results.errors)}")

    print(f"\nAll results saved in: Results/{domain}_results/")
    print("\nOUTPUT FILES:")
    print(f"  - Enumeration: {domain}_Active_Enum_subdomains.txt")
    print(f"  - Probing: {domain}_probe_results.txt")
    print(f"  - Filtered: {domain}_probe_filter_results.txt")
    print(f"  - Crawling: crawl_results/ directory")

    print(f"\nScan completed for: {domain}")

if __name__ == "__main__":
    main()
