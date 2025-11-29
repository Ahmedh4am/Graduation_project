#!/usr/bin/env python3
from subdomain_enumeration.subdomain_active_enumeration import enumerate_subdomains, subdomain_printer
from Proping.prope import probe_subdomains_from_file
from Proping.filter_probe import filter_probe_results_sync
from Crawler.async_crawler import run_crawler

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

    domain = input("\nEnter domain to scan: ").strip()
    print(f"Results will be saved in: Results/{domain}_results/")

    # =========================================================================
    # STEP 1: Subdomain Enumeration
    # =========================================================================
    print_section("PHASE 1: SUBDOMAIN ENUMERATION")

    print_step(1, "Enumerating subdomains")
    print("Scanning for subdomains...")

    activeEnum_subdomains = enumerate_subdomains(domain)

    if len(activeEnum_subdomains) > 0:
        print(f"SUCCESS: Found {len(activeEnum_subdomains)} subdomains")
    else:
        print("ERROR: No subdomains found")
        return

    # =========================================================================
    # STEP 2: Subdomain Probing
    # =========================================================================
    print_section("PHASE 2: SUBDOMAIN PROBING")

    print_step(2, "Probing subdomains for HTTP responses")

    # Build the path to the Active Enumeration file that was just created
    active_enum_file_path = f"Results/{domain}_results/{domain}_Active_Enum_subdomains.txt"
    # active_enum_file_path = f"Results/tests/probe_test.txt"  # TEST PATH

    print(f"Reading subdomains from: {active_enum_file_path}")
    print("Probing subdomains (HTTP/HTTPS)...")

    probe_results = probe_subdomains_from_file(active_enum_file_path, domain)

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
