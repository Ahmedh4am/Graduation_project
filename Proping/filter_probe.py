#!/usr/bin/env python3
import asyncio
import aiohttp
import os
from urllib.parse import urlparse

async def follow_redirects(url, session, timeout=5):
    """
    Follow redirects for a URL and return the final URL
    """
    try:
        async with session.get(url, timeout=timeout, ssl=False, allow_redirects=True) as response:
            return str(response.url)
    except Exception as e:
        print(f"[-] Error following redirects for {url}: {e}")
        return url

async def process_urls_with_redirects(urls, concurrency=10):
    """
    Process URLs and follow redirects for each one
    """
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    timeout = aiohttp.ClientTimeout(total=10)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [follow_redirects(url, session) for url in urls]
        results = await asyncio.gather(*tasks)

    return results

def read_probe_results(file_path):
    """
    Read probe results file and return list of subdomains with their status codes
    """
    results = []
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()

        # Skip header line
        for line in lines[1:]:  # Skip the header
            line = line.strip()
            if not line:
                continue

            parts = line.split(',')
            if len(parts) >= 2:
                subdomain = parts[0].strip()
                status = parts[1].strip()
                results.append({
                    'subdomain': subdomain,
                    'status': status,
                    'url': f"https://{subdomain}"  # Default to https
                })

        print(f"[+] Read {len(results)} entries from: {file_path}")
        return results

    except FileNotFoundError:
        print(f"[-] Error: File not found - {file_path}")
        return []
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return []

def filter_by_status(results, status_filter):
    """
    Filter results by HTTP status code pattern
    """
    if not status_filter:
        return results

    filtered_results = []

    for result in results:
        status_code = result['status']

        if status_filter.endswith('*'):
            # Handle wildcard patterns like 20*, 30*, etc.
            status_prefix = status_filter[:-1]
            if str(status_code).startswith(status_prefix):
                filtered_results.append(result)
        else:
            # Handle specific status codes
            try:
                if status_code == int(status_filter):
                    filtered_results.append(result)
            except ValueError:
                print(f"[-] Invalid status filter: {status_filter}")
                return results

    print(f"[+] Filtered to {len(filtered_results)} results with status {status_filter}")
    return filtered_results

def save_filtered_urls(urls, output_file):
    """
    Save filtered URLs to output file (one URL per line)
    """
    try:
        with open(output_file, 'w') as f:
            for url in urls:
                f.write(url + '\n')
        print(f"[+] Saved {len(urls)} URLs to: {output_file}")
    except Exception as e:
        print(f"[-] Error saving to file: {e}")

async def filter_probe_results(input_file, status_filter, output_file, follow_redirects_30x=True):
    """
    Main function to filter probe results and optionally follow redirects for 30* status codes

    Args:
        input_file: Path to probe results file
        status_filter: Status code filter (e.g., '20*', '30*', '40*')
        output_file: Path to save filtered URLs
        follow_redirects_30x: Whether to follow redirects for 30* status codes
    """
    print("\n============================")
    print("[+] Filtering Probe Results")
    print("============================\n")

    # Read probe results
    probe_results = read_probe_results(input_file)

    if not probe_results:
        print("[-] No probe results to filter")
        return []

    # Filter by status
    filtered_results = filter_by_status(probe_results, status_filter)

    if not filtered_results:
        print("[-] No results after filtering")
        return []

    # Extract URLs
    urls = [result['url'] for result in filtered_results]

    # Follow redirects for 30* status codes if requested
    if status_filter.startswith('30') and follow_redirects_30x:
        print("[+] Following redirects for 30* status codes...")
        final_urls = await process_urls_with_redirects(urls)

        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in final_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)

        print(f"[+] After redirects: {len(unique_urls)} unique URLs")
        urls_to_save = unique_urls
    else:
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)

        urls_to_save = unique_urls

    # Save filtered URLs
    save_filtered_urls(urls_to_save, output_file)

    return urls_to_save

def filter_probe_results_sync(input_file, status_filter, output_file, follow_redirects_30x=True):
    """
    Synchronous wrapper for the async filter function
    """
    return asyncio.run(filter_probe_results(input_file, status_filter, output_file, follow_redirects_30x))

# Example usage
if __name__ == "__main__":
    # Example usage
    domain = "example.com"
    input_file = f"Results/{domain}_results/{domain}_probe_results.txt"
    output_file = f"Results/{domain}_results/{domain}_probe_filter_results.txt"

    # Filter for 20* status codes
    results = filter_probe_results_sync(
        input_file=input_file,
        status_filter="20*",
        output_file=output_file
    )

    print(f"\n[+] Filtered {len(results)} URLs saved to: {output_file}")
