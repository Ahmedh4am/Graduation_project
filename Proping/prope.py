#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import os
from datetime import datetime

def read_subdomains_from_file(file_path):
    """
    Read subdomains from Active Enumeration results file
    """
    subdomains = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                subdomain = line.strip()
                if subdomain:  # Skip empty lines
                    subdomains.append(subdomain)
        print(f"\t- Read {len(subdomains)} subdomains from: {file_path}")
        return subdomains
    except FileNotFoundError:
        print(f"[-] Error: File not found - {file_path}")
        return []
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return []

async def probe_subdomain(subdomain, session, timeout=5):
    """
    Simple HTTP probe for a subdomain
    Returns: dict with status, title, and other info if available
    """
    results = {}

    for scheme in ['https', 'http']:
        url = f"{scheme}://{subdomain}"
        try:
            async with session.get(url, timeout=timeout, ssl=False) as response:
                results = {
                    'subdomain': subdomain,
                    'url': str(response.url),
                    'scheme': scheme,
                    'status': response.status,
                    'server': response.headers.get('Server', ''),
                    'content_length': response.headers.get('Content-Length', '0'),
                    'timestamp': datetime.now().isoformat()
                }

                # Try to get page title
                try:
                    content = await response.text()
                    if '<title>' in content.lower():
                        title_start = content.lower().find('<title>') + 7
                        title_end = content.lower().find('</title>')
                        if title_end > title_start:
                            results['title'] = content[title_start:title_end].strip()[:100]
                except:
                    results['title'] = ''

                return results

        except Exception as e:
            continue

    # If both schemes failed
    return None

async def probe_all_subdomains(subdomains, concurrency=10, timeout=5):
    """
    Probe all subdomains concurrently
    """
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    timeout = aiohttp.ClientTimeout(total=timeout)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [probe_subdomain(subdomain, session, timeout) for subdomain in subdomains]
        results = await asyncio.gather(*tasks)

    # Filter out None results (failed probes)
    return [r for r in results if r is not None]

def save_to_txt(results, output_file):
    """
    Save results to simple TXT file format: subdomain, status, title, server
    """
    with open(output_file, 'w') as f:
        f.write("subdomain, status, title, server\n")
        for result in results:
            subdomain = result['subdomain']
            status = result['status']
            title = result.get('title', '').replace(',', ';')  # Replace commas to avoid CSV issues
            server = result.get('server', '').replace(',', ';')
            f.write(f"{subdomain}, {status}, {title}, {server}\n")

def save_to_json(results, output_file):
    """
    Save detailed results to JSON for later use
    """
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

def probe_subdomains_from_file(active_enum_file_path, domain=None, results_dir="Results"):
    print("\n============================\n[+] Subdomain Probing ")
    """
    Read subdomains from Active Enumeration file and probe them
    Creates TXT by default, JSON for later use
    """
    # Read subdomains from the provided file path
    subdomains_list = read_subdomains_from_file(active_enum_file_path)

    if not subdomains_list:
        print("[-] No subdomains to probe")
        return []


    # Extract domain from file path if not provided
    if domain is None:
        # Try to extract domain from filename (e.g., example.com_Active_Enum_subdomains.txt -> example.com)
        base_name = os.path.basename(active_enum_file_path)
        domain = base_name.split('_Active_Enum_subdomains')[0]
        print(f"[+] Auto-detected domain: {domain}")

    # Run the async function
    results = asyncio.run(probe_all_subdomains(subdomains_list))

    print(f"\t- Found {len(results)} responsive subdomains")

    # Create results directory if it doesn't exist
    domain_dir = os.path.join(results_dir, f"{domain}_results")
    os.makedirs(domain_dir, exist_ok=True)

    # Save to TXT (default)
    txt_file = os.path.join(domain_dir, f"{domain}_probe_results.txt")
    save_to_txt(results, txt_file)

    # Save to JSON (for later use)
    # json_file = os.path.join(domain_dir, f"{domain}_probe_results.json")
    # save_to_json(results, json_file)


    print(f"\t- TXT results saved to: {txt_file}")
    # print(f"[+] JSON results saved to: {json_file} (for later use)")
    return results
