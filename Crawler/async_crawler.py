#!/usr/bin/env python3
"""
Advanced Async XSS Recon Crawler

Supports:
--cookie for authenticated crawling

Outputs:
pages.txt
urls.txt
params.txt
forms.txt
js_files.txt
api_endpoints.txt
dom_sinks.txt
files.txt
errors.txt
"""

import asyncio
import argparse
import time
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Set, List, Dict
from urllib.parse import urlparse, urljoin, parse_qs

import aiohttp
from aiohttp import ClientError
from bs4 import BeautifulSoup


# ================= CONFIG =================

MAX_CONCURRENCY = 20
PER_HOST_DELAY = 0.5
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3
MAX_PAGES = 10000
USER_AGENT = "XSS-Recon-Crawler/1.0 (authorized testing)"

# ==========================================


JS_ENDPOINT_REGEX = re.compile(
    r'["\'](/api/[^"\']+|/v1/[^"\']+|/rest/[^"\']+)["\']'
)

DOM_SINKS = [
    "document.write",
    "innerHTML",
    "outerHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "location.href"
]


@dataclass
class CrawlResult:
    visited_pages: Set[str]
    discovered_urls: Set[str]
    discovered_files: Set[str]
    errors: List[str]


# ================= STATS =================

class CrawlStats:

    def __init__(self):
        self.start_time = time.time()
        self.visited = 0
        self.urls = 0
        self.files = 0
        self.errors = 0

    def update(self, visited=0, urls=0, files=0, errors=0):
        self.visited += visited
        self.urls += urls
        self.files += files
        self.errors += errors

    def display(self):

        elapsed = time.time() - self.start_time
        rate = self.visited / elapsed if elapsed else 0

        print(
            f"\r[Stats] Visited:{self.visited} | URLs:{self.urls} | "
            f"Files:{self.files} | Errors:{self.errors} | Rate:{rate:.2f}/s",
            end="",
            flush=True
        )


# ================= HELPERS =================

def normalize_start_url(raw: str) -> str:

    raw = raw.strip()

    if not urlparse(raw).scheme:
        raw = "https://" + raw

    return raw


def in_scope(url: str, allowed_domains: Set[str]) -> bool:

    try:

        host = (urlparse(url).hostname or "").lower()

        return any(host == d or host.endswith("." + d) for d in allowed_domains)

    except:

        return False


def classify_resource(url: str) -> str:

    path = urlparse(url).path.lower()

    if path.endswith(".js"):
        return "js"

    for ext in (
        ".css", ".png", ".jpg", ".jpeg", ".gif",
        ".svg", ".ico", ".pdf", ".zip", ".txt"
    ):
        if path.endswith(ext):
            return "file"

    return "html"


def has_params(url: str) -> bool:
    return bool(parse_qs(urlparse(url).query))


def extract_links(base_url: str, html: str):

    soup = BeautifulSoup(html, "html.parser")
    urls = set()

    for tag in soup.find_all(True):

        for attr in ("href", "src"):

            link = tag.get(attr)

            if not link:
                continue

            if link.startswith(("#", "javascript:", "mailto:")):
                continue

            urls.add(urljoin(base_url, link))

    return urls


def extract_forms(base_url: str, html: str):

    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form in soup.find_all("form"):

        action = form.get("action") or base_url
        method = form.get("method", "GET").upper()

        inputs = []

        for inp in form.find_all("input"):

            name = inp.get("name")

            if name:
                inputs.append(name)

        forms.append((urljoin(base_url, action), method, inputs))

    return forms


# ================= RATE LIMITER =================

class RateLimiter:

    def __init__(self, delay):

        self.delay = delay
        self.last_request = defaultdict(float)
        self.lock = asyncio.Lock()

    async def wait(self, host):

        async with self.lock:

            now = asyncio.get_event_loop().time()

            wait = self.last_request[host] + self.delay - now

            if wait > 0:
                await asyncio.sleep(wait)

            self.last_request[host] = asyncio.get_event_loop().time()


# ================= FETCH =================

async def fetch(session, rate_limiter, url):

    host = urlparse(url).hostname or ""

    for attempt in range(1, MAX_RETRIES + 1):

        try:

            await rate_limiter.wait(host)

            async with session.get(url, allow_redirects=True) as resp:

                return (
                    str(resp.url),
                    resp.headers.get("Content-Type", ""),
                    await resp.read()
                )

        except (ClientError, asyncio.TimeoutError):

            if attempt == MAX_RETRIES:
                raise

            await asyncio.sleep(attempt * 0.5)


# ================= WORKER =================

async def worker(
    wid,
    queue,
    session,
    rate_limiter,
    allowed_domains,
    visited,
    discovered_urls,
    discovered_files,
    errors,
    page_counter,
    page_lock,
    stats,
    output_dir,
    written_sets  # New parameter to track what's been written
):

    while True:

        url = await queue.get()

        if url is None:
            queue.task_done()
            break

        if url in visited:
            queue.task_done()
            continue

        visited.add(url)

        try:

            final_url, content_type, body = await fetch(
                session,
                rate_limiter,
                url
            )

            print(f"\n[worker-{wid}] ✓ {final_url}")

        except Exception as e:

            error_msg = f"{url}\t{repr(e)}"
            errors.append(error_msg)
            
            # Write error if not already written
            if error_msg not in written_sets['errors']:
                written_sets['errors'].add(error_msg)
                with open(output_dir / "errors.txt", "a") as f:
                    f.write(error_msg + "\n")
            
            stats.update(errors=1)
            queue.task_done()
            continue

        new_urls = 0

        if "text/html" in content_type:

            async with page_lock:
                page_counter["count"] += 1
            
            # Write page if not already written
            if final_url not in written_sets['pages']:
                written_sets['pages'].add(final_url)
                with open(output_dir / "pages.txt", "a") as f:
                    f.write(final_url + "\n")

            text = body.decode(errors="ignore")

            for link in extract_links(final_url, text):

                if not link.startswith(("http://", "https://")):
                    continue

                if not in_scope(link, allowed_domains):
                    continue

                rtype = classify_resource(link)

                if link not in discovered_urls:

                    discovered_urls.add(link)
                    new_urls += 1

                    # Write URL if not already written
                    if link not in written_sets['urls']:
                        written_sets['urls'].add(link)
                        with open(output_dir / "urls.txt", "a") as f:
                            f.write(link + "\n")

                # Check for param URLs
                if has_params(link) and link not in written_sets['params']:
                    written_sets['params'].add(link)
                    with open(output_dir / "params.txt", "a") as f:
                        f.write(link + "\n")

                # Check for JS files
                if rtype == "js" and link not in written_sets['js_files']:
                    written_sets['js_files'].add(link)
                    with open(output_dir / "js_files.txt", "a") as f:
                        f.write(link + "\n")

                # Check for other files
                if rtype == "file" and link not in written_sets['files']:
                    written_sets['files'].add(link)
                    with open(output_dir / "files.txt", "a") as f:
                        f.write(link + "\n")

                if rtype == "html":
                    await queue.put(link)

            # Process forms
            for action, method, inputs in extract_forms(final_url, text):
                form_entry = f"{method} {action} {' '.join(inputs)}"
                if form_entry not in written_sets['forms']:
                    written_sets['forms'].add(form_entry)
                    with open(output_dir / "forms.txt", "a") as f:
                        f.write(form_entry + "\n")

            # Process API endpoints
            for match in JS_ENDPOINT_REGEX.findall(text):
                endpoint = urljoin(final_url, match)
                if endpoint not in written_sets['api_endpoints']:
                    written_sets['api_endpoints'].add(endpoint)
                    with open(output_dir / "api_endpoints.txt", "a") as f:
                        f.write(endpoint + "\n")

            # Process DOM sinks
            for sink in DOM_SINKS:
                if sink in text:
                    sink_entry = f"{final_url} -> {sink}"
                    if sink_entry not in written_sets['dom_sinks']:
                        written_sets['dom_sinks'].add(sink_entry)
                        with open(output_dir / "dom_sinks.txt", "a") as f:
                            f.write(sink_entry + "\n")

        stats.update(visited=1, urls=new_urls)
        stats.display()

        queue.task_done()


# ================= MAIN =================

async def crawl_async(start_urls, allowed_domains, output_prefix, cookie):

    queue = asyncio.Queue()

    for u in start_urls:
        await queue.put(u)

    visited = set()
    discovered_urls = set()
    discovered_files = set()
    errors = []

    page_counter = {"count": 0}
    page_lock = asyncio.Lock()

    stats = CrawlStats()

    output_dir = Path(output_prefix)
    output_dir.mkdir(exist_ok=True)

    # Initialize tracking sets for each output file
    written_sets = {
        'pages': set(),
        'urls': set(),
        'params': set(),
        'forms': set(),
        'js_files': set(),
        'files': set(),
        'api_endpoints': set(),
        'dom_sinks': set(),
        'errors': set()
    }

    # Clear/create empty files
    for fname in (
        "pages.txt",
        "urls.txt",
        "params.txt",
        "forms.txt",
        "js_files.txt",
        "files.txt",
        "api_endpoints.txt",
        "dom_sinks.txt",
        "errors.txt"
    ):
        (output_dir / fname).write_text("")

    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

    headers = {
        "User-Agent": USER_AGENT
    }

    if cookie:
        headers["Cookie"] = cookie

    rate_limiter = RateLimiter(PER_HOST_DELAY)

    async with aiohttp.ClientSession(
        timeout=timeout,
        headers=headers
    ) as session:

        workers = [

            asyncio.create_task(
                worker(
                    i,
                    queue,
                    session,
                    rate_limiter,
                    allowed_domains,
                    visited,
                    discovered_urls,
                    discovered_files,
                    errors,
                    page_counter,
                    page_lock,
                    stats,
                    output_dir,
                    written_sets  # Pass tracking sets to workers
                )
            )

            for i in range(MAX_CONCURRENCY)
        ]

        await queue.join()

        for _ in workers:
            await queue.put(None)

        await asyncio.gather(*workers)

    print("\n\n=== CRAWL FINISHED ===")
    
    # Print summary statistics
    print(f"\nUnique results written to files:")
    for file_type, written_set in written_sets.items():
        print(f"  {file_type}: {len(written_set)} unique entries")

    return CrawlResult(
        visited,
        discovered_urls,
        discovered_files,
        errors
    )


# ================= RUNNER =================

def load_start_urls(file_path):

    urls = []

    with open(file_path) as f:

        for line in f:

            url = normalize_start_url(line.strip())

            if url:
                urls.append(url)

    return urls


def run_crawler(input_file, domain, output_prefix, cookie):

    start_urls = load_start_urls(input_file)

    allowed_domains = {domain}

    start_urls = [
        u for u in start_urls if in_scope(u, allowed_domains)
    ]

    return asyncio.run(
        crawl_async(start_urls, allowed_domains, output_prefix, cookie)
    )


# ================= CLI =================

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-o", "--output-prefix", default="crawl_output")
    parser.add_argument("--cookie", help="Authentication cookie")

    args = parser.parse_args()

    run_crawler(args.input, args.domain, args.output_prefix, args.cookie)