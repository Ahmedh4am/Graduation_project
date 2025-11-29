#!/usr/bin/env python3
"""
Async crawler core for your project.

Implements the ideas from your "3. Crawling" section:

- Discovers URLs/endpoints/JS files in-scope.
- Input: alive subdomains (file).
- Outputs: pages visited, unique URLs, files, errors.
- Core functions: HTTP requests, extract links, normalize, scope filter, save.
- Security/safety: rate limiting, scope restriction, timeout & retry limits.
"""

import asyncio
import argparse
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Set, Tuple, List, Dict
import time

import aiohttp
from aiohttp import ClientError
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


# ==================== CONFIG ====================

# Concurrency: how many requests in flight at once
MAX_CONCURRENCY = 20

# Rate limiting: minimum delay (seconds) between two requests to the same host
PER_HOST_DELAY = 0.5

# Global request timeout (seconds)
REQUEST_TIMEOUT = 10

# Max retries per URL
MAX_RETRIES = 3

# Max pages (HTML responses) to fully crawl
MAX_PAGES = 2000

# User agent
USER_AGENT = "YourProjectCrawler/1.0 (for-authorized-testing-only)"

# =================================================


@dataclass
class CrawlResult:
    visited_pages: Set[str]
    discovered_urls: Set[str]
    discovered_files: Set[str]
    errors: List[str]


class CrawlStats:
    """Track and display real-time crawling statistics"""
    def __init__(self):
        self.start_time = time.time()
        self.visited = 0
        self.discovered_urls = 0
        self.discovered_files = 0
        self.errors = 0
        self.lock = asyncio.Lock()

    def update(self, visited=0, urls=0, files=0, errors=0):
        """Update statistics in a thread-safe manner"""
        self.visited += visited
        self.discovered_urls += urls
        self.discovered_files += files
        self.errors += errors

    def display(self):
        """Display current statistics"""
        elapsed = time.time() - self.start_time
        rate = self.visited / elapsed if elapsed > 0 else 0
        print(f"\r[Stats] Visited: {self.visited} | URLs: {self.discovered_urls} | Files: {self.discovered_files} | Errors: {self.errors} | Rate: {rate:.1f}/s", end="", flush=True)


def normalize_start_url(raw: str) -> str:
    """Ensure a starting URL has a scheme; default to https:// if missing."""
    raw = raw.strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if not parsed.scheme:
        return "https://" + raw
    return raw


def in_scope(url: str, allowed_domains: Set[str]) -> bool:
    """Return True if URL's hostname is inside the allowed scope."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    host = (parsed.hostname or "").lower()
    if not host:
        return False

    for d in allowed_domains:
        d = d.lower()
        if host == d or host.endswith("." + d):
            return True
    return False


def classify_resource(url: str) -> str:
    """Return 'html' or 'file' based on extension (very simple heuristic)."""
    path = urlparse(url).path.lower()
    for ext in (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                ".ico", ".pdf", ".zip", ".txt"):
        if path.endswith(ext):
            return "file"
    # default: assume HTML
    return "html"


def extract_links(base_url: str, html: str) -> Set[str]:
    """Extract and normalize links from HTML content."""
    soup = BeautifulSoup(html, "html.parser")
    urls: Set[str] = set()

    # attributes that usually contain URLs
    for tag in soup.find_all(True):
        for attr in ("href", "src"):
            link = tag.get(attr)
            if not link:
                continue
            if link.startswith("#") or link.startswith("javascript:") or link.startswith("mailto:"):
                continue
            absolute = urljoin(base_url, link)
            urls.add(absolute)

    return urls


class RateLimiter:
    """Simple per-host rate limiter using timestamps."""

    def __init__(self, delay: float):
        self.delay = delay
        self._host_times: Dict[str, float] = defaultdict(float)
        self._lock = asyncio.Lock()

    async def wait(self, host: str):
        async with self._lock:
            now = asyncio.get_event_loop().time()
            earliest = self._host_times[host] + self.delay
            if earliest > now:
                await asyncio.sleep(earliest - now)
            self._host_times[host] = asyncio.get_event_loop().time()


async def fetch(session: aiohttp.ClientSession,
                rate_limiter: RateLimiter,
                url: str) -> Tuple[str, str, bytes]:
    """Fetch URL with rate limiting and retries.

    Returns (final_url, content_type, body) on success.
    Raises on failure so caller can record error.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            await rate_limiter.wait(host)

            async with session.get(url, allow_redirects=True) as resp:
                ct = resp.headers.get("Content-Type", "")
                body = await resp.read()
                return str(resp.url), ct, body

        except (asyncio.TimeoutError, ClientError) as e:
            if attempt == MAX_RETRIES:
                raise e
            # simple backoff
            await asyncio.sleep(0.5 * attempt)


async def worker(name: int,
                 queue: asyncio.Queue,
                 session: aiohttp.ClientSession,
                 rate_limiter: RateLimiter,
                 allowed_domains: Set[str],
                 visited_pages: Set[str],
                 discovered_urls: Set[str],
                 discovered_files: Set[str],
                 errors: List[str],
                 pages_counter: Dict[str, int],
                 stats: CrawlStats,
                 output_dir: Path):
    """Single worker task: pulls URLs from queue and crawls them."""
    while True:
        url = await queue.get()
        if url is None:   # poison pill to stop workers
            queue.task_done()
            break

        if pages_counter["count"] >= MAX_PAGES:
            queue.task_done()
            continue

        if url in visited_pages:
            queue.task_done()
            continue

        visited_pages.add(url)
        print(f"\n[worker-{name}] Visiting: {url}")

        try:
            final_url, content_type, body = await fetch(session, rate_limiter, url)
            print(f"[worker-{name}] ✓ Success: {final_url}")
        except Exception as e:
            msg = f"{url}\tREQUEST_ERROR\t{repr(e)}"
            print(f"[worker-{name}] ✗ Error: {msg}")
            errors.append(msg)
            stats.update(errors=1)
            stats.display()
            queue.task_done()
            continue

        # Stream results to files immediately
        new_urls = 0
        new_files = 0

        # classify and process
        if "text/html" in content_type:
            pages_counter["count"] += 1
            discovered_urls.add(final_url)
            new_urls += 1

            # Write visited page immediately
            with open(output_dir / "pages.txt", "a", encoding="utf-8") as f:
                f.write(final_url + "\n")

            try:
                text = body.decode(errors="ignore")
            except Exception:
                text = body.decode("utf-8", errors="ignore")

            links = extract_links(final_url, text)

            for link in links:
                if not link.startswith(("http://", "https://")):
                    continue
                if not in_scope(link, allowed_domains):
                    continue

                resource_type = classify_resource(link)

                if link not in discovered_urls:
                    discovered_urls.add(link)
                    new_urls += 1
                    # Write new URL immediately
                    with open(output_dir / "urls.txt", "a", encoding="utf-8") as f:
                        f.write(link + "\n")

                if resource_type == "file" and link not in discovered_files:
                    discovered_files.add(link)
                    new_files += 1
                    # Write new file immediately
                    with open(output_dir / "files.txt", "a", encoding="utf-8") as f:
                        f.write(link + "\n")
                else:
                    # schedule HTML pages for further crawling
                    if link not in visited_pages:
                        await queue.put(link)

        else:
            # treat non-HTML as files if in scope
            if in_scope(final_url, allowed_domains):
                if final_url not in discovered_urls:
                    discovered_urls.add(final_url)
                    new_urls += 1
                    with open(output_dir / "urls.txt", "a", encoding="utf-8") as f:
                        f.write(final_url + "\n")

                if final_url not in discovered_files:
                    discovered_files.add(final_url)
                    new_files += 1
                    with open(output_dir / "files.txt", "a", encoding="utf-8") as f:
                        f.write(final_url + "\n")

        # Update and display stats
        stats.update(visited=1, urls=new_urls, files=new_files)
        stats.display()
        queue.task_done()


async def crawl_async(start_urls: List[str],
                      allowed_domains: Set[str],
                      output_prefix: str) -> CrawlResult:
    """Main async crawl driver."""
    queue: asyncio.Queue = asyncio.Queue()

    for u in start_urls:
        await queue.put(u)

    visited_pages: Set[str] = set()
    discovered_urls: Set[str] = set()
    discovered_files: Set[str] = set()
    errors: List[str] = []
    pages_counter = {"count": 0}
    stats = CrawlStats()

    # Create output directory and initialize files
    output_dir = Path(output_prefix)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize output files with headers
    for file_name in ["pages.txt", "urls.txt", "files.txt", "errors.txt"]:
        with open(output_dir / file_name, "w", encoding="utf-8") as f:
            f.write("")  # Clear files at start

    print(f"\n[+] Starting crawl with {len(start_urls)} initial URLs")
    print(f"[+] Output directory: {output_dir}")
    print(f"[+] Real-time streaming enabled - results will be saved immediately\n")

    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    rate_limiter = RateLimiter(PER_HOST_DELAY)

    headers = {"User-Agent": USER_AGENT}

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        # launch workers
        workers = [
            asyncio.create_task(
                worker(i, queue, session, rate_limiter, allowed_domains,
                       visited_pages, discovered_urls, discovered_files,
                       errors, pages_counter, stats, output_dir)
            )
            for i in range(MAX_CONCURRENCY)
        ]

        # Display progress while waiting
        last_size = 0
        while not queue.empty() or any(not w.done() for w in workers):
            await asyncio.sleep(1)
            current_size = len(visited_pages)
            if current_size != last_size:
                stats.display()
                last_size = current_size

        # wait until queue is empty
        await queue.join()

        # tell workers to exit
        for _ in workers:
            await queue.put(None)
        await asyncio.gather(*workers)

    # Write final errors file
    if errors:
        with open(output_dir / "errors.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(errors))

    print(f"\n\n=== Crawl finished ===")
    print(f"Visited pages:   {len(visited_pages)}  -> {output_dir / 'pages.txt'}")
    print(f"Unique in-scope: {len(discovered_urls)}  -> {output_dir / 'urls.txt'}")
    print(f"Files:           {len(discovered_files)}  -> {output_dir / 'files.txt'}")
    print(f"Errors:          {len(errors)}  -> {output_dir / 'errors.txt'}")

    return CrawlResult(
        visited_pages=visited_pages,
        discovered_urls=discovered_urls,
        discovered_files=discovered_files,
        errors=errors,
    )


def load_start_urls(file_path: str) -> List[str]:
    """Read alive subdomains from file and convert to URLs."""
    start_urls: List[str] = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            # Skip the header line if it exists
            if line.strip().startswith("subdomain, status"):
                continue
            parts = line.split(',')
            if parts:  # Take the first part (subdomain)
                url = normalize_start_url(parts[0].strip())
                if url:
                    start_urls.append(url)
    return start_urls


def run_crawler(input_file: str, domain: str, output_prefix: str = "crawl_output"):
    """Run the crawler with given parameters."""
    start_urls = load_start_urls(input_file)
    allowed_domains = {domain}

    # Filter seeds by scope:
    start_urls = [u for u in start_urls if in_scope(u, allowed_domains)]

    if not start_urls:
        print("No valid start URLs found in input file.")
        return

    print("[*] Start URLs:", len(start_urls))
    print("[*] Allowed domains:", ", ".join(allowed_domains))
    print("[*] Max concurrency:", MAX_CONCURRENCY)
    print("[*] Per-host delay:", PER_HOST_DELAY, "seconds")
    print("[*] Max pages:", MAX_PAGES)

    return asyncio.run(crawl_async(start_urls, allowed_domains, output_prefix))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Async in-scope crawler core.")
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="File containing alive subdomains / URLs (one per line).",
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        action="append",
        help="Allowed in-scope domain. Can be given multiple times. "
             "Example: -d example.com -d api.example.com",
    )
    parser.add_argument(
        "-o", "--output-prefix",
        default="crawl_output",
        help="Prefix for output files (default: crawl_output)",
    )

    args = parser.parse_args()

    start_urls = load_start_urls(args.input)
    allowed_domains = set(args.domain)

    # Filter seeds by scope:
    start_urls = [u for u in start_urls if in_scope(u, allowed_domains)]

    if not start_urls:
        print("No valid start URLs found in input file.")
        exit(1)

    print("[*] Start URLs:", len(start_urls))
    print("[*] Allowed domains:", ", ".join(allowed_domains))
    print("[*] Max concurrency:", MAX_CONCURRENCY)
    print("[*] Per-host delay:", PER_HOST_DELAY, "seconds")
    print("[*] Max pages:", MAX_PAGES)

    asyncio.run(crawl_async(start_urls, allowed_domains, args.output_prefix))
