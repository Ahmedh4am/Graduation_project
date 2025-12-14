#!/usr/bin/env python3
"""
Async in-scope web crawler (FIXED VERSION)

- No deadlocks
- Proper worker shutdown
- Safe MAX_PAGES handling
- Real-time streaming to disk
"""

import asyncio
import argparse
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Set, Tuple, List, Dict
from urllib.parse import urlparse, urljoin

import aiohttp
from aiohttp import ClientError
from bs4 import BeautifulSoup

# ==================== CONFIG ====================

MAX_CONCURRENCY = 20
PER_HOST_DELAY = 0.5
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3
MAX_PAGES = 2000
USER_AGENT = "YourProjectCrawler/1.0 (authorized-testing-only)"

# =================================================


@dataclass
class CrawlResult:
    visited_pages: Set[str]
    discovered_urls: Set[str]
    discovered_files: Set[str]
    errors: List[str]


# ==================== STATS ====================

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
            f"\r[Stats] Visited: {self.visited} | URLs: {self.urls} | "
            f"Files: {self.files} | Errors: {self.errors} | Rate: {rate:.2f}/s",
            end="",
            flush=True
        )


# ==================== HELPERS ====================

def normalize_start_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if not urlparse(raw).scheme:
        return "https://" + raw
    return raw


def in_scope(url: str, allowed_domains: Set[str]) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
        return any(host == d or host.endswith("." + d) for d in allowed_domains)
    except Exception:
        return False


def classify_resource(url: str) -> str:
    path = urlparse(url).path.lower()
    if path.endswith(".js"):
        return "js"
    for ext in (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                ".ico", ".pdf", ".zip", ".txt"):
        if path.endswith(ext):
            return "file"
    return "html"


def extract_links(base_url: str, html: str) -> Set[str]:
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


# ==================== RATE LIMITER ====================

class RateLimiter:
    def __init__(self, delay: float):
        self.delay = delay
        self.last_request: Dict[str, float] = defaultdict(float)
        self.lock = asyncio.Lock()

    async def wait(self, host: str):
        async with self.lock:
            now = asyncio.get_event_loop().time()
            wait_time = self.last_request[host] + self.delay - now
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self.last_request[host] = asyncio.get_event_loop().time()


# ==================== FETCH ====================

async def fetch(session, rate_limiter, url) -> Tuple[str, str, bytes]:
    host = urlparse(url).hostname or ""

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            await rate_limiter.wait(host)
            async with session.get(url, allow_redirects=True) as resp:
                return str(resp.url), resp.headers.get("Content-Type", ""), await resp.read()
        except (ClientError, asyncio.TimeoutError):
            if attempt == MAX_RETRIES:
                raise
            await asyncio.sleep(0.5 * attempt)


# ==================== WORKER ====================

async def worker(
    wid: int,
    queue: asyncio.Queue,
    session: aiohttp.ClientSession,
    rate_limiter: RateLimiter,
    allowed_domains: Set[str],
    visited: Set[str],
    discovered_urls: Set[str],
    discovered_files: Set[str],
    errors: List[str],
    page_counter: Dict[str, int],
    page_lock: asyncio.Lock,
    stats: CrawlStats,
    output_dir: Path
):
    while True:
        url = await queue.get()
        if url is None:
            queue.task_done()
            break

        if url in visited:
            queue.task_done()
            continue

        async with page_lock:
            if page_counter["count"] >= MAX_PAGES:
                queue.task_done()
                continue

        visited.add(url)

        try:
            final_url, content_type, body = await fetch(session, rate_limiter, url)
            print(f"\n[worker-{wid}] ✓ {final_url}")
        except Exception as e:
            errors.append(f"{url}\t{repr(e)}")
            stats.update(errors=1)
            queue.task_done()
            continue

        new_urls = new_files = 0

        if "text/html" in content_type:
            async with page_lock:
                page_counter["count"] += 1

            with open(output_dir / "pages.txt", "a", encoding="utf-8") as f:
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
                    with open(output_dir / "urls.txt", "a", encoding="utf-8") as f:
                        f.write(link + "\n")

                if rtype in ("js", "file"):
                    if link not in discovered_files:
                        discovered_files.add(link)
                        new_files += 1
                        fname = "js_files.txt" if rtype == "js" else "files.txt"
                        with open(output_dir / fname, "a", encoding="utf-8") as f:
                            f.write(link + "\n")
                else:
                    if link not in visited:
                        await queue.put(link)

        stats.update(visited=1, urls=new_urls, files=new_files)
        stats.display()
        queue.task_done()


# ==================== MAIN CRAWL ====================

async def crawl_async(start_urls: List[str], allowed_domains: Set[str], output_prefix: str) -> CrawlResult:
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
    output_dir.mkdir(parents=True, exist_ok=True)

    for fname in ("pages.txt", "urls.txt", "files.txt", "js_files.txt", "errors.txt"):
        (output_dir / fname).write_text("", encoding="utf-8")

    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    headers = {"User-Agent": USER_AGENT}
    rate_limiter = RateLimiter(PER_HOST_DELAY)

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        workers = [
            asyncio.create_task(
                worker(
                    i, queue, session, rate_limiter, allowed_domains,
                    visited, discovered_urls, discovered_files,
                    errors, page_counter, page_lock, stats, output_dir
                )
            )
            for i in range(MAX_CONCURRENCY)
        ]

        # ✅ WAIT UNTIL ALL WORK IS DONE
        await queue.join()

        # ✅ STOP WORKERS
        for _ in workers:
            await queue.put(None)

        await asyncio.gather(*workers, return_exceptions=True)

    if errors:
        (output_dir / "errors.txt").write_text("\n".join(errors), encoding="utf-8")

    print("\n\n=== CRAWL FINISHED ===")
    return CrawlResult(visited, discovered_urls, discovered_files, errors)


# ==================== RUNNER ====================

def load_start_urls(file_path: str) -> List[str]:
    urls = []
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            url = normalize_start_url(line.split(",")[0])
            if url:
                urls.append(url)
    return urls


def run_crawler(input_file: str, domain: str, output_prefix: str):
    start_urls = load_start_urls(input_file)
    allowed_domains = {domain}

    start_urls = [u for u in start_urls if in_scope(u, allowed_domains)]
    if not start_urls:
        print("No valid start URLs")
        return None

    return asyncio.run(crawl_async(start_urls, allowed_domains, output_prefix))


# ==================== CLI ====================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-o", "--output-prefix", default="crawl_output")
    args = parser.parse_args()

    run_crawler(args.input, args.domain, args.output_prefix)
#!/usr/bin/env python3
"""
Async in-scope web crawler (FIXED VERSION)

- No deadlocks
- Proper worker shutdown
- Safe MAX_PAGES handling
- Real-time streaming to disk
"""

import asyncio
import argparse
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Set, Tuple, List, Dict
from urllib.parse import urlparse, urljoin

import aiohttp
from aiohttp import ClientError
from bs4 import BeautifulSoup

# ==================== CONFIG ====================

MAX_CONCURRENCY = 20
PER_HOST_DELAY = 0.5
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3
MAX_PAGES = 10000
USER_AGENT = "YourProjectCrawler/1.0 (authorized-testing-only)"

# =================================================


@dataclass
class CrawlResult:
    visited_pages: Set[str]
    discovered_urls: Set[str]
    discovered_files: Set[str]
    errors: List[str]


# ==================== STATS ====================

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
            f"\r[Stats] Visited: {self.visited} | URLs: {self.urls} | "
            f"Files: {self.files} | Errors: {self.errors} | Rate: {rate:.2f}/s",
            end="",
            flush=True
        )


# ==================== HELPERS ====================

def normalize_start_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if not urlparse(raw).scheme:
        return "https://" + raw
    return raw


def in_scope(url: str, allowed_domains: Set[str]) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
        return any(host == d or host.endswith("." + d) for d in allowed_domains)
    except Exception:
        return False


def classify_resource(url: str) -> str:
    path = urlparse(url).path.lower()
    if path.endswith(".js"):
        return "js"
    for ext in (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                ".ico", ".pdf", ".zip", ".txt"):
        if path.endswith(ext):
            return "file"
    return "html"


def extract_links(base_url: str, html: str) -> Set[str]:
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


# ==================== RATE LIMITER ====================

class RateLimiter:
    def __init__(self, delay: float):
        self.delay = delay
        self.last_request: Dict[str, float] = defaultdict(float)
        self.lock = asyncio.Lock()

    async def wait(self, host: str):
        async with self.lock:
            now = asyncio.get_event_loop().time()
            wait_time = self.last_request[host] + self.delay - now
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self.last_request[host] = asyncio.get_event_loop().time()


# ==================== FETCH ====================

async def fetch(session, rate_limiter, url) -> Tuple[str, str, bytes]:
    host = urlparse(url).hostname or ""

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            await rate_limiter.wait(host)
            async with session.get(url, allow_redirects=True) as resp:
                return str(resp.url), resp.headers.get("Content-Type", ""), await resp.read()
        except (ClientError, asyncio.TimeoutError):
            if attempt == MAX_RETRIES:
                raise
            await asyncio.sleep(0.5 * attempt)


# ==================== WORKER ====================

async def worker(
    wid: int,
    queue: asyncio.Queue,
    session: aiohttp.ClientSession,
    rate_limiter: RateLimiter,
    allowed_domains: Set[str],
    visited: Set[str],
    discovered_urls: Set[str],
    discovered_files: Set[str],
    errors: List[str],
    page_counter: Dict[str, int],
    page_lock: asyncio.Lock,
    stats: CrawlStats,
    output_dir: Path
):
    while True:
        url = await queue.get()
        if url is None:
            queue.task_done()
            break

        if url in visited:
            queue.task_done()
            continue

        async with page_lock:
            if page_counter["count"] >= MAX_PAGES:
                queue.task_done()
                continue

        visited.add(url)

        try:
            final_url, content_type, body = await fetch(session, rate_limiter, url)
            print(f"\n[worker-{wid}] ✓ {final_url}")
        except Exception as e:
            errors.append(f"{url}\t{repr(e)}")
            stats.update(errors=1)
            queue.task_done()
            continue

        new_urls = new_files = 0

        if "text/html" in content_type:
            async with page_lock:
                page_counter["count"] += 1

            with open(output_dir / "pages.txt", "a", encoding="utf-8") as f:
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
                    with open(output_dir / "urls.txt", "a", encoding="utf-8") as f:
                        f.write(link + "\n")

                if rtype in ("js", "file"):
                    if link not in discovered_files:
                        discovered_files.add(link)
                        new_files += 1
                        fname = "js_files.txt" if rtype == "js" else "files.txt"
                        with open(output_dir / fname, "a", encoding="utf-8") as f:
                            f.write(link + "\n")
                else:
                    async with page_lock:
                        if page_counter["count"] < MAX_PAGES and link not in visited:
                            await queue.put(link)


        stats.update(visited=1, urls=new_urls, files=new_files)
        stats.display()
        queue.task_done()


# ==================== MAIN CRAWL ====================

async def crawl_async(start_urls: List[str], allowed_domains: Set[str], output_prefix: str) -> CrawlResult:
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
    output_dir.mkdir(parents=True, exist_ok=True)

    for fname in ("pages.txt", "urls.txt", "files.txt", "js_files.txt", "errors.txt"):
        (output_dir / fname).write_text("", encoding="utf-8")

    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    headers = {"User-Agent": USER_AGENT}
    rate_limiter = RateLimiter(PER_HOST_DELAY)

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        workers = [
            asyncio.create_task(
                worker(
                    i, queue, session, rate_limiter, allowed_domains,
                    visited, discovered_urls, discovered_files,
                    errors, page_counter, page_lock, stats, output_dir
                )
            )
            for i in range(MAX_CONCURRENCY)
        ]


        await queue.join()

        for _ in workers:
            await queue.put(None)

        await asyncio.gather(*workers, return_exceptions=True)

    if errors:
        (output_dir / "errors.txt").write_text("\n".join(errors), encoding="utf-8")

    print("\n\n=== CRAWL FINISHED ===")
    return CrawlResult(visited, discovered_urls, discovered_files, errors)


# ==================== RUNNER ====================

def load_start_urls(file_path: str) -> List[str]:
    urls = []
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            url = normalize_start_url(line.split(",")[0])
            if url:
                urls.append(url)
    return urls


def run_crawler(input_file: str, domain: str, output_prefix: str):
    start_urls = load_start_urls(input_file)
    allowed_domains = {domain}

    start_urls = [u for u in start_urls if in_scope(u, allowed_domains)]
    if not start_urls:
        print("No valid start URLs")
        return None

    return asyncio.run(crawl_async(start_urls, allowed_domains, output_prefix))


# ==================== CLI ====================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-o", "--output-prefix", default="crawl_output")
    args = parser.parse_args()

    run_crawler(args.input, args.domain, args.output_prefix)
