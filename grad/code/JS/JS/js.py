#!/usr/bin/env python3
"""
Local JavaScript / Endpoint Analysis Tool

- Takes a local text or JS file as input
- If the file contains local JS file paths, it loads and scans those files
- If the file contains raw endpoints, it scans them directly
- Scans for API keys, tokens, passwords, AWS keys, DB URLs, emails, IPs
- Analyzes HTTP requests in JS (fetch, axios, XHR) and flags critical endpoints
- Writes a comprehensive report to an output text file (no colors)
- Shows detailed source: main file => nested file / endpoint
"""

import re
import sys
import argparse
from urllib.parse import urlparse, parse_qs
import time
from collections import defaultdict
from pathlib import Path


class JSLocalAnalyzer:
    def __init__(self):
        # Patterns for secrets / interesting data
        self.patterns = {
            "api_keys": [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,60})["\']',
                r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,60})["\']',
                r'secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,60})["\']',
                r'key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,60})["\']',
            ],
            "jwt_tokens": [
                r'eyJhbGciOiJ[^\s"\']+',
                r'["\']eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+["\']',
            ],
            "passwords": [
                r'password["\']?\s*[:=]\s*["\']([^"\'\s]{3,50})["\']',
                r'pass["\']?\s*[:=]\s*["\']([^"\'\s]{3,50})["\']',
                r'pwd["\']?\s*[:=]\s*["\']([^"\'\s]{3,50})["\']',
                r'psw["\']?\s*[:=]\s*["\']([^"\'\s]{3,50})["\']',
            ],
            "endpoints": [
                # JS-style endpoints (inside quotes)
                r'["\'](https?://[^"\']+?/api/[^"\']*?)["\']',
                r'["\'](/api/[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/v[0-9]/[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/graphql[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/rest/[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/auth[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/login[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/register[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/user[^"\']*?)["\']',
                r'["\'](https?://[^"\']+?/admin[^"\']*?)["\']',

                # Plain endpoints (no quotes, for .txt files)
                r'(https?://[^\s"\']+/api/[^\s"\']*)',
                r'(/api/[^\s"\']*)',
                r'(https?://[^\s"\']+/v[0-9]/[^\s"\']*)',
                r'(https?://[^\s"\']+/graphql[^\s"\']*)',
                r'(https?://[^\s"\']+/rest/[^\s"\']*)',
                r'(https?://[^\s"\']+/auth[^\s"\']*)',
                r'(https?://[^\s"\']+/login[^\s"\']*)',
                r'(https?://[^\s"\']+/register[^\s"\']*)',
                r'(https?://[^\s"\']+/user[^\s"\']*)',
                r'(https?://[^\s"\']+/admin[^\s"\']*)',
            ],
            "aws_keys": [
                r"AKIA[0-9A-Z]{16}",
                r'aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([^"\']+?)["\']',
                r'aws[_-]?secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+?)["\']',
            ],
            "database_urls": [
                r'mongodb[+]srv://[^"\'\s]+',
                r'postgresql://[^"\'\s]+',
                r'mysql://[^"\'\s]+',
                r'redis://[^"\'\s]+',
                r'database["\']?\s*[:=]\s*["\']([^"\']+?)["\']',
            ],
            "emails": [
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            ],
            "ip_addresses": [
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            ],
        }

        # Words that indicate a critical endpoint
        self.critical_endpoints = [
            "login",
            "register",
            "auth",
            "password",
            "reset",
            "admin",
            "user",
            "account",
            "profile",
            "payment",
            "credit",
            "bank",
            "secret",
            "key",
            "token",
            "oauth",
            "callback",
            "api",
        ]

        self.results = defaultdict(list)
        self.analyzed_sources = set()

        # Simple URL regex to detect raw endpoints per line
        self.raw_url_pattern = re.compile(r"^(https?://[^\s]+|/api/[^\s]+)$", re.IGNORECASE)

        # Mapping from positions to source segments
        self.segments = []
        self.main_source = None

    def print_header(self):
        print("==================================================")
        print("          Local JavaScript / Endpoint Tool        ")
        print("==================================================")

    # -------- grab full lines around match -------- #
    def get_context_lines(self, content: str, start: int, end: int, before: int = 1, after: int = 1) -> str:
        """
        Return full lines around a match:
        - 'before' lines before the match line
        - the match line itself
        - 'after' lines after
        """
        lines = content.splitlines(keepends=True)

        pos = 0
        match_line_idx = 0

        for idx, line in enumerate(lines):
            line_start = pos
            line_end = pos + len(line)
            if line_start <= start < line_end:
                match_line_idx = idx
                break
            pos = line_end

        start_idx = max(0, match_line_idx - before)
        end_idx = min(len(lines) - 1, match_line_idx + after)

        snippet = "".join(lines[start_idx : end_idx + 1])
        return snippet.strip("\n")

    # -------- resolve which segment a match came from -------- #
    def resolve_source_detail(self, position: int):
        """
        Given a character offset in the combined content,
        return the 'detail' source (nested file path, endpoint, or line info).
        """
        for seg in self.segments:
            if seg["start"] <= position < seg["end"]:
                return seg["origin_detail"]
        return None

    # ---------------- HTTP request analysis ---------------- #

    def extract_http_requests_advanced(self, content):
        requests_found = []

        fetch_patterns = [
            r'fetch\([\s]*["\']([^"\']+?)["\'][\s]*(?:,[\s]*({[^}]+?(?:{[^}]*?}[^}]*?)?}))?[\s]*\)',
            r'fetch\([\s]*`([^`]+?)`[\s]*(?:,[\s]*({[^}]+?(?:{[^}]*?}[^}]*?)?}))?[\s]*\)',
        ]

        for pattern in fetch_patterns:
            matches = re.finditer(pattern, content, re.DOTALL)
            for match in matches:
                url = match.group(1).strip()
                options = match.group(2) if match.group(2) else None

                method = "GET"
                if options:
                    method_match = re.search(
                        r'method[\s]*:[\s]*["\']([^"\']+?)["\']', options, re.IGNORECASE
                    )
                    if method_match:
                        method = method_match.group(1).upper()

                src_detail = self.resolve_source_detail(match.start())

                request_info = {
                    "type": "fetch",
                    "method": method,
                    "url": url,
                    "full_match": match.group(0)[:200] + "..."
                    if len(match.group(0)) > 200
                    else match.group(0),
                    "source_main": self.main_source,
                    "source_detail": src_detail,
                }
                requests_found.append(request_info)

        axios_patterns = [
            r'axios\.(get|post|put|delete|patch)\([\s]*["\']([^"\']+?)["\']',
            r'axios\([\s]*{[\s]*method[\s]*:[\s]*["\'](GET|POST|PUT|DELETE|PATCH)["\'][^}]+url[\s]*:[\s]*["\']([^"\']+?)["\']',
        ]

        for pattern in axios_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) == 2:
                    method = match.group(1).upper()
                    url = match.group(2)
                else:
                    method = match.group(2).upper() if match.group(2) else "GET"
                    url = match.group(1)

                src_detail = self.resolve_source_detail(match.start())

                request_info = {
                    "type": "axios",
                    "method": method,
                    "url": url,
                    "source_main": self.main_source,
                    "source_detail": src_detail,
                }
                requests_found.append(request_info)

        xhr_pattern = r'\.open\([\s]*["\'](GET|POST|PUT|DELETE)["\'][\s]*,[\s]*["\']([^"\']+?)["\']'
        matches = re.finditer(xhr_pattern, content)
        for match in matches:
            src_detail = self.resolve_source_detail(match.start())

            request_info = {
                "type": "xhr",
                "method": match.group(1),
                "url": match.group(2),
                "source_main": self.main_source,
                "source_detail": src_detail,
            }
            requests_found.append(request_info)

        return requests_found

    def analyze_parameters(self, url):
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            path_params = re.findall(r"/:([a-zA-Z_]\w*)", parsed.path)
            return {
                "query_params": list(query_params.keys()),
                "path_params": path_params,
            }
        except Exception:
            return {"query_params": [], "path_params": []}

    def is_critical_endpoint(self, url):
        url_lower = url.lower()
        for critical in self.critical_endpoints:
            if critical in url_lower:
                return True, critical
        return False, None

    # ---------------- Core scanning logic ---------------- #

    def scan_js_content(self, content):
        local_results = defaultdict(list)

        for category, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    value = match.group(1) if match.groups() else match.group(0)

                    context = self.get_context_lines(content, match.start(), match.end())
                    src_detail = self.resolve_source_detail(match.start())

                    local_results[category].append(
                        {
                            "value": value,
                            "source_main": self.main_source,
                            "source_detail": src_detail,
                            "context": context,
                        }
                    )

        http_requests = self.extract_http_requests_advanced(content)
        for req in http_requests:
            param_analysis = self.analyze_parameters(req["url"])
            req.update(param_analysis)

            is_critical, critical_type = self.is_critical_endpoint(req["url"])
            req["is_critical"] = is_critical
            req["critical_type"] = critical_type

            local_results["http_requests"].append(req)

        return local_results

    def _build_combined_content(self, filepath: Path) -> str:
        """
        Read the main file.
        For each line:
          - if it looks like a URL (/api/... or http...) -> keep it as content
          - if it looks like a local file path that exists -> load that file's content
          - else -> keep the line as-is
        Also build self.segments = list of {start, end, origin_detail}.
        """
        try:
            raw = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            sys.exit(1)

        lines = raw.splitlines()
        parts = []
        segments = []
        pos = 0

        def append_chunk(text: str, origin_detail: str):
            nonlocal pos
            if not text:
                return
            parts.append(text)
            start = pos
            end = pos + len(text)
            segments.append(
                {
                    "start": start,
                    "end": end,
                    "origin_detail": origin_detail,
                }
            )
            pos = end

        for line in lines:
            stripped = line.strip()
            handled = False

            if stripped:
                # URL or /api/... line
                if self.raw_url_pattern.match(stripped):
                    append_chunk(stripped + "\n", stripped)
                    handled = True
                else:
                    # Possible local path to another file (like "C:\\...\\example.js")
                    candidate = stripped
                    if (
                        (candidate.startswith('"') and candidate.endswith('"'))
                        or (candidate.startswith("'") and candidate.endswith("'"))
                    ) and len(candidate) >= 2:
                        candidate = candidate[1:-1]

                    candidate_path = Path(candidate)
                    if candidate_path.is_file():
                        try:
                            nested = candidate_path.read_text(
                                encoding="utf-8", errors="replace"
                            )
                            append_chunk(nested + "\n", str(candidate_path))
                            handled = True
                        except Exception:
                            # If we can't read it, just fall back to keeping the line itself
                            pass

            if not handled:
                # Keep original line (JS code etc.) as belonging to main file
                append_chunk(line + "\n", f"(line in main file) {stripped}")

        self.segments = segments
        return "".join(parts)

    def analyze_local_file(self, filepath_str):
        filepath = Path(filepath_str)
        self.main_source = str(filepath)
        self.analyzed_sources.add(str(filepath))

        combined_content = self._build_combined_content(filepath)

        print(
            f"[+] Analyzing combined content from: {filepath} "
            f"({len(combined_content):,} characters)"
        )

        results = self.scan_js_content(combined_content)

        for category, items in results.items():
            self.results[category].extend(items)

    # ---------------- Reporting (console) ---------------- #

    def print_summary_console(self, source_label):
        total_findings = sum(len(items) for items in self.results.values())
        critical_requests = len(
            [r for r in self.results.get("http_requests", []) if r.get("is_critical")]
        )
        total_critical = sum(
            len(self.results.get(cat, []))
            for cat in ["api_keys", "jwt_tokens", "passwords", "aws_keys", "database_urls"]
        )

        print("\n==================== SUMMARY ====================")
        print(f"Source file       : {source_label}")
        print(f"Date              : {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Critical secrets  : {total_critical}")
        print(f"HTTP requests     : {len(self.results.get('http_requests', []))}")
        print(f"Critical endpoints: {critical_requests}")
        print(f"Total findings    : {total_findings}")

        if total_critical > 0 or critical_requests > 0:
            print("Overall risk      : HIGH")
        elif total_findings > 0:
            print("Overall risk      : MEDIUM")
        else:
            print("Overall risk      : LOW")
        print("================================================")

    # ---------------- Reporting (file) ---------------- #

    def save_report(self, source_label, filename):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("Local JavaScript / Endpoint Analysis Report\n")
            f.write(f"Source file: {source_label}\n")
            f.write(f"Date      : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")

        total_findings = sum(len(items) for items in self.results.values())
        critical_requests = len(
            [r for r in self.results.get("http_requests", []) if r.get("is_critical")]
        )
        total_critical = sum(
            len(self.results.get(cat, []))
            for cat in ["api_keys", "jwt_tokens", "passwords", "aws_keys", "database_urls"]
        )

        with open(filename, "a", encoding="utf-8") as f:
            f.write("SUMMARY\n")
            f.write("-------\n")
            f.write(f"Critical secrets   : {total_critical}\n")
            f.write(f"HTTP requests      : {len(self.results.get('http_requests', []))}\n")
            f.write(f"Critical endpoints : {critical_requests}\n")
            f.write(f"Total findings     : {total_findings}\n\n")

            for category, items in self.results.items():
                if not items:
                    continue

                f.write(f"{category.upper()}:\n")
                f.write("-" * 70 + "\n")

                if category == "http_requests":
                    for item in items:
                        f.write(
                            f"- {item.get('type', '').upper()} "
                            f"{item.get('method', '')} {item.get('url', '')}\n"
                        )
                        source_main = item.get("source_main", "N/A")
                        source_detail = item.get("source_detail")
                        if source_detail:
                            f.write(
                                f"  Source         : {source_main} => \"{source_detail}\"\n"
                            )
                        else:
                            f.write(f"  Source         : {source_main}\n")

                        if item.get("is_critical"):
                            f.write(f"  Critical type  : {item.get('critical_type', 'N/A')}\n")
                        if item.get("query_params"):
                            f.write(
                                f"  Query params   : {', '.join(item['query_params'])}\n"
                            )
                        if item.get("path_params"):
                            f.write(
                                f"  Path params    : {', '.join(item['path_params'])}\n"
                            )
                        f.write("\n")
                else:
                    for item in items:
                        if isinstance(item, dict):
                            f.write(f"- Value  : {item.get('value', '')}\n")
                            source_main = item.get("source_main", "N/A")
                            source_detail = item.get("source_detail")
                            if source_detail:
                                f.write(
                                    f"  Source : {source_main} => \"{source_detail}\"\n"
                                )
                            else:
                                f.write(f"  Source : {source_main}\n")

                            ctx = item.get("context", "")
                            if ctx:
                                f.write("  Context:\n")
                                for line in ctx.splitlines():
                                    f.write(f"    {line}\n")
                        else:
                            f.write(f"- {str(item)}\n")
                        f.write("\n")

                f.write("\n")

            f.write("=" * 70 + "\n")
            f.write("End of report\n")


def main():
    analyzer = JSLocalAnalyzer()
    analyzer.print_header()

    parser = argparse.ArgumentParser(
        description="Local JavaScript / Endpoint Analysis (secrets, endpoints, HTTP requests)"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to local file (JS or TXT) to analyze",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Path to output report file",
    )

    args = parser.parse_args()

    analyzer.analyze_local_file(args.input)
    analyzer.print_summary_console(args.input)
    analyzer.save_report(args.input, args.output)
    print(f"[+] Report saved to: {args.output}")


if __name__ == "__main__":
    main()
