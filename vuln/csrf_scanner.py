#!/usr/bin/env python3

import requests
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 10

EXTENSIONS_TO_SKIP = [
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg",
    ".css", ".js",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".rar", ".exe", ".mp4", ".mp3"
]

# Common CSRF token parameter names
CSRF_TOKEN_NAMES = [
    'csrf_token', 'csrf', '_csrf', 'token', '_token',
    'authenticity_token', 'xsrf_token', 'xsrf', '_xsrf',
    'csrfmiddlewaretoken', 'csrf_token', 'anticsrf'
]

# State-changing HTTP methods
STATE_CHANGING_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH']


def extract_forms_from_html(html_content, base_url):
    """Extract forms from HTML content"""
    forms = []
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }

            # Get absolute URL for action
            if form_data['action']:
                form_data['action'] = urljoin(base_url, form_data['action'])
            else:
                form_data['action'] = base_url

            # Extract input fields
            for input_tag in form.find_all('input'):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', ''),
                    'type': input_tag.get('type', 'text')
                }
                form_data['inputs'].append(input_data)

            # Extract select fields
            for select_tag in form.find_all('select'):
                select_data = {
                    'name': select_tag.get('name', ''),
                    'value': '',  # Could be enhanced to get first option
                    'type': 'select'
                }
                form_data['inputs'].append(select_data)

            forms.append(form_data)

    except Exception:
        pass

    return forms


def check_csrf_token_in_form(form):
    """Check if a form contains CSRF token protection"""
    has_csrf_token = False
    token_names = []

    for input_field in form['inputs']:
        name = input_field.get('name', '').lower()
        if any(token_name in name for token_name in CSRF_TOKEN_NAMES):
            has_csrf_token = True
            token_names.append(input_field['name'])

    return has_csrf_token, token_names


def test_csrf_protection_form(form, session, timeout=DEFAULT_TIMEOUT, verify=True):
    """Test CSRF protection for a specific form"""
    findings = []

    if form['method'] not in STATE_CHANGING_METHODS:
        return findings

    has_token, token_names = check_csrf_token_in_form(form)

    if not has_token:
        findings.append({
            "type": "Missing CSRF Token",
            "severity": "High",
            "details": f"Form with {form['method']} method lacks CSRF token protection"
        })
    else:
        findings.append({
            "type": "CSRF Token Present",
            "severity": "Info",
            "details": f"Form has CSRF token(s): {', '.join(token_names)}"
        })

        # Test if request works without token
        try:
            # Prepare form data without CSRF tokens
            data = {}
            for input_field in form['inputs']:
                name = input_field.get('name', '')
                if name and not any(token_name in name.lower() for token_name in CSRF_TOKEN_NAMES):
                    data[name] = input_field.get('value', '')

            # Try the request without CSRF token
            r = session.request(
                form['method'],
                form['action'],
                data=data,
                timeout=timeout,
                verify=verify,
                allow_redirects=True
            )

            if r.status_code in [200, 302, 301]:
                findings.append({
                    "type": "CSRF Token Bypass Possible",
                    "severity": "High",
                    "details": f"Request succeeded without CSRF token (status: {r.status_code})"
                })

        except Exception as e:
            findings.append({
                "type": "CSRF Test Error",
                "severity": "Info",
                "details": f"Could not test CSRF bypass: {str(e)}"
            })

    return findings


def check_cookies_for_samesite(url, session, timeout=DEFAULT_TIMEOUT, verify=True):
    """Check cookies for SameSite attribute"""
    findings = []

    try:
        r = session.get(url, timeout=timeout, verify=verify)

        # Check Set-Cookie headers
        for cookie_header in r.headers.get('Set-Cookie', []):
            if 'SameSite' not in cookie_header:
                findings.append({
                    "type": "Missing SameSite Cookie Attribute",
                    "severity": "Medium",
                    "details": f"Cookie lacks SameSite attribute: {cookie_header.split(';')[0]}"
                })
            elif 'SameSite=None' in cookie_header and 'Secure' not in cookie_header:
                findings.append({
                    "type": "SameSite=None Without Secure",
                    "severity": "Medium",
                    "details": f"SameSite=None cookie missing Secure flag: {cookie_header.split(';')[0]}"
                })

    except Exception:
        pass

    return findings


def check_origin_referer_validation(url, session, timeout=DEFAULT_TIMEOUT, verify=True):
    """Check for Origin/Referer header validation"""
    findings = []

    try:
        # Test with malicious Origin
        headers = {'Origin': 'https://evil-attacker.com'}
        r = session.post(url, headers=headers, timeout=timeout, verify=verify)

        if r.status_code in [200, 201, 302]:
            findings.append({
                "type": "Weak Origin Validation",
                "severity": "Medium",
                "details": "Request with malicious Origin header was accepted"
            })

        # Test with malicious Referer
        headers = {'Referer': 'https://evil-attacker.com/malicious'}
        r = session.post(url, headers=headers, timeout=timeout, verify=verify)

        if r.status_code in [200, 201, 302]:
            findings.append({
                "type": "Weak Referer Validation",
                "severity": "Low",
                "details": "Request with malicious Referer header was accepted"
            })

    except Exception:
        pass

    return findings


def scan_csrf_single(url, timeout=DEFAULT_TIMEOUT, verify=True, cookie_header=None):
    """Scan a single URL for CSRF vulnerabilities"""
    findings = []

    session = requests.Session()

    # Add cookie if provided
    if cookie_header:
        session.headers.update({'Cookie': cookie_header})

    try:
        # Get the page content
        r = session.get(url, timeout=timeout, verify=verify)

        if r.status_code != 200:
            return findings

        # Extract forms
        forms = extract_forms_from_html(r.text, url)

        if not forms:
            findings.append({
                "type": "No Forms Found",
                "severity": "Info",
                "details": "No HTML forms detected on the page"
            })
            return findings

        findings.append({
            "type": "Forms Detected",
            "severity": "Info",
            "details": f"Found {len(forms)} form(s) on the page"
        })

        # Test each form
        for i, form in enumerate(forms):
            form_findings = test_csrf_protection_form(form, session, timeout, verify)
            for finding in form_findings:
                finding['form_index'] = i
            findings.extend(form_findings)

        # Check cookies
        cookie_findings = check_cookies_for_samesite(url, session, timeout, verify)
        findings.extend(cookie_findings)

        # Check Origin/Referer validation
        origin_findings = check_origin_referer_validation(url, session, timeout, verify)
        findings.extend(origin_findings)

    except Exception as e:
        findings.append({
            "type": "Scan Error",
            "severity": "Info",
            "details": f"Could not scan URL: {str(e)}"
        })

    return findings


def run_csrf_scan_file(input_file, cookie_header=None, timeout=DEFAULT_TIMEOUT, verify=True):
    """Scan multiple URLs from a file for CSRF vulnerabilities"""
    try:
        with open(input_file, "r") as f:
            urls = [u.strip() for u in f if u.strip()]

        for url in urls:
            if any(url.lower().endswith(ext) for ext in EXTENSIONS_TO_SKIP):
                continue

            print(f"\n[*] Testing: {url}")

            results = scan_csrf_single(url, timeout, verify, cookie_header)

            if results:
                for r in results:
                    print(f"  [!] {r['severity']} | {r['type']}")
                    print(f"      {r['details']}")
            else:
                print("  [-] No issues found")

    except Exception as e:
        print(f"[!] Error: {e}")