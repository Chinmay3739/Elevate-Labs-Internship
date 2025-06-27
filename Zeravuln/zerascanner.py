import requests
from bs4 import BeautifulSoup
import urllib.parse
import argparse
import os
import json
from datetime import datetime
import sys

# Globals
visited = set()
verbose = 0
log_entries = []

# Load payloads from files
def load_payloads(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

# Extract form details
def get_all_forms(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            name = input_tag.attrs.get("name")
            if name:
                inputs.append({"type": input_type, "name": name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
    except:
        pass
    return details

# Submit form with payload
def submit_form(form_details, url, payload):
    target_url = urllib.parse.urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = payload
        else:
            data[input["name"]] = "test"
    try:
        return requests.post(target_url, data=data, timeout=5)
    except requests.exceptions.RequestException as e:
        if verbose >= 2:
            print(f"[!] Form submission failed: {e}")
        return None

# Log vulnerabilities
def log_vulnerability(url, payload, vuln_type, endpoint):
    entry = {
        "time": str(datetime.now()),
        "type": vuln_type,
        "url": url,
        "payload": payload,
        "endpoint": endpoint
    }
    log_entries.append(entry)
    if verbose:
        print(f"[{entry['time']}] {vuln_type} Detected!\nURL: {url}\nPayload: {payload}\nEndpoint: {endpoint}\n{'-'*40}")

# Save reports

def save_reports():
    if not os.path.exists("logs"):
        os.mkdir("logs")
    with open("logs/report.json", "w") as f:
        json.dump(log_entries, f, indent=4)

    with open("logs/report.html", "w") as f:
        f.write("<html><head><title>Zeravuln Report</title></head><body>")
        f.write("<h1>Zeravuln Vulnerability Report</h1><ul>")
        for entry in log_entries:
            f.write(f"<li><b>{entry['type']}</b> at <a href='{entry['endpoint']}'>{entry['url']}</a><br>Payload: {entry['payload']}<br>Time: {entry['time']}</li><hr>")
        f.write("</ul></body></html>")

# Vulnerability Scanners
def scan_url(url, sqli, xss, lfi, redirect, cmd):
    forms = get_all_forms(url)
    if verbose:
        print(f"[+] Found {len(forms)} form(s) on {url}")
    for form in forms:
        form_details = get_form_details(form)

        # CSRF check
        token_present = any('csrf' in inp['name'].lower() for inp in form_details['inputs'])
        if not token_present:
            log_vulnerability(url, "None", "Missing CSRF Token", url)

        for payload in sqli:
            response = submit_form(form_details, url, payload)
            if response and ("syntax" in response.text.lower() or "sql" in response.text.lower()):
                log_vulnerability(url, payload, "SQL Injection", response.url)

        for payload in xss:
            response = submit_form(form_details, url, payload)
            if response and payload in response.text:
                log_vulnerability(url, payload, "XSS", response.url)

        for payload in lfi:
            response = submit_form(form_details, url, payload)
            if response and ("root:" in response.text or "/bin/bash" in response.text):
                log_vulnerability(url, payload, "LFI", response.url)

        for payload in redirect:
            response = submit_form(form_details, url, payload)
            if response and payload in response.url:
                log_vulnerability(url, payload, "Open Redirect", response.url)

        for payload in cmd:
            response = submit_form(form_details, url, payload)
            if response and ("uid=" in response.text or "gid=" in response.text):
                log_vulnerability(url, payload, "Command Injection", response.url)

# Crawl and scan

def crawl_and_scan(base_url, sqli, xss, lfi, redirect, cmd):
    to_visit = [base_url]
    while to_visit:
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        visited.add(current_url)
        if verbose >= 2:
            print(f"[*] Scanning: {current_url}")
        try:
            res = requests.get(current_url, timeout=5)
            if "text/html" in res.headers.get("Content-Type", ""):
                soup = BeautifulSoup(res.text, "html.parser")
                scan_url(current_url, sqli, xss, lfi, redirect, cmd)
                for link in soup.find_all("a", href=True):
                    href = urllib.parse.urljoin(base_url, link['href'])
                    if href.startswith(base_url) and href not in visited:
                        to_visit.append(href)
        except requests.exceptions.RequestException as e:
            if verbose >= 2:
                print(f"[!] Failed to crawl {current_url}: {e}")

# Main function

def main():
    global verbose
    parser = argparse.ArgumentParser(description="Zeravuln Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase output verbosity (-v, -vv)")
    args = parser.parse_args()
    verbose = args.verbose

    print(f"[+] Target: {args.url}")
    sqli = load_payloads("payloads/sqli.txt")
    xss = load_payloads("payloads/xss.txt")
    lfi = load_payloads("payloads/lfi.txt")
    redirect = load_payloads("payloads/open_redirect.txt")
    cmd = load_payloads("payloads/cmd_injection.txt")
    print(f"[+] Payloads Loaded → SQLi: {len(sqli)}, XSS: {len(xss)}, LFI: {len(lfi)}, OpenRedirect: {len(redirect)}, CMDi: {len(cmd)}")

    try:
        crawl_and_scan(args.url.rstrip("/"), sqli, xss, lfi, redirect, cmd)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Saving reports...")
        save_reports()
        sys.exit(0)

    save_reports()
    print("[+] Scan complete. Reports saved to logs/")

if __name__ == "__main__":
    main()
