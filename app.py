from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
import logging

app = Flask(__name__)

name = "XYNN ALMEYDA"
title = "Security Analyst | CE|H(Certified Ethical Hacking) | ComTIA+ | Manual Tester | Artificial Intelligence Developer | API maker"

@app.route("/")
def home():
    return render_template("index.html", name=name, title=title)

@app.route("/scan", methods=["POST"])
def scan_website():
    url = request.form["url"]
    discovered_urls = discover_urls(url)
    vulnerabilities = []

    for page_url in discovered_urls:
        page_vulnerabilities = scan_url(page_url)
        vulnerabilities.extend(page_vulnerabilities)

    return render_template("scan_results.html", vulnerabilities=vulnerabilities)

def discover_urls(url):
    discovered_urls = []
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        soup = BeautifulSoup(response.text, "html.parser")
        for anchor_tag in soup.find_all("a"):
            href = anchor_tag.get("href")
            if href:
                absolute_url = urllib.parse.urljoin(url, href)
                if urllib.parse.urlparse(absolute_url).scheme in ["http", "https"]:
                    discovered_urls.append(absolute_url)
    except requests.RequestException as e:
        logging.error(f"Error fetching URL {url}: {e}")
    return discovered_urls

def scan_url(url):
    vulnerabilities = []
    if is_sql_injection_vulnerable(url):
        vulnerabilities.append("SQL injection vulnerability")

    if is_xss_vulnerable(url):
        vulnerabilities.append("Cross-site scripting (XSS) vulnerability")

    if has_insecure_configuration(url):
        vulnerabilities.append("Insecure server configuration")

    if is_command_injection_vulnerable(url):
        vulnerabilities.append("Command injection vulnerability")

    if is_path_traversal_vulnerable(url):
        vulnerabilities.append("Path traversal vulnerability")

    if is_csrf_vulnerable(url):
        vulnerabilities.append("Cross-site request forgery (CSRF) vulnerability")

    if is_idor_vulnerable(url):
        vulnerabilities.append("Insecure direct object reference (IDOR) vulnerability")

    if is_lfi_vulnerable(url):
        vulnerabilities.append("Local file inclusion (LFI) vulnerability")

    if is_rfi_vulnerable(url):
        vulnerabilities.append("Remote file inclusion (RFI) vulnerability")

    if is_ssrf_vulnerable(url):
        vulnerabilities.append("Server-side request forgery (SSRF) vulnerability")

    if is_xxe_vulnerable(url):
        vulnerabilities.append("XML external entity (XXE) vulnerability")

    return vulnerabilities

def is_sql_injection_vulnerable(url):
    payloads = [
        "' OR 1=1 --",
        "' OR '1'='1",
        "' OR 'x'='x",
        "' OR ''='"
    ]
    for payload in payloads:
        response = requests.get(url + "?id=" + payload)
        if re.search(r"error|warning", response.text, re.IGNORECASE):
            return True
    return False

def is_xss_vulnerable(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')"
    ]
    for payload in payloads:
        response = requests.get(url + "?input=" + payload)
        if payload in response.text:
            return True
    return False

def is_command_injection_vulnerable(url):
    payload = "; cat /etc/passwd"
    response = requests.get(url + "?cmd=" + payload)
    if re.search(r"root:x:", response.text):
        return True
    return False

def is_path_traversal_vulnerable(url):
    payload = "../../../../etc/passwd"
    response = requests.get(url + "/" + payload)
    if response.status_code == 200:
        return True
    return False

def is_csrf_vulnerable(url):
    # Implement CSRF vulnerability check
    # This involves sending a POST request with a malicious payload
    # and checking if the application accepts the request without validating the CSRF token.
    return False

def is_idor_vulnerable(url):
    # Implement IDOR vulnerability check
    # This involves attempting to access resources or perform actions on behalf of other users
    # without proper authorization.
    return False

def is_lfi_vulnerable(url):
    # Implement LFI vulnerability check
    # This involves attempting to include local files through user-supplied input
    # without proper validation and sanitization.
    return False

def is_rfi_vulnerable(url):
    # Implement RFI vulnerability check
    # This involves attempting to include remote files through user-supplied input
    # without proper validation and sanitization.
    return False

def is_ssrf_vulnerable(url):
    # Implement SSRF vulnerability check
    # This involves attempting to make requests to internal or external resources
    # through user-supplied input without proper validation and filtering.
    return False

def is_xxe_vulnerable(url):
    # Implement XXE vulnerability check
    # This involves attempting to parse external XML entities through user-supplied input
    # without proper validation and sanitization.
    return False

if __name__ == "__main__":
    app.run(host="1.1.1.1", port=2710)
