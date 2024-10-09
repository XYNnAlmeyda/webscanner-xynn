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

    return vulnerabilities

def is_sql_injection_vulnerable(url):
    payload = "OR '1' = '1"
    response = requests.get(url + "?id=" + payload)
    if re.search(r"error|warning", response.text, re.IGNORECASE):
        return True
    return False

def is_xss_vulnerable(url):
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url + "?input=" + payload)
    if payload in response.text:
        return True
    return False

def has_insecure_configuration(url):
    return not url.startswith("https")

if __name__ == "__main__":
    app.run(host="1.1.1.1", port=2710)
