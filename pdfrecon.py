#!/usr/bin/env python3
import argparse
import os
import re
import sys
import json
import csv
import tempfile
import subprocess
from urllib.parse import urlparse
from urllib.request import urlopen
from pathlib import Path

import logging
import fitz  # PyMuPDF
from pdfminer.high_level import extract_text
import yaml
import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Regex patterns for URL and token extraction
REGISTRATION_LINK_PATTERN = re.compile(
    r'https?://[^\s"\']*(register|invite|signup|token)[^\s"\']*', re.IGNORECASE)
ADMIN_LINK_PATTERN = re.compile(
    r'https?://[^\s"\']*(admin|dashboard)[^\s"\']*', re.IGNORECASE)
JWT_PATTERN = re.compile(
    r'[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}')
UUID_PATTERN = re.compile(
    r'[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}', re.IGNORECASE)
API_KEY_PATTERN = re.compile(
    r'[A-Za-z0-9]{32,}')  # Simplified pattern for API keys

def download_pdf(url):
    try:
        from urllib.request import urlopen
        with urlopen(url) as response:
            if response.status != 200:
                logger.error(f"Failed to download PDF from {url}, status code {response.status}")
                return None
            data = response.read()
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
            tmp_file.write(data)
            tmp_file.close()
            return tmp_file.name
    except Exception as e:
        logger.error(f"Error downloading PDF from {url}: {e}")
        return None

def extract_metadata(filepath):
    # Use exiftool to extract metadata
    try:
        result = subprocess.run(['exiftool', '-j', filepath], capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"Exiftool error: {result.stderr.strip()}")
            return {}
        metadata_list = json.loads(result.stdout)
        if metadata_list and isinstance(metadata_list, list):
            return metadata_list[0]
        return {}
    except FileNotFoundError:
        logger.error("exiftool not found. Please install exiftool to extract metadata.")
        return {}
    except Exception as e:
        logger.error(f"Error extracting metadata: {e}")
        return {}

def extract_urls_and_text(filepath):
    urls = set()
    text_content = ""

    # Extract text using pdfminer.six
    try:
        text_content = extract_text(filepath)
    except Exception as e:
        logger.error(f"Error extracting text with pdfminer: {e}")

    # Extract URLs using PyMuPDF
    try:
        doc = fitz.open(filepath)
        for page in doc:
            links = page.get_links()
            for link in links:
                uri = link.get("uri", "")
                if uri:
                    urls.add(uri)
    except Exception as e:
        logger.error(f"Error extracting URLs with PyMuPDF: {e}")

    return text_content, list(urls)

def extract_tokens(text):
    tokens = set()
    tokens.update(JWT_PATTERN.findall(text))
    tokens.update(UUID_PATTERN.findall(text))
    tokens.update(API_KEY_PATTERN.findall(text))
    return list(tokens)

def get_surrounding_text(full_text, match, window=50):
    # Return text surrounding the match for context analysis
    try:
        start = full_text.index(match)
        begin = max(0, start - window)
        end = min(len(full_text), start + len(match) + window)
        return full_text[begin:end]
    except ValueError:
        return None

def classify_finding(url_or_token, surrounding_text=None):
    # Enhanced heuristic for severity and confidence with context-aware analysis
    severity = "Low"
    confidence = "Low"

    # Basic pattern matching
    if REGISTRATION_LINK_PATTERN.search(url_or_token):
        severity = "High"
        confidence = "High"
    elif ADMIN_LINK_PATTERN.search(url_or_token):
        severity = "High"
        confidence = "High"
    elif JWT_PATTERN.match(url_or_token):
        severity = "High"
        confidence = "High"
    elif UUID_PATTERN.match(url_or_token):
        severity = "Medium"
        confidence = "Medium"
    elif API_KEY_PATTERN.match(url_or_token):
        severity = "Medium"
        confidence = "Medium"

    # Context-aware NLP analysis to reduce false positives
    if surrounding_text:
        # Simple keyword context check (can be expanded with NLP libraries)
        context_keywords = ['password', 'token', 'secret', 'key', 'admin', 'login', 'invite', 'register']
        context_found = any(word in surrounding_text.lower() for word in context_keywords)
        if context_found:
            confidence = "High"
            if severity == "Low":
                severity = "Medium"
        else:
            # If no suspicious context, reduce confidence
            if confidence == "High":
                confidence = "Medium"
            elif confidence == "Medium":
                confidence = "Low"

    return severity, confidence

def load_custom_rules(filepath):
    if not filepath or not os.path.isfile(filepath):
        return []
    try:
        with open(filepath, 'r') as f:
            rules = yaml.safe_load(f)
            return rules if isinstance(rules, list) else []
    except Exception as e:
        print(f"Error loading custom rules: {e}")
        return []

def apply_custom_rules(text, rules):
    findings = []
    for rule in rules:
        pattern = rule.get("pattern")
        severity = rule.get("severity", "Low")
        confidence = rule.get("confidence", "Low")
        if not pattern:
            continue
        try:
            regex = re.compile(pattern)
            matches = regex.findall(text)
            for match in matches:
                findings.append({
                    "match": match,
                    "severity": severity,
                    "confidence": confidence,
                    "type": "custom_rule"
                })
        except re.error as e:
            print(f"Invalid regex in custom rule: {pattern} - {e}")
    return findings

def scan_pdf(filepath, custom_rules=None, threat_feed=None, whitelist=None):
    result = {
        "file": filepath,
        "suspicious_links": [],
        "tokens": [],
        "metadata": {}
    }

    text, urls = extract_urls_and_text(filepath)
    metadata = extract_metadata(filepath)
    result["metadata"] = {
        "author": metadata.get("Author"),
        "creator": metadata.get("Creator"),
        "file_path": metadata.get("SourceFile")
    }

    # Extract suspicious links
    for url in urls:
        # Skip whitelisted domains
        domain = urlparse(url).netloc.lower()
        if whitelist and domain in whitelist:
            continue

        # Get surrounding text for context-aware analysis
        surrounding_text = get_surrounding_text(text, url)

        severity, confidence = classify_finding(url, surrounding_text)
        if threat_feed:
            if domain in threat_feed:
                severity = "High"
                confidence = "High"
        if severity != "Low":
            link_type = "unknown"
            if REGISTRATION_LINK_PATTERN.search(url):
                link_type = "registration_link"
            elif ADMIN_LINK_PATTERN.search(url):
                link_type = "admin_link"
            result["suspicious_links"].append({
                "url": url,
                "type": link_type,
                "confidence": confidence.lower(),
                "severity": severity
            })

    # Extract tokens from text
    tokens = extract_tokens(text)
    filtered_tokens = []
    for token in tokens:
        # Skip whitelisted tokens
        if whitelist and token.lower() in whitelist:
            continue
        surrounding_text = get_surrounding_text(text, token)
        severity, confidence = classify_finding(token, surrounding_text)
        if threat_feed:
            # For tokens, threat feed matching can be domain or token string
            if token.lower() in threat_feed:
                severity = "High"
                confidence = "High"
        filtered_tokens.append(token)
    result["tokens"] = filtered_tokens

    # Apply custom rules if any
    if custom_rules:
        custom_findings = apply_custom_rules(text, custom_rules)
        for finding in custom_findings:
            # Skip if in whitelist
            if whitelist and finding.get("match", "").lower() in whitelist:
                continue
            result["suspicious_links"].append(finding)

    return result

def scan_directory(directory, custom_rules=None, threat_feed=None):
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(".pdf"):
                filepath = os.path.join(root, file)
                res = scan_pdf(filepath, custom_rules, threat_feed)
                results.append(res)
    return results

def save_output(results, output_path, output_format="json"):
    if output_format == "json":
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
    elif output_format == "csv":
        # Flatten results for CSV
        with open(output_path, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["file", "url_or_token", "type", "confidence", "severity"])
            for res in results:
                for link in res.get("suspicious_links", []):
                    writer.writerow([
                        res.get("file"),
                        link.get("url") or link.get("match"),
                        link.get("type"),
                        link.get("confidence"),
                        link.get("severity", "")
                    ])
                for token in res.get("tokens", []):
                    writer.writerow([res.get("file"), token, "token", "", ""])
    else:
        print(f"Unsupported output format: {output_format}")

def crawl_pdfs(start_url, max_depth=2, domain_limit=None):
    visited = set()
    pdf_urls = set()

    def crawl(url, depth):
        if depth > max_depth or url in visited:
            return
        visited.add(url)
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                return
            content_type = resp.headers.get('Content-Type', '')
            if 'application/pdf' in content_type:
                pdf_urls.add(url)
                return
            if 'text/html' not in content_type:
                return
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('//'):
                    href = 'http:' + href
                elif href.startswith('/'):
                    parsed = urlparse(url)
                    href = f"{parsed.scheme}://{parsed.netloc}{href}"
                elif not href.startswith('http'):
                    parsed = urlparse(url)
                    href = f"{parsed.scheme}://{parsed.netloc}/{href}"
                if domain_limit:
                    parsed_href = urlparse(href)
                    if parsed_href.netloc != domain_limit:
                        continue
                if href.lower().endswith('.pdf'):
                    pdf_urls.add(href)
                else:
                    crawl(href, depth + 1)
        except Exception:
            pass

    crawl(start_url, 0)
    return list(pdf_urls)

def send_webhook_alert(webhook_url, message):
    headers = {'Content-Type': 'application/json'}
    try:
        resp = requests.post(webhook_url, json=message, headers=headers, timeout=10)
        if resp.status_code not in (200, 204):
            print(f"Webhook POST failed with status {resp.status_code}")
    except Exception as e:
        print(f"Error sending webhook alert: {e}")

def load_threat_feed(filepath):
    if not filepath or not os.path.isfile(filepath):
        return set()
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            return set(line.strip().lower() for line in lines if line.strip())
    except Exception as e:
        print(f"Error loading threat feed: {e}")
        return set()

def main():
    parser = argparse.ArgumentParser(description="ZAKPDF - PDF Vulnerability Scanner")
    parser.add_argument("command", choices=["scan", "crawl", "interactive"], help="Command to execute")
    parser.add_argument("path", nargs="?", help="Path to PDF file or directory")
    parser.add_argument("--url", help="URL to PDF file or start URL for crawling")
    parser.add_argument("--dir", help="Directory containing PDFs")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format")
    parser.add_argument("--custom-rules", help="YAML file with custom rules")
    parser.add_argument("--webhook", help="Webhook URL for live alerts")
    parser.add_argument("--threat-feed", help="File with list of known malicious domains")
    parser.add_argument("--max-depth", type=int, default=2, help="Max crawl depth for crawling")
    parser.add_argument("--domain-limit", help="Domain limit for crawling")
    parser.add_argument("--whitelist", help="File with list of whitelisted domains or tokens")

    # Add a nicer CLI interface banner
    print("=======================================")
    print("        Welcome to ZAKPDF Scanner      ")
    print("  A powerful PDF vulnerability scanner ")
    print("=======================================")

    args = parser.parse_args()

    if args.command == "scan":
        custom_rules = load_custom_rules(args.custom_rules) if args.custom_rules else None
        threat_feed = load_threat_feed(args.threat_feed) if args.threat_feed else None
        whitelist = load_threat_feed(args.whitelist) if args.whitelist else None
        results = []

        if args.url:
            pdf_path = download_pdf(args.url)
            if not pdf_path:
                print("Failed to download PDF from URL.")
                sys.exit(1)
            res = scan_pdf(pdf_path, custom_rules, threat_feed, whitelist)
            results.append(res)
            if args.webhook:
                send_webhook_alert(args.webhook, res)
            os.unlink(pdf_path)
        elif args.dir:
            if not os.path.isdir(args.dir):
                print(f"Directory not found: {args.dir}")
                sys.exit(1)
            results = scan_directory(args.dir, custom_rules, threat_feed, whitelist)
            if args.webhook:
                for res in results:
                    send_webhook_alert(args.webhook, res)
        elif args.path:
            if not os.path.isfile(args.path):
                print(f"File not found: {args.path}")
                sys.exit(1)
            res = scan_pdf(args.path, custom_rules, threat_feed, whitelist)
            results.append(res)
            if args.webhook:
                send_webhook_alert(args.webhook, res)
        else:
            print("No input specified. Provide a file path, --url, or --dir.")
            sys.exit(1)

        if args.output:
            save_output(results, args.output, args.format)
        else:
            print(json.dumps(results, indent=2))

    elif args.command == "crawl":
        if not args.url:
            print("Please specify a start URL with --url for crawling.")
            sys.exit(1)
        domain_limit = args.domain_limit
        if domain_limit is None:
            parsed = urlparse(args.url)
            domain_limit = parsed.netloc
        pdf_urls = crawl_pdfs(args.url, args.max_depth, domain_limit)
        print(f"Found {len(pdf_urls)} PDF(s) to scan.")
        custom_rules = load_custom_rules(args.custom_rules) if args.custom_rules else None
        threat_feed = load_threat_feed(args.threat_feed) if args.threat_feed else None
        whitelist = load_threat_feed(args.whitelist) if args.whitelist else None
        results = []
        for pdf_url in pdf_urls:
            pdf_path = download_pdf(pdf_url)
            if not pdf_path:
                print(f"Failed to download PDF from {pdf_url}")
                continue
            res = scan_pdf(pdf_path, custom_rules, threat_feed, whitelist)
            results.append(res)
            if args.webhook:
                send_webhook_alert(args.webhook, res)
            os.unlink(pdf_path)
        if args.output:
            save_output(results, args.output, args.format)
        else:
            print(json.dumps(results, indent=2))

    elif args.command == "interactive":
        # Interactive mode for user feedback to improve detection accuracy
        print("Interactive mode started. Please label findings as true or false positives.")
        custom_rules = load_custom_rules(args.custom_rules) if args.custom_rules else None
        threat_feed = load_threat_feed(args.threat_feed) if args.threat_feed else None
        whitelist = load_threat_feed(args.whitelist) if args.whitelist else None

        if args.url:
            pdf_path = download_pdf(args.url)
            if not pdf_path:
                print("Failed to download PDF from URL.")
                sys.exit(1)
            results = [scan_pdf(pdf_path, custom_rules, threat_feed, whitelist)]
            os.unlink(pdf_path)
        elif args.dir:
            if not os.path.isdir(args.dir):
                print(f"Directory not found: {args.dir}")
                sys.exit(1)
            results = scan_directory(args.dir, custom_rules, threat_feed, whitelist)
        elif args.path:
            if not os.path.isfile(args.path):
                print(f"File not found: {args.path}")
                sys.exit(1)
            results = [scan_pdf(args.path, custom_rules, threat_feed, whitelist)]
        else:
            print("No input specified. Provide a file path, --url, or --dir.")
            sys.exit(1)

        for res in results:
            print(f"\nFile: {res['file']}")
            for idx, link in enumerate(res.get("suspicious_links", [])):
                print(f"{idx+1}. URL/Match: {link.get('url') or link.get('match')}")
                print(f"   Type: {link.get('type')}")
                print(f"   Confidence: {link.get('confidence')}")
                print(f"   Severity: {link.get('severity', '')}")
                label = input("Is this a true positive? (y/n): ").strip().lower()
                if label == 'n':
                    # Add to whitelist to exclude in future scans
                    if whitelist is None:
                        whitelist = set()
                    whitelist.add((link.get('url') or link.get('match')).lower())
                    print("Added to whitelist.")
            if args.output:
                save_output(results, args.output, args.format)
            else:
                print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
