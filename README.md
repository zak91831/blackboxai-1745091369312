# ZAKPDF - PDF Vulnerability Scanner

ZAKPDF is a powerful command-line tool to scan PDF files for potential vulnerabilities and sensitive information leaks. It extracts URLs, tokens, and metadata from PDFs and applies heuristics and custom rules to identify suspicious content. It supports crawling websites for public PDFs, webhook alerts, threat intelligence integration, and interactive feedback to improve detection accuracy.

---

## Installation

1. Clone or download the repository containing `pdfrecon.py` (now ZAKPDF).
2. Install Python 3.10 or higher.
3. Install required dependencies using pip:

```bash
pip install -r requirements.txt
```

Dependencies include:
- pdfminer.six
- PyMuPDF
- pyyaml
- requests
- beautifulsoup4
- exiftool (external tool, install separately)

4. Ensure `exiftool` is installed on your system for metadata extraction.

---

## Usage

Run the tool using Python:

```bash
python3 pdfrecon.py <command> [options]
```

### Commands

- `scan`: Scan a PDF file, directory, or URL.
- `crawl`: Crawl a website to find and scan public PDFs.
- `interactive`: Interactive mode to label findings as true/false positives.

### Common Options

- `--url URL`: URL to a PDF file or start URL for crawling.
- `--dir DIR`: Directory containing PDFs to scan.
- `--output FILE`: Output file path for results.
- `--format json|csv`: Output format (default: json).
- `--custom-rules FILE`: YAML file with custom regex rules.
- `--webhook URL`: Webhook URL for live alerts.
- `--threat-feed FILE`: File with known malicious domains or tokens.
- `--whitelist FILE`: File with safe domains or tokens to exclude.
- `--max-depth N`: Max crawl depth (for crawl command).
- `--domain-limit DOMAIN`: Limit crawling to this domain.

### Examples

Scan a single PDF file:

```bash
python3 pdfrecon.py scan /path/to/file.pdf
```

Scan PDFs in a directory:

```bash
python3 pdfrecon.py scan --dir /path/to/pdfs --output results.json
```

Scan a PDF from a URL:

```bash
python3 pdfrecon.py scan --url https://example.com/sample.pdf
```

Crawl a website for PDFs and scan them:

```bash
python3 pdfrecon.py crawl --url https://example.com --max-depth 3
```

Run interactive mode:

```bash
python3 pdfrecon.py interactive /path/to/file.pdf
```

---

## Vulnerability Types Detected

ZAKPDF detects the following types of potential vulnerabilities and sensitive information:

- **Registration/Invite Links**: URLs containing keywords like `register`, `invite`, `signup`, or `token` that may expose user registration or invitation endpoints.
- **Admin/Dashboard Links**: URLs pointing to admin panels or dashboards that may be exposed unintentionally.
- **JWT Tokens**: JSON Web Tokens that may be leaked in PDFs.
- **UUIDs and API Keys**: Potentially sensitive tokens or keys embedded in the document.
- **Custom Rules**: User-defined regex patterns to detect other sensitive data.

---

## Exploiting Vulnerabilities Using ZAKPDF

While ZAKPDF is primarily a scanner, it helps identify potential attack vectors by extracting sensitive URLs and tokens from PDFs. For example:

- **Registration/Invite Links**: Attackers may use leaked invite codes or registration URLs to gain unauthorized access.
- **Admin Links**: Exposed admin URLs can be targeted for brute force or other attacks.
- **JWT Tokens**: Leaked tokens can be used to impersonate users or escalate privileges.
- **API Keys**: Exposed keys can be abused to access backend services.

By identifying these, security teams can remediate exposures before attackers exploit them.

---

## Contributing

Contributions and improvements are welcome. Please submit issues or pull requests.

---

## License

MIT License
