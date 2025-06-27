# Zeravuln: Web Vulnerability Scanner

Zeravuln is a Python-based automated web vulnerability scanner designed to identify and report common web application vulnerabilities. It includes crawling, payload injection, and report generation in both JSON and HTML formats.

---

## 🚀 Features

- ✅ Intelligent web crawler
- ✅ Form detection and automatic fuzzing
- ✅ Vulnerability detection for:
  - SQL Injection (SQLi)
  - Cross-site Scripting (XSS)
  - Local File Inclusion (LFI)
  - Command Injection (CMDi)
  - Open Redirect
  - Missing CSRF Tokens
- ✅ Verbosity levels using `-v` or `-vv`
- ✅ Output in both JSON and HTML format (inside `logs/`)
- ✅ Ready for future support with Selenium (JS rendering)

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Chinmay3739/Elevate-Labs-Internship.git
cd Elevate-Labs-Internship

# (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🧪 Steps to Use

### 1. Navigate to the project folder

```bash
cd Elevate-Labs-Internship
```

### 2. Run the scanner on a target URL

```bash
python3 zerascanner.py -u <target_url>
```

### 3. Use verbosity for more output (optional)

- Basic verbosity (shows detected issues):

  ```bash
  python3 zerascanner.py -u <target_url> -v
  ```

- Full debug mode (shows all payloads, form data, responses):

  ```bash
  python3 zerascanner.py -u <target_url> -vv
  ```

### 4. After scan completes, view output in the `logs/` directory

- JSON report:  
  `logs/report_<timestamp>.json`

- HTML report:  
  `logs/report_<timestamp>.html`

### 5. Open the HTML report in a browser

```bash
xdg-open logs/report_<timestamp>.html
```

Or inspect JSON with:

```bash
cat logs/report_<timestamp>.json | jq .
```

---

## 📁 Payload Files Used

- `sqli.txt` – SQL Injection payloads  
- `xss.txt` – XSS payloads  
- `lfi.txt` – Local File Inclusion payloads  
- `cmd_injection.txt` – Command Injection payloads  
- `open_redirect.txt` – Open Redirect payloads  

---

## 📌 Upcoming Additions

- ✅ JS-rendered page support via Selenium  
- ✅ Cookie/session support  
- ✅ PDF/CSV report generation  
- ✅ Integration with Burp/ZAP  

---

## 👤 Author

**Chinmay Rahangdale**
LinkedIN: www.linkedin.com/in/0xchinmay            Github: https://github.com/Chinmay3739
Built as part of Elevate Labs Internship — 2025  
📧 chinmayrahangdale3739@gmail.com

![Python](https://img.shields.io/badge/Python-3.10-blue)
![Status](https://img.shields.io/badge/status-Active-brightgreen)
