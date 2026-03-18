<<<<<<< HEAD
# VAPT Automation Tool

A professional, modular, and scalable Vulnerability Assessment and Penetration Testing (VAPT) automation tool built with Python and Flask.

## Features

- **Web-based UI**: Easy to use interface for starting scans and viewing results.
- **Authentication Support**: Handle authenticated scans using sessions and cookies.
- **Internal Crawler**: Automatically discover links within the target domain.
- **Vulnerability Modules**:
    - **XSS**: Detect Reflected Cross-Site Scripting.
    - **SQL Injection**: Detect potential SQLi through error-based testing.
    - **Security Headers**: Identify missing security-critical HTTP headers.
    - **IIS Checks**: IIS-specific vulnerability detection (TRACE, WebDAV/PUT).
    - **Directory Bruteforce**: Discover common sensitive files and directories.
- **Nmap Integration**: Infrastructure-level port scanning.
- **Reporting**: Generate both JSON and styled HTML reports.
- **Multi-threaded Engine**: Fast scanning using `concurrent.futures`.

## Project Structure

```text
vapt_tool/
├── app.py              # Flask Web Application
├── config.py           # Configuration & Payloads
├── core/               # Main Scanner Engine
├── modules/            # Vulnerability Scanning Modules
├── integrations/       # Third-party Tools (Nmap, etc.)
├── report/             # Report Generation Logic
├── utils/              # Logging & Helper Functions
├── templates/          # Web UI Templates
└── static/             # Static Assets (CSS/JS)
```

## Setup & Usage

1. **Prerequisites**:
   - Python 3.8+
   - Nmap (optional, for port scanning)

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**:
   ```bash
   python app.py
   ```

4. **Access the Tool**:
   Open your browser and navigate to `http://localhost:5000`.

5. **Start a Scan**:
   - Enter the target URL (e.g., `http://testphp.vulnweb.com`).
   - (Optional) Provide credentials for authenticated scanning.
   - Click "Generate VAPT Report".

## Security Warning

This tool is for **educational and ethical security testing purposes only**. Never use it against targets you do not have explicit permission to test.
=======
# VAPT-Tool
A Vapt Tool for Testing the software through Automation
>>>>>>> 7ed224233a07ca83dcb6843e2278e57795fa29c5
