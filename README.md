# VulnScanX - OWASP Top 10 Vulnerability Scanner

## About the Tool
**VulnScanX** is a Python-based vulnerability scanner designed to identify and explain security weaknesses based on the **OWASP Top 10**. This tool is created for ethical hackers, cybersecurity enthusiasts, and penetration testers to test and secure websites effectively.

## Key Features
Detects the following vulnerabilities:
- SQL Injection
- Cross-Site Scripting (XSS)
- Sensitive Data Exposure
- Insecure Direct Object References (IDOR)
- Security Misconfigurations

### Additional Features:
- Provides verbose results explaining detected vulnerabilities and the payloads used.
- Saves scan results to a file for further analysis.
- Offers an interactive, user-friendly experience with continuous scanning support.

## Installation and Usage
Prerequisites
Python 3.x
Libraries: requests, colorama (install using pip)
**1. Step-by-Step Guide**
Clone the repository:
```
git clone https://github.com/techcorp/vulnscanx.git
cd vulnscanx
```
**2. Install required dependencies:**
```
pip install -r requirements.txt
```
**3. Run the tool:**
```
python vulnscanx.py
```
Input the target URL when prompted and analyze vulnerabilities.

## Example Usage
Input:
```
Enter the target website URL (e.g., http://example.com): http://testphp.vulnweb.com
Output:
Scan Results:
SQL Injection: Vulnerable
  - Why: Detected using payload: ' OR '1'='1
Cross-Site Scripting (XSS): Not Vulnerable
Sensitive Data Exposure: Vulnerable
  - Why: Detected sensitive keyword: password
Insecure Direct Object References (IDOR): Not Vulnerable
Security Misconfiguration: Vulnerable
  - Why: Detected server header: {'Server': 'Apache', 'X-Powered-By': 'PHP/7.4.0'}

Results saved to scan_results_20241202123045.txt
```
## Contribution
Contributions are welcome!
Fork the repository.
Open an issue to suggest features or report bugs.
Submit a pull request to enhance the tool.

## Disclaimer
This tool is intended for ethical use only. Use it only on systems you own or have explicit permission to test. Misuse of this tool may result in legal consequences.

## Author
Technical Corp
Subscribe to our YouTube Channel for tutorials and updates on cybersecurity and ethical hacking tools.
[YouTube Channel](https://youtube.com/@technicalcorp)

License
This project is licensed under the MIT License.


