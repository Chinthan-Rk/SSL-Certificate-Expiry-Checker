#!/usr/bin/env python3
"""
SSL Certificate Expiry Checker

A utility script to check SSL certificate expiration dates for multiple domains.
The script connects to each domain, retrieves the SSL certificate, and reports
on expiry dates, remaining days, and certificate issuers.

Author: Chinthan Rk
GitHub: https://github.com/Chinthan-Rk/SSL-Certificate-Expiry-Checker.git
License: MIT
"""

import ssl
import socket
import datetime
import argparse
from typing import Dict, List, Tuple, Optional


def get_ssl_expiry_date(hostname: str, port: int = 443) -> Tuple[datetime.datetime, str]:
    """
    Check the SSL certificate of a domain and return its expiry date.
    
    This function establishes an SSL connection to the specified hostname and port,
    retrieves the certificate details, and extracts the expiry date and issuer information.
    
    Args:
        hostname: Domain name to check
        port: Port to connect on (default: 443)
        
    Returns:
        Tuple of (expiry_date, issuer)
    
    Raises:
        socket.error: If the connection to the server fails
        ssl.SSLError: If there's an SSL-specific error
        ValueError: If certificate data cannot be parsed correctly
    """
    context = ssl.create_default_context()
    
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            
            # Extract expiry date
            expiry_date_str = cert['notAfter']
            expiry_date = datetime.datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y %Z")
            
            # Extract issuer information
            issuer = dict(x[0] for x in cert['issuer'])
            issuer_str = issuer.get('organizationName', 'Unknown')
            
            return expiry_date, issuer_str


def check_domains(domains: List[str], port: int = 443) -> Dict[str, Dict]:
    """
    Check SSL certificates for a list of domains.
    
    Processes multiple domains and collects their certificate information.
    Each domain's result includes status, expiry date, days left until expiry,
    and certificate issuer information. If a connection error occurs, the 
    error message is captured and included in the results.
    
    Args:
        domains: List of domain names to check
        port: Port to connect on (default: 443)
        
    Returns:
        Dictionary with results for each domain in the format:
        {
            "domain.com": {
                "status": "Valid|Expiring Soon|Expired|Error",
                "expiry_date": "YYYY-MM-DD",
                "days_left": 42,
                "issuer": "Certificate Authority Name"
            },
            ...
        }
    """
    results = {}
    
    for domain in domains:
        try:
            expiry_date, issuer = get_ssl_expiry_date(domain, port)
            now = datetime.datetime.now()
            days_left = (expiry_date - now).days
            
            status = "Valid"
            if days_left < 0:
                status = "Expired"
            elif days_left < 30:
                status = "Expiring Soon"
                
            results[domain] = {
                "status": status,
                "expiry_date": expiry_date.strftime("%Y-%m-%d"),
                "days_left": days_left,
                "issuer": issuer
            }
        except Exception as e:
            results[domain] = {
                "status": "Error",
                "error": str(e)
            }
    
    return results


def format_results(results: Dict[str, Dict]) -> str:
    """
    Format the results for terminal display with proper alignment.
    
    Handles dynamic column widths based on the length of domain names and issuer 
    information. Adds ANSI color coding for different status types: green for valid, 
    yellow for expiring soon, and red for expired certificates.
    
    Args:
        results: Dictionary containing the check results for each domain
        
    Returns:
        Formatted string ready for terminal display
    """
    # Find the longest domain name for better formatting
    max_domain_len = max(len(domain) for domain in results.keys())
    max_domain_len = max(max_domain_len, 6)  # minimum "Domain" header length
    
    # Find the longest issuer name
    max_issuer_len = 6  # minimum "Issuer" header length
    for result in results.values():
        if result["status"] != "Error" and len(result.get("issuer", "")) > max_issuer_len:
            max_issuer_len = len(result.get("issuer", ""))
    
    # Set column widths
    domain_width = max_domain_len + 2
    status_width = 15
    days_width = 10
    date_width = 15
    issuer_width = max_issuer_len + 2
    
    # Build headers
    output = "\n"
    output += f"{'Domain':<{domain_width}} {'Status':<{status_width}} {'Days Left':<{days_width}} {'Expiry Date':<{date_width}} {'Issuer':<{issuer_width}}\n"
    output += "-" * (domain_width + status_width + days_width + date_width + issuer_width) + "\n"
    
    for domain, result in results.items():
        if result["status"] == "Error":
            output += f"{domain:<{domain_width}} {'ERROR':<{status_width}} {'N/A':<{days_width}} {'N/A':<{date_width}} {result['error'][:30]}\n"
        else:
            status_display = result["status"]
            # Add color coding for terminal output (ANSI escape codes)
            if status_display == "Expired":
                status_display = f"\033[91m{status_display}\033[0m"  # Red
            elif status_display == "Expiring Soon":
                status_display = f"\033[93m{status_display}\033[0m"  # Yellow
            elif status_display == "Valid":
                status_display = f"\033[92m{status_display}\033[0m"  # Green
                
            output += f"{domain:<{domain_width}} {status_display:<{status_width}} {result['days_left']:<{days_width}} {result['expiry_date']:<{date_width}} {result['issuer']:<{issuer_width}}\n"
    
    return output


def save_to_csv(results: Dict[str, Dict], filename: str) -> None:
    """
    Save the results to a CSV file.
    
    Creates a CSV file with columns for Domain, Status, Days Left, Expiry Date,
    Issuer, and Error. Each domain gets a single row in the CSV.
    
    Args:
        results: Dictionary containing the check results for each domain
        filename: Path to save the CSV file
        
    Raises:
        IOError: If the file cannot be written
    """
    import csv
    
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Domain', 'Status', 'Days Left', 'Expiry Date', 'Issuer', 'Error']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for domain, result in results.items():
            if result["status"] == "Error":
                writer.writerow({
                    'Domain': domain,
                    'Status': 'ERROR',
                    'Error': result.get('error', 'Unknown error')
                })
            else:
                writer.writerow({
                    'Domain': domain,
                    'Status': result['status'],
                    'Days Left': result['days_left'],
                    'Expiry Date': result['expiry_date'],
                    'Issuer': result['issuer'],
                    'Error': ''
                })


def save_to_text(results: Dict[str, Dict], filename: str, summary: Dict) -> None:
    """
    Save the results to a formatted plain text file.
    
    Creates a well-formatted text report with aligned columns and a summary
    section. The file includes a timestamp of when the report was generated.
    
    Args:
        results: Dictionary containing the check results for each domain
        filename: Path to save the text file
        summary: Dictionary containing summary statistics
        
    Raises:
        IOError: If the file cannot be written
    """
    # Find the longest domain name for better formatting
    max_domain_len = max(len(domain) for domain in results.keys())
    max_domain_len = max(max_domain_len, 6)  # minimum "Domain" header length
    
    # Find the longest issuer name
    max_issuer_len = 6  # minimum "Issuer" header length
    for result in results.values():
        if result["status"] != "Error" and len(result.get("issuer", "")) > max_issuer_len:
            max_issuer_len = len(result.get("issuer", ""))
    
    # Set column widths
    domain_width = max_domain_len + 2
    status_width = 15
    days_width = 10
    date_width = 15
    issuer_width = max_issuer_len + 2
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("SSL Certificate Expiry Report\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Write headers
        f.write(f"{'Domain':<{domain_width}} {'Status':<{status_width}} {'Days Left':<{days_width}} ")
        f.write(f"{'Expiry Date':<{date_width}} {'Issuer':<{issuer_width}}\n")
        f.write("-" * (domain_width + status_width + days_width + date_width + issuer_width) + "\n")
        
        # Write each domain result
        for domain, result in results.items():
            if result["status"] == "Error":
                f.write(f"{domain:<{domain_width}} {'ERROR':<{status_width}} {'N/A':<{days_width}} ")
                f.write(f"{'N/A':<{date_width}} {result.get('error', 'Unknown error')[:30]}\n")
            else:
                f.write(f"{domain:<{domain_width}} {result['status']:<{status_width}} {result['days_left']:<{days_width}} ")
                f.write(f"{result['expiry_date']:<{date_width}} {result['issuer']:<{issuer_width}}\n")
        
        # Write summary
        f.write("\nSummary:\n")
        f.write(f"  Total domains checked: {summary['total']}\n")
        f.write(f"  Valid certificates: {summary['valid']}\n")
        f.write(f"  Expiring within {summary['warning_days']} days: {summary['expiring_soon']}\n")
        f.write(f"  Expired certificates: {summary['expired']}\n")
        f.write(f"  Errors: {summary['errors']}\n")


def main():
    """
    Main function that handles command-line arguments and program execution.
    
    Parses command line arguments, reads domains from file if specified,
    performs the SSL certificate checks, displays results, and saves
    to output files if requested.
    """
    parser = argparse.ArgumentParser(description='Check SSL certificate expiry for domains')
    parser.add_argument('domains', nargs='*', help='Domains to check')
    parser.add_argument('-f', '--file', help='File containing domain names (one per line)')
    parser.add_argument('-p', '--port', type=int, default=443, help='Port to connect on (default: 443)')
    parser.add_argument('-o', '--output', help='Save results to CSV file')
    parser.add_argument('-t', '--text-output', help='Save results to formatted text file')
    parser.add_argument('-w', '--warning', type=int, default=30, 
                        help='Days threshold for warning (default: 30)')
    parser.add_argument('--no-color', action='store_true', 
                        help='Disable color output in terminal')
    
    args = parser.parse_args()
    
    domains = args.domains
    
    # If file is provided, read domains from file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_domains = [line.strip() for line in f if line.strip()]
                domains.extend(file_domains)
        except Exception as e:
            print(f"Error reading domain file: {e}")
            return
    
    if not domains:
        parser.print_help()
        return
    
    print(f"Checking SSL certificates for {len(domains)} domains...")
    results = check_domains(domains, args.port)
    
    # Display results
    print(format_results(results))
    
    # Summary
    total = len(domains)
    errors = sum(1 for result in results.values() if result["status"] == "Error")
    expired = sum(1 for result in results.values() 
                 if result.get("status") == "Expired")
    expiring_soon = sum(1 for result in results.values() 
                       if result.get("status") == "Expiring Soon")
    valid = total - errors - expired - expiring_soon
    
    summary = {
        'total': total,
        'valid': valid,
        'expiring_soon': expiring_soon,
        'expired': expired,
        'errors': errors,
        'warning_days': args.warning
    }
    
    print(f"\nSummary:")
    print(f"  Total domains checked: {total}")
    print(f"  Valid certificates: {valid}")
    print(f"  Expiring within {args.warning} days: {expiring_soon}")
    print(f"  Expired certificates: {expired}")
    print(f"  Errors: {errors}")
    
    # Save to CSV if requested
    if args.output:
        try:
            save_to_csv(results, args.output)
            print(f"\nResults saved to CSV: {args.output}")
        except Exception as e:
            print(f"Error saving to CSV: {e}")
    
    # Save to text file if requested
    if args.text_output:
        try:
            save_to_text(results, args.text_output, summary)
            print(f"\nResults saved to text file: {args.text_output}")
        except Exception as e:
            print(f"Error saving to text file: {e}")


if __name__ == "__main__":
    main()