# SSL Certificate Expiry Checker

A Python utility to check SSL certificate expiration dates for multiple domains.

## Features

- Check SSL certificate expiry for multiple domains
- Color-coded terminal output for easy status identification
- Export results to CSV and formatted text files
- Read domains from command line or from a file
- Summary report with certificate status counts
- Customizable warning threshold for expiring certificates

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library modules)

## Installation

Clone this repository:

```bash
git clone https://github.com/Chinthan-Rk/SSL-Certificate-Expiry-Checker.git
cd SSL-Certificate-Expiry-Checker
```

No additional installation required.

## Usage

### Basic Usage

```bash
python ssl_checker.py example.com
```

### Check Multiple Domains

```bash
python ssl_checker.py example.com google.com github.com
```

### Check Domains from a File

Create a text file with one domain per line:

```
example.com
google.com
github.com
```

Then run:

```bash
python ssl_checker.py -f domains.txt
```

### Save Results

```bash
# Save to CSV
python ssl_checker.py example.com -o results.csv

# Save to formatted text file
python ssl_checker.py example.com -t report.txt

# Save to both formats
python ssl_checker.py example.com -o results.csv -t report.txt
```

### Additional Options

```bash
# Customize warning threshold (default is 30 days)
python ssl_checker.py example.com -w 60

# Specify a different port (default is 443)
python ssl_checker.py example.com -p 8443

# Disable colored output
python ssl_checker.py example.com --no-color
```

### Full Command Reference

```
usage: ssl_checker.py [-h] [-f FILE] [-p PORT] [-o OUTPUT] [-t TEXT_OUTPUT] [-w WARNING] [--no-color] [domains ...]

Check SSL certificate expiry for domains

positional arguments:
  domains               Domains to check

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File containing domain names (one per line)
  -p PORT, --port PORT  Port to connect on (default: 443)
  -o OUTPUT, --output OUTPUT
                        Save results to CSV file
  -t TEXT_OUTPUT, --text-output TEXT_OUTPUT
                        Save results to formatted text file
  -w WARNING, --warning WARNING
                        Days threshold for warning (default: 30)
  --no-color            Disable color output in terminal
```

## Example Output

Terminal output:

```
Checking SSL certificates for 3 domains...

Domain           Status          Days Left   Expiry Date     Issuer
-------------------------------------------------------------------------
google.com       Valid           66          2025-05-21      Google Trust Services
github.com       Valid           326         2026-02-05      Sectigo Limited
example.com      Valid           305         2026-01-15      DigiCert Inc

Summary:
  Total domains checked: 3
  Valid certificates: 3
  Expiring within 30 days: 0
  Expired certificates: 0
  Errors: 0
```

## How It Works

The script connects to each domain using SSL and retrieves the certificate information. It then extracts the expiry date and issuer details, calculates the remaining days, and categorizes each certificate as:

- **Valid**: Certificate is valid and not expiring soon
- **Expiring Soon**: Certificate will expire within the warning threshold (default 30 days)
- **Expired**: Certificate has already expired
- **Error**: Failed to retrieve certificate information
