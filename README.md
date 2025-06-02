# subdomain_takeover_advanced.py
this script subdomain takeovers
useges: runpython3 subdomain_takeover_advanced.py -f subs.txt -o report.json
install:pip install requests dnspython rich
or subdomain_takeover_advanced.py file create then save under script.





#!/usr/bin/env python3
import argparse
import requests
import socket
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()

# Known fingerprints of takeover-vulnerable services
fingerprints = {
    "GitHub": "There isn't a GitHub Pages site here.",
    "AWS S3": "NoSuchBucket",
    "Shopify": "Sorry, this shop is currently unavailable.",
    "Tumblr": "Do you want to register",
    "GitLab": "Project doesn't exist...",
    "Heroku": "unrecognized domain",
    "JetBrains": "not a registered InCloud YouTrack domain"
}

def get_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except Exception:
        return None

def check_takeover(domain):
    result = {
        "domain": domain,
        "resolves": False,
        "cname": None,
        "status": "Unknown",
        "fingerprint": None
    }

    try:
        ip = socket.gethostbyname(domain)
        result["resolves"] = True
    except socket.gaierror:
        console.print(f"[red][-] {domain} does not resolve.[/red]")
        return result

    cname = get_cname(domain)
    if cname:
        result["cname"] = cname

    try:
        response = requests.get(f"http://{domain}", timeout=5)
        body = response.text.lower()
        for service, fingerprint in fingerprints.items():
            if fingerprint.lower() in body:
                result["status"] = "Takeover Possible"
                result["fingerprint"] = service
                console.print(f"[bold yellow][!] {domain} => Potential takeover ({service})[/bold yellow]")
                return result
        result["status"] = "OK"
        console.print(f"[green][+] {domain} => OK (No takeover patterns)[/green]")
    except requests.RequestException:
        result["status"] = "Unreachable"
        console.print(f"[magenta][x] {domain} => Could not connect[/magenta]")

    return result

def main():
    parser = argparse.ArgumentParser(description="🛡️ Advanced Subdomain Takeover Checker")
    parser.add_argument("-f", "--file", required=True, help="File containing subdomains list")
    parser.add_argument("-o", "--output", help="Optional: Save result to JSON file")
    args = parser.parse_args()

    with open(args.file, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    results = []

    console.print(f"\n[bold blue]🔍 Checking {len(domains)} subdomains for potential takeovers...[/bold blue]\n")
    for domain in domains:
        results.append(check_takeover(domain))

    # Optional: Save to JSON
    if args.output:
        import json
        with open(args.output, "w") as outfile:
            json.dump(results, outfile, indent=4)
        console.print(f"\n[cyan]📄 Results saved to:[/cyan] {args.output}")

if __name__ == "__main__":
    main()
