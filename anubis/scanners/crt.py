import re
import requests


def search_crtsh(self, target):
    """
    Search crt.sh for certificates related to the target and extract both
    subdomains and root domains.
    """
    print("Searching crt.sh")
    headers = {
        'authority': 'crt.sh',
        'cache-control': 'max-age=0',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.28 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
    }

    # Clean target input to ensure we have just the domain
    target = clean_domain(target)

    # Search for both wildcard and explicit domain
    params = (('q', '%.' + target),)
    try:
        res = requests.get('https://crt.sh/', headers=headers, params=params)
        scraped = res.text

        # Extract domains from response
        domains = extract_domains(scraped, target)

        # Add all found domains to our list
        for domain in domains:
            if domain not in self.domains:
                self.domains.append(domain)
                if self.options["--verbose"]:
                    print("Crt.sh Found Domain:", domain)

    except Exception as e:
        self.handle_exception(e, "Error searching crt.sh")


def clean_domain(domain):
    """Clean input to get the base domain without protocol or path."""
    # Remove protocol if present
    domain = re.sub(r'^(http|https)://', '', domain)
    # Remove path, query params, etc.
    domain = domain.split('/')[0].strip()
    return domain


def extract_domains(html_content, target):
    """Extract all domains and subdomains from HTML content."""
    # Match domains in TD tags (crt.sh specific)
    domain_pattern = re.compile(r'<TD>((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' +
                                re.escape(target) + r')</TD>')
    domains = set()

    # Find all matches
    matches = domain_pattern.findall(html_content)

    # Process matches
    for domain in matches:
        # Handle <BR> separated values
        for subdomain in domain.lower().split('<br>'):
            clean_domain = subdomain.strip()
            if clean_domain:
                domains.add(clean_domain)

    # Also add the root domain
    if target not in domains:
        domains.add(target)

    return list(domains)