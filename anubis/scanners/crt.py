import re
from html.parser import HTMLParser

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


class _CertificateNamesParser(HTMLParser):
  """Collect direct cell text, separating names at BR and cell boundaries.

  Unsupported nested markup discards the current name and the rest of its cell.
  """

  _CELL_BOUNDARIES = ('td', 'th', 'tr', 'thead', 'tbody', 'tfoot', 'table')

  def __init__(self):
    super().__init__(convert_charrefs=True)
    self.names = []
    self._parts = None

  def _finish_name(self):
    if self._parts is not None:
      self.names.append(''.join(self._parts))
    self._parts = None

  def handle_starttag(self, tag, attrs):
    if tag == 'td':
      self._finish_name()
      self._parts = []
    elif tag == 'br' and self._parts is not None:
      self._finish_name()
      self._parts = []
    elif tag in self._CELL_BOUNDARIES:
      self._finish_name()
    elif self._parts is not None:
      # Do not interpret scripts, links, or other nested markup as names.
      self._parts = None

  def handle_endtag(self, tag):
    if tag in self._CELL_BOUNDARIES:
      self._finish_name()
    elif tag == 'br' and self._parts is not None:
      self._finish_name()
      self._parts = []
    elif self._parts is not None:
      self._parts = None

  def handle_data(self, data):
    if self._parts is not None:
      self._parts.append(data)

  def close(self):
    super().close()
    self._finish_name()


def extract_domains(html_content, target):
  """Return concrete in-scope hostnames, always including the normalized target.

  Wildcard certificate names are skipped: stripping ``*.`` would invent a
  concrete hostname. As before, labels preceding the caller's target must be
  ASCII DNS labels. The target suffix is not revalidated or converted via IDNA.
  """
  target = target.strip().lower()
  domains = {target}
  parser = _CertificateNamesParser()
  parser.feed(html_content)
  parser.close()
  label_pattern = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
  target_labels = len(target.split('.'))

  for name in parser.names:
    domain = name.strip()
    if '*' in domain or len(domain.rstrip('.')) > 253:
      continue
    if target.isascii() and not domain.isascii():
      continue
    prefix_labels = domain.split('.')[:-target_labels]
    domain = domain.lower()
    if domain != target and not domain.endswith('.' + target):
      continue
    if all(label.isascii() and label_pattern.fullmatch(label.lower())
           for label in prefix_labels):
      domains.add(domain)

  return list(domains)
