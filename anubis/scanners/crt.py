import re

import requests


def _clean_links(links):
  deduped = set()
  for domain in links:
    lower = (domain or '').lower()
    split = lower.split('<br>')
    for full_domain in split:
      deduped.add(full_domain.strip())
  return list(deduped)


def search_crtsh(self, target):
  print("Searching crt.sh")
  headers = {'authority':                 'crt.sh',
             'cache-control':             'max-age=0',
             'upgrade-insecure-requests': '1',
             'user-agent':                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.28 Safari/537.36',
             'sec-metadata':              'cause=forced, destination=document, site=cross-site',
             'sec-origin-policy':         '0', 'dnt': '1',
             'accept':                    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
             'accept-encoding':           'gzip, deflate, br',
             'accept-language':           'en-US,en;q=0.9,it;q=0.8,la;q=0.7', }

  params = (('q', '%.' + target),)

  try:
    res = requests.get('https://crt.sh/', headers=headers, params=params)
    scraped = res.text
    subdomain_finder = re.compile('<TD>(.*\.' + target + ')</TD>')
    links = subdomain_finder.findall(scraped)
    parsed_links = _clean_links(links)

    for domain in parsed_links:
      if domain.strip() not in self.domains and domain.endswith("." + target):
        self.domains.append(domain.strip())
        if self.options["--verbose"]:
          print("Crt.sh Found Domain:", domain.strip())
  except Exception as e:
    self.handle_exception(e, "Error searching crt.sh")
