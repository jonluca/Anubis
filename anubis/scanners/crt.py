import re

import requests


def search_crtsh(self, target):
  print("Searching crt.sh")
  headers = {'Pragma':          'no-cache', 'DNT': '1',
             'Accept-Encoding': 'gzip, deflate, br',
             'Accept-Language': 'en-US,en;q=0.9,it;q=0.8',
             'User-Agent':      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36',
             'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
             'Cache-Control':   'no-cache', 'Connection': 'keep-alive', }

  params = (('q', '%.' + target),)

  try:
    res = requests.get('https://crt.sh/', headers=headers, params=params)
    scraped = res.text
    subdomain_finder = re.compile('<TD>(.*\.' + target + ')</TD>')
    links = subdomain_finder.findall(scraped)
    for domain in links:
      if domain.strip() not in self.domains and domain.endswith("." + target):
        self.domains.append(domain.strip())
        if self.options["--verbose"]:
          print("Crt.sh Found Domain:", domain.strip())
  except Exception as e:
    self.handle_exception(e, "Error searching crt.sh")
