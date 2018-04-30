import re

import requests


def subdomain_fsd(self, target):
  print("Searching FindSubDomains")
  headers = {'Connection':      'keep-alive', 'Upgrade-Insecure-Requests': '1',
             'User-Agent':      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36',
             'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
             'DNT':             '1', 'Referer': 'https://findsubdomains.com/',
             'Accept-Encoding': 'gzip, deflate, br',
             'Accept-Language': 'en-US,en;q=0.9,it;q=0.8', }

  response = requests.get('https://findsubdomains.com/subdomains-of/' + target,
                          headers=headers)
  scraped = response.text
  trimmed = scraped[scraped.find('<div class="blogtitle">'):scraped.rfind(
    '<div id="copyright">')]
  subdomain_finder = re.compile('href="(.*' + target + ').*"')
  links = subdomain_finder.findall(trimmed)

  for domain in links:
    print(domain)
    # if domain.strip() not in self.domains and domain.endswith("." + target):
    #   self.domains.append(domain.strip())
    #   if self.options["--verbose"]:
    #     print("FindSubDomains Found Domain:", domain.strip())


subdomain_fsd(None, "jonlu.ca")