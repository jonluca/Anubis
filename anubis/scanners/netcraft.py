import re

import requests


def search_netcraft(self, target):
  print("Searching NetCraft.com")
  headers = {'Pragma':          'no-cache', 'DNT': '1',
             'Accept-Encoding': 'gzip, deflate, br',
             'Accept-Language': 'en-US,en;q=0.9,it;q=0.8',
             'User-Agent':      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
             'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
             'Cache-Control':   'no-cache',
             'Referer':         'https://searchdns.netcraft.com/?restriction=site+ends+with&host=',
             'Connection':      'keep-alive', }

  params = (('restriction', 'site contains'), ('host', target))
  try:
    res = requests.get('https://searchdns.netcraft.com/', headers=headers,
                       params=params)
    scraped = res.text
    trimmed = scraped[scraped.find('<div class="blogtitle">'):scraped.rfind(
      '<div id="copyright">')]
    subdomain_finder = re.compile(
      '<a href="http://toolbar.netcraft.com/site_report\?url=(.*)">')
    links = subdomain_finder.findall(trimmed)
    for domain in links:
      if domain.strip() not in self.domains and domain.endswith("." + target):
        self.domains.append(domain.strip())
        if self.options["--verbose"]:
          print("Netcraft Found Domain:", domain.strip())
  except Exception as e:
    self.handle_exception(e, "Error searching NetCraft")
    pass
