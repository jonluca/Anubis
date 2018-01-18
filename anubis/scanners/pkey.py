import requests


def search_pkey(self, target):
  print("Searching Pkey.in")
  headers = {'Pragma':          'no-cache', 'Origin': 'https://www.pkey.in',
             'Accept-Encoding': 'gzip, deflate, br',
             'Accept-Language': 'en-US,en;q=0.9,it;q=0.8',
             'User-Agent':      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
             'Content-Type':    'application/x-www-form-urlencoded',
             'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
             'Cache-Control':   'no-cache',
             'Referer':         'http://www.pkey.in/tools-i/search-subdomains',
             'Connection':      'keep-alive', 'DNT': '1', }

  data = [('zone', target), ('submit', ''), ]
  try:
    res = requests.post('https://www.pkey.in/tools-i/search-subdomains',
                      headers=headers, data=data, verify=False, timeout=10.0)
    scraped = res.text
    trimmed = scraped[scraped.find('<table class="clearborder">'):scraped.rfind(
      '</tbody>')].split('\n')
    for entry in trimmed:
      if entry.strip().startswith('<td style="border-left-style: none;">'):
        domain = entry.replace('<td style="border-left-style: none;">', '')
        domain = domain.replace('</td>', '')
        if target in domain:
          if domain.strip() not in self.domains:
            self.domains.append(domain.strip())
            if self.options["--verbose"]:
              print("Pkey Found Domain:", domain.strip())
              
  except Exception as e:
    self.handle_exception(e, "Error parsing pkey")
    pass
