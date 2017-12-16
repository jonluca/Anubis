import re

import requests


def search_dnsdumpster(self, target):
  print("Searching DNSDumpster")
  headers = {'Pragma':          'no-cache', 'Origin': 'https://dnsdumpster.com',
             'Accept-Encoding': 'gzip, deflate, br',
             'Accept-Language': 'en-US,en;q=0.9,it;q=0.8',
             'User-Agent':      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
             'Content-Type':    'application/x-www-form-urlencoded',
             'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
             'Cache-Control':   'no-cache',
             'Referer':         'https://dnsdumpster.com/',
             'Connection':      'keep-alive', 'DNT': '1', }

  get_csrf_res = requests.get('https://dnsdumpster.com', headers=headers)

  try:
    csrf_token = get_csrf_res.headers['Set-Cookie']
    csrf_token = csrf_token[10:]
    csrf_token = csrf_token.split(";")[0]
  except Exception as e:
    self.handle_exception(e, "Retrieving CSRF Token for DNSDumpster failed")
    return

  cookies = {'csrftoken': csrf_token, }

  data = [('csrfmiddlewaretoken', csrf_token), ('targetip', target)]

  res = requests.post('https://dnsdumpster.com/', headers=headers,
                      cookies=cookies, data=data)
  try:
    scraped = res.text
    subdomain_finder = re.compile('\">(.*\.' + target + ')<br>')
    links = subdomain_finder.findall(scraped)
    for domain in links:
      if domain.strip() not in self.domains and domain.endswith("." + target):
        self.domains.append(domain.strip())
        if self.options["--verbose"]:
          print("DNSDumpster Found Domain:", domain.strip())
  except Exception as e:
    self.handle_exception(e, "Error searching DNS Dumpster")
    pass
