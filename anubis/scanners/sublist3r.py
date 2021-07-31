import requests

from json import loads


def subdomain_sublist3r(self, target):
  print("Searching Sublist3r")
  headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36', }
  params = (('domain', target),)

  results = requests.get('https://api.sublist3r.com/search.php',
                         headers=headers, params=params)
  results = loads(results.text)
  seld.domains.extend(results)
  if self.options["--verbose"]:
    for res in results:
      print("Sublist3r Found Domain:", res)
