from json import loads

import requests


def search_sublist3r(self, target):
  print("Searching Sublist3r")
  headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36', }
  params = (('domain', target),)

  try:
    results = requests.get('https://api.sublist3r.com/search.php',
                           headers=headers, params=params)
    list_results = loads(results.text)
    if list_results:
      self.domains.extend(list_results)
  except Exception as e:
    print("Exception when searching sublist3r")
    return
  if list_results and self.options["--verbose"]:
    for res in list_results:
      print("Sublist3r Found Domain:", res)
