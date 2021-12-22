from json import loads

import requests

from anubis.API import SPYSE_TOKEN


def search_spyse(self, target):
  if SPYSE_TOKEN:
    print("Searching Spyse")
    headers = {
      'accept': 'application/json',
      'Authorization': f"Bearer {SPYSE_TOKEN}",
      'Content-Type': 'application/json',
    }

    data = {"limit": 100, "offset": 0, "search_params": [], "query": target}

    domains = []
    try:
      response = requests.post('https://api.spyse.com/v4/data/domain/search', headers=headers, json=data)
      list_results = loads(response.text)
      if 'data' in list_results:
        for item in list_results['data']['items']:
          domains.append(item['name'])
      if domains:
        self.domains.extend(domains)
    except Exception as e:
      print("Exception when searching spyse")
      return
    if domains and self.options["--verbose"]:
      for res in domains:
        print("Spyse Found Domain:", res)
