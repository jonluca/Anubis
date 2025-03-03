from json import loads

import requests

from anubis.utils.color_print import ColorPrint


def search_hudsonrock(self, target):
    try:
      print("Searching HudsonRock")
      res = requests.get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=" + target)
      data = res.json()
      if hasattr(data, "data") and hasattr(data['data'], 'all_urls'):
          urls = data['data']['all_urls']
          for url_entry in urls:
              if hasattr(url_entry, 'url'):
                  url = url_entry['url']
                  if url not in self.domains:
                      self.domains.append(url)
                      if self.options["--verbose"]:
                          print("HudsonRock Found Domain:", url)

    except:
        print("Error searching HudsonRock")
        return