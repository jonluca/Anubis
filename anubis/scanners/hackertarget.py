import requests


def subdomain_hackertarget(self, target):
  print("Searching HackerTarget")
  headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36', }
  params = (('q', target),)

  results = requests.get('http://api.hackertarget.com/hostsearch/',
                         headers=headers, params=params)
  results = results.text.split('\n')
  for res in results:
    try:
      if res.split(",")[0] != "":
        domain = res.split(",")[0]
        domain = domain.strip()
        if domain not in self.domains and domain.endswith("." + target):
          self.domains.append(domain)
          if self.options["--verbose"]:
            print("HackerTarget Found Domain:", domain.strip())
    except:
      print("except")
      pass
