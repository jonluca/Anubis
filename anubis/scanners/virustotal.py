import requests

from anubis.utils.ColorPrint import ColorPrint


def search_virustotal(self, target):
  print("Searching VirusTotal")
  headers = {'dnt':             '1', 'accept-encoding': 'gzip, deflate, br',
             'accept-language': 'en-US,en;q=0.9,it;q=0.8',
             'user-agent':      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
             'accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
             'authority':       'www.virustotal.com',
             'cookie':          'VT_PREFERRED_LANGUAGE=en', }
  res = requests.get(
    'https://www.virustotal.com/ui/domains/' + target + '/subdomains?relationships=resolutions',
    headers=headers)
  # VirusTotal rate limits aggressively to prevent botting - the user must
  # manually visit a URL and complete a captcha to continue
  if res.status_code == 403:
    ColorPrint.red(
      "VirusTotal is currently ratelimiting this IP - go to https://www.virustotal.com/en/domain/" + target + "/information/ and complete the captcha to continue.")
    return

  try:
    data = res.json()
    for entry in data['data']:
      domain = entry['id']
      if domain.strip() not in self.domains and domain.endswith(target):
        self.domains.append(domain.strip())
        if self.options["--verbose"]:
          print("VirustTotal Found Domain:", domain.strip())
  except Exception as e:
    self.handle_exception(e, "Error parsing virustotal")
    pass
