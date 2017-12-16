from json import dumps

import shodan

from anubis.utils.ColorPrint import ColorPrint


def search_shodan(self):
  print("Searching Shodan.io for additional information")
  try:
    from anubis.API import SHODAN_KEY
  except ImportError:
    ColorPrint.red("Unable to import API keys - make sure API.py exists!")
    return

  api = shodan.Shodan(SHODAN_KEY)

  try:
    results = api.host(self.ip)

    if self.options["--verbose"]:
      print(dumps(results, indent=2, sort_keys=True))

    print('Server Location:', results['city'] + ", " + results['country_code'],
          '-', results['postal_code'])

    print("ISP  or Hosting Company: %s" % results['isp'])

    if results['os'] is not None:
      print("Possible OS: %s" % results['os'])
  except Exception as e:
    self.handle_exception(e, "Error retrieving additional info")
