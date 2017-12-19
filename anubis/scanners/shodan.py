import socket
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
  for i in range(len(self.options["TARGET"])):
    try:
      results = api.host(socket.gethostbyname(self.options["TARGET"][i]))

      if self.options["--verbose"]:
        print(dumps(results, indent=2, sort_keys=True))

      print('Server Location: ' + str(results['city']) + ", " + str(
        results['country_code']) + ' - ' + str(results['postal_code']))

      print("ISP  or Hosting Company: %s" % str(results['isp']))

      if results['os'] is not None:
        print("Possible OS: %s" % str(results['os']))
    except Exception as e:
      self.handle_exception(e, "Error retrieving additional info")
