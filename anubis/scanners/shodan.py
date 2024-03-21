import os
import socket
import shodan

def search_shodan(self):
  print("Searching Shodan.io for additional information")
  api_key = os.environ.get("SHODAN_API_KEY", None)
  if api_key is None:
      return

  api = shodan.Shodan(api_key)
  for i in range(len(self.options["TARGET"])):
    try:
      results = api.host(socket.gethostbyname(self.options["TARGET"][i]))

      print('Server Location: ' + str(results['city']) + ", " + str(
        results['country_code']) + ' - ' + str(results['postal_code']))

      print("ISP  or Hosting Company: %s" % str(results['isp']))

      if results['os'] is not None:
        print("Possible OS: %s" % str(results['os']))
    except Exception as e:
      self.handle_exception(e, "Error retrieving additional info")
