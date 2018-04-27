import socket

import dns.query
import dns.resolver
import dns.zone


# Checks for zone transfers on that domain. Very rare to succeed, but when you
# do, it's a gold mine
def dns_zonetransfer(self, target):
  print("Testing for zone transfers")

  zonetransfers = []
  resolver = dns.resolver.Resolver()

  try:
    answers = resolver.query(target, 'NS')
  except Exception as e:
    self.handle_exception(e, "Error checking for Zone Transfers")
    return

  resolved_ips = []

  for ns in answers:
    ns = str(ns).rstrip('.')
    resolved_ips.append(socket.gethostbyname(ns))

  for ip in resolved_ips:
    try:
      zone = dns.zone.from_xfr(dns.query.xfr(ip, target))
      for name, node in zone.nodes.items():
        name = str(name)
        if name not in ["@", "*"]:
          zonetransfers.append(name + '.' + target)
    except:
      pass

  if zonetransfers:
    print("\tZone transfers possible:")
    for zone in zonetransfers:
      print(zone)
