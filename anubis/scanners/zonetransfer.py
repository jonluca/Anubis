import socket

import dns

from anubis.utils import ColorPrint


def dns_zonetransfer(self):
  print("Testing for zone transfers")
  zonetransfers = []
  resolver = dns.resolver.Resolver()
  try:
    answers = resolver.query(self.options["TARGET"], 'NS')
  except Exception as e:
    self.handle_exception(e, "Error checking for Zone Transfers")
    return

  resolved_ips = []
  for ns in answers:
    ns = str(ns).rstrip('.')
    resolved_ips.append(socket.gethostbyname(ns))

  for ip in resolved_ips:
    try:
      zone = dns.zone.from_xfr(dns.query.xfr(ip, self.options["TARGET"]))
      for name, node in zone.nodes.items():
        name = str(name)
        if name not in ["@", "*"]:
          zonetransfers.append(name + '.' + self.options["TARGET"])
    except:
      pass

  if zonetransfers:
    print("\tZone transfers possible:")
    for zone in zonetransfers:
      ColorPrint.red(zone)
  else:
    print("\tNo zone transfers possible")
