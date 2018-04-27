import censys

from anubis.utils.ColorPrint import ColorPrint


def search_censys(self, target):
  print("Searching Censys")
  try:
    from anubis.API import CENSYS_ID, CENSYS_SECRET
  except ImportError:
    ColorPrint.red(
      "To run a Censys scan, you must add your API keys to anubis/API.py")
    return
  if not CENSYS_SECRET or not CENSYS_ID:
    ColorPrint.red(
      "To run a Censys scan, you must add your API keys to anubis/API.py")
    return
  # Print certificate information for domains
  c = censys.certificates.CensysCertificates(CENSYS_ID, CENSYS_SECRET)
  for cert in c.search("." + target):
    print(cert)
