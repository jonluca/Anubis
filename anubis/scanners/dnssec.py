import os

from nmap import nmap

from anubis.utils.ColorPrint import ColorPrint


def dnssecc_subdomain_enum(self, target):
  # Must run as root
  if os.getuid() == 0:
    print("Starting DNSSEC Enum")
    nm = nmap.PortScanner()
    arguments = '-sSU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=' + target

    nm.scan(hosts=self.ip, arguments=arguments)
    for host in nm.all_hosts():
      try:
        print(nm[host]['udp'][53]['script']['dns-nsec-enum'])
      except:
        pass
  else:
    ColorPrint.red(
      "To run a DNSSEC subdomain enumeration, Anubis must be run as root")
