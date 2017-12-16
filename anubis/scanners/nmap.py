import shutil
from json import dumps

import nmap


# Performs an nmap scan of a target, and outputs interesting services/ssl information
def scan_host(self):
  if shutil.which("nmap") is None:
    print("Nmap must be installed to run --with-nmap!")
    return

  print("Starting Nmap Scan")
  nm = nmap.PortScanner()
  arguments = '-nPn -sV -sC'
  if self.options["--overwrite-nmap-scan"]:
    arguments = self.options["--overwrite-nmap-scan"]
  nm.scan(hosts=self.ip, arguments=arguments)
  # Could be extended to scan multiple hosts in the future
  for host in nm.all_hosts():
    if self.options["--verbose"]:
      print(dumps(nm[host], indent=2, sort_keys=True))
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    for proto in nm[host].all_protocols():
      print('----------')
    print('Protocol: %s' % proto)
    lport = nm[host][proto].keys()
    for port in lport:
      print('port: %s\tstate: %s' % (port, nm[host][proto][port]['state']))
      try:
        if nm[host][proto][port]['product']:
          print('\tservice: %s' % nm[host][proto][port]['product'], end='')
          if nm[host][proto][port]['version']:
            print('\tversion: %s' % nm[host][proto][port]['version'])
          else:
            print('')
      except Exception as e:
        self.handle_exception(e)
      try:
        fix_newline = nm[host][proto][port]['script']['ssl-cert'].split('\n')
        print('\tCertificate:')
        for i in range(len(fix_newline)):
          print('\t', fix_newline[i])
          if fix_newline[i].startswith("Subject Alternative Name: "):
            content = fix_newline[i].replace("Subject Alternative Name: ", '')
            content = content.replace("DNS:", '')
            new_domains = content.split(",")
            for domain in new_domains:
              domain = domain.strip()
              if domain not in self.domains:
                self.domains.append(domain)
                if self.options["--verbose"]:
                  print("Nmap Found Domain:", domain.strip())
      except Exception as e:
        self.handle_exception(e)
