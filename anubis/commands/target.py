"""The target command."""
import sys

import re
import socket
import threading
from urllib.parse import urlsplit

from anubis.scanners.anubis_db import search_anubisdb, send_to_anubisdb
from anubis.scanners.crt import search_crtsh
from anubis.scanners.dnsdumpster import search_dnsdumpster
from anubis.scanners.dnssec import dnssecc_subdomain_enum
from anubis.scanners.hackertarget import subdomain_hackertarget
from anubis.scanners.netcraft import search_netcraft
from anubis.scanners.nmap import scan_host
from anubis.scanners.recursive import recursive_search
from anubis.scanners.shodan import search_shodan
from anubis.scanners.ssl import search_subject_alt_name, ssl_scan
from anubis.scanners.virustotal import search_virustotal
from anubis.scanners.zonetransfer import dns_zonetransfer
from anubis.utils.ColorPrint import ColorPrint
from .base import Base


class Target(Base):
  """Main enumeration module"""
  domains = list()
  ip = str()
  dedupe = set()

  stdout = sys.stdout

  def handle_exception(self, e, message=""):
    if self.options["--verbose"]:
      print(e)
    if message:
      ColorPrint.red(message)

  def init(self):
    self.options["TARGET"] = self.options["TARGET"].split(",")
    # Clean up targets
    for i in range(len(self.options["TARGET"])):
      url = self.options["TARGET"][i]
      # Inject protocol if not there
      if not re.match(r'http(s?):', url):
        url = 'http://' + url

      parsed = urlsplit(url)
      host = parsed.netloc

      self.options["TARGET"][i] = host

      try:
        ColorPrint.green("Searching for subdomains for " + socket.gethostbyname(
          self.options["TARGET"][i]) + " (" + self.options["TARGET"][i] + ")")
      except Exception as e:
        self.handle_exception(e,
                              "Error connecting to target! Make sure you spelled it correctly and it is a resolvable address")
        raise e

  def run(self):
    # Retrieve IP of target and run initial configurations
    self.init()
    # If multiple targets, create scans for each
    for i in range(len(self.options["TARGET"])):
      # Default scans that run every time
      target = self.options["TARGET"][i]
      threads = [threading.Thread(target=dns_zonetransfer, args=(self, target)),
                 threading.Thread(target=subdomain_hackertarget,
                                  args=(self, target)),
                 threading.Thread(target=search_subject_alt_name,
                                  args=(self, target)),
                 threading.Thread(target=search_virustotal,
                                  args=(self, target)),
                 # threading.Thread(target=search_pkey, args=(self, target)),
                 # Removed pkey as of June 18 2018 due to issues on their end (not connecting)
                 threading.Thread(target=search_netcraft, args=(self, target)),
                 threading.Thread(target=search_crtsh, args=(self, target)),
                 threading.Thread(target=search_dnsdumpster,
                                  args=(self, target)),
                 threading.Thread(target=search_anubisdb, args=(self, target))]

      # Additional options - shodan.io scan
      if self.options["--additional-info"]:
        threads.append(threading.Thread(target=search_shodan, args=(self,)))

      # Additional options - ssl
      if self.options["--ssl"]:
        threads.append(threading.Thread(target=ssl_scan, args=(self, target)))

      # Additional options - nmap scan of dnssec script and a host/port scan
      if self.options["--with-nmap"]:
        threads.append(
          threading.Thread(target=dnssecc_subdomain_enum, args=(self, target)))
        threads.append(threading.Thread(target=scan_host, args=(self,)))

    # Start all threads and wait for them to finish
    for x in threads:
      x.start()

    for x in threads:
      x.join()

    # Run a recursive search on each subdomain - rarely useful, but nice to have
    # just in case
    if self.options["--recursive"]:
      recursive_search(self)

    # remove duplicates and clean up
    self.domains = self.clean_domains(self.domains)
    self.dedupe = set(self.domains)

    print("Found", len(self.dedupe), "subdomains")
    print("----------------")

    if self.options["--ip"]:
      self.resolve_ips()
    else:
      for domain in self.dedupe:
        ColorPrint.green(domain.strip())

    if self.options["--send-to-anubis-db"]:
      send_to_anubisdb(self, self.options["TARGET"])

  def resolve_ips(self):
    unique_ips = set()
    for domain in self.dedupe:
      try:
        # Attempt to get IP
        resolved_ip = socket.gethostbyname(domain)
      except Exception as e:
        self.handle_exception(e)
        # If getting IP fails, fallback to empty string
        resolved_ip = ""
      # TODO - Align domains and ips in stdout
      ColorPrint.green(domain + ": " + resolved_ip)
      if resolved_ip:
        unique_ips.add(resolved_ip)
    print("Found %s unique IPs" % len(unique_ips))
    for ip in unique_ips:
      # Ignore empty strings, final sanity check
      if ip:
        ColorPrint.green(ip)

  @staticmethod
  def clean_domains(domains):
    cleaned = []
    for subdomain in domains:
      subdomain = subdomain.lower()
      if subdomain.find("//") != -1:
        subdomain = subdomain[subdomain.find("//") + 2:]
      # Some pkey return instances like example.com. - remove the final .
      if subdomain.endswith('.'):
        subdomain = subdomain[:-1]
      # sometimes we'll get something like /www.example.com
      if subdomain[0] in ["\\", ".", "/", "#", "$", "%"]:
        subdomain = subdomain[1:]
      # If it's an email address, only take the domain part
      if "@" in subdomain:
        subdomain = subdomain.split("@")
        # If it's an actual email like mail@example.com, take example.com
        if len(subdomain) > 1:
          subdomain = subdomain[1]
        else:
          # If for some reason it's example.com@, take example.com
          subdomain = subdomain[0]

      cleaned.append(subdomain.strip())
    return cleaned
