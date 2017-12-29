"""The target command."""
import re
import socket
import sys
from threading import Thread
from urllib.parse import urlsplit

from anubis.scanners.anubis_db import search_anubisdb, send_to_anubisdb
from anubis.scanners.brute_force import brute_force
from anubis.scanners.crt import search_crtsh
from anubis.scanners.dnsdumpster import search_dnsdumpster
from anubis.scanners.dnssec import dnssecc_subdomain_enum
from anubis.scanners.hackertarget import subdomain_hackertarget
from anubis.scanners.netcraft import search_netcraft
from anubis.scanners.nmap import scan_host
from anubis.scanners.pkey import search_pkey
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
    for i in range(len(self.options["TARGET"])):
      url = self.options["TARGET"][i]

      if not re.match(r'http(s?):', url):
        url = 'http://' + url

      parsed = urlsplit(url)
      host = parsed.netloc

      if host.startswith('www.'):
        host = host[4:]

      self.options["TARGET"][i] = host

      try:
        ColorPrint.green("Searching for subdomains for " + socket.gethostbyname(
          self.options["TARGET"][i]) + " (" + self.options["TARGET"][i] + ")")
      except Exception as e:
        self.handle_exception(e,
                              "Error connecting to target! Make sure you spelled it correctly and it is a resolvable address")
        raise e
    print("")

  def run(self):
    # Retrieve IP of target and run initial configurations
    self.init()
    for i in range(len(self.options["TARGET"])):
      # Default scans that run every time
      threads = [
        Thread(target=dns_zonetransfer(self, self.options["TARGET"][i])),
        Thread(target=search_subject_alt_name(self, self.options["TARGET"][i])),
        Thread(target=subdomain_hackertarget(self, self.options["TARGET"][i])),
        Thread(target=search_virustotal(self, self.options["TARGET"][i])),
        Thread(target=search_pkey(self, self.options["TARGET"][i])),
        Thread(target=search_netcraft(self, self.options["TARGET"][i])),
        Thread(target=search_crtsh(self, self.options["TARGET"][i])),
        Thread(target=search_dnsdumpster(self, self.options["TARGET"][i])),
        Thread(target=search_anubisdb(self, self.options["TARGET"][i]))]
      # Additional options - ssl cert scan
      if self.options["--ssl"]:
        threads.append(Thread(target=ssl_scan(self, self.options["TARGET"][i])))

      # Additional options - shodan.io scan
      if self.options["--additional-info"]:
        threads.append(Thread(target=search_shodan(self)))

      # Additional options - nmap scan of dnssec script and a host/port scan
      if self.options["--with-nmap"]:
        threads.append(Thread(
          target=dnssecc_subdomain_enum(self, self.options["TARGET"][i])))
        threads.append(Thread(target=scan_host(self)))

      # Additional options - brute force common subdomains
      if self.options["--brute-force"]:
        threads.append(
          Thread(target=brute_force(self, self.options["TARGET"][i])))

      # Start all threads
    for x in threads:
      x.start()

    # Wait for all of them to finish
    for x in threads:
      x.join()

    # remove duplicates and clean up

    if self.options["--recursive"]:
      recursive_search(self)

    self.domains = self.clean_domains(self.domains)
    self.dedupe = set(self.domains)

    print("Found", len(self.dedupe), "subdomains")
    print("----------------")

    if self.options["--ip"]:
      self.resolve_ips()
    else:
      for domain in self.dedupe:
        ColorPrint.green(domain.strip())

    if not self.options["--no-anubis-db"]:
      send_to_anubisdb(self, self.options["TARGET"])

  def clean_domains(self, domains):
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
      unique_ips.add(resolved_ip)
    print("Found %s unique IPs" % len(unique_ips))
    for ip in unique_ips:
      # String truthiness ignores empty strings
      if ip:
        ColorPrint.green(ip)
