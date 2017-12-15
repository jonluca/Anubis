"""The target command."""

import re
import socket
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

  def handle_exception(self, e, message=""):
    if self.options["--verbose"]:
      print(e)
    if message:
      ColorPrint.red(message)

  def init(self):
    url = self.options["TARGET"]

    if not re.match(r'http(s?):', url):
      url = 'http://' + url

    parsed = urlsplit(url)
    host = parsed.netloc

    if host.startswith('www.'):
      host = host[4:]

    self.options["TARGET"] = host

    try:
      self.ip = socket.gethostbyname(self.options["TARGET"])
    except Exception as e:
      self.handle_exception(e,
                            "Error connecting to target! Make sure you spelled it correctly and it is a reachable address")

  def run(self):
    # Retrieve IP of target and run initial configurations
    self.init()
    ColorPrint.green(
      "Searching for subdomains for " + self.ip + " (" + self.options[
        "TARGET"] + ")\n")

    # Multithreaded scans
    threads = [
      Thread(target=search_subject_alt_name(self, self.options["TARGET"])),
      Thread(target=dns_zonetransfer(self, self.options["TARGET"])),
      Thread(target=subdomain_hackertarget(self, self.options["TARGET"])),
      Thread(target=search_virustotal(self, self.options["TARGET"])),
      Thread(target=search_pkey(self, self.options["TARGET"])),
      Thread(target=search_netcraft(self, self.options["TARGET"])),
      Thread(target=search_crtsh(self, self.options["TARGET"])),
      Thread(target=search_dnsdumpster(self, self.options["TARGET"]))]

    # Default scans that run every time

    # If they want to send and receive results from Anubis DB
    if not self.options["--no-anubis-db"]:
      threads.append(
        Thread(target=search_anubisdb(self, self.options["TARGET"])))

    # Additional options - ssl cert scan
    if self.options["--ssl"]:
      threads.append(Thread(target=ssl_scan(self, self.options["TARGET"])))

    # Additional options - shodan.io scan
    if self.options["--additional-info"]:
      threads.append(Thread(target=search_shodan(self)))

    # Additional options - nmap scan of dnssec script and a host/port scan
    if self.options["--with-nmap"]:
      threads.append(
        Thread(target=dnssecc_subdomain_enum(self, self.options["TARGET"])))
      threads.append(Thread(target=scan_host(self)))

    # Additional options - brute force common subdomains
    if self.options["--brute-force"]:
      threads.append(Thread(target=brute_force(self, self.options["TARGET"])))

    # Start all threads
    for x in threads:
      x.start()

    # Wait for all of them to finish
    for x in threads:
      x.join()

    # remove duplicates and clean up

    if self.options["--recursive"]:
      self.recursive_search()

    self.domains = self.clean_domains()
    self.dedupe = set(self.domains)

    print("Found", len(self.dedupe), "domains")
    print("----------------")
    if self.options["--ip"]:
      self.resolve_ips()
    else:
      for domain in self.dedupe:
        ColorPrint.green(domain.strip())

    if not self.options["--no-anubis-db"]:
      send_to_anubisdb()

  def clean_domains(self):
    cleaned = []
    for subdomain in self.domains:
      subdomain = subdomain.replace("http://", "")
      subdomain = subdomain.replace("https://", "")
      subdomain = subdomain.replace("ftp://", "")
      subdomain = subdomain.replace("sftp://", "")
      cleaned.append(subdomain.strip())
    return cleaned

  def resolve_ips(self):
    unique_ips = set()
    for domain in self.dedupe:
      try:
        resolved_ip = socket.gethostbyname(domain)
        # TODO - Align domains and ips
        ColorPrint.green(domain + ": " + resolved_ip)
        unique_ips.add(resolved_ip)
      except Exception as e:
        self.handle_exception(e)
    print("Found %s unique IPs" % len(unique_ips))
    for ip in unique_ips:
      ColorPrint.green(ip)

  # TsODO - implement searching google, bing, yahoo, baidu, and ask
  def search_google(self):
    print("Searching Google")
    base_url = "https://google.com/search?q="
    append = "&hl=en-US&start="
    query = "site:" + self.options["TARGET"]
    for domain in self.domains:
      query += " -" + domain
    page_num = 0
    url = base_url + query + append + str(page_num)

  def recursive_search(self):
    print("todo")
