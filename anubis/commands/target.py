"""The target command."""

import os
import re
import shutil
import socket
from json import loads, dumps
from threading import Thread
from urllib.parse import urlsplit

import censys.certificates
import censys.ipv4
import dns.query
import dns.resolver
import dns.zone
import nmap
import requests
import shodan
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.http_headers_plugin import HttpHeadersScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand, Tlsv12ScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.synchronous_scanner import SynchronousScanner

from anubis.utils.ColorPrint import ColorPrint
from .base import Base


class Target(Base):
  """Main enumeration module"""
  domains = []
  ip = ""
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
    threads = [Thread(target=self.scan_subject_alt_name()),
               Thread(target=self.dns_zonetransfer()),
               Thread(target=self.subdomain_hackertarget()),
               Thread(target=self.search_virustotal()),
               Thread(target=self.search_pkey()),
               Thread(target=self.search_netcraft()),
               Thread(target=self.search_dnsdumpster())]

    # Default scans that run every time

    # If they want to send and receive results from Anubis DB
    if not self.options["--no-anubis-db"]:
      threads.append(Thread(target=self.scan_anubisdb()))

    # Additional options - ssl cert scan
    if self.options["--ssl"]:
      threads.append(Thread(target=self.ssl_scan()))

    # Additional options - shodan.io scan
    if self.options["--additional-info"]:
      threads.append(Thread(target=self.search_shodan()))

    # Additional options - nmap scan of dnssec script and a host/port scan
    if self.options["--with-nmap"]:
      threads.append(Thread(target=self.dnssecc_subdomain_enum()))
      threads.append(Thread(target=self.scan_host()))

    # Additional options - brute force common subdomains
    if self.options["--brute-force"]:
      threads.append(Thread(target=self.brute_force()))

    # Not sure what data we can get from censys yet, but might be useful in the future
    # self.search_censys()

    # Start all threads
    for x in threads:
      x.start()

    # Wait for all of them to finish
    for x in threads:
      x.join()

    # remove duplicates and clean up

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
      self.send_to_anubisdb()

  def clean_domains(self):
    cleaned = []
    for subdomain in self.domains:
      subdomain = subdomain.replace("http://", "")
      subdomain = subdomain.replace("https://", "")
      subdomain = subdomain.replace("ftp://", "")
      subdomain = subdomain.replace("sftp://", "")
      cleaned.append(subdomain.strip())
    return cleaned

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

  def subdomain_hackertarget(self):
    print("Searching HackerTarget")
    headers = {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36', }
    params = (('q', self.options["TARGET"]),)

    results = requests.get('http://api.hackertarget.com/hostsearch/',
                           headers=headers, params=params)
    results = results.text.split('\n')
    for res in results:
      try:
        if res.split(",")[0] != "":
          domain = res.split(",")[0]
          domain = domain.strip()
          if domain not in self.domains and domain.endswith(
                  "." + self.options["TARGET"]):
            self.domains.append(domain)
            if self.options["--verbose"]:
              print("HackerTarget Found Domain:", domain.strip())
      except:
        pass

  def search_virustotal(self):
    print("Searching VirusTotal")
    headers = {'dnt': '1', 'accept-encoding': 'gzip, deflate, br',
               'accept-language': 'en-US,en;q=0.9,it;q=0.8',
               'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
               'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
               'authority': 'www.virustotal.com',
               'cookie': 'VT_PREFERRED_LANGUAGE=en', }
    res = requests.get('https://www.virustotal.com/en/domain/' + self.options[
      "TARGET"] + '/information/', headers=headers, verify=False)
    if res.status_code == 403:
      ColorPrint.red(
        "VirusTotal is currently ratelimiting this IP - go to https://www.virustotal.com/en/domain/" +
        self.options[
          "TARGET"] + "/information/ and complete the captcha to continue.")
      return
    scraped = res.text
    try:
      trim_to_subdomain = scraped[
                          scraped.find("observed-subdomains"):scraped.rfind(
                            "<script>")].split('\n')
      for domain in trim_to_subdomain:
        if domain.strip().endswith("." + self.options["TARGET"]):
          if domain.strip() not in self.domains and domain.endswith(
                  self.options["TARGET"]):
            self.domains.append(domain.strip())
            if self.options["--verbose"]:
              print("VirustTotal Found Domain:", domain.strip())
    except Exception as e:
      self.handle_exception(e, "Error parsing virustotal")
      pass

  def search_netcraft(self):
    print("Searching NetCraft.com")
    headers = {'Pragma': 'no-cache', 'DNT': '1',
               'Accept-Encoding': 'gzip, deflate, br',
               'Accept-Language': 'en-US,en;q=0.9,it;q=0.8',
               'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
               'Cache-Control': 'no-cache',
               'Referer': 'https://searchdns.netcraft.com/?restriction=site+ends+with&host=',
               'Connection': 'keep-alive', }

    params = (
      ('restriction', 'site contains'), ('host', self.options["TARGET"]))

    res = requests.get('https://searchdns.netcraft.com/', headers=headers,
                       params=params)

    try:
      scraped = res.text
      trimmed = scraped[scraped.find('<div class="blogtitle">'):scraped.rfind(
        '<div id="copyright">')]
      subdomain_finder = re.compile(
        '<a href="http://toolbar.netcraft.com/site_report\?url=(.*)">')
      links = subdomain_finder.findall(trimmed)
      for domain in links:
        if domain.strip() not in self.domains and domain.endswith(
                "." + self.options["TARGET"]):
          self.domains.append(domain.strip())
          if self.options["--verbose"]:
            print("Netcraft Found Domain:", domain.strip())
    except Exception as e:
      self.handle_exception(e, "Error parsing netcraft output")
      pass

  def search_pkey(self):
    print("Searching Pkey.in")
    headers = {'Pragma': 'no-cache', 'Origin': 'https://www.pkey.in',
               'Accept-Encoding': 'gzip, deflate, br',
               'Accept-Language': 'en-US,en;q=0.9,it;q=0.8',
               'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
               'Content-Type': 'application/x-www-form-urlencoded',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
               'Cache-Control': 'no-cache',
               'Referer': 'http://www.pkey.in/tools-i/search-subdomains',
               'Connection': 'keep-alive', 'DNT': '1', }

    data = [('zone', self.options["TARGET"]), ('submit', ''), ]
    res = requests.post('http://www.pkey.in/tools-i/search-subdomains',
                        headers=headers, data=data, verify=False)
    scraped = res.text
    try:
      trimmed = scraped[
                scraped.find('<table class="clearborder">'):scraped.rfind(
                  '</tbody>')].split('\n')
      for entry in trimmed:
        if entry.strip().startswith('<td style="border-left-style: none;">'):
          domain = entry.replace('<td style="border-left-style: none;">', '')
          domain = domain.replace('</td>', '')
          if self.options["TARGET"] in domain:
            if domain.strip() not in self.domains:
              self.domains.append(domain.strip())
              if self.options["--verbose"]:
                print("Pkey Found Domain:", domain.strip())
    except Exception as e:
      self.handle_exception(e, "Error parsing pkey")
      pass

  def search_shodan(self):
    print("Scanning Shodan.io")
    try:
      from anubis.API import SHODAN_KEY
    except ImportError:
      ColorPrint.red("Unable to import API keys - make sure API.py exists!")
      return

    if not SHODAN_KEY:
      print(
        "To run with additional information, you must set http://shodan.io's API key. You can either set it manually here, or set it within anubis/API.py\nKey: ",
        end='')
      key = input()
      api = shodan.Shodan(key)
    else:
      api = shodan.Shodan(SHODAN_KEY)

    if self.ip != "":
      try:
        results = api.host(self.ip)
        if self.options["--verbose"]:
          print(dumps(results, indent=2, sort_keys=True))

        print('Server Location:',
              results['city'] + ", " + results['country_code'], '-',
              results['postal_code'])
        print("ISP: %s" % results['isp'])
        if results['os'] is not None:
          print("Possible OS: %s" % results['os'])
      except Exception as e:
        self.handle_exception(e, "Error retrieving additional info")

  def scan_subject_alt_name(self):
    print("Scanning for Subject Alt Names")
    try:
      server_info = ServerConnectivityInfo(hostname=self.options["TARGET"])
      server_info.test_connectivity_to_server()
      synchronous_scanner = SynchronousScanner()

      # Certificate information
      command = CertificateInfoScanCommand()
      scan_result = synchronous_scanner.run_scan_command(server_info, command)
      # Direct object reference is pretty bad, but then again so is the crypto.x509 implementation, so...
      extensions = scan_result.certificate_chain[0].extensions[6]
      for entry in extensions.value:
        if entry.value.strip() not in self.domains:
          self.domains.append(entry.value.strip())

    except Exception as e:
      self.handle_exception(e)

  def ssl_scan(self):
    print("Running SSL Scan")
    try:
      server_info = ServerConnectivityInfo(hostname=self.options["TARGET"])
      server_info.test_connectivity_to_server()
      synchronous_scanner = SynchronousScanner()

      # TLS 1.0
      command = Tlsv10ScanCommand()
      scan_result = synchronous_scanner.run_scan_command(server_info, command)
      print("Available TLSv1.0 Ciphers:")
      for cipher in scan_result.accepted_cipher_list:
        print('    {}'.format(cipher.name))

      # TLSv1.2
      command = Tlsv12ScanCommand()
      scan_result = synchronous_scanner.run_scan_command(server_info, command)
      print("Available TLSv1.2 Ciphers:")
      for cipher in scan_result.accepted_cipher_list:
        print('    {}'.format(cipher.name))

      # Certificate information
      command = CertificateInfoScanCommand()
      scan_result = synchronous_scanner.run_scan_command(server_info, command)
      for entry in scan_result.as_text():
        print(entry)

      # Heartbleed vulnerability info
      command = HeartbleedScanCommand()
      scan_result = synchronous_scanner.run_scan_command(server_info, command)
      for entry in scan_result.as_text():
        print(entry)

      # HTTP Headers info
      command = HttpHeadersScanCommand()
      scan_result = synchronous_scanner.run_scan_command(server_info, command)
      for entry in scan_result.as_text():
        print(entry)

    except Exception as e:
      self.handle_exception(e, "Error running SSL scan")
      pass

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

  def dnssecc_subdomain_enum(self):
    if os.getuid() == 0:
      print("Starting DNSSEC Enum")
      nm = nmap.PortScanner()
      arguments = '-sSU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=' + \
                  self.options["TARGET"]
      nm.scan(hosts=self.ip, arguments=arguments)
      for host in nm.all_hosts():
        try:
          print(nm[host]['udp'][53]['script']['dns-nsec-enum'])
        except:
          pass
    else:
      ColorPrint.red(
        "To run a DNSSEC subdomain enumeration, Anubis must be run as root")

  def search_dnsdumpster(self):
    print("Searching DNSDumpster")
    headers = {'Pragma': 'no-cache', 'Origin': 'https://dnsdumpster.com',
               'Accept-Encoding': 'gzip, deflate, br',
               'Accept-Language': 'en-US,en;q=0.9,it;q=0.8',
               'Upgrade-Insecure-Requests': '1',
               'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
               'Content-Type': 'application/x-www-form-urlencoded',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
               'Cache-Control': 'no-cache',
               'Referer': 'https://dnsdumpster.com/',
               'Connection': 'keep-alive', 'DNT': '1', }

    get_csrf_res = requests.get('https://dnsdumpster.com', headers=headers)

    try:
      csrf_token = get_csrf_res.headers['Set-Cookie']
      csrf_token = csrf_token[10:]
      csrf_token = csrf_token.split(";")[0]
    except Exception as e:
      self.handle_exception(e, "Retrieving CSRF Token for DNSDumpster failed")
      return

    cookies = {'csrftoken': csrf_token, }

    data = [('csrfmiddlewaretoken', csrf_token),
            ('targetip', self.options["TARGET"])]

    res = requests.post('https://dnsdumpster.com/', headers=headers,
                        cookies=cookies, data=data)
    try:
      scraped = res.text
      subdomain_finder = re.compile(
        '\">(.*\.' + self.options["TARGET"] + ')<br>')
      links = subdomain_finder.findall(scraped)
      for domain in links:
        if domain.strip() not in self.domains and domain.endswith(
                "." + self.options["TARGET"]):
          self.domains.append(domain.strip())
          if self.options["--verbose"]:
            print("DNSDumpster Found Domain:", domain.strip())
    except:
      pass

  def search_censys(self):
    print("Searching Censys")
    try:
      from anubis.API import CENSYS_ID, CENSYS_SECRET
    except ImportError:
      ColorPrint.red(
        "To run a Censys scan, you must add your API keys to anubis/API.py")
    if not CENSYS_SECRET or not CENSYS_ID:
      ColorPrint.red(
        "To run a Censys scan, you must add your API keys to anubis/API.py")
      return
    c = censys.certificates.CensysCertificates(CENSYS_ID, CENSYS_SECRET)
    for cert in c.search("." + self.options["TARGET"]):
      print(cert)

  # TODO - implement scanning google, bing, yahoo, baidu, and ask
  def scan_google(self):
    print("Searching Google")
    base_url = "https://google.com/search?q="
    append = "&hl=en-US&start="
    query = "site:" + self.options["TARGET"]
    for domain in self.domains:
      query += " -" + domain
    page_num = 0
    url = base_url + query + append + str(page_num)

  # TODO - Need to implement brute forcing in a non blocking, multi threaded way
  def brute_force(self):
    print(
      "NOT YET IMPLEMENTED - Starting brute force enumartin (warning - will take a while)")

  def scan_anubisdb(self):
    print("Searching Anubis-DB")
    res = requests.get(
      "https://jonlu.ca/anubis/subdomains/" + self.options["TARGET"])

    if res.status_code == 200 and res.text:
      subdomains = loads(res.text)

      for subdomain in subdomains:
        if subdomain not in self.domains:
          self.domains.append(subdomain)

  def send_to_anubisdb(self):
    print("Sending to AnubisDB")
    data = {'subdomains': dumps(self.domains)}
    res = requests.post(
      "https://jonlu.ca/anubis/subdomains/" + self.options["TARGET"], data=data)
    if res.status_code != 200:
      ColorPrint.red(
        "Error sending results to AnubisDB - Status Code: " + res.status_code)
