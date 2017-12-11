"""The target command."""

import os
import re
import shutil
from json import *
from pprint import pprint

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
from sslyze.plugins.openssl_cipher_suites_plugin import *
from sslyze.server_connectivity import *
from sslyze.synchronous_scanner import *

from anubis.utils.ColorPrint import *
from .base import Base


class Target(Base):
	"""Main enumeration module"""
	domains = []
	ip = ""

	def handle_exception(self, e, message=""):
		if self.options["--verbose"]:
			ColorPrint.red(e)
		if message:
			ColorPrint.red(message)

	def init(self):
		try:
			self.ip = socket.gethostbyname(self.options["TARGET"])
		except Exception as e:
			self.handle_exception(e,
			                      "Error connecting to target! Make sure you spelled it correctly and it is a reachable address")

	def run(self):
		# retrieve IP of target
		self.init()
		ColorPrint.green("Searching for subdomains for " + self.ip)

		# perform scans
		self.dns_zonetransfer()
		self.subdomain_hackertarget()
		self.search_virustotal()
		self.search_pkey()
		self.search_netcraft()
		self.search_dnsdumpster()
		self.scan_subject_alt_name()

		# Not sure what data we can get from censys yet, but might be useful in the future
		# self.search_censys()

		if self.options["--ssl"]:
			self.ssl_scan()
		if self.options["--additional-info"]:
			self.search_shodan()
		if self.options["--with-nmap"]:
			# self.scan_host()
			self.dnssecc_subdomain_enum()

		# remove duplicates and clean up
		self.domains = [x.strip() for x in self.domains]
		self.dedupe = set(self.domains)
		print("Found", len(self.dedupe), "domains")
		print("----------------")
		if self.options["--ip"]:
			self.resolve_ips()
		else:
			for domain in self.dedupe:
				ColorPrint.green(domain.strip())

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
						print('\tservice: %s' % (nm[host][proto][port]['product']), end='')
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
									self.options["TARGET"]):
						self.domains.append(domain)
						if self.options["--verbose"]:
							print("HackerTarget Found Domain:", domain.strip())
			except Exception as e:
				pass

	def search_virustotal(self):
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
				"VirusTotal is currently ratelimiting this IP - go to virustotal.com and complete the captcha to continue.")
			return
		scraped = res.text
		try:
			trim_to_subdomain = scraped[
			                    scraped.find("observed-subdomains"):scraped.rfind(
				                    "<script>")].split('\n')
			for domain in trim_to_subdomain:
				if domain.strip().endswith(self.options["TARGET"]):
					if domain.strip() not in self.domains and domain.endswith(
									self.options["TARGET"]):
						self.domains.append(domain.strip())
						if self.options["--verbose"]:
							print("VirustTotal Found Domain:", domain.strip())
		except Exception as e:
			self.handle_exception(e, "Error parsing virustotal")
			pass

	def search_netcraft(self):

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
								self.options["TARGET"]):
					self.domains.append(domain.strip())
					if self.options["--verbose"]:
						print("Netcraft Found Domain:", domain.strip())
		except Exception as e:
			self.handle_exception(e, "Error parsing netcraft output")
			pass

	def search_pkey(self):
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
		from anubis.API import SHODAN_KEY

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
		try:
			server_info = ServerConnectivityInfo(hostname=self.options["TARGET"])
			server_info.test_connectivity_to_server()
			synchronous_scanner = SynchronousScanner()

			# Certificate information
			command = CertificateInfoScanCommand()
			scan_result = synchronous_scanner.run_scan_command(server_info, command)
			for entry in scan_result.extensions:
				print(entry)
			pprint(vars(scan_result.extensions['subjectAltName']))
			for entry in scan_result.as_text():
				print(entry)
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
			print("Zone transfers possible:")
			for zone in zonetransfers:
				ColorPrint.red(zone)
		else:
			print("No zone transfers possible")

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
				'\"\>(.*\.' + self.options["TARGET"] + ')<br>')
			links = subdomain_finder.findall(scraped)
			for domain in links:
				if domain.strip() not in self.domains and domain.endswith(
								self.options["TARGET"]):
					self.domains.append(domain.strip())
					if self.options["--verbose"]:
						print("DNSDumpster Found Domain:", domain.strip())
		except:
			pass

	def search_censys(self):
		from anubis.API import CENSYS_ID, CENSYS_SECRET
		if not CENSYS_SECRET or not CENSYS_ID:
			ColorPrint.red(
				"To run a Censys scan, you must add your API keys to anubis/API.py")
			return
		c = censys.certificates.CensysCertificates(CENSYS_ID, CENSYS_SECRET)
		for cert in c.search("." + self.options["TARGET"]):
			print(cert)

	def scan_google(self):
		base_url = "https://google.com/search?q="
		append = "&hl=en-US&start="
		query = "site:" + self.options["TARGET"]
		for domain in self.domains:
			query += " -" + domain
		page_num = 0
		url = base_url + query + append + page_num
