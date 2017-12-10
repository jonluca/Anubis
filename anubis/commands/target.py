"""The target command."""

import socket

import nmap
import requests
import shodan

from anubis.API import *
from anubis.utils.ColorPrint import *

api = shodan.Shodan(SHODAN_KEY)
from .base import Base


class Target(Base):
	"""Main enumeration module"""
	domains = []
	ip = ""

	def init(self):
		try:
			self.ip = socket.gethostbyname(self.options["TARGET"])
		except:
			ColorPrint.red(
				"Error connecting to target! Make sure you spelled it correctly and it is a reachable address")

	def run(self):
		self.init()
		print("Searching for subdomains for", self.ip)
		self.subdomain_hackertarget()
		self.search_virustotal()
		self.search_pkey()
		if self.options["--with-nmap"]:
			self.scan_host()
		print("Found", len(self.domains), "domains")
		print("----------------")
		# remove duplicates and clean up
		map(str.strip, self.domains)
		dedupe = set(self.domains)
		for domain in dedupe:
			ColorPrint.green(domain.strip())

		# should_scan_host = input("Scan host " + self.ip + "? (y or n)\n")
		# if should_scan_host == "y" or should_scan_host == "yes":

	# Performs an nmap scan of a target, and outputs interesting services/ssl information
	def scan_host(self):
		print("Scanning for services...")

		nm = nmap.PortScanner()
		# nm.scan(hosts=self.ip, arguments='-nPn -sV -sC -F')
		nm.analyse_nmap_xml_scan(
			'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?><!-- Nmap 7.60 scan initiated Sun Dec 10 12:02:50 2017 as: nmap -oX - -nPn -sV -sC -F 138.197.125.24 --><nmaprun scanner="nmap" args="nmap -oX - -nPn -sV -sC -F 138.197.125.24" start="1512936170" startstr="Sun Dec 10 12:02:50 2017" version="7.60" xmloutputversion="1.04"><scaninfo type="connect" protocol="tcp" numservices="100" services="7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"/><verbose level="0"/><debugging level="0"/><host starttime="1512936170" endtime="1512936210"><status state="up" reason="user-set" reason_ttl="0"/><address addr="138.197.125.24" addrtype="ipv4"/><hostnames></hostnames><ports><extraports state="filtered" count="97"><extrareasons reason="no-responses" count="97"/></extraports><port protocol="tcp" portid="53"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="domain" method="probed" conf="10"/></port><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="nginx" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx</cpe></service><script id="http-server-header" output="nginx"><elem>nginx</elem></script><script id="http-title" output="Did not follow redirect to https://138.197.125.24/"><elem key="redirect_url">https://138.197.125.24/</elem></script></port><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="nginx" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx</cpe></service><script id="http-title" output=" GitHub Field Day"><elem key="title"> GitHub Field Day</elem></script><script id="ssl-cert" output="Subject: commonName=jonlu.ca&#xa;Subject Alternative Name: DNS:blackboard.today, DNS:blackboardusc.com, DNS:githubfieldday.me, DNS:jonlu.ca, DNS:jonluca.me, DNS:secure.jonlu.ca, DNS:secure.scopeusc.com, DNS:shibboleth.blackboardusc.com, DNS:www.blackboard.today, DNS:www.blackboardusc.com, DNS:www.githubfieldday.me, DNS:www.jonlu.ca, DNS:www.jonluca.me&#xa;Not valid before: 2017-11-09T02:05:58&#xa;Not valid after:  2018-02-07T02:05:58"><table key="subject"><elem key="commonName">jonlu.ca</elem></table><table key="issuer"><elem key="commonName">Let&apos;s Encrypt Authority X3</elem><elem key="organizationName">Let&apos;s Encrypt</elem><elem key="countryName">US</elem></table><table key="pubkey"><elem key="bits">2048</elem><elem key="type">rsa</elem><elem key="exponent">userdata: 0x7f956d60bd98</elem></table><table key="extensions"><table><elem key="name">X509v3 Key Usage</elem><elem key="value">Digital Signature, Key Encipherment</elem><elem key="critical">true</elem></table><table><elem key="name">X509v3 Extended Key Usage</elem><elem key="value">TLS Web Server Authentication, TLS Web Client Authentication</elem></table><table><elem key="name">X509v3 Basic Constraints</elem><elem key="value">CA:FALSE</elem><elem key="critical">true</elem></table><table><elem key="name">X509v3 Subject Key Identifier</elem><elem key="value">0E:4B:9B:7F:18:CC:02:44:30:5E:74:6D:DD:96:6A:CF:8C:8C:88:84</elem></table><table><elem key="name">X509v3 Authority Key Identifier</elem><elem key="value">keyid:A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1&#xa;</elem></table><table><elem key="name">Authority Information Access</elem><elem key="value">OCSP - URI:http://ocsp.int-x3.letsencrypt.org&#xa;CA Issuers - URI:http://cert.int-x3.letsencrypt.org/&#xa;</elem></table><table><elem key="name">X509v3 Subject Alternative Name</elem><elem key="value">DNS:blackboard.today, DNS:blackboardusc.com, DNS:githubfieldday.me, DNS:jonlu.ca, DNS:jonluca.me, DNS:secure.jonlu.ca, DNS:secure.scopeusc.com, DNS:shibboleth.blackboardusc.com, DNS:www.blackboard.today, DNS:www.blackboardusc.com, DNS:www.githubfieldday.me, DNS:www.jonlu.ca, DNS:www.jonluca.me</elem></table><table><elem key="name">X509v3 Certificate Policies</elem><elem key="value">Policy: 2.23.140.1.2.1&#xa;Policy: 1.3.6.1.4.1.44947.1.1.1&#xa;  CPS: http://cps.letsencrypt.org&#xa;  User Notice:&#xa;    Explicit Text: This Certificate may only be relied upon by Relying Parties and only in accordance with the Certificate Policy found at https://letsencrypt.org/repository/&#xa;</elem></table></table><elem key="sig_algo">sha256WithRSAEncryption</elem><table key="validity"><elem key="notBefore">2017-11-09T02:05:58</elem><elem key="notAfter">2018-02-07T02:05:58</elem></table><elem key="md5">abe2fecb545348142014721b13253367</elem><elem key="sha1">002a6cf9e5ee41f731a7c12f77a81264b98a5015</elem><elem key="pem">-&#45;&#45;&#45;&#45;BEGIN CERTIFICATE-&#45;&#45;&#45;&#45;&#xa;MIIF4DCCBMigAwIBAgISA2wJKfmIxe9eLT5G8jhdzM/5MA0GCSqGSIb3DQEBCwUA&#xa;MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD&#xa;ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNzExMDkwMjA1NThaFw0x&#xa;ODAyMDcwMjA1NThaMBMxETAPBgNVBAMTCGpvbmx1LmNhMIIBIjANBgkqhkiG9w0B&#xa;AQEFAAOCAQ8AMIIBCgKCAQEAnLEWJ6egtfoGX7aqvBpF3BHJEpzWnxrxzwcgOIo4&#xa;0zw4l61t/GWTeStqfYPzI0c4AtYXFpiVxbn5YJeiaozAR4ILP1G0nvgihnhhuPRk&#xa;+UdOBAYNNdWX+D9dbiXAbrkJmzBh+dqp8wrE6KeQg7gzd70ataKb8gh0G5dhiL0B&#xa;vMXzJfOEOYZMAknxOV1BRzLuvWD48AIDD85bKf55UJBJfxyUfFkPh2susuPNRhqp&#xa;BZnNixnsN97wpeBnOVCEE+UpxgZ3QKbcZ8rqKGCu3ErOgCiSHwqcwH1B/zKenqSx&#xa;wcxONBQ5vqOE76WNTN/6GWZkT3bTdJDvRUZG1xqaFS8pWwIDAQABo4IC9TCCAvEw&#xa;DgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAM&#xa;BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQOS5t/GMwCRDBedG3dlmrPjIyIhDAfBgNV&#xa;HSMEGDAWgBSoSmpjBH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRjMGEwLgYI&#xa;KwYBBQUHMAGGImh0dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcwLwYI&#xa;KwYBBQUHMAKGI2h0dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMIH/&#xa;BgNVHREEgfcwgfSCEGJsYWNrYm9hcmQudG9kYXmCEWJsYWNrYm9hcmR1c2MuY29t&#xa;ghFnaXRodWJmaWVsZGRheS5tZYIIam9ubHUuY2GCCmpvbmx1Y2EubWWCD3NlY3Vy&#xa;ZS5qb25sdS5jYYITc2VjdXJlLnNjb3BldXNjLmNvbYIcc2hpYmJvbGV0aC5ibGFj&#xa;a2JvYXJkdXNjLmNvbYIUd3d3LmJsYWNrYm9hcmQudG9kYXmCFXd3dy5ibGFja2Jv&#xa;YXJkdXNjLmNvbYIVd3d3LmdpdGh1YmZpZWxkZGF5Lm1lggx3d3cuam9ubHUuY2GC&#xa;Dnd3dy5qb25sdWNhLm1lMIH+BgNVHSAEgfYwgfMwCAYGZ4EMAQIBMIHmBgsrBgEE&#xa;AYLfEwEBATCB1jAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5v&#xa;cmcwgasGCCsGAQUFBwICMIGeDIGbVGhpcyBDZXJ0aWZpY2F0ZSBtYXkgb25seSBi&#xa;ZSByZWxpZWQgdXBvbiBieSBSZWx5aW5nIFBhcnRpZXMgYW5kIG9ubHkgaW4gYWNj&#xa;b3JkYW5jZSB3aXRoIHRoZSBDZXJ0aWZpY2F0ZSBQb2xpY3kgZm91bmQgYXQgaHR0&#xa;cHM6Ly9sZXRzZW5jcnlwdC5vcmcvcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQAD&#xa;ggEBAAUeWprDZM3h66hSGQ7PrdBejI/hOBfFgcds/4GCGI2Oha+xahuNsIV4BpTi&#xa;hu7Br1BiYB3fU7WaPouuZOIgHW0ZfFS8uKf3DSFtBN/VFR6zVOr9+TUz1p7sjOsr&#xa;OcrqKMuxdVDPXOYIMih1SY9yUFmP+8rx/b7cnqRjQzpNQDsDkOrV6NZHDSqeePV2&#xa;y4gCECATqNHHJTIakw0a/7FC0V9AbhVmaks4d74HB1XjhqlPR1QpTJYmeGxfTDtm&#xa;2JuAh6nEm8O9wCxXn3H2+fS0FFVZk/Mi54hQfxxV0kweJdaFxyiWhXZO0JufXjQ5&#xa;xMIMcqxbx0Q5BOdmWyMuT0sf41w=&#xa;-&#45;&#45;&#45;&#45;END CERTIFICATE-&#45;&#45;&#45;&#45;&#xa;</elem></script><script id="ssl-date" output="TLS randomness does not represent time"></script><script id="tls-nextprotoneg" output="&#xa;  http/1.1"><elem>http/1.1</elem></script></port></ports><times srtt="111124" rttvar="78118" to="423596"/></host><runstats><finished time="1512936210" timestr="Sun Dec 10 12:03:30 2017" elapsed="40.52" summary="Nmap done at Sun Dec 10 12:03:30 2017; 1 IP address (1 host up) scanned in 40.52 seconds" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>')
		# Could be extended to scan multiple hosts in the future
		for host in nm.all_hosts():
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
				except:
					pass
				try:
					fix_newline = nm[host][proto][port]['script']['ssl-cert'].split('\n')
					print('\tssl-cert:')
					for i in range(len(fix_newline)):
						print('\t', fix_newline[i])
						if fix_newline[i].startswith("Subject Alternative Name: "):
							content = fix_newline[i].replace("Subject Alternative Name: ", '')
							content = content.replace("DNS:", '')
							new_domains = content.split(",")
							for domain in new_domains:
								if domain not in self.domains:
									self.domains.append(domain)
				except:
					pass

	def subdomain_hackertarget(self):
		headers = {
			'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36', }
		params = (('q', self.options["TARGET"]),)

		results = requests.get('http://api.hackertarget.com/hostsearch/',
		                       headers=headers, params=params)
		results = results.text.split('\n')
		for res in results:
			if res.split(",")[0] != "":
				self.domains.append(res.split(",")[0])

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
			for entry in trim_to_subdomain:
				if entry.strip().endswith(self.options["TARGET"]):
					if entry.strip() not in self.domains:
						self.domains.append(entry.strip())
		except:
			ColorPrint.red("Error parsing virustotal")
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
					content = entry.replace('<td style="border-left-style: none;">', '')
					content = content.replace('</td>', '')
					if self.options["TARGET"] in content:
						if content.strip() not in self.domains:
							self.domains.append(content.strip())
		except:
			print("Error parsing pkey")
			pass

	def search_shodan(self):
		if self.ip != "":
			try:
				results = api.search(self.ip)
				print('Results found: %s' % results['total'])
				for result in results['matches']:
					print('IP: %s' % result['ip_str'])
					print(result['data'])
			except shodan.APIError as e:
				print('Error: %s' % e)
