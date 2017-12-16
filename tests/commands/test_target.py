"""Tests for our main anubis CLI module."""

import os
import sys
from io import StringIO
from subprocess import PIPE, Popen as popen
from unittest import TestCase

from anubis.scanners.anubis_db import search_anubisdb, send_to_anubisdb
from anubis.scanners.brute_force import brute_force
from anubis.scanners.crt import search_crtsh
from anubis.scanners.dnsdumpster import search_dnsdumpster
from anubis.scanners.dnssec import dnssecc_subdomain_enum
from anubis.scanners.hackertarget import subdomain_hackertarget
from anubis.scanners.netcraft import search_netcraft
from anubis.scanners.pkey import search_pkey
from anubis.scanners.shodan import search_shodan
from anubis.scanners.ssl import search_subject_alt_name, ssl_scan
from anubis.scanners.virustotal import search_virustotal
from anubis.scanners.zonetransfer import dns_zonetransfer


class TestScanners(TestCase):
  domains = list()
  options = {"--verbose": True}

  def handle_exception(self, e, message=""):
    print(e)
    if message:
      print(message)

  def setUp(self):
    # catch stdout
    self.held, sys.stdout = sys.stdout, StringIO()
    # reset domains
    self.domains = list()

  def test_anubis_db(self):
    search_anubisdb(self, "example.com")
    self.assertIn("www.example.com", self.domains)

  def test_send_to_anubis(self):
    self.domains.append("www.example.com")
    send_to_anubisdb(self, "example.com")
    self.assertTrue("Error" not in sys.stdout.getvalue())

  def test_crt(self):
    search_crtsh(self, "jonlu.ca")
    self.assertIn("secure.jonlu.ca", self.domains)

  def test_bruteforce(self):
    brute_force(self, "jonlu.ca")
    # TODO implement bruteforce tests
    self.assertTrue(True)

  def test_zonetransfer(self):
    dns_zonetransfer(self, "jonlu.ca")
    self.assertTrue("Error" not in sys.stdout.getvalue())

  def test_virustotal(self):
    search_virustotal(self, "example.com")
    if "limiting" in sys.stdout.getvalue():
      print("VirusTotal rate limiting")
      return
    self.assertIn("yy.example.com", self.domains)

  def test_dnsdumpster(self):
    search_dnsdumpster(self, "example.com")
    self.assertIn("www.example.com", self.domains)

  def test_dnssec(self):
    if os.getuid() == 0:
      dnssecc_subdomain_enum(self, "google.com")
      self.assertTrue("google" in sys.stdout.getvalue())
    else:
      print("To run DNSSEC test, run as root")

  def test_hackertarget(self):
    subdomain_hackertarget(self, "example.com")
    self.assertIn("www.example.com", self.domains)

  def test_netcraft(self):
    search_netcraft(self, "example.com")
    self.assertIn("http://www.example.com", self.domains)

  def test_pkey(self):
    search_pkey(self, "google.com")
    self.assertIn("google.com", self.domains)

  def test_shodan(self):
    self.ip = "138.197.125.24"
    search_shodan(self)
    self.assertIn("ISP", sys.stdout.getvalue())

  def test_ssl(self):
    ssl_scan(self, "jonlu.ca")
    # Check that Lets Encrypt Cert id is in output
    self.assertIn("YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
                  sys.stdout.getvalue())

  def test_san(self):
    ssl_scan(self, "jonlu.ca")
    search_subject_alt_name(self, "jonlu.ca")
    self.assertIn("www.jonlu.ca", self.domains)


class TestVersion(TestCase):

  def test_returns_version_information(self):
    output = popen(['anubis', '--version'], stdout=PIPE).communicate()[0]
