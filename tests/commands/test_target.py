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
from anubis.scanners.virustotal import search_virustotal
from anubis.scanners.zonetransfer import dns_zonetransfer


class TestScanners(TestCase):
  domains = list()

  def handle_exception(self, e, message=""):
    print(e)
    if message:
      print(message)

  def setUp(self):
    self.held, sys.stdout = sys.stdout, StringIO()

  def test_anubis_db(self):
    search_anubisdb(self, "example.com")
    self.assertIn("www.example.com", self.domains)

  def test_send_to_anubis(self):
    self.domains.append("www.example.com")
    send_to_anubisdb(self, "example.com")
    self.assertTrue("Error" not in sys.stdout.getvalue())

  def test_crt(self):
    self.domains = list()
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
    self.domains = list()
    search_virustotal(self, "example.com")
    if "limiting" in sys.stdout.getvalue():
      print("VirusTotal rate limiting")
      return
    self.assertIn("yy.example.com", self.domains)

  def test_dnsdumpster(self):
    self.domains = list()
    search_dnsdumpster(self, "example.com")
    self.assertIn("www.example.com", self.domains)

  def test_dnssec(self):
    if os.getuid() == 0:
      dnssecc_subdomain_enum(self, "google.com")
      self.assertTrue("google" in sys.stdout.getvalue())
    else:
      print("To run DNSSEC test, run as root")


class TestVersion(TestCase):

  def test_returns_version_information(self):
    output = popen(['anubis', '--version'], stdout=PIPE).communicate()[0]
