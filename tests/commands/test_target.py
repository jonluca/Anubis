"""Tests for our main anubis CLI module."""

import os
import signal
import sys
from io import StringIO
from subprocess import PIPE, Popen as popen
from threading import Timer
from time import sleep
from unittest import TestCase

from anubis.commands.target import Target
from anubis.scanners.anubis_db import search_anubisdb, send_to_anubisdb
from anubis.scanners.crt import search_crtsh
from anubis.scanners.dnsdumpster import search_dnsdumpster
from anubis.scanners.dnssec import dnssecc_subdomain_enum
from anubis.scanners.hackertarget import subdomain_hackertarget
from anubis.scanners.netcraft import search_netcraft
from anubis.scanners.pkey import search_pkey
from anubis.scanners.recursive import recursive_search
from anubis.scanners.shodan import search_shodan
from anubis.scanners.zonetransfer import dns_zonetransfer
from anubis.utils.ColorPrint import ColorPrint


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
    self.stdout = sys.stdout
    # reset domains
    self.domains = list()

  def tearDown(self):
    self.held.write(sys.stdout.getvalue())

  def test_anubis_db(self):
    search_anubisdb(self, "example.com")
    self.assertIn("www.example.com", self.domains)

  def test_send_to_anubis(self):
    self.domains.append("www.example.com")
    send_to_anubisdb(self,
                     ["example.com"])  # Send to anubis db takes in an array
    self.assertTrue("Error" not in sys.stdout.getvalue())

    send_to_anubisdb(self, ["example.com", "www.example.com"])
    self.assertTrue("multiple" in sys.stdout.getvalue())

    send_to_anubisdb(self, ["example"])
    self.assertTrue("Error" in sys.stdout.getvalue())

  def test_crt(self):
    search_crtsh(self, "jonlu.ca")

    if 'TRAVIS' in os.environ:
      self.assertTrue(True) # crt.sh times out on Travis
      return
    self.assertIn("secure.jonlu.ca", self.domains)

  def test_zonetransfer(self):
    dns_zonetransfer(self, "jonlu.ca")
    self.assertTrue("Error" not in sys.stdout.getvalue())
    dns_zonetransfer(self, "$FALSE$")
    self.assertTrue("Error" in sys.stdout.getvalue())

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
    self.assertTrue(True) # patch after netcraft no long returns valid results, 1/6/19
    # self.assertIn("http://www.example.com", self.domains)

  # As of 1/18/18, Pkey currently constantly times out
  def test_pkey(self):
    search_pkey(self, "google.com")
    # self.assertIn("google.com", self.domains)
    self.assertTrue(True)

  def test_shodan(self):
    self.ip = "138.197.125.24"
    self.options = {}
    self.options["TARGET"] = ["jonlu.ca"]
    self.options["--verbose"] = True
    search_shodan(self)
    self.assertIn("ISP", sys.stdout.getvalue())

  def test_recursive(self):
    self.options = {}
    # Set target to domain we know only has 1 subdomain, for speeds sake
    self.options["TARGET"] = ["neverssl.com"]
    self.domains.append("neverssl.com")
    self.options["--verbose"] = True
    self.options["--queue-workers"] = False
    recursive_search(self)
    self.domains = self.clean_domains(self.domains)
    self.assertIn("www.neverssl.com", self.domains)

  # Pass through function for recursive search
  def clean_domains(self, domains):
    return Target.clean_domains(domains)

  def test_sigints(self):
    # Declare function to send sigint, after timer

    proc1 = popen(['anubis', '-tr', 'neverssl.com'], stdout=PIPE)

    # Function to send sigint to our processes, make sure that it outputss "Quitting" then ends
    def send_siginit():
      popen.send_signal(proc1, signal.SIGINT)
      self.assertTrue("Quitting" in sys.stdout.getvalue())

    t = Timer(3.0, send_siginit)
    t.start()
    sleep(5)

  def test_exception(self):
    self.options["--verbose"] = True
    try:
      raise Exception("Oh No")
    except Exception as e:
      Target.handle_exception(self, e, "Test Exception")
      self.assertTrue("Test" in sys.stdout.getvalue())


class TestColorPrint(TestCase):

  def setUp(self):
    # catch stdout
    self.held, sys.stdout = sys.stdout, StringIO()
    # reset domains
    self.domains = list()

  def tearDown(self):
    # Kind of hacky as it'll dump all of stdout at the end, but better than losing it entirely
    self.held.write(sys.stdout.getvalue())

  def test_color_print(self):
    ColorPrint.red("red")
    self.assertIn("91m", sys.stdout.getvalue())
    ColorPrint.green("green")
    self.assertIn("92m", sys.stdout.getvalue())
    ColorPrint.light_purple("light_purple")
    self.assertIn("94m", sys.stdout.getvalue())
    ColorPrint.purple("purple")
    self.assertIn("95m", sys.stdout.getvalue())
    ColorPrint.yellow("yellow")
    self.assertIn("93m", sys.stdout.getvalue())
