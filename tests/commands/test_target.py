"""Tests for our main anubis CLI module."""

import sys
from io import StringIO
from subprocess import PIPE, Popen as popen
from unittest import TestCase

from anubis.scanners.anubis_db import search_anubisdb, send_to_anubisdb


class TestScanners(TestCase):
  domains = list()

  def setUp(self):
    self.held, sys.stdout = sys.stdout, StringIO()

  def test_anubis_db(self):
    search_anubisdb(self, "example.com")
    self.assertIn("www.example.com", self.domains)

  def test_send_to_anubis(self):
    self.domains.append("www.example.com")
    send_to_anubisdb(self, "example.com")
    self.assertTrue("Error" not in sys.stdout.getvalue())


class TestVersion(TestCase):

  def test_returns_version_information(self):
    output = popen(['anubis', '--version'], stdout=PIPE).communicate()[0]
