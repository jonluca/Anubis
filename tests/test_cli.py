"""Tests for our main anubis CLI module."""

import os
import shutil
import tempfile
from subprocess import PIPE, Popen as popen
from unittest import TestCase

from anubis import __version__ as VERSION
from anubis.cli import StdOutHook


class TestHelp(TestCase):

  def test_returns_usage_information(self):
    output = popen(['anubis', '-h'], stdout=PIPE).communicate()[0]
    output = output.decode("utf-8")
    self.assertTrue('Usage:' in output)

    output = popen(['anubis', '--help'], stdout=PIPE).communicate()[0]
    output = output.decode("utf-8")
    self.assertTrue('Usage:' in output)


class TestVersion(TestCase):

  def test_returns_version_information(self):
    output = popen(['anubis', '--version'], stdout=PIPE).communicate()[0]
    output = output.decode("utf-8")
    self.assertEqual(output.strip(), VERSION)


class TestOptions(TestCase):

  def setUp(self):
    # Create a temporary directory
    self.test_dir = tempfile.mkdtemp()

  def tearDown(self):
    # Remove the directory after the test
    shutil.rmtree(self.test_dir)

  def test_stdouthook(self):
    temp = StdOutHook(os.path.join(self.test_dir, 'test.txt'))
    temp.write("test")
    temp.write_out()
    temp.flush()
    f = open(os.path.join(self.test_dir, 'test.txt'), 'r')
    self.assertIn("test", f.readlines())


class TestFullRun(TestCase):

  def test_run(self):
    output = popen(
      ['anubis', '-tip', 'jonlu.ca', '--with-nmap', '--overwrite-nmap-scan',
       '"-F"'], stdout=PIPE).communicate()[0]
    output = output.decode("utf-8")
    self.assertIn("www.jonlu.ca", output)
