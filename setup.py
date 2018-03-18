"""Packaging settings."""

from codecs import open
from os.path import abspath, dirname, join
from subprocess import call

from setuptools import Command, find_packages, setup

from anubis import __version__

this_dir = abspath(dirname(__file__))
with open(join(this_dir, 'README.md'), encoding='utf-8') as file:
  long_description = file.read()


class RunTests(Command):
  """Run all tests."""
  description = 'run tests'
  user_options = []

  def initialize_options(self):
    pass

  def finalize_options(self):
    pass

  def run(self):
    """Run all tests!"""
    errno = call(['py.test', '--cov=anubis', '--cov-report=term-missing'])
    raise SystemExit(errno)


setup(name='anubis-netsec', version=__version__,
      description='Modern and efficient subdomain enumeration and information gathering',
      long_description=long_description,
      url='https://github.com/jonluca/anubis', author='JonLuca DeCaro',
      author_email='jdecaro@usc.edu', license='GPL',
      classifiers=['Intended Audience :: Developers',
                   'Development Status :: 3 - Alpha', 'Topic :: Utilities',
                   'License :: Public Domain', 'Natural Language :: English',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python :: 3.4',
                   'Programming Language :: Python :: 3.5',
                   'Programming Language :: Python :: 3.6', ], keywords='cli',
      packages=find_packages(exclude=['docs', 'tests*']), python_requires='>=3',
      install_requires=['docopt', 'setuptools', 'SSLyze==1.4.0', 'python_nmap',
                        'shodan', 'requests', 'censys', 'dnspython'],
      extras_require={'test': ['coverage', 'pytest', 'pytest-cov'], },
      entry_points={'console_scripts': ['anubis=anubis.cli:main', ], },
      cmdclass={'test': RunTests},
      py_modules=["anubis.utils", "anubis.scanners"], )
