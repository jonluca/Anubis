"""Example of program with many options using docopt.
Usage:
  anubis -t TARGET [-o FILENAME] [--with-nmap]
  anubis -h
  anubis --version
  
Options:
  -h --help            show this help message and exit
  -t --target          set target
  --with-nmap          perform an nmap service/script scan
  -o --output          save to filename
  --version            show version and exit

Help:
  For help using this tool, please open an issue on the Github repository:
  https://github.com/jonluca/anubis
"""

import sys

from docopt import docopt

VERSION = 1.0


class StdOutHook():
	lines = []
	filename = ""

	def __init__(self, filename):
		self.filename = filename

	def write(self, text):
		sys.__stdout__.write(text)
		self.lines.append(text)

	def writeout(self):
		with open(self.filename, "w") as file:
			for line in self.lines:
				# remove stdout colors
				line = line.replace('\033[91m', '')
				line = line.replace('\033[92m', '')
				line = line.replace('\033[93m', '')
				line = line.replace('\033[94m', '')
				line = line.replace('\033[95m', '')
				line = line.replace('\033[0m', '')
				file.write(line)

	def flush(self):
		# python3 compatability, does nothing
		pass


def main():
	import anubis.commands
	options = docopt(__doc__, version=VERSION)

	if options["--output"]:
		sys.stdout = StdOutHook(options["FILENAME"])

	# Here we'll try to dynamically match the command the user is trying to run
	# with a pre-defined command class we've already created.
	if not options["--target"]:
		print("Target required! Run with -h for usage instructions.")
		return

	print("""
        d8888                   888      d8b
       d88888                   888      Y8P
      d88P888                   888
     d88P 888 88888b.  888  888 88888b.  888 .d8888b
    d88P  888 888 "88b 888  888 888 "88b 888 88K
   d88P   888 888  888 888  888 888  888 888 "Y8888b.
  d8888888888 888  888 Y88b 888 888 d88P 888      X88
 d88P     888 888  888  "Y88888 88888P"  888  88888P'
	""")

	command = anubis.commands.Target
	command = command(options)
	command.run()
	if options["--output"]:
		sys.stdout.writeout()
