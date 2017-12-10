"""Example of program with many options using docopt.
Usage:
  anubis -t TARGET [-ov]
  anubis -h
  anubis --version
  
Options:
  -h --help            show this help message and exit
  --version            show version and exit
  -v --verbose         print status messages
  -o --o               report only file names
  -t --target          set target
  
Help:
  For help using this tool, please open an issue on the Github repository:
  https://github.com/jonluca/anubis
"""
from inspect import getmembers, isclass

from docopt import docopt

from . import __version__ as VERSION


def main():
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
	import anubis.commands
	options = docopt(__doc__, version=VERSION)

	# Here we'll try to dynamically match the command the user is trying to run
	# with a pre-defined command class we've already created.
	if not options["--target"]:
		print("Target required! Run with -h for usage instructions.")
		return
	command = anubis.commands.Target
	command = command(options)
	command.run()
