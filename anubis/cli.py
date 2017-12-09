"""
Usage:
  anubis -h | --help
  anubis --version

Options:
  -h --help                         Show this screen.
  --version                         Show version.
  -t --target <ip or url>           Run Anubis on the target

Examples:
	anubis -h                         Prints this menu
	anubis -t 192.168.0.1             Attempts to find subdomains and information on 192.168.0.1
	anubis -t google.com              Attempts to find subdomains and information on google.com

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
	for (k, v) in options.items():
		if hasattr(anubis.commands, k) and v:
			module = getattr(anubis.commands, k)
			anubis.commands = getmembers(module, isclass)
			command = \
				[command[1] for command in anubis.commands if command[0] != 'Base'][0]
			command = command(options)
			command.run()
