"""The target command."""


from json import dumps

from .base import Base


class Target(Base):
    """Main enumeration module"""

    def run(self):
        print('Hello, target!')
        print('You supplied the following options:', dumps(self.options, indent=2, sort_keys=True))
