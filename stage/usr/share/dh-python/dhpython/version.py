# Copyright © 2010-2013 Piotr Ożarowski <piotr@debian.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import logging
import re
from os.path import exists

from dhpython import _defaults

RANGE_PATTERN = r'(-)?(\d\.\d+)(?:(-)(\d\.\d+)?)?'
RANGE_RE = re.compile(RANGE_PATTERN)
VERSION_RE = re.compile(r'''
    (?P<major>\d+)\.?
    (?P<minor>\d+)?\.?
    (?P<micro>\d+)?[.\s]?
    (?P<releaselevel>alpha|beta|candidate|final)?[.\s]?
    (?P<serial>\d+)?''', re.VERBOSE)

log = logging.getLogger('dhpython')
Interpreter = None


class Version:
    def __init__(self, value=None, major=None, minor=None, micro=None,
                 releaselevel=None, serial=None):
        if isinstance(value, (tuple, list)):
            value = '.'.join(str(i) for i in value)
        if isinstance(value, Version):
            for name in ('major', 'minor', 'micro', 'releaselevel', 'serial'):
                setattr(self, name, getattr(value, name))
            return
        comp = locals()
        del comp['self']
        del comp['value']
        if value:
            match = VERSION_RE.match(value)
            for name, value in match.groupdict().items() if match else []:
                if value is not None and comp[name] is None:
                    comp[name] = value
        for name, value in comp.items():
            if name != 'releaselevel' and value is not None:
                value = int(value)
            setattr(self, name, value)
        if not self.major:
            raise ValueError('major component is required')

    def __str__(self):
        """Return major.minor or major string.

        >>> str(Version(major=3, minor=2, micro=1, releaselevel='final', serial=4))
        '3.2'
        >>> str(Version(major=2))
        '2'
        """
        result = str(self.major)
        if self.minor is not None:
            result += '.{}'.format(self.minor)
        return result

    def __hash__(self):
        return hash(repr(self))

    def __repr__(self):
        """Return full version string.

        >>> repr(Version(major=3, minor=2, micro=1, releaselevel='final', serial=4))
        "Version('3.2.1.final.4')"
        >>> repr(Version(major=2))
        "Version('2')"
        """
        result = "Version('{}".format(self)
        for name in ('micro', 'releaselevel', 'serial'):
            value = getattr(self, name)
            if not value:
                break
            result += '.{}'.format(value)
        return result + "')"

    def __add__(self, other):
        """Return next version.

        >>> Version('3.1') + 1
        Version('3.2')
        >>> Version('2') + '1'
        Version('3')
        """
        result = Version(self)
        if self.minor is None:
            result.major += int(other)
        else:
            result.minor += int(other)
        return result

    def __sub__(self, other):
        """Return previous version.

        >>> Version('3.1') - 1
        Version('3.0')
        >>> Version('3') - '1'
        Version('2')
        """
        result = Version(self)
        if self.minor is None:
            result.major -= int(other)
            new = result.major
        else:
            result.minor -= int(other)
            new = result.minor
        if new < 0:
            raise ValueError('cannot decrease version further')
        return result

    def __eq__(self, other):
        try:
            other = Version(other)
        except Exception:
            return False
        return self.__cmp(other) == 0

    def __lt__(self, other):
        return self.__cmp(other) < 0

    def __le__(self, other):
        return self.__cmp(other) <= 0

    def __gt__(self, other):
        return self.__cmp(other) > 0

    def __ge__(self, other):
        return self.__cmp(other) >= 0

    def __lshift__(self, other):
        """Compare major.minor or major only (if minor is not set).

        >>> Version('2.6') << Version('2.7')
        True
        >>> Version('2.6') << Version('2.6.6')
        False
        >>> Version('3') << Version('2')
        False
        >>> Version('3.1') << Version('2')
        False
        >>> Version('2') << Version('3.2.1.alpha.3')
        True
        """
        if not isinstance(other, Version):
            other = Version(other)
        if self.minor is None or other.minor is None:
            return self.__cmp(other, ignore='minor') < 0
        else:
            return self.__cmp(other, ignore='micro') < 0

    def __rshift__(self, other):
        """Compare major.minor or major only (if minor is not set).

        >>> Version('2.6') >> Version('2.7')
        False
        >>> Version('2.6.7') >> Version('2.6.6')
        False
        >>> Version('3') >> Version('2')
        True
        >>> Version('3.1') >> Version('2')
        True
        >>> Version('2.1') >> Version('3.2.1.alpha.3')
        False
        """
        if not isinstance(other, Version):
            other = Version(other)
        if self.minor is None or other.minor is None:
            return self.__cmp(other, ignore='minor') > 0
        else:
            return self.__cmp(other, ignore='micro') > 0

    def __cmp(self, other, ignore=None):
        if not isinstance(other, Version):
            other = Version(other)
        for name in ('major', 'minor', 'micro', 'releaselevel', 'serial'):
            if name == ignore:
                break
            value1 = getattr(self, name) or 0
            value2 = getattr(other, name) or 0
            if name == 'releaselevel':
                rmap = {'alpha': -3, 'beta': -2, 'candidate': -1, 'final': 0}
                value1 = rmap.get(value1, 0)
                value2 = rmap.get(value2, 0)
            if value1 == value2:
                continue
            return (value1 > value2) - (value1 < value2)
        return 0


class VersionRange:
    def __init__(self, value=None, minver=None, maxver=None):
        if minver:
            self.minver = Version(minver)
        else:
            self.minver = None
        if maxver:
            self.maxver = Version(maxver)
        else:
            self.maxver = None

        if value:
            minver, maxver = self.parse(value)
            if minver and self.minver is None:
                self.minver = minver
            if maxver and self.maxver is None:
                self.maxver = maxver

    def __bool__(self):
        if self.minver is not None or self.maxver is not None:
            return True
        return False

    def __str__(self):
        """Return version range string from given range.

        >>> str(VersionRange(minver='3.4'))
        '3.4-'
        >>> str(VersionRange(minver='3.4', maxver='3.6'))
        '3.4-3.6'
        >>> str(VersionRange(minver='3.4', maxver='4.0'))
        '3.4-4.0'
        >>> str(VersionRange(maxver='3.7'))
        '-3.7'
        >>> str(VersionRange(minver='3.5', maxver='3.5'))
        '3.5'
        >>> str(VersionRange())
        '-'
        """
        if self.minver is None is self.maxver:
            return '-'
        if self.minver == self.maxver:
            return str(self.minver)
        elif self.minver is None:
            return '-{}'.format(self.maxver)
        elif self.maxver is None:
            return '{}-'.format(self.minver)
        else:
            return '{}-{}'.format(self.minver, self.maxver)

    def __repr__(self):
        """Return version range string.

        >>> repr(VersionRange('5.0-'))
        "VersionRange(minver='5.0')"
        >>> repr(VersionRange('3.0-3.5'))
        "VersionRange(minver='3.0', maxver='3.5')"
        """
        result = 'VersionRange('
        if self.minver is not None:
            result += "minver='{}'".format(self.minver)
        if self.maxver is not None:
            result += ", maxver='{}'".format(self.maxver)
        result = result.replace('(, ', '(')
        return result + ")"

    @staticmethod
    def parse(value):
        """Return minimum and maximum Python version from given range.

        >>> VersionRange.parse('3.0-')
        (Version('3.0'), None)
        >>> VersionRange.parse('3.1-3.3')
        (Version('3.1'), Version('3.3'))
        >>> VersionRange.parse('3.2-4.0')
        (Version('3.2'), Version('4.0'))
        >>> VersionRange.parse('-3.7')
        (None, Version('3.7'))
        >>> VersionRange.parse('3.2')
        (Version('3.2'), Version('3.2'))
        >>> VersionRange.parse('') == VersionRange.parse('-')
        True
        >>> VersionRange.parse('>= 4.0')
        (Version('4.0'), None)
        """
        if value in ('', '-'):
            return None, None

        match = RANGE_RE.match(value)
        if not match:
            try:
                minv, maxv = VersionRange._parse_pycentral(value)
            except Exception:
                raise ValueError("version range is invalid: %s" % value)
        else:
            groups = match.groups()

            if list(groups).count(None) == 3:  # only one version is allowed
                minv = Version(groups[1])
                return minv, minv

            minv = maxv = None
            if groups[0]:  # maximum version only
                maxv = groups[1]
            else:
                minv = groups[1]
                maxv = groups[3]

            minv = Version(minv) if minv else None
            maxv = Version(maxv) if maxv else None

        if maxv and minv and minv > maxv:
            raise ValueError("version range is invalid: %s" % value)

        return minv, maxv

    @staticmethod
    def _parse_pycentral(value):
        """Parse X-Python3-Version.

        >>> VersionRange._parse_pycentral('>= 3.1')
        (Version('3.1'), None)
        >>> VersionRange._parse_pycentral('<< 4.0')
        (None, Version('4.0'))
        >>> VersionRange._parse_pycentral('3.1')
        (Version('3.1'), Version('3.1'))
        >>> VersionRange._parse_pycentral('3.1, 3.2')
        (Version('3.1'), None)
        """

        minv = maxv = None
        hardcoded = set()

        for item in value.split(','):
            item = item.strip()

            match = re.match('>=\s*([\d\.]+)', item)
            if match:
                minv = "%.3s" % match.group(1)
                continue
            match = re.match('<<\s*([\d\.]+)', item)
            if match:
                maxv = "%.3s" % match.group(1)
                continue
            match = re.match('^[\d\.]+$', item)
            if match:
                hardcoded.add("%.3s" % match.group(0))

        if len(hardcoded) == 1:
            ver = hardcoded.pop()
            return Version(ver), Version(ver)

        if not minv and hardcoded:
            # yeah, no maxv!
            minv = sorted(hardcoded)[0]

        return Version(minv) if minv else None, Version(maxv) if maxv else None


def default(impl):
    """Return default interpreter version for given implementation."""
    if impl not in _defaults.DEFAULT:
        raise ValueError("interpreter implementation not supported: %r" % impl)
    ver = _defaults.DEFAULT[impl]
    return Version(major=ver[0], minor=ver[1])


def supported(impl):
    """Return list of supported interpreter versions for given implementation."""
    if impl not in _defaults.SUPPORTED:
        raise ValueError("interpreter implementation not supported: %r" % impl)
    versions = _defaults.SUPPORTED[impl]
    return [Version(major=v[0], minor=v[1]) for v in versions]


def get_requested_versions(impl, vrange=None, available=None):
    """Return a set of requested and supported Python versions.

    :param impl: interpreter implementation
    :param available: if set to `True`, return installed versions only,
        if set to `False`, return requested versions that are not installed.
        By default returns all requested versions.
    :type available: bool

    >>> sorted(get_requested_versions('cpython3', '')) == sorted(supported('cpython3'))
    True
    >>> sorted(get_requested_versions('cpython3', '-')) == sorted(supported('cpython3'))
    True
    >>> get_requested_versions('cpython3', '>= 5.0')
    set()
    """
    if isinstance(vrange, str):
        vrange = VersionRange(vrange)

    if not vrange:
        versions = set(supported(impl))
    else:
        minv = Version(major=0, minor=0) if vrange.minver is None else vrange.minver
        maxv = Version(major=99, minor=99) if vrange.maxver is None else vrange.maxver
        if minv == maxv:
            versions = set([minv] if minv in supported(impl) else tuple())
        else:
            versions = set(v for v in supported(impl) if minv <= v < maxv)

    if available is not None:
        # to avoid circular imports
        global Interpreter
        if Interpreter is None:
            from dhpython.interpreter import Interpreter
    if available:
        interpreter = Interpreter(impl=impl)
        versions = set(v for v in versions
                       if exists(interpreter.binary(v)))
    elif available is False:
        interpreter = Interpreter(impl=impl)
        versions = set(v for v in versions
                       if not exists(interpreter.binary(v)))

    return versions


def build_sorted(versions, impl='cpython3'):
    """Return sorted list of versions in a build friendly order.

    i.e. default version, if among versions, is sorted last.

    >>> build_sorted([(2, 6), (3, 4), default('cpython3'), (3, 6), (2, 7)])[-1] == default('cpython3')
    True
    >>> build_sorted(('3.2', (3, 0), '3.1'))
    [Version('3.0'), Version('3.1'), Version('3.2')]
    """
    default_ver = default(impl)

    result = sorted(Version(v) for v in versions)
    try:
        result.remove(default_ver)
    except ValueError:
        pass
    else:
        result.append(default_ver)
    return result
