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
import os
import re
from os.path import exists, isdir, join
from subprocess import PIPE, Popen
from dhpython import PKG_PREFIX_MAP, PUBLIC_DIR_RE,\
    PYDIST_DIRS, PYDIST_OVERRIDES_FNAMES, PYDIST_DPKG_SEARCH_TPLS
from dhpython.version import get_requested_versions, Version
from dhpython.tools import memoize

log = logging.getLogger('dhpython')

PYDIST_RE = re.compile(r"""
    (?P<name>[A-Za-z][A-Za-z0-9_.\-]*)             # Python distribution name
    \s*
    (?P<vrange>(?:-?\d\.\d+(?:-(?:\d\.\d+)?)?)?) # version range
    \s*
    (?P<dependency>(?:[a-z][^;]*)?)              # Debian dependency
    (?:  # optional upstream version -> Debian version translator
        ;\s*
        (?P<standard>PEP386)?                    # PEP-386 mode
        \s*
        (?P<rules>(?:s|tr|y).*)?                 # translator rules
    )?
    """, re.VERBOSE)
REQUIRES_RE = re.compile(r'''
    (?P<name>[A-Za-z][A-Za-z0-9_.]*)     # Python distribution name
    \s*
    (?P<enabled_extras>(?:\[[^\]]*\])?)  # ignored for now
    \s*
    \(?  # optional parenthesis
    (?:  # optional minimum/maximum version
        (?P<operator><=?|>=?|==|!=)
        \s*
        (?P<version>(\w|[-.])+)
    )?
    \)?  # optional closing parenthesis
    ''', re.VERBOSE)


def validate(fpath):
    """Check if pydist file looks good."""
    with open(fpath, encoding='utf-8') as fp:
        for line in fp:
            line = line.strip('\r\n')
            if line.startswith('#') or not line:
                continue
            if not PYDIST_RE.match(line):
                log.error('invalid pydist data in file %s: %s',
                          fpath.rsplit('/', 1)[-1], line)
                return False
    return True


@memoize
def load(impl):
    """Load iformation about installed Python distributions.

    :param impl: interpreter implementation, f.e. cpython2, cpython3, pypy
    :type impl: str
    """
    fname = PYDIST_OVERRIDES_FNAMES.get(impl)
    if exists(fname):
        to_check = [fname]  # first one!
    else:
        to_check = []

    dname = PYDIST_DIRS.get(impl)
    if isdir(dname):
        to_check.extend(join(dname, i) for i in os.listdir(dname))

    fbname = '/usr/share/dh-python/dist/{}_fallback'.format(impl)
    if exists(fbname):  # fall back generated at dh-python build time
        to_check.append(fbname)  # last one!

    result = {}
    for fpath in to_check:
        with open(fpath, encoding='utf-8') as fp:
            for line in fp:
                line = line.strip('\r\n')
                if line.startswith('#') or not line:
                    continue
                dist = PYDIST_RE.search(line)
                if not dist:
                    raise Exception('invalid pydist line: %s (in %s)' % (line, fpath))
                dist = dist.groupdict()
                name = safe_name(dist['name'])
                dist['versions'] = get_requested_versions(impl, dist['vrange'])
                dist['dependency'] = dist['dependency'].strip()
                if dist['rules']:
                    dist['rules'] = dist['rules'].split(';')
                else:
                    dist['rules'] = []
                result.setdefault(name, []).append(dist)
    return result


def guess_dependency(impl, req, version=None):
    log.debug('trying to find dependency for %s (python=%s)',
              req, version)
    if isinstance(version, str):
        version = Version(version)

    # some upstreams have weird ideas for distribution name...
    name, rest = re.compile('([^!><= \(\)\[]+)(.*)').match(req).groups()
    # TODO: check stdlib and dist-packaged for name.py and name.so files
    req = safe_name(name) + rest

    data = load(impl)
    req_d = REQUIRES_RE.match(req)
    if not req_d:
        log.info('please ask dh_python3 author to fix REQUIRES_RE '
                 'or your upstream author to fix requires.txt')
        raise Exception('requirement is not valid: %s' % req)
    req_d = req_d.groupdict()
    name = req_d['name']
    details = data.get(name.lower())
    if details:
        for item in details:
            if version and version not in item.get('versions', version):
                # rule doesn't match version, try next one
                continue

            if not item['dependency']:
                return  # this requirement should be ignored
            if item['dependency'].endswith(')'):
                # no need to translate versions if version is hardcoded in
                # Debian dependency
                return item['dependency']
            if req_d['version'] and (item['standard'] or item['rules']) and\
                    req_d['operator'] not in (None, '==', '!='):
                v = _translate(req_d['version'], item['rules'], item['standard'])
                return "%s (%s %s)" % (item['dependency'], req_d['operator'], v)
            else:
                return item['dependency']

    # search for Egg metadata file or directory (using dpkg -S)
    query = PYDIST_DPKG_SEARCH_TPLS[impl].format(ci_regexp(safe_name(name)))

    log.debug("invoking dpkg -S %s", query)
    process = Popen("/usr/bin/dpkg -S %s" % query,
                    shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        result = set()
        stdout = str(stdout, 'utf-8')
        for line in stdout.split('\n'):
            if not line.strip():
                continue
            result.add(line.split(':')[0])
        if len(result) > 1:
            log.error('more than one package name found for %s dist', name)
        else:
            return result.pop()
    else:
        log.debug('dpkg -S did not find package for %s: %s', name, stderr)

    pname = sensible_pname(impl, name)
    log.info('Cannot find package that provides %s. '
             'Please add package that provides it to Build-Depends or '
             'add "%s %s" line to %s or add proper '
             ' dependency to Depends by hand and ignore this info.',
             name, safe_name(name), pname, PYDIST_OVERRIDES_FNAMES[impl])
    # return pname


def parse_pydep(impl, fname):
    public_dir = PUBLIC_DIR_RE[impl].match(fname)
    ver = None
    if public_dir and public_dir.groups() and len(public_dir.group(1)) != 1:
        ver = public_dir.group(1)

    result = []
    modified = optional_section = False
    processed = []
    with open(fname, 'r', encoding='utf-8') as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith('#'):
                processed.append(line)
                continue
            if line.startswith('['):
                optional_section = True
            if optional_section:
                processed.append(line)
                continue
            dependency = guess_dependency(impl, line, ver)
            if dependency:
                result.append(dependency)
                modified = True
            else:
                processed.append(line)
    if modified:
        with open(fname, 'w', encoding='utf-8') as fp:
            fp.writelines(i + '\n' for i in processed)
    return result


def safe_name(name):
    """Emulate distribute's safe_name."""
    return re.compile('[^A-Za-z0-9.]+').sub('_', name).lower()


def sensible_pname(impl, egg_name):
    """Guess Debian package name from Egg name."""
    egg_name = safe_name(egg_name).replace('_', '-')
    if egg_name.startswith('python-'):
        egg_name = egg_name[7:]
    return '{}-{}'.format(PKG_PREFIX_MAP[impl], egg_name.lower())


def ci_regexp(name):
    """Return case insensitive dpkg -S regexp."""
    return ''.join("[%s%s]" % (i.upper(), i) if i.isalpha() else i for i in name.lower())


PRE_VER_RE = re.compile(r'[-.]?(alpha|beta|rc|dev|a|b|c)')
GROUP_RE = re.compile(r'\$(\d+)')


def _pl2py(pattern):
    """Convert Perl RE patterns used in uscan to Python's

    >>> print(_pl2py('foo$3'))
    foo\g<3>
    """
    return GROUP_RE.sub(r'\\g<\1>', pattern)


def _translate(version, rules, standard):
    """Translate Python version into Debian one.

    >>> _translate('1.C2betac', ['s/c//gi'], None)
    '1.2beta'
    >>> _translate('5-fooa1.2beta3-fooD',
    ...     ['s/^/1:/', 's/-foo//g', 's:([A-Z]):+$1:'], 'PEP386')
    '1:5~a1.2~beta3+D'
    >>> _translate('x.y.x.z', ['tr/xy/ab/', 'y,z,Z,'], None)
    'a.b.a.Z'
    """
    for rule in rules:
        # uscan supports s, tr and y operations
        if rule.startswith(('tr', 'y')):
            # Note: no support for escaped separator in the pattern
            pos = 1 if rule.startswith('y') else 2
            tmp = rule[pos + 1:].split(rule[pos])
            version = version.translate(str.maketrans(tmp[0], tmp[1]))
        elif rule.startswith('s'):
            # uscan supports: g, u and x flags
            tmp = rule[2:].split(rule[1])
            pattern = re.compile(tmp[0])
            count = 1
            if tmp[2:]:
                flags = tmp[2]
                if 'g' in flags:
                    count = 0
                if 'i' in flags:
                    pattern = re.compile(tmp[0], re.I)
            version = pattern.sub(_pl2py(tmp[1]), version, count)
        else:
            log.warn('unknown rule ignored: %s', rule)
    if standard == 'PEP386':
        version = PRE_VER_RE.sub(r'~\g<1>', version)
    return version
