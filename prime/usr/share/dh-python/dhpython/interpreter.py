# Copyright © 2012-2013 Piotr Ożarowski <piotr@debian.org>
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
from os.path import join, split
from dhpython import INTERPRETER_DIR_TPLS, PUBLIC_DIR_RE, OLD_SITE_DIRS

SHEBANG_RE = re.compile(r'''
    (?:\#!\s*){0,1}  # shebang prefix
    (?P<path>
        .*?/bin/.*?)?
    (?P<name>
        python|pypy)
    (?P<version>
        \d[\.\d]*)?
    (?P<debug>
        -dbg)?
    (?P<options>.*)
    ''', re.VERBOSE)
EXTFILE_RE = re.compile(r'''
    (?P<name>.*?)
    (?:\.
        (?P<stableabi>abi\d+)
     |(?:\.
        (?P<soabi>
            (?P<impl>cpython|pypy)
            -
            (?P<ver>\d{2})
            (?P<flags>[a-z]*)
        )?
        (?:
            (?:(?<!\.)-)?  # minus sign only if soabi is defined
            (?P<multiarch>[^/]*?)
        )?
    ))?
    (?P<debug>_d)?
    \.so$''', re.VERBOSE)
log = logging.getLogger('dhpython')


class Interpreter:
    """
    :attr path: /usr/bin/ in most cases
    :attr name: pypy or python (even for python3 and python-dbg) or empty string
    :attr version: interpreter's version
    :attr debug: -dbg version of the interpreter
    :attr impl: implementation (cpytho2, cpython3 or pypy)
    :attr options: options parsed from shebang
    :type path: str
    :type name: str
    :type version: Version or None
    :type debug: bool
    :type impl: str
    :type options: tuple
    """
    path = '/usr/bin/'
    name = 'python'
    version = None
    debug = False
    impl = ''
    options = ()
    _cache = {}

    def __init__(self, value=None, path=None, name=None, version=None,
                 debug=None, impl=None, options=None):
        params = locals()
        del params['self']
        del params['value']

        if isinstance(value, Interpreter):
            for key in params.keys():
                if params[key] is None:
                    params[key] = getattr(value, key)
        elif value:
            if value.replace('.', '').isdigit() and not version:
                # version string
                params['version'] = Version(value)
            else:
                # shebang or other string
                for key, val in self.parse(value).items():
                    # prefer values passed to constructor over shebang ones:
                    if params[key] is None:
                        params[key] = val

        for key, val in params.items():
            if val is not None:
                setattr(self, key, val)
            elif key == 'version':
                setattr(self, key, val)

    def __setattr__(self, name, value):
        if name == 'name':
            if value not in ('python', 'pypy', ''):
                raise ValueError("interpreter not supported: %s" % value)
            if value == 'python':
                if self.version:
                    if self.version.major == 3:
                        self.__dict__['impl'] = 'cpython3'
                    else:
                        self.__dict__['impl'] = 'cpython2'
            elif value == 'pypy':
                self.__dict__['impl'] = 'pypy'
        elif name == 'version' and value is not None:
            value = Version(value)
            if not self.impl and self.name == 'python':
                if value.major == 3:
                    self.impl = 'cpython3'
                else:
                    self.impl = 'cpython2'
        if name in ('path', 'name', 'impl', 'options') and value is None:
            pass
        elif name == 'debug':
            self.__dict__[name] = bool(value)
        else:
            self.__dict__[name] = value

    def __repr__(self):
        result = self.path
        if not result.endswith('/'):
            result += '/'
        result += self._vstr(self.version)
        if self.options:
            result += ' ' + ' '.join(self.options)
        return result

    def __str__(self):
        return self._vstr(self.version)

    def _vstr(self, version=None, consider_default_ver=False):
        if self.impl == 'pypy':
            # TODO: will Debian support more than one PyPy version?
            return self.name
        version = version or self.version or ''
        if consider_default_ver and (not version or version == self.default_version):
            version = '3' if self.impl == 'cpython3' else ''
        elif isinstance(version, Version) and version == Version(major=2):
            version = ''  # do not promote /usr/bin/python2
        if self.debug:
            return 'python{}-dbg'.format(version)
        return self.name + str(version)

    def binary(self, version=None):
        return '{}{}'.format(self.path, self._vstr(version))

    @property
    def binary_dv(self):
        """Like binary(), but returns path to default intepreter symlink
        if version matches default one for given implementation.
        """
        return '{}{}'.format(self.path, self._vstr(consider_default_ver=True))

    @property
    def default_version(self):
        if self.impl:
            return default(self.impl)

    @staticmethod
    def parse(shebang):
        """Return dict with parsed shebang

        >>> sorted(Interpreter.parse('/usr/bin/python3.2-dbg').items())
        [('debug', '-dbg'), ('name', 'python'), ('options', ()), ('path', '/usr/bin/'), ('version', '3.2')]
        >>> sorted(Interpreter.parse('#! /usr/bin/python3.2').items())
        [('debug', None), ('name', 'python'), ('options', ()), ('path', '/usr/bin/'), ('version', '3.2')]
        >>> sorted(Interpreter.parse('/usr/bin/python3.2-dbg --foo --bar').items())
        [('debug', '-dbg'), ('name', 'python'), ('options', ('--foo', '--bar')),\
 ('path', '/usr/bin/'), ('version', '3.2')]
        """
        result = SHEBANG_RE.search(shebang)
        if not result:
            return {}
        result = result.groupdict()
        if 'options' in result:
            # TODO: do we need "--key value" here?
            result['options'] = tuple(result['options'].split())
        if result['name'] == 'python' and result['version'] is None:
            result['version'] = '2'
        return result

    @classmethod
    def from_file(cls, fpath):
        """Read file's shebang and parse it."""
        interpreter = Interpreter()
        with open(fpath, 'rb') as fp:
            data = fp.read(96)
            if b"\0" in data:
                raise ValueError('cannot parse binary file')
        # make sure only first line is checkeed
        data = str(data, 'utf-8').split('\n')[0]
        if not data.startswith('#!'):
            raise ValueError("doesn't look like a shebang: %s" % data)

        parsed = cls.parse(data)
        if not parsed:
            raise ValueError("doesn't look like a shebang: %s" % data)
        for key, val in parsed.items():
            setattr(interpreter, key, val)
        return interpreter

    def sitedir(self, package=None, version=None, gdb=False):
        """Return path to site-packages directory.

        Note that returned path is not the final location of .py files

        >>> i = Interpreter('python')
        >>> i.sitedir(version='3.1')
        '/usr/lib/python3/dist-packages/'
        >>> i.sitedir(version='2.5')
        '/usr/lib/python2.5/site-packages/'
        >>> i.sitedir(version=Version('2.7'))
        '/usr/lib/python2.7/dist-packages/'
        >>> i.sitedir(version='3.1', gdb=True, package='python3-foo')
        'debian/python3-foo/usr/lib/debug/usr/lib/python3/dist-packages/'
        >>> i.sitedir(version=Version('3.2'))
        '/usr/lib/python3/dist-packages/'
        """
        try:
            version = Version(version or self.version)
        except Exception as err:
            raise ValueError("cannot find valid version: %s" % err)
        if self.impl == 'pypy':
            path = '/usr/lib/pypy/dist-packages/'
        elif version << Version('2.6'):
            path = "/usr/lib/python%s/site-packages/" % version
        elif version << Version('3.0'):
            path = "/usr/lib/python%s/dist-packages/" % version
        else:
            path = '/usr/lib/python3/dist-packages/'

        if gdb:
            path = "/usr/lib/debug%s" % path
        if package:
            path = "debian/%s%s" % (package, path)

        return path

    def old_sitedirs(self, package=None, version=None, gdb=False):
        """Return deprecated paths to site-packages directories."""
        try:
            version = Version(version or self.version)
        except Exception as err:
            raise ValueError("cannot find valid version: %s" % err)
        result = []
        for item in OLD_SITE_DIRS.get(self.impl, []):
            if isinstance(item, str):
                result.append(item.format(version))
            else:
                res = item(version)
                if res is not None:
                    result.append(res)

        if gdb:
            result = ['/usr/lib/debug{}'.format(i) for i in result]
            if self.impl.startswith('cpython'):
                result.append('/usr/lib/debug/usr/lib/pyshared/python{}'.format(version))
        if package:
            result = ['debian/{}{}'.format(package, i) for i in result]

        return result

    def parse_public_dir(self, path):
        """Return version assigned to site-packages path
        or True is it's unversioned public dir."""
        match = PUBLIC_DIR_RE[self.impl].match(path)
        if match:
            vers = match.groups(0)
            if vers and vers[0]:
                return Version(vers)
            return True

    def should_ignore(self, path):
        """Return True if path is used by another interpreter implementation."""
        cache_key = 'should_ignore_{}'.format(self.impl)
        if cache_key not in self.__class__._cache:
            expr = [v for k, v in INTERPRETER_DIR_TPLS.items() if k != self.impl]
            regexp = re.compile('|'.join('({})'.format(i) for i in expr))
            self.__class__._cache[cache_key] = regexp
        else:
            regexp = self.__class__._cache[cache_key]
        return regexp.search(path)

    def cache_file(self, fpath, version=None):
        """Given path to a .py file, return path to its .pyc/.pyo file.

        This function is inspired by Python 3.2's imp.cache_from_source.

        :param fpath: path to file name
        :param version: Python version

        >>> i = Interpreter('python')
        >>> i.cache_file('foo.py', Version('3.1'))
        'foo.pyc'
        >>> i.cache_file('bar/foo.py', '3.4')
        'bar/__pycache__/foo.cpython-34.pyc'
        """
        version = Version(version or self.version)
        last_char = 'o' if '-O' in self.options else 'c'
        if version <= Version('3.1'):
            return fpath + last_char

        fdir, fname = split(fpath)
        if not fname.endswith('.py'):
            fname += '.py'
        return join(fdir, '__pycache__', "%s.%s.py%s" %
                    (fname[:-3], self.magic_tag(version), last_char))

    def magic_number(self, version=None):
        """Return magic number."""
        version = Version(version or self.version)
        if self.impl == 'cpython2':
            return ''
        result = self._execute('import imp; print(imp.get_magic())', version)
        return eval(result)

    def magic_tag(self, version=None):
        """Return Python magic tag (used in __pycache__ dir to tag files).

        >>> i = Interpreter('python')
        >>> i.magic_tag(version='3.4')
        'cpython-34'
        """
        version = Version(version or self.version)
        if self.impl.startswith('cpython') and version << Version('3.2'):
            return ''
        return self._execute('import imp; print(imp.get_tag())', version)

    def multiarch(self, version=None):
        """Return multiarch tag."""
        version = Version(version or self.version)
        try:
            soabi, multiarch = self._get_config(version)[:2]
        except Exception:
            log.debug('cannot get multiarch', exc_info=True)
            # interpreter without multiarch support
            return ''
        return multiarch

    def stableabi(self, version=None):
        version = Version(version or self.version)
        # stable ABI was introduced in Python 3.3
        if self.impl == 'cpython3' and version >> Version('3.2'):
            return 'abi{}'.format(version.major)

    def soabi(self, version=None):
        """Return SOABI flag (used to in .so files)."""
        version = Version(version or self.version)
        # NOTE: it's not the same as magic_tag
        try:
            soabi, multiarch = self._get_config(version)[:2]
        except Exception:
            log.debug('cannot get soabi', exc_info=True)
            # interpreter without soabi support
            return ''
        return soabi

    @property
    def include_dir(self):
        """Return INCLUDE_DIR path.

        >>> Interpreter('python2.7').include_dir
        '/usr/include/python2.7'
        >>> Interpreter('python3.4-dbg').include_dir
        '/usr/include/python3.4dm'
        """
        if self.impl == 'pypy':
            return '/usr/lib/pypy/include'
        try:
            result = self._get_config()[2]
            if result:
                return result
        except Exception:
            result = ''
            log.debug('cannot get include path', exc_info=True)
        result = '/usr/include/{}'.format(self.name)
        version = self.version
        if self.debug:
            if version << '3.3':
                result += '_d'
            else:
                result += 'dm'
        else:
            if version >> '3.2':
                result += 'm'
            elif version == '3.2':
                result += 'mu'
        return result

    @property
    def library_file(self):
        """Return libfoo.so file path."""
        if self.impl == 'pypy':
            return ''
        libpl, ldlibrary = self._get_config()[3:5]
        if ldlibrary.endswith('.a'):
            # python3.1-dbg, python3.2, python3.2-dbg returned static lib
            ldlibrary = ldlibrary.replace('.a', '.so')
        if libpl and ldlibrary:
            return join(libpl, ldlibrary)
        raise Exception('cannot find library file for {}'.format(self))

    def check_extname(self, fname, version=None):
        """Return extension file name if file can be renamed."""
        if not version and not self.version:
            return

        version = Version(version or self.version)

        if '/' in fname:
            fdir, fname = fname.rsplit('/', 1)  # in case full path was passed
        else:
            fdir = ''

        info = EXTFILE_RE.search(fname)
        if not info:
            return
        info = info.groupdict()
        if info['ver'] and (not version or version.minor is None):
            # get version from soabi if version is not set of only major
            # version number is set
            version = Version("%s.%s" % (info['ver'][0], info['ver'][1]))

        if info['stableabi']:
            # files with stable ABI in name don't need changes
            return
        if info['debug'] and self.debug is False:
            # do not change Python 2.X extensions already marked as debug
            # (the other way arround is acceptable)
            return
        if info['soabi'] and info['multiarch']:
            # already tagged, nothing we can do here
            return

        try:
            soabi, multiarch = self._get_config(version)[:2]
        except Exception:
            log.debug('cannot get soabi/multiarch', exc_info=True)
            return

        if info['soabi'] and soabi and info['soabi'] != soabi:
            return

        tmp_soabi = info['soabi'] or soabi
        tmp_multiarch = info['multiarch'] or multiarch

        result = info['name']
        if result.endswith('module') and (self.impl == 'cpython3' and version >> '3.2'
                                          or self.impl == 'cpython2' and version == '2.7'):
            result = result[:-6]

        if tmp_soabi:
            result = "{}.{}".format(result, tmp_soabi)
            if tmp_multiarch and not (self.impl == 'cpython3' and version << '3.3') and tmp_multiarch not in soabi:
                result = "{}-{}".format(result, tmp_multiarch)
        elif self.impl == 'cpython2' and version == '2.7' and tmp_multiarch:
            result = "{}.{}".format(result, tmp_multiarch)

        if self.debug and self.impl == 'cpython2':
            result += '_d'
        result += '.so'
        if fname == result:
            return
        return join(fdir, result)

    def suggest_pkg_name(self, name):
        """Suggest binary package name with for given library name

        >>> Interpreter('python3.1').suggest_pkg_name('foo')
        'python3-foo'
        >>> Interpreter('python3.4').suggest_pkg_name('foo')
        'python3-foo'
        >>> Interpreter('python2.7-dbg').suggest_pkg_name('bar')
        'python-bar-dbg'
        """
        if self.impl == 'pypy':
            return 'pypy-{}'.format(name)
        version = '3' if self.impl == 'cpython3' else ''
        result = 'python{}-{}'.format(version, name)
        if self.debug:
            result += '-dbg'
        return result

    def _get_config(self, version=None):
        version = Version(version or self.version)
        # sysconfig module is available since Python 3.2
        # (also backported to Python 2.7)
        if self.impl == 'pypy' or self.impl.startswith('cpython') and (
                version >> '2.6' and version << '3'
                or version >> '3.1' or version == '3'):
            cmd = 'import sysconfig as s;'
        else:
            cmd = 'from distutils import sysconfig as s;'
        cmd += 'print("__SEP__".join(i or "" ' \
               'for i in s.get_config_vars('\
               '"SOABI", "MULTIARCH", "INCLUDEPY", "LIBPL", "LDLIBRARY")))'
        conf_vars = self._execute(cmd, version).split('__SEP__')
        if conf_vars[1] in conf_vars[0]:
            # Python >= 3.5 includes MILTIARCH in SOABI
            conf_vars[0] = conf_vars[0].replace("-%s" % conf_vars[1], '')
        try:
            conf_vars[1] = os.environ['DEB_HOST_MULTIARCH']
        except KeyError:
            pass
        return conf_vars

    def _execute(self, command, version=None, cache=True):
        version = Version(version or self.version)
        command = "{} -c '{}'".format(self._vstr(version), command.replace("'", "\'"))
        if cache and command in self.__class__._cache:
            return self.__class__._cache[command]

        output = execute(command)
        if output['returncode'] != 0:
            log.debug(output['stderr'])
            raise Exception('{} failed with status code {}'.format(command, output['returncode']))

        result = output['stdout'].splitlines()

        if len(result) == 1:
            result = result[0]

        if cache:
            self.__class__._cache[command] = result

        return result

# due to circular imports issue
from dhpython.tools import execute
from dhpython.version import Version, default
