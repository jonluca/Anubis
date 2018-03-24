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

import re

PKG_PREFIX_MAP = {'cpython2': 'python',
                  'cpython3': 'python3',
                  'pypy': 'pypy'}

# minimum version required for compile/clean scripts:
MINPYCDEP = {'cpython2': 'python:any (>= 2.7.5-5~)',
             'cpython3': 'python3:any (>= 3.3.2-2~)',
             'pypy': 'pypy'}

PUBLIC_DIR_RE = {
    'cpython2': re.compile(r'.*?/usr/lib/python(2\.\d)(?:/|$)'),
    'cpython3': re.compile(r'.*?/usr/lib/python(3(?:\.\d+)?)(?:/|$)'),
    'pypy': re.compile(r'.*?/usr/lib/pypy(?:/|$)')}

INTERPRETER_DIR_TPLS = {
    'cpython2': r'.*/python2\.\d/',
    'cpython3': r'.*/python3(?:\.\d+)?/',
    'pypy': r'.*/pypy/'}

MULTIARCH_DIR_TPL = re.compile(
    '.*/([a-z][^/-]+-(?:linux|kfreebsd|gnu)(?:-[^/-]+)?)(?:/.*|$)')

# Interpreter site-directories
OLD_SITE_DIRS = {
    'cpython2': [
        '/usr/local/lib/python{}/site-packages',
        '/usr/local/lib/python{}/dist-packages',
        '/var/lib/python-support/python{}',
        '/usr/lib/pymodules/python{}',
        lambda version: '/usr/lib/python{}/site-packages'.format(version)
                        if version >= '2.6' else None],
    'cpython3': [
        '/usr/local/lib/python{}/site-packages',
        '/usr/local/lib/python{}/dist-packages',
        '/usr/lib/python{}/site-packages',
        '/usr/lib/python{}/dist-packages',
        '/var/lib/python-support/python{}',
        '/usr/lib/pymodules/python{}'],
    'pypy': [
        '/usr/local/lib/pypy/site-packages',
        '/usr/local/lib/pypy/dist-packages',
        '/usr/lib/pypy/site-packages']}

# PyDist related
PYDIST_DIRS = {
    'cpython2': '/usr/share/python/dist/',
    'cpython3': '/usr/share/python3/dist/',
    'pypy': '/usr/share/pypy/dist/'}

PYDIST_OVERRIDES_FNAMES = {
    'cpython2': 'debian/pydist-overrides',
    'cpython3': 'debian/py3dist-overrides',
    'pypy': 'debian/pypydist-overrides'}

PYDIST_DPKG_SEARCH_TPLS = {
    'cpython2': "*/{}-?*\.egg-info | grep '/python2\../\|/pyshared/'",
    'cpython3': '*python3/*/{}-?*\.egg-info',
    'pypy': '*pypy/*/{}-?\.egg-info'}

# DebHelper related
DEPENDS_SUBSTVARS = {
    'cpython2': '${python:Depends}',
    'cpython3': '${python3:Depends}',
    'pypy': '${pypy:Depends}',
}
PKG_NAME_TPLS = {
    'cpython2': ('python-', 'python2.'),
    'cpython3': ('python3-', 'python3.'),
    'pypy': ('pypy-',)
}
RT_LOCATIONS = {
    'cpython2': '/usr/share/python/runtime.d/',
    'cpython3': '/usr/share/python3/runtime.d/',
    'pypy': '/usr/share/pypy/runtime.d/',
}
RT_TPLS = {
    'cpython2': '''
if [ "$1" = rtupdate ]; then
\tpyclean {pkg_arg} {dname}
\tpycompile {pkg_arg} {args} {dname}
fi''',
    'cpython3': '''
if [ "$1" = rtupdate ]; then
\tpy3clean {pkg_arg} {dname}
\tpy3compile {pkg_arg} {args} {dname}
fi''',
    'pypy': ''
}
