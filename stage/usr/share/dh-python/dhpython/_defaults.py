#!/usr/bin/env python3
# Copyright © 2013 Piotr Ożarowski <piotr@debian.org>
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
from configparser import ConfigParser
from os import environ
from os.path import exists
from subprocess import Popen, PIPE

SUPPORTED = {
    'cpython2': [(2, 7)],
    'cpython3': [(3, 4), (3, 5)],
    'pypy': [(4, 0)]}
DEFAULT = {
    'cpython2': (2, 7),
    'cpython3': (3, 4),
    'pypy': (4, 0)}

log = logging.getLogger('dhpython')


def cpython_versions(major):
    result = [None, None]
    ver = '' if major == 2 else '3'
    supported = environ.get("DEBPYTHON{}_SUPPORTED".format(ver))
    default = environ.get("DEBPYTHON{}_DEFAULT".format(ver))
    if not supported or not default:
        config = ConfigParser()
        config.read("/usr/share/python{}/debian_defaults".format(ver))
        if not default:
            default = config.get('DEFAULT', 'default-version', fallback='')[6:]
        if not supported:
            supported = config.get('DEFAULT', 'supported-versions', fallback='')\
                .replace('python', '')
    if default:
        try:
            result[0] = tuple(int(i) for i in default.split('.'))
        except Exception as err:
            log.warn('invalid debian_defaults file: %s', err)
    if supported:
        try:
            result[1] = tuple(tuple(int(j) for j in i.strip().split('.'))
                              for i in supported.split(','))
        except Exception as err:
            log.warn('invalid debian_defaults file: %s', err)
    return result


def from_file(fpath):
    if not exists(fpath):
        raise ValueError("missing interpreter: %s" % fpath)
    command = "{} --version".format(fpath)
    with Popen(command, shell=True, stdout=PIPE) as process:
        stdout, stderr = process.communicate()
        stdout = str(stdout, 'utf-8')

    print(stdout)


cpython2 = cpython_versions(2)
cpython3 = cpython_versions(3)
if cpython2[0]:
    DEFAULT['cpython2'] = cpython2[0]
if cpython3[0]:
    DEFAULT['cpython3'] = cpython3[0]
if cpython2[1]:
    SUPPORTED['cpython2'] = cpython2[1]
if cpython3[1]:
    SUPPORTED['cpython3'] = cpython3[1]
#from_file('/usr/bin/pypy')


if __name__ == '__main__':
    from sys import argv, stderr
    if len(argv) != 3:
        print('invalid number of arguments', file=stderr)
        exit(1)
    if argv[1] == 'default':
        print('.'.join(str(i) for i in DEFAULT[argv[2]]))
    elif argv[1] == 'supported':
        print(','.join(('.'.join(str(i) for i in v) for v in SUPPORTED[argv[2]])))
