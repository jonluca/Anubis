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
from os import makedirs, chmod
from os.path import exists, join, dirname
from dhpython import DEPENDS_SUBSTVARS, PKG_NAME_TPLS, RT_LOCATIONS, RT_TPLS

log = logging.getLogger('dhpython')


class DebHelper:
    """Reinvents the wheel / some dh functionality (Perl is ugly ;-P)"""

    def __init__(self, options, impl='cpython3'):
        self.options = options
        self.packages = {}
        self.python_version = None
        source_section = True
        binary_package = None
        # Note that each DebHelper instance supports ONE interpreter type only
        # it's not possible to mix cpython2, cpython3 and pypy here
        self.impl = impl
        skip_tpl = set()
        for name, tpls in PKG_NAME_TPLS.items():
            if name != impl:
                skip_tpl.update(tpls)
        skip_tpl = tuple(skip_tpl)
        substvar = DEPENDS_SUBSTVARS[impl]

        pkgs = options.package
        skip_pkgs = options.no_package

        try:
            fp = open('debian/control', 'r', encoding='utf-8')
        except IOError:
            raise Exception('cannot find debian/control file')

        for line in fp:
            if line.startswith('#'):
                continue
            if not line.strip():
                source_section = False
                binary_package = None
                inside_depends_field = False
                continue
            line_l = line.lower()  # field names are case-insensitive
            if binary_package:
                if binary_package not in self.packages:
                    continue
                if line_l.startswith('architecture:'):
                    arch = line[13:].strip()
                    # TODO: if arch doesn't match current architecture:
                    #del self.packages[binary_package]
                    self.packages[binary_package]['arch'] = arch
                    continue
                if not binary_package.startswith(PKG_NAME_TPLS[impl]):
                    # package doesn't have common prefix (python-, python3-, pypy-)
                    # so lets check if Depends contains appropriate substvar
                    if line_l.startswith('depends:'):
                        if substvar in line:
                            continue
                        inside_depends_field = True
                    elif inside_depends_field:  # multiline continuation
                        if not line.startswith((' ', '\t')):
                            inside_depends_field = False
                            log.debug('skipping package %s (missing %s in Depends)',
                                      binary_package, substvar)
                            del self.packages[binary_package]
                        elif substvar in line:
                            inside_depends_field = None
            elif line_l.startswith('package:'):
                binary_package = line[8:].strip()
                if skip_tpl and binary_package.startswith(skip_tpl):
                    log.debug('skipping package: %s', binary_package)
                    continue
                if pkgs and binary_package not in pkgs:
                    continue
                if skip_pkgs and binary_package in skip_pkgs:
                    continue
                self.packages[binary_package] = {'substvars': {},
                                                 'autoscripts': {},
                                                 'rtupdates': [],
                                                 'arch': 'any'}
            elif line_l.startswith('source:'):
                self.source_name = line[7:].strip()
            elif source_section and self.impl == 'cpython3' and line_l.startswith('x-python3-version:'):
                self.python_version = line[18:]
                if len(self.python_version.split(',')) > 2:
                    raise ValueError('too many arguments provided for X-Python3-Version: min and max only.')
            elif source_section and self.impl == 'cpython2':
                if line_l.startswith('xs-python-version:'):
                    if not self.python_version:
                        self.python_version = line[18:].strip()
                if line_l.startswith('x-python-version:'):
                    self.python_version = line[17:].strip()

        fp.close()
        log.debug('source=%s, binary packages=%s', self.source_name,
                  list(self.packages.keys()))

    def addsubstvar(self, package, name, value):
        """debhelper's addsubstvar"""
        self.packages[package]['substvars'].setdefault(name, []).append(value)

    def autoscript(self, package, when, template, args):
        """debhelper's autoscript"""
        self.packages[package]['autoscripts'].setdefault(when, {})\
            .setdefault(template, []).append(args)

    def add_rtupdate(self, package, value):
        self.packages[package]['rtupdates'].append(value)

    def save_autoscripts(self):
        for package, settings in self.packages.items():
            autoscripts = settings.get('autoscripts')
            if not autoscripts:
                continue

            for when, templates in autoscripts.items():
                fn = "debian/%s.%s.debhelper" % (package, when)
                if exists(fn):
                    with open(fn, 'r', encoding='utf-8') as datafile:
                        data = datafile.read()
                else:
                    data = ''

                new_data = ''
                for tpl_name, args in templates.items():
                    for i in args:
                        # try local one first (useful while testing dh_python3)
                        fpath = join(dirname(__file__), '..',
                                     "autoscripts/%s" % tpl_name)
                        if not exists(fpath):
                            fpath = "/usr/share/debhelper/autoscripts/%s" % tpl_name
                        with open(fpath, 'r', encoding='utf-8') as tplfile:
                            tpl = tplfile.read()
                        if self.options.compile_all and args:
                            # TODO: should args be checked to contain dir name?
                            tpl = tpl.replace('-p #PACKAGE#', '')
                        else:
                            tpl = tpl.replace('#PACKAGE#', package)
                        tpl = tpl.replace('#ARGS#', i)
                        if tpl not in data and tpl not in new_data:
                            new_data += "\n%s" % tpl
                if new_data:
                    data += '\n# Automatically added by dhpython:' +\
                            '{}\n# End automatically added section\n'.format(new_data)
                    fp = open(fn, 'w', encoding='utf-8')
                    fp.write(data)
                    fp.close()

    def save_substvars(self):
        for package, settings in self.packages.items():
            substvars = settings.get('substvars')
            if not substvars:
                continue
            fn = "debian/%s.substvars" % package
            if exists(fn):
                with open(fn, 'r', encoding='utf-8') as datafile:
                    data = datafile.read()
            else:
                data = ''
            for name, values in substvars.items():
                p = data.find("%s=" % name)
                if p > -1:  # parse the line and remove it from data
                    e = data[p:].find('\n')
                    line = data[p + len("%s=" % name):
                                p + e if e > -1 else None]
                    items = [i.strip() for i in line.split(',') if i]
                    if e > -1 and data[p + e:].strip():
                        data = "%s\n%s" % (data[:p], data[p + e:])
                    else:
                        data = data[:p]
                else:
                    items = []
                for j in values:
                    if j not in items:
                        items.append(j)
                if items:
                    if data:
                        data += '\n'
                    data += "%s=%s\n" % (name, ', '.join(items))
            data = data.replace('\n\n', '\n')
            if data:
                fp = open(fn, 'w', encoding='utf-8')
                fp.write(data)
                fp.close()

    def save_rtupdate(self):
        for package, settings in self.packages.items():
            pkg_arg = '' if self.options.compile_all else "-p %s" % package
            values = settings.get('rtupdates')
            if not values:
                continue
            d = 'debian/{}/{}'.format(package, RT_LOCATIONS[self.impl])
            if not exists(d):
                makedirs(d)
            fn = "%s/%s.rtupdate" % (d, package)
            if exists(fn):
                data = open(fn, 'r', encoding='utf-8').read()
            else:
                data = "#! /bin/sh\nset -e"
            for dname, args in values:
                cmd = RT_TPLS[self.impl].format(pkg_arg=pkg_arg,
                                                dname=dname,
                                                args=args)
                if cmd not in data:
                    data += "\n%s" % cmd
            if data:
                fp = open(fn, 'w', encoding='utf-8')
                fp.write(data)
                fp.close()
                chmod(fn, 0o755)

    def save(self):
        self.save_substvars()
        self.save_autoscripts()
        self.save_rtupdate()
