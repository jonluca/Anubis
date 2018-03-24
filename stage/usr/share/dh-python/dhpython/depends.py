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
from os.path import exists
from dhpython import PKG_PREFIX_MAP, MINPYCDEP
from dhpython.pydist import parse_pydep, guess_dependency
from dhpython.version import default, supported, VersionRange

log = logging.getLogger('dhpython')


class Dependencies:
    """Store relations (dependencies, etc.) between packages."""

    def __init__(self, package, impl='cpython3'):
        self.impl = impl
        self.package = package
        self.is_debug_package = dbgpkg = package.endswith('-dbg')

        # TODO: move it to PyPy and CPython{2,3} classes
        self.ipkg_vtpl = 'python%s-dbg' if dbgpkg else 'python%s'
        if impl == 'cpython3':
            self.ipkg_tpl = 'python3-dbg' if dbgpkg else 'python3'
        elif impl == 'cpython2':
            self.ipkg_tpl = 'python-dbg' if dbgpkg else 'python'
        elif impl == 'pypy':
            self.ipkg_tpl = 'pypy-dbg' if dbgpkg else 'pypy'
            self.ipkg_vtpl = 'pypy%s-dbg' if dbgpkg else 'pypy%s'
        if impl == 'pypy':
            self.ipkg_tpl_ma = self.ipkg_tpl
            self.ipkg_vtpl_ma = self.ipkg_vtpl
        else:
            self.ipkg_tpl_ma = self.ipkg_tpl + ':any'
            self.ipkg_vtpl_ma = self.ipkg_vtpl + ':any'

        self.depends = set()
        self.recommends = []
        self.suggests = []
        self.enhances = []
        self.breaks = []
        self.rtscripts = []

    def export_to(self, dh):
        """Fill in debhelper's substvars."""
        prefix = PKG_PREFIX_MAP.get(self.impl, 'misc')
        for i in sorted(self.depends):
            dh.addsubstvar(self.package, '{}:Depends'.format(prefix), i)
        for i in sorted(self.recommends):
            dh.addsubstvar(self.package, '{}:Recommends'.format(prefix), i)
        for i in sorted(self.suggests):
            dh.addsubstvar(self.package, '{}:Suggests'.format(prefix), i)
        for i in sorted(self.enhances):
            dh.addsubstvar(self.package, '{}:Enhances'.format(prefix), i)
        for i in sorted(self.breaks):
            dh.addsubstvar(self.package, '{}:Breaks'.format(prefix), i)
        for i in sorted(self.rtscripts):
            dh.add_rtupdate(self.package, i)

    def __str__(self):
        return "D=%s; R=%s; S=%s; E=%s, B=%s; RT=%s" %\
            (self.depends, self.recommends, self.suggests,
             self.enhances, self.breaks, self.rtscripts)

    def depend(self, value):
        if value and value not in self.depends:
            self.depends.add(value)

    def recommend(self, value):
        if value and value not in self.recommends:
            self.recommends.append(value)

    def suggest(self, value):
        if value and value not in self.suggests:
            self.suggests.append(value)

    def enhance(self, value):
        if value and value not in self.enhances:
            self.enhances.append(value)

    def break_(self, value):
        if value and value not in self.breaks:
            self.breaks.append(value)

    def rtscript(self, value):
        if value not in self.rtscripts:
            self.rtscripts.append(value)

    def parse(self, stats, options):
        log.debug('generating dependencies for package %s', self.package)
        tpl = self.ipkg_tpl
        vtpl = self.ipkg_vtpl
        tpl_ma = self.ipkg_tpl_ma
        vtpl_ma = self.ipkg_vtpl_ma
        vrange = options.vrange

        if vrange and any((stats['compile'], stats['public_vers'],
                           stats['ext_vers'], stats['ext_no_version'],
                           stats['shebangs'])):
            if any((stats['compile'], stats['public_vers'], stats['shebangs'])):
                tpl_tmp = tpl_ma
            else:
                tpl_tmp = tpl
            minv = vrange.minver
            # note it's an open interval (i.e. do not add 1 here!):
            maxv = vrange.maxver
            if minv == maxv:
                self.depend(vtpl % minv)
                minv = maxv = None
            if minv:
                self.depend("%s (>= %s~)" % (tpl_tmp, minv))
            if maxv:
                self.depend("%s (<< %s)" % (tpl_tmp, maxv))

        if self.impl == 'cpython2' and stats['public_vers']:
            # additional Depends to block python package transitions
            sorted_vers = sorted(stats['public_vers'])
            minv = sorted_vers[0]
            maxv = sorted_vers[-1]
            if minv <= default(self.impl):
                self.depend("%s (>= %s~)" % (tpl_ma, minv))
            if maxv >= default(self.impl):
                self.depend("%s (<< %s)" % (tpl_ma, maxv + 1))

        if self.impl == 'pypy' and stats.get('ext_soabi'):
            # TODO: make sure alternative is used only for the same extension names
            # ie. for foo.ABI1.so, foo.ABI2.so, bar.ABI3,so, bar.ABI4.so generate:
            # pypy-abi-ABI1 | pypy-abi-ABI2, pypy-abi-ABI3 | pypy-abi-ABI4
            self.depend('|'.join(soabi.replace('-', '-abi-')
                                 for soabi in sorted(stats['ext_soabi'])))

        if stats['ext_vers']:
            # TODO: what about extensions with stable ABI?
            sorted_vers = sorted(stats['ext_vers'])
            minv = sorted_vers[0]
            maxv = sorted_vers[-1]
            #self.depend('|'.join(vtpl % i for i in stats['ext_vers']))
            if minv <= default(self.impl):
                self.depend("%s (>= %s~)" % (tpl, minv))
            if maxv >= default(self.impl):
                self.depend("%s (<< %s)" % (tpl, maxv + 1))

        # make sure py{,3}compile binary is available
        if stats['compile'] and self.impl in MINPYCDEP:
            self.depend(MINPYCDEP[self.impl])

        for ipreter in stats['shebangs']:
            self.depend("%s%s" % (ipreter, '' if self.impl == 'pypy' else ':any'))

        supported_versions = supported(self.impl)
        default_version = default(self.impl)
        for private_dir, details in stats['private_dirs'].items():
            versions = list(i.version for i in details.get('shebangs', []) if i.version and i.version.minor)

            for v in versions:
                if v in supported_versions:
                    self.depend(vtpl_ma % v)
                else:
                    log.info('dependency on %s (from shebang) ignored'
                             ' - it\'s not supported anymore', vtpl % v)
            # /usr/bin/python{,3} shebang → add python{,3} to Depends
            if any(True for i in details.get('shebangs', []) if i.version is None):
                self.depend(tpl_ma)

            extensions = sorted(details.get('ext_vers', set()))
            #self.depend('|'.join(vtpl % i for i in extensions))
            if extensions:
                self.depend("%s (>= %s~)" % (tpl, extensions[0]))
                self.depend("%s (<< %s)" % (tpl, extensions[-1] + 1))
            elif details.get('ext_no_version'):
                # assume unrecognized extension was built for default interpreter version
                self.depend("%s (>= %s~)" % (tpl, default_version))
                self.depend("%s (<< %s)" % (tpl, default_version + 1))

            if details.get('compile'):
                if self.impl in MINPYCDEP:
                    self.depend(MINPYCDEP[self.impl])
                args = ''
                if extensions:
                    args += "-V %s" % VersionRange(minver=extensions[0], maxver=extensions[-1])
                elif len(versions) == 1:  # only one version from shebang
                    #if versions[0] in supported_versions:
                    args += "-V %s" % versions[0]
                    # ... otherwise compile with default version
                elif details.get('ext_no_version'):
                    # assume unrecognized extension was built for default interpreter version
                    args += "-V %s" % default_version
                elif vrange:
                    args += "-V %s" % vrange
                    if vrange.minver == vrange.maxver:
                        self.depend(vtpl % vrange.minver)
                    else:
                        if vrange.minver:  # minimum version specified
                            self.depend("%s (>= %s~)" % (tpl_ma, vrange.minver))
                        if vrange.maxver:  # maximum version specified
                            self.depend("%s (<< %s)" % (tpl_ma, vrange.maxver + 1))

                for pattern in options.regexpr or []:
                    args += " -X '%s'" % pattern.replace("'", r"'\''")
                self.rtscript((private_dir, args))

        if options.guess_deps:
            for fn in stats['requires.txt']:
                # TODO: should options.recommends and options.suggests be
                # removed from requires.txt?
                for i in parse_pydep(self.impl, fn):
                    self.depend(i)
            for fpath in stats['egg-info']:
                with open(fpath, 'r', encoding='utf-8') as fp:
                    for line in fp:
                        if line.startswith('Requires: '):
                            req = line[10:].strip()
                            self.depend(guess_dependency(self.impl, req))

        # add dependencies from --depends
        for item in options.depends or []:
            self.depend(guess_dependency(self.impl, item))
        # add dependencies from --recommends
        for item in options.recommends or []:
            self.recommend(guess_dependency(self.impl, item))
        # add dependencies from --suggests
        for item in options.suggests or []:
            self.suggest(guess_dependency(self.impl, item))
        # add dependencies from --requires
        for fn in options.requires or []:
            if not exists(fn):
                log.warn('cannot find requirements file: %s', fn)
                continue
            for i in parse_pydep(self.impl, fn):
                self.depend(i)

        log.debug(self)
