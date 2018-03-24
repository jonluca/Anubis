# -*- coding: UTF-8 -*-
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
from datetime import datetime
from glob import glob
from pickle import dumps
from shutil import rmtree
from os.path import exists, getsize, isdir, islink, join, split
from subprocess import Popen, PIPE

log = logging.getLogger('dhpython')
EGGnPTH_RE = re.compile(r'(.*?)(-py\d\.\d(?:-[^.]*)?)?(\.egg-info|\.pth)$')
SHAREDLIB_RE = re.compile(r'NEEDED.*libpython(\d\.\d)')


def relpath(target, link):
    """Return relative path.

    >>> relpath('/usr/share/python-foo/foo.py', '/usr/bin/foo', )
    '../share/python-foo/foo.py'
    """
    t = target.split('/')
    l = link.split('/')
    while l and l[0] == t[0]:
        del l[0], t[0]
    return '/'.join(['..'] * (len(l) - 1) + t)


def relative_symlink(target, link):
    """Create relative symlink."""
    return os.symlink(relpath(target, link), link)


def move_file(fpath, dstdir):
    """Move file to dstdir. Works with symlinks (including relative ones)."""
    if isdir(fpath):
        dname = split(fpath)[-1]
        for fn in os.listdir(fpath):
            move_file(join(fpath, fn), join(dstdir, dname))

    if islink(fpath):
        dstpath = join(dstdir, split(fpath)[-1])
        relative_symlink(os.readlink(fpath), dstpath)
        os.remove(fpath)
    else:
        os.rename(fpath, dstdir)


def move_matching_files(src, dst, pattern):
    """Move files (preserving path) that match given pattern.

    move_matching_files('foo/bar/', 'foo/baz/', 'spam/.*\.so$')
    will move foo/bar/a/b/c/spam/file.so to foo/baz/a/b/c/spam/file.so
    """
    match = re.compile(pattern).search
    for root, dirs, filenames in os.walk(src):
        for fn in filenames:
            spath = join(root, fn)
            if match(spath):
                dpath = join(dst, relpath(spath, src))
                os.renames(spath, dpath)


def fix_shebang(fpath, replacement=None):
    """Normalize file's shebang.

    :param replacement: new shebang command (path to interpreter and options)
    """
    try:
        interpreter = Interpreter.from_file(fpath)
    except Exception as err:
        log.debug('fix_shebang (%s): %s', fpath, err)
        return None

    if not replacement and interpreter.path != '/usr/bin/':  # f.e. /usr/local/* or */bin/env
        interpreter.path = '/usr/bin'
        replacement = repr(interpreter)
    if replacement:
        log.info('replacing shebang in %s', fpath)
        try:
            with open(fpath, 'rb') as fp:
                fcontent = fp.readlines()
        except IOError:
            log.error('cannot open %s', fpath)
            return False
        # do not catch IOError here, the file is zeroed at this stage so it's
        # better to fail
        with open(fpath, 'wb') as fp:
            fp.write(("#! %s\n" % replacement).encode('utf-8'))
            fp.writelines(fcontent[1:])
    return True


def so2pyver(fpath):
    """Return libpython version file is linked to or None.

    :rtype: tuple
    :returns: Python version
    """

    cmd = "readelf -Wd '%s'" % fpath
    process = Popen(cmd, stdout=PIPE, shell=True)
    match = SHAREDLIB_RE.search(str(process.stdout.read(), encoding='utf-8'))
    if match:
        return Version(match.groups()[0])


def clean_egg_name(name):
    """Remove Python version and platform name from Egg files/dirs.

    >>> clean_egg_name('python_pipeline-0.1.3_py3k-py3.1.egg-info')
    'python_pipeline-0.1.3_py3k.egg-info'
    >>> clean_egg_name('Foo-1.2-py2.7-linux-x86_64.egg-info')
    'Foo-1.2.egg-info'
    """
    match = EGGnPTH_RE.match(name)
    if match and match.group(2) is not None:
        return ''.join(match.group(1, 3))
    return name


def parse_ns(fpaths, other=None):
    """Parse namespace_packages.txt files."""
    result = set(other or [])
    for fpath in fpaths:
        with open(fpath, 'r', encoding='utf-8') as fp:
            for line in fp:
                if line:
                    result.add(line.strip())
    return result


def remove_ns(interpreter, package, namespaces, versions):
    """Remove empty __init__.py files for requested namespaces."""
    if not isinstance(namespaces, set):
        namespaces = set(namespaces)
    keep = set()
    for ns in namespaces:
        for version in versions:
            fpath = join(interpreter.sitedir(package, version), *ns.split('.'))
            fpath = join(fpath, '__init__.py')
            if not exists(fpath):
                continue
            if getsize(fpath) != 0:
                log.warning('file not empty, cannot share %s namespace', ns)
                keep.add(ns)
                break

    # return a set of namespaces that should be handled by pycompile/pyclean
    result = namespaces - keep

    # remove empty __init__.py files, if available
    for ns in result:
        for version in versions:
            dpath = join(interpreter.sitedir(package, version), *ns.split('.'))
            fpath = join(dpath, '__init__.py')
            if exists(fpath):
                os.remove(fpath)
                if not os.listdir(dpath):
                    os.rmdir(dpath)
        # clean pyshared dir as well
        dpath = join('debian', package, 'usr/share/pyshared', *ns.split('.'))
        fpath = join(dpath, '__init__.py')
        if exists(fpath):
            os.remove(fpath)
            if not os.listdir(dpath):
                os.rmdir(dpath)
    return result


def execute(command, cwd=None, env=None, log_output=None, shell=True):
    """Execute external shell commad.

    :param cdw: currennt working directory
    :param env: environment
    :param log_output:
        * opened log file or path to this file, or
        * None if output should be included in the returned dict, or
        * False if output should be redirectored to stdout/stderr
    """
    args = {'shell': shell, 'cwd': cwd, 'env': env}
    close = False
    if log_output is False:
        pass
    elif log_output is None:
        args.update(stdout=PIPE, stderr=PIPE)
    elif log_output:
        if isinstance(log_output, str):
            close = True
            log_output = open(log_output, 'a', encoding='utf-8')
        log_output.write('\n# command executed on {}'.format(datetime.now().isoformat()))
        log_output.write('\n$ {}\n'.format(command))
        log_output.flush()
        args.update(stdout=log_output, stderr=log_output)

    log.debug('invoking: %s', command)
    with Popen(command, **args) as process:
        stdout, stderr = process.communicate()
        close and log_output.close()
        return dict(returncode=process.returncode,
                    stdout=stdout and str(stdout, 'utf-8'),
                    stderr=stderr and str(stderr, 'utf-8'))


class memoize:
    def __init__(self, func):
        self.func = func
        self.cache = {}

    def __call__(self, *args, **kwargs):
        key = dumps((args, kwargs))
        if key not in self.cache:
            self.cache[key] = self.func(*args, **kwargs)
        return self.cache[key]


def pyinstall(interpreter, package, vrange):
    """Install local files listed in pkg.pyinstall files as public modules."""
    srcfpath = "./debian/%s.pyinstall" % package
    if not exists(srcfpath):
        return
    impl = interpreter.impl
    versions = get_requested_versions(impl, vrange)

    for line in open(srcfpath, encoding='utf-8'):
        if not line or line.startswith('#'):
            continue
        details = INSTALL_RE.match(line)
        if not details:
            raise ValueError("unrecognized line: %s" % line)
        details = details.groupdict()
        if details['module']:
            details['module'] = details['module'].replace('.', '/')
        myvers = versions & get_requested_versions(impl, details['vrange'])
        if not myvers:
            log.debug('%s.pyinstall: no matching versions for line %s',
                      package, line)
            continue
        files = glob(details['pattern'])
        if not files:
            raise ValueError("missing file(s): %s" % details['pattern'])
        for fpath in files:
            fpath = fpath.lstrip('/.')
            if details['module']:
                dstname = join(details['module'], split(fpath)[1])
            elif fpath.startswith('debian/'):
                dstname = fpath[7:]
            else:
                dstname = fpath
            for version in myvers:
                dstfpath = join(interpreter.sitedir(package, version), dstname)
                dstdir = split(dstfpath)[0]
                if not exists(dstdir):
                    os.makedirs(dstdir)
                if exists(dstfpath):
                    os.remove(dstfpath)
                os.link(fpath, dstfpath)


def pyremove(interpreter, package, vrange):
    """Remove public modules listed in pkg.pyremove file."""
    srcfpath = "./debian/%s.pyremove" % package
    if not exists(srcfpath):
        return
    impl = interpreter.impl
    versions = get_requested_versions(impl, vrange)

    for line in open(srcfpath, encoding='utf-8'):
        if not line or line.startswith('#'):
            continue
        details = REMOVE_RE.match(line)
        if not details:
            raise ValueError("unrecognized line: %s: %s" % (package, line))
        details = details.groupdict()
        myvers = versions & get_requested_versions(impl, details['vrange'])
        if not myvers:
            log.debug('%s.pyremove: no matching versions for line %s',
                      package, line)
        for version in myvers:
            site_dirs = interpreter.old_sitedirs(package, version)
            site_dirs.append(interpreter.sitedir(package, version))
            for sdir in site_dirs:
                files = glob(sdir + '/' + details['pattern'])
                for fpath in files:
                    if isdir(fpath):
                        rmtree(fpath)
                    else:
                        os.remove(fpath)

from dhpython.interpreter import Interpreter
from dhpython.version import Version, get_requested_versions, RANGE_PATTERN
INSTALL_RE = re.compile(r"""
    (?P<pattern>.+?)  # file pattern
    (?:\s+  # optional Python module name:
    (?P<module>[A-Za-z][A-Za-z0-9_.]*)?
    )?
    \s*  # optional version range:
    (?P<vrange>%s)?$
""" % RANGE_PATTERN, re.VERBOSE)
REMOVE_RE = re.compile(r"""
    (?P<pattern>.+?)  # file pattern
    \s*  # optional version range:
    (?P<vrange>%s)?$
""" % RANGE_PATTERN, re.VERBOSE)
