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
import os
import re
from filecmp import cmp as cmpfile
from os.path import exists, dirname, isdir, islink, join, split, splitext
from shutil import rmtree
from stat import ST_MODE, S_IXUSR, S_IXGRP, S_IXOTH
from dhpython import MULTIARCH_DIR_TPL
from dhpython.tools import fix_shebang, clean_egg_name
from dhpython.interpreter import Interpreter

log = logging.getLogger('dhpython')


def fix_locations(package, interpreter, versions, options):
    """Move files to the right location."""
    # make a copy since we change version later
    interpreter = Interpreter(interpreter)

    for version in versions:
        interpreter.version = version

        dstdir = interpreter.sitedir(package)
        for srcdir in interpreter.old_sitedirs(package):
            if isdir(srcdir):
                # TODO: what about relative symlinks?
                log.debug('moving files from %s to %s', srcdir, dstdir)
                share_files(srcdir, dstdir, interpreter, options)
                parent_dir = '/'.join(srcdir.split('/')[:-1])
                while parent_dir:
                    if exists(parent_dir):
                        if os.listdir(parent_dir):
                            break
                        os.rmdir(parent_dir)
                    parent_dir = dirname(parent_dir)

        # do the same with debug locations
        dstdir = interpreter.sitedir(package, gdb=True)
        for srcdir in interpreter.old_sitedirs(package, gdb=True):
            if isdir(srcdir):
                log.debug('moving files from %s to %s', srcdir, dstdir)
                share_files(srcdir, dstdir, interpreter, options)
                parent_dir = '/'.join(srcdir.split('/')[:-1])
                while parent_dir:
                    if exists(parent_dir):
                        if os.listdir(parent_dir):
                            break
                        os.rmdir(parent_dir)
                    parent_dir = dirname(parent_dir)


def share_files(srcdir, dstdir, interpreter, options):
    """Try to move as many files from srcdir to dstdir as possible."""
    for i in os.listdir(srcdir):
        fpath1 = join(srcdir, i)
        if not options.no_ext_rename and splitext(i)[-1] == '.so':
            # try to rename extension here as well (in :meth:`scan` info about
            # Python version is gone)
            version = interpreter.parse_public_dir(srcdir)
            # if version is True it means it's unversioned dist-packages dir
            if version and version is not True:
                # note that if ver is empty, default Python version will be used
                fpath1_orig = fpath1
                new_name = interpreter.check_extname(i, version)
                if new_name:
                    fpath1 = join(srcdir, new_name)
                    if exists(fpath1):
                        log.warn('destination file exist, '
                                 'cannot rename %s to %s', fpath1_orig, fpath1)
                    else:
                        log.info('renaming %s to %s', fpath1_orig, fpath1)
                        os.renames(fpath1_orig, fpath1)
                        i = new_name
        fpath2 = join(dstdir, i)
        if not isdir(fpath1) and not exists(fpath2):
            # do not rename directories here - all .so files have to be renamed first
            os.renames(fpath1, fpath2)
            continue
        if isdir(fpath1):
            share_files(fpath1, fpath2, interpreter, options)
        elif cmpfile(fpath1, fpath2, shallow=False):
            os.remove(fpath1)
        # XXX: check symlinks

    if exists(srcdir) and not os.listdir(srcdir):
        os.rmdir(srcdir)


class Scan:
    UNWANTED_DIRS = re.compile(r'.*/__pycache__(/.*)?$')
    UNWANTED_FILES = re.compile(r'.*\.py[co]$')

    def __init__(self, interpreter, package, dpath=None, options=None):
        self.interpreter = interpreter
        self.impl = interpreter.impl

        self.package = package

        if not dpath:
            self.proot = "debian/%s" % self.package
        else:
            dpath = dpath.strip('/')
            self.proot = join('debian', self.package, dpath)
        self.dpath = dpath
        del dpath

        self.options = options
        self.result = {'requires.txt': set(),
                       'egg-info': set(),
                       'nsp.txt': set(),
                       'shebangs': set(),
                       'public_vers': set(),
                       'private_dirs': {},
                       'compile': False,
                       'ext_vers': set(),
                       'ext_no_version': set()}

        for root, dirs, file_names in os.walk(self.proot):
            if interpreter.should_ignore(root):
                del dirs[:]
                continue

            self.current_private_dir = self.current_pub_version = None
            version = interpreter.parse_public_dir(root)
            if version:
                self.current_dir_is_public = True
                if version is True:
                    version = None
                else:
                    self.current_pub_version = version
            else:
                self.current_dir_is_public = False

            if self.current_dir_is_public:
                if root.endswith('-packages'):
                    if version is not None:
                        self.result['public_vers'].add(version)
                    for name in ('test', 'tests'):
                        if name in dirs:
                            log.debug('removing dist-packages/%s (too common name)', name)
                            rmtree(join(root, name))
                            dirs.remove(name)
            else:
                self.current_private_dir = self.check_private_dir(root)
                if not self.current_private_dir:
                    # i.e. not a public dir and not a private dir
                    is_bin_dir = self.is_bin_dir(root)
                    if is_bin_dir:
                        self.handle_bin_dir(root, file_names)
                    else:  # not a public, private or bin directory
                        # continue with a subdirectory
                        continue

            for name in dirs:
                dpath = join(root, name)
                if self.is_unwanted_dir(dpath):
                    rmtree(dpath)
                    dirs.remove(name)
                    continue

            if self.is_egg_dir(root):
                self.handle_egg_dir(root, file_names)
                continue

            # check files
            for fn in sorted(file_names):
                # sorted() to make sure .so files are handled before .so.foo
                fpath = join(root, fn)

                if self.is_unwanted_file(fpath):
                    log.debug('removing unwanted: %s', fpath)
                    os.remove(fpath)
                    continue

                if self.is_egg_file(fpath):
                    self.handle_egg_file(fpath)
                    continue

                if not exists(fpath):
                    # possibly removed while handling .so symlinks
                    if islink(fpath) and '.so.' in split(fpath)[-1]:
                        # dangling symlink to (now removed/renamed) .so file
                        # which wasn't removed yet (see test203's quux.so.0)
                        log.info('removing dangling symlink: %s', fpath)
                        os.remove(fpath)
                    continue

                fext = splitext(fn)[-1][1:]
                if fext == 'so':
                    if not self.options.no_ext_rename:
                        fpath = self.rename_ext(fpath)
                    ver = self.handle_ext(fpath)
                    ver = ver or version
                    if ver:
                        self.current_result.setdefault('ext_vers', set()).add(ver)
                    else:
                        self.current_result.setdefault('ext_no_version', set()).add(fpath)

                if self.current_private_dir:
                    if exists(fpath) and fext != 'so':
                        mode = os.stat(fpath)[ST_MODE]
                        if mode & S_IXUSR or mode & S_IXGRP or mode & S_IXOTH:
                            if (options.no_shebang_rewrite or
                                fix_shebang(fpath, self.options.shebang)) and \
                                    not self.options.ignore_shebangs:
                                try:
                                    res = Interpreter.from_file(fpath)
                                except Exception as e:
                                    log.debug('cannot parse shebang %s: %s', fpath, e)
                                else:
                                    self.current_result.setdefault('shebangs', set()).add(res)

                if fext == 'py' and self.handle_public_module(fpath) is not False:
                    self.current_result['compile'] = True

            if not dirs:
                # try to remove directory if it's empty (and its parent if it's empty afterwards)
                while root:
                    try:
                        os.rmdir(root)
                        log.debug('removing empty directory: %s', root)
                    except Exception:
                        break
                    root = root.rsplit('/', 1)[0]

                    if not root.startswith(self.proot):
                        break

        log.debug("package %s details = %s", package, self.result)

    @property
    def current_result(self):
        if self.current_private_dir:
            return self.result['private_dirs'].setdefault(self.current_private_dir, {})
        return self.result

    def is_unwanted_dir(self, dpath):
        return self.__class__.UNWANTED_DIRS.match(dpath)

    def is_unwanted_file(self, fpath):
        if self.__class__.UNWANTED_FILES.match(fpath):
            return True
        if self.current_dir_is_public and self.is_dbg_package\
                and self.options.clean_dbg_pkg\
                and splitext(fpath)[-1][1:] not in ('so', 'h'):
            return True

    @property
    def private_dirs_to_check(self):
        if self.dpath:
            # scan private directory *only*
            return [self.dpath]

        if self.dpath is False:
            result = []
        else:
            result = [i % self.package for i in (
                      'usr/lib/%s',
                      'usr/lib/games/%s',
                      'usr/share/%s',
                      'usr/share/games/%s')]
        return result

    @property
    def is_dbg_package(self):
        #return self.interpreter.debug
        return self.package.endswith('-dbg')

    def check_private_dir(self, dpath):
        """Return private dir's root if it's a private dir."""
        for i in self.private_dirs_to_check:
            if dpath.startswith(join('debian', self.package, i)):
                return '/' + i

    def rename_ext(self, fpath):
        """Add multiarch triplet, etc. Return new name.

        This method is invoked for all .so files in public or private directories.
        """
        path, fname = fpath.rsplit('/', 1)
        if self.current_dir_is_public and islink(fpath):
            # replace symlinks with extensions in dist-packages directory
            dstfpath = fpath
            links = set()
            while islink(dstfpath):
                links.add(dstfpath)
                dstfpath = join(path, os.readlink(dstfpath))
            if exists(dstfpath) and '.so.' in split(dstfpath)[-1]:
                # rename .so.$FOO symlinks, remove other ones
                for lpath in links:
                    log.info('removing symlink: %s', lpath)
                    os.remove(lpath)
                log.info('renaming %s to %s', dstfpath, fname)
                os.rename(dstfpath, fpath)

        if MULTIARCH_DIR_TPL.match(fpath):
            # ignore /lib/i386-linux-gnu/, /usr/lib/x86_64-kfreebsd-gnu/, etc.
            return fpath

        new_fn = self.interpreter.check_extname(fname, self.current_pub_version)
        if new_fn:
            # TODO: what about symlinks pointing to this file
            new_fpath = join(path, new_fn)
            if exists(new_fpath):
                log.warn('destination file exist, '
                         'cannot rename %s to %s', fname, new_fn)
            else:
                log.info('renaming %s to %s', fname, new_fn)
                os.rename(fpath, new_fpath)
            return new_fpath
        return fpath

    def handle_ext(self, fpath):
        """Handle .so file, return its version if detected."""

    def handle_public_module(self, fpath):
        pass

    def is_bin_dir(self, dpath):
        """Check if dir is one from PATH ones."""
        # dname = debian/packagename/usr/games
        spath = dpath.strip('/').split('/', 4)
        if len(spath) > 4:
            return False  # assume bin directories don't have subdirectories
        if dpath.endswith(('/sbin', '/bin', '/usr/games')):
            # /(s)bin or /usr/(s)bin or /usr/games
            return True

    def handle_bin_dir(self, dpath, file_names):
        if self.options.no_shebang_rewrite or self.options.ignore_shebangs:
            return
        for fn in file_names:
            fpath = join(dpath, fn)
            if fix_shebang(fpath, self.options.shebang):
                try:
                    res = Interpreter.from_file(fpath)
                except Exception as e:
                    log.debug('cannot parse shebang %s: %s', fpath, e)
                else:
                    self.result['shebangs'].add(res)

    def is_egg_dir(self, dname):
        """Check if given directory contains egg-info."""
        return dname.endswith('.egg-info')

    def handle_egg_dir(self, dpath, file_names):
        path, dname = dpath.rsplit('/', 1)
        if self.is_dbg_package and self.options.clean_dbg_pkg:
            rmtree(dpath)
            return

        clean_name = clean_egg_name(dname)
        if clean_name != dname:
            if exists(join(path, clean_name)):
                log.info('removing %s (%s is already available)', dname, clean_name)
                rmtree(dpath)
                return
            else:
                log.info('renaming %s to %s', dname, clean_name)
                os.rename(dpath, join(path, clean_name))
                dname = clean_name
                dpath = join(path, dname)
        if file_names:
            if 'requires.txt' in file_names:
                self.result['requires.txt'].add(join(dpath, 'requires.txt'))
            if 'namespace_packages.txt' in file_names:
                self.result['nsp.txt'].add(join(dpath, 'namespace_packages.txt'))
            if 'SOURCES.txt' in file_names:
                os.remove(join(dpath, 'SOURCES.txt'))
                file_names.remove('SOURCES.txt')

    def is_egg_file(self, fpath):
        """Check if given file contains egg-info."""
        return fpath.endswith('.egg-info')

    def handle_egg_file(self, fpath):
        root, name = fpath.rsplit('/', 1)
        clean_name = clean_egg_name(name)
        if clean_name != name:
            if exists(join(root, clean_name)):
                log.info('removing %s (%s is already available)',
                         name, clean_name)
                os.remove(fpath)
            else:
                log.info('renaming %s to %s', name, clean_name)
                os.rename(fpath, join(root, clean_name))
        self.result['egg-info'].add(join(root, clean_name))

    def cleanup(self):
        if self.is_dbg_package and self.options.clean_dbg_pkg:
            # remove empty directories in -dbg packages
            proot = self.proot + '/usr/lib'
            for root, dirs, file_names in os.walk(proot, topdown=False):
                if '-packages/' in root and not file_names:
                    try:
                        os.rmdir(root)
                    except Exception:
                        pass
