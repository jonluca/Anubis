============
PyDist files
============

DISTNAME [VRANGE] [DEPENDENCY][; [PEP386] [RULES]]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PyDist files help tools like dh_python2/3 to translate Python dependencies
(from setup.py's install_requires or egg's requires.txt file) to Debian
dependencies.


Required fields:
~~~~~~~~~~~~~~~~

DISTNAME
````````
Python distribution name (you can find it at the beginning of .egg-info
file/directory name that your package provides).

Examples:
 * SQLAlchemy
 * Jinja2
 * numpy


Optional fields:
~~~~~~~~~~~~~~~~

VRANGE
``````
Python version or version range the line applies to.

Examples:
 * 2.6		(Python 2.6 only)
 * 2.5-		(Python 2.5 and newer)
 * 2.5-2.7	(Python 2.5 or 2.6)
 * -2.7		(Python 2.6 or older)

 * 3.1		(Python 3.1 only)
 * 3.1-		(Python 3.1 and newer)
 * 3.1-3.3	(Python 3.1 or 3.2)
 * -3.4		(Python 3.3 or older)

DEPENDENCY
``````````
Debian dependency, multiple packages or versions are allowed.
If not set, given Python distribution name will be ignored.

Examples:
 * python-mako
 * python-jinja2 | python (>= 2.6)
 * python-sqlalchemy (>= 0.5), python-sqlalchemy (<< 0.6)

 * python3-mako
 * python3-jinja2 | python3 (>= 3.0)
 * python3-sqlalchemy (>= 0.5), python3-sqlalchemy (<< 0.6)

PEP386
``````
Standards flag: upstream uses versioning schema described in PEP 386.

RULES
`````
Rules needed to translate upstream version to Debian one. If PEP386 is
set, its rules will be applied later. Multiple rules are allowed, separate them
with a space.

Examples:
 * s/^/2:/
 * s/alpha/~alpha/ s/^/1:/


Notes:
~~~~~~

You can use multiple lines if binary package provides more than one Python
distribution or if you want to specify different dependencies for each Python
version or version range.

If you use dh_python2, it will install debian/binary_package_name.pydist file
to /usr/share/dh-python/dist/cpython2/binary_package_name automatically.

If you use dh_python3, it will install debian/binary_package_name.pydist file
to /usr/share/dh-python/dist/cpython3/binary_package_name automatically.


Complete examples:
~~~~~~~~~~~~~~~~~~
 * SQLAlchemy python-sqlalchemy (>= 0.5), python-sqlalchemy (<< 0.6)
 * Mako python-mako; PEP386
 * foo -2.5 python-oldfoo; s/^/3:/
 * foo 2.5- python-foo; PEP386
 * Bar 2.6-

 * SQLAlchemy python3-sqlalchemy (>= 0.5), python3-sqlalchemy (<< 0.6)
 * Mako python3-mako; PEP386
 * foo -3.2 python3-oldfoo; s/^/3:/
 * foo 3.2- python3-foo; PEP386
 * Bar 2.6-

.. vim: ft=rst
