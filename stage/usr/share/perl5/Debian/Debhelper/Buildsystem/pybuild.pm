# A debhelper build system class for building Python libraries
#
# Copyright: © 2012-2013 Piotr Ożarowski

# TODO:
# * support for dh --parallel

package Debian::Debhelper::Buildsystem::pybuild;

use strict;
use Dpkg::Control;
use Debian::Debhelper::Dh_Lib qw(error doit);
use base 'Debian::Debhelper::Buildsystem';

sub DESCRIPTION {
	"Python pybuild"
}

sub check_auto_buildable {
	my $this=shift;
	return doit('pybuild', '--detect', '--really-quiet', '--dir', $this->get_sourcedir());
}

sub new {
	my $class=shift;
	my $this=$class->SUPER::new(@_);
	$this->enforce_in_source_building();

	if (!$ENV{'PYBUILD_INTERPRETERS'}) {
		$this->{pydef} = `pyversions -vd 2>/dev/null`;
		$this->{pydef} =~ s/\s+$//;
		$this->{pyvers} = `pyversions -vr 2>/dev/null`;
		$this->{pyvers} =~ s/\s+$//;
		$this->{py3def} = `py3versions -vd 2>/dev/null`;
		$this->{py3def} =~ s/\s+$//;
		$this->{py3vers} = `py3versions -vr 2>/dev/null`;
		$this->{py3vers} =~ s/\s+$//;
		$this->{pypydef} = `pypy -c 'from sys import pypy_version_info as i; print("%s.%s" % (i.major, i.minor))' 2>/dev/null`;
		$this->{pypydef} =~ s/\s+$//;
	}

	return $this;
}

sub configure {
	my $this=shift;
	foreach my $command ($this->pybuild_commands('configure', @_)) {
		doit(@$command, '--dir', $this->get_sourcedir());
	}
}

sub build {
	my $this=shift;
	foreach my $command ($this->pybuild_commands('build', @_)) {
		doit(@$command, '--dir', $this->get_sourcedir());
	}
}

sub install {
	my $this=shift;
	my $destdir=shift;
	foreach my $command ($this->pybuild_commands('install', @_)) {
		doit(@$command, '--dir', $this->get_sourcedir(), '--dest-dir', $destdir);
	}
}

sub test {
	my $this=shift;
	foreach my $command ($this->pybuild_commands('test', @_)) {
		doit(@$command, '--dir', $this->get_sourcedir());
	}
}

sub clean {
	my $this=shift;
	foreach my $command ($this->pybuild_commands('clean', @_)) {
		doit(@$command, '--dir', $this->get_sourcedir());
	}
	doit('rm', '-rf', '.pybuild/');
	doit('find', '.', '-name', '*.pyc', '-exec', 'rm', '{}', ';');
}

sub pybuild_commands {
	my $this=shift;
	my $step=shift;
	my @options = @_;
	my @result;

	if ($ENV{'PYBUILD_INTERPRETERS'}) {
		push @result, ['pybuild', "--$step", @options];
	}
	else {
		# get interpreter packages from Build-Depends{,-Indep}:
		# NOTE: possible problems with alternative/versioned dependencies
		my @deps = $this->python_build_dependencies();

		my @py2opts = ('pybuild', "--$step");
		my @py3opts = ('pybuild', "--$step");

		if ($step == 'test' and $ENV{'PYBUILD_TEST_PYTEST'} != '1' &&
		       			$ENV{'PYBUILD_TEST_NOSE'} != '1' &&
		       			$ENV{'PYBUILD_TEST_TOX'} != '1') {
			if (grep {$_ eq 'python-tox'} @deps) {
				push @py2opts, '--test-tox'}
			elsif (grep {$_ eq 'python-pytest'} @deps) {
				push @py2opts, '--test-pytest'}
			elsif (grep {$_ eq 'python-nose'} @deps) {
				push @py2opts, '--test-nose'}
			if (grep {$_ eq 'python3-tox'} @deps) {
				push @py3opts, '--test-tox'}
			elsif (grep {$_ eq 'python3-pytest'} @deps) {
				push @py3opts, '--test-pytest'}
			elsif (grep {$_ eq 'python3-nose'} @deps) {
				push @py3opts, '--test-nose'}
		}

		my $pyall = 0;
		my $pyalldbg = 0;
		my $py3all = 0;
		my $py3alldbg = 0;

		my $i = 'python{version}';

		# Python
		if ($this->{pyvers}) {
			if (grep {$_ eq 'python-all' or $_ eq 'python-all-dev'} @deps) {
				$pyall = 1;
				push @result, [@py2opts, '-i', $i, '-p', $this->{pyvers}, @options];
			}
			if (grep {$_ eq 'python-all-dbg'} @deps) {
				$pyalldbg = 1;
				push @result, [@py2opts, '-i', "$i-dbg", '-p', $this->{pyvers}, @options];
			}
		}
		if ($this->{pydef}) {
			if (not $pyall and grep {$_ eq 'python' or $_ eq 'python-dev'} @deps) {
				push @result, [@py2opts, '-i', $i, '-p', $this->{pydef}, @options];
			}
			if (not $pyalldbg and grep {$_ eq 'python-dbg'} @deps) {
				push @result, [@py2opts, '-i', "$i-dbg", '-p', $this->{pydef}, @options];
			}
		}

		# Python 3
		if ($this->{py3vers}) {
			if (grep {$_ eq 'python3-all' or $_ eq 'python3-all-dev'} @deps) {
				$py3all = 1;
				push @result, [@py3opts, '-i', $i, '-p', $this->{py3vers}, @options];
			}
			if (grep {$_ eq 'python3-all-dbg'} @deps) {
				$py3alldbg = 1;
				push @result, [@py3opts, '-i', "$i-dbg", '-p', $this->{py3vers}, @options];
			}
		}
		if ($this->{py3def}) {
			if (not $py3all and grep {$_ eq 'python3' or $_ eq 'python3-dev'} @deps) {
				push @result, [@py3opts, '-i', $i, '-p', $this->{py3def}, @options];
			}
			if (not $py3alldbg and grep {$_ eq 'python3-dbg'} @deps) {
				push @result, [@py3opts, '-i', "$i-dbg", '-p', $this->{py3def}, @options];
			}
		}
		# TODO: pythonX.Y → `pybuild -i python{version} -p X.Y`

		# PyPy
		if ($this->{pypydef} and grep {$_ eq 'pypy'} @deps) {
			push @result, ['pybuild', "--$step", '-i', 'pypy', '-p', $this->{pypydef}, @options];
		}
	}
	return @result;
}

sub python_build_dependencies {
	my $this=shift;

	my @result;
	my $c = Dpkg::Control->new(type => CTRL_INFO_SRC);
	if ($c->load('debian/control')) {
		for my $field (grep /^Build-Depends/, keys %{$c}) {
			my $builddeps = $c->{$field};
			while ($builddeps =~ /(?:^|[\s,])(pypy|python[0-9\.]*(-[^\s,]+)?)(?:[\s,]|$)/g) {
				if ($1) {push @result, $1};
			}
		}
	}

	return @result;
}

1
