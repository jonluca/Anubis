#! /usr/bin/perl
# debhelper sequence file for dh_pypy

use warnings;
use strict;
use Debian::Debhelper::Dh_Lib;

insert_before("dh_installinit", "dh_pypy");

1
