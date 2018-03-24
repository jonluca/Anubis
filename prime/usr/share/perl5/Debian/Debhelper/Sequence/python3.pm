#! /usr/bin/perl
# debhelper sequence file for dh_python3

use warnings;
use strict;
use Debian::Debhelper::Dh_Lib;

insert_before("dh_installinit", "dh_python3");

1
