#!/usr/bin/perl
#
# This file is part of the Openfirewall.
#
# Openfirewall is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Openfirewall is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Openfirewall.  If not, see <http://www.gnu.org/licenses/>.
#
# (c) 2011-2015 The Openfirewall Team
#
# Usage: package-diff.pl <lfs-package-name>
#
# Purpose: find and list differences for package by searching in doc/diff-list.txt.
#   The differences can then be more easily added to update ROOTFILE
#
#
# TODO: support for non-i486 architectures
#
# $Id: package-diff.pl 7904 2015-02-23 20:04:40Z owes $
#


use strict;
use warnings;


unless (defined($ARGV[0])) {
    die "No package name.";
}
my $package = $ARGV[0];
my $package_version = `grep "^VER" lfs/${package} | cut -d '=' -f 2`;
$package_version =~ s/^\s*(.*?)\s*$/$1/;
my $rootfile = "";
my $filelist = `find files_i486 -name ${package}-${package_version}  | grep -v 01_toolchain`;
chomp($filelist);
if (! -f "${filelist}") {
    # Look for alternative names
    $filelist = `find files_i486 -name ${package}.${package_version}  | grep -v 01_toolchain`;
    chomp($filelist);
    if (! -f "${filelist}") {
        $filelist = `find files_i486 -name ${package}${package_version}  | grep -v 01_toolchain`;
        chomp($filelist);
    }
}

# Get IPCop version
my $ipcop_version = `grep "^VERSION=" make.sh | cut -d '=' -f 2`;
chomp(${ipcop_version});

my $diff_file = "doc/IPCop-${ipcop_version}-diff-list.i486.txt";

# Get Perl version
my $perl_version = `grep "^VER" lfs/perl | cut -d '=' -f 2`;
chomp(${perl_version});

#
# Search rootfile and filelist for differences
#
if (-f "config/rootfiles/common/${package}") {
    $rootfile = "config/rootfiles/common/${package}";
}
elsif (-f "config/rootfiles/arch_i486/${package}") {
    $rootfile = "config/rootfiles/arch_i486/${package}";
}
else {
    print "No rootfile for package ${package}?\n";
}

if (! -f "${filelist}") {
    print "Filelist for ${package} version ${package_version} not found.\n";
}
elsif (! -f "${rootfile}") {
    # Already informed
}
else {
    print "## rootfile differences >>\n";
    print `sed "s,PERLVER,$perl_version,g" ${rootfile} | sed "s,MACHINE,i486,g"  | diff -Nuw - ${filelist}`;
    print "<<\n";
}


unless (-e $diff_file) {
    print "#\n#\n$diff_file does not exist\n";
    exit(0);
}

#
# Search diff-list.txt for matches
#
print "##\n";
print "## ${package}-${package_version}\n";

open (LIST, "$diff_file") or die "Unable to open $diff_file";
while (<LIST>) {
    my @temp = split(' ',$_);

    next unless (($temp[0] eq 'DIFF') || ($temp[0] eq 'NEW'));
    next unless (defined($temp[2]) && ($temp[2] eq "${package}"));
    
    print "$temp[1]\n";
}
