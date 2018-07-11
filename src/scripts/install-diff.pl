#!/usr/bin/perl

# $Id: install-diff.pl 5769 2011-08-08 06:35:10Z gespinasse $

# This script try to do his best but is not capable to see when a file is replaced
# by a later package.

use strict;

my %allfiles=();

( my $prog = $0 ) =~ s!^.*/!!; #prog name without path
unless ($#ARGV ==1) { die "$prog invalid parameter number $#ARGV : need a diff file and a rootfile to check\n"; }
unless ( -f $ARGV[0]) { die "$prog invalid parameter : DIFF_FILE not found\n"; }
unless ( -f $ARGV[1]) { die "$prog invalid parameter : ROOTFILE not found\n"; }

# create a hash that contain all files names from a passed rootfile name
open (ROOTFILE,"<$ARGV[1]");
while (<ROOTFILE>) {
	$allfiles{$_} = "x";
}
close (ROOTFILE);

# check if a file exist in the hash in include or exclude states or is new
open (DIFF_FILE,"<$ARGV[0]");
while (<DIFF_FILE>) {
	if ( defined ($allfiles{$_}) ) {
		print "$_";
	} elsif ( defined ($allfiles{"#$_"}) ) {
		print "#$_";
	} else {
		print "+$_";
	}
}
close (DIFF_FILE);
