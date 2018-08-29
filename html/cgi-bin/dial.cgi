#!/usr/bin/perl
#
# SmoothWall CGIs
#
# This code is distributed under the terms of the GPL
#
# (c) The SmoothWall Team
#
# $Id: dial.cgi 4273 2010-02-21 21:38:20Z owes $
#

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my %cgiparams = ();

$cgiparams{'ACTION'} = '';
&General::getcgihash(\%cgiparams);

if ($cgiparams{'ACTION'} eq $Lang::tr{'dial'}) {
    &General::log('red', 'GUI dial');
    system('/usr/local/bin/red', '--start') == 0
        or &General::log("Dial failed: $?");
}
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'hangup'}) {
    &General::log('red', 'GUI hangup');
    system('/usr/local/bin/red', '--stop') == 0
        or &General::log("Hangup failed: $?");
}
sleep 1;

print "Status: 302 Moved\nLocation: /cgi-bin/index.cgi\n\n";
