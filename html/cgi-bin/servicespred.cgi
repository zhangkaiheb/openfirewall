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
# (c) 2018-2020, the Openfirewall Team
#
# Add entry in menu
# MENUTHRDLVL "alt services" 030 "pred services" "pred services"
#
# Make sure translation exists $Lang::tr{'pred services'}

use strict;

# enable only the following on debugging purpose
use warnings;
no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';

&Header::showhttpheaders();

# vars for setting up sort order
my $sort_col  = '1';
my $sort_type = 'a';
my $sort_dir  = 'asc';
my $junk;

if ($ENV{'QUERY_STRING'} ne '') {
    my ($item1, $item2, $item3) = split(/\&/, $ENV{'QUERY_STRING'});
    if ($item1 ne '') {
        ($junk, $sort_col) = split(/\=/, $item1);
    }
    if ($item2 ne '') {
        ($junk, $sort_type) = split(/\=/, $item2);
    }
    if ($item3 ne '') {
        ($junk, $sort_dir) = split(/\=/, $item3);
    }
}



# Bring in the protocols file built from /etc/protocols into hash %protocol
require '/usr/lib/ofw/protocols.pl';


&Header::openpage($Lang::tr{'services settings'}, 1, '');

&Header::openbox('100%', 'left', "$Lang::tr{'default services'}:");
print <<END;
<div align='center'>
<table width='100%' align='center'>
<tr align="center">
    <td><strong>$Lang::tr{'servicename'}</strong></td>
    <td><strong>$Lang::tr{'ports'}</strong></td>
    <td><strong>$Lang::tr{'protocol'}</strong></td>
</tr>
END

&display_default_services();
print <<END;
</table>
</div>
END

&Header::closebox();
&Header::closebigbox();
&Header::closepage();


sub display_default_services {
    my $prev    = "";
    my $newline = "";

    my %defaultServices = ();
    &DATA::readDefaultServices(\%defaultServices);

    my %ofwServices = ();
    &DATA::readOfwServices(\%ofwServices);

    my $id = 0;
    foreach my $defService (sort keys %ofwServices) {
        print "<tr class='table".int(($id % 2) + 1)."colour'>";
        print "<td>$defService</td>\n";
        print "<td align='center'>$ofwServices{$defService}{'PORT_NR'}</td>\n";
        print "<td align='center'>" . &cleanprotocol($ofwServices{$defService}{'PROTOCOL'}) . "</td>\n";
        print "</tr>\n";
        $id++;
    }

    print
"<tr><td colspan='3' bgcolor='#000000'><img src='/images/null.gif' width='1' height='1' border='0' alt='--------' /></td></tr>\n";

    foreach my $defService (sort keys %defaultServices) {
        print "<tr class='table".int(($id % 2) + 1)."colour'>";
        print "<td>$defService</td>\n";
        print "<td align='center'>$defaultServices{$defService}{'PORT_NR'}</td>\n";
        print "<td align='center'>" . &cleanprotocol($defaultServices{$defService}{'PROTOCOL'}) . "</td>\n";
        print "</tr>\n";
        $id++;
    }
}

sub cleanprotocol {
    my $prtcl = $_[0];
    chomp($prtcl);
    if ($prtcl eq 'tcpudp') {
        $prtcl = 'TCP &amp; UDP';
    }
    else {
        $prtcl = uc($prtcl);
    }
    return $prtcl;
}

sub cleanport {
    my $prt = $_[0];
    chomp($prt);

    # Format the ports
    $prt =~ s/-/ - /;
    $prt =~ s/:/ - /;
    return $prt;
}
