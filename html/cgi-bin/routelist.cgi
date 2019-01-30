#!/usr/bin/perl
#
# This code is distributed under the terms of the GPL
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

# Add entry in menu
# MENUTHRDLVL "routing table" 020 "routing table entries" "routing table entries"
#
# Make sure translation exists $Lang::tr{'routing table entries'}
#

use strict;

# enable only the following on debugging purpose
use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';

my $output='';

&Header::showhttpheaders();

my %cgiparams    = ();
my $errormessage = '';
my $error        = '';
&General::getcgihash(\%cgiparams);

# vars for setting up sort order
my $sort_col  = '1';
my $sort_type = 'a';
my $sort_dir  = 'asc';
my $junk;
my $lineNumber = 0;

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


$cgiparams{'ADDRESS'}  = '';
$cgiparams{'NETMASK'}  = '';
$cgiparams{'GATEWAY'}  = '';
$cgiparams{'IFACE'}    = '';
&General::getcgihash(\%cgiparams);


&Header::openpage($Lang::tr{'network status information'}, 1, '');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

print "<a name='routing'/>\n";
##&Header::openbox('100%', 'left', "$Lang::tr{'routing table entries'}:");
$output = `/sbin/ip route list`;
$output = &Header::cleanhtml($output,"y");
print <<END
<div align='center'>
<table width='100%'>
<tr class='headbar'>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'destination ip or net'}</td>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'gateway ip'}</td>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'interface'}</td>
    <td width='25%' class='boldbase'>$Lang::tr{'remark'}</td>
</tr>
END
;
my $count = 0;
foreach my $line (split(/\n/, $output))
{
    print "<tr class='table".int(($count % 2) + 1)."colour'>";
    if ($line =~ m/^(.*) dev ([^ ]+) (.*) src (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>$4</td>";
        print "<td align='center'>".&General::color_devices($2)."</td><td>$3</td></tr>";
    }
    elsif ($line =~ m/^(.*) via (.*) dev (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>$2</td>";
        print "<td align='center'>".&General::color_devices($3)."</td><td>&nbsp;</td></tr>";
    }
    elsif ($line =~ m/^(.*) dev ipsec(\d*)  (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>&nbsp;</td>";
        print "<td align='center'>".&General::color_devices("ipsec$2")."</td><td>$3</td></tr>";
    }
    else {
        print "<td colspan='4'>$line</td></tr>";
    }

    $count++;
}
print "</table> </div>";
#&Header::closebox();

#&Header::closebigbox();
&Header::closepage();

