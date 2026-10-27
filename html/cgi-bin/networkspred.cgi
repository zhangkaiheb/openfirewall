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
# MENUTHRDLVL "addresses" 030 "predefined addresses" "predefined addresses"
#
# Make sure translation exists $Lang::tr{'predefined addresses'}

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

&Header::openpage($Lang::tr{'predefined addresses'}, 1, '');

&Header::openbox('100%', 'left', "$Lang::tr{'predefined addresses'}:");
print <<END;
<div align='center'>
<table width='100%' align='center'>
<tr align="center">
    <td><strong>$Lang::tr{'name'}</strong></td>
    <td><strong>$Lang::tr{'color'}</strong></td>
    <td><strong>$Lang::tr{'ip address'}</strong></td>
    <td><strong>$Lang::tr{'netmask'}</strong></td>
</tr>
END

&display_default_networks();
print <<END;
</table>
</div>
END

&Header::closebox();
&Header::closebigbox();
&Header::closepage();

sub display_default_networks {
    my %networks = ();
    &DATA::setup_default_networks(\%networks);

    my $id = 0;
    foreach my $name (sort keys %networks) {
        my $adrColor = '';
        print "<tr class='table".int(($id % 2) + 1)."colour'>";

        if ($networks{$name}{'COLOR'} eq 'GREEN_COLOR') {
            $adrColor = "class='ofw_iface_bg_green'";
        }
        elsif ($networks{$name}{'COLOR'} eq 'BLUE_COLOR') {
            $adrColor = "class='ofw_iface_bg_blue'";
        }
        elsif ($networks{$name}{'COLOR'} eq 'ORANGE_COLOR') {
            $adrColor = "class='ofw_iface_bg_orange'";
        }
        elsif ($networks{$name}{'COLOR'} eq 'RED_COLOR') {
            $adrColor = "class='ofw_iface_bg_red'";
        }
        elsif ($networks{$name}{'COLOR'} eq 'IPSEC_COLOR') {
            $adrColor = "class='ofw_iface_bg_ipsec'";
        }
        elsif ($networks{$name}{'COLOR'} eq 'OVPN_COLOR') {
            $adrColor = "class='ofw_iface_bg_ovpn'";
        }
        elsif ($networks{$name}{'COLOR'} eq 'LOCAL_COLOR') {
            $adrColor = "class='ofw_iface_bg_fw'";
        }

        print "<td>$name</td>\n";
        print "<td width='4%' align='center' $adrColor></td>\n";
        print "<td align='center'>$networks{$name}{'ADR'}</td>\n";
        print "<td align='center'>$networks{$name}{'MASK'}</td>\n";
        print "</tr>\n";
        $id++;
    }
}
