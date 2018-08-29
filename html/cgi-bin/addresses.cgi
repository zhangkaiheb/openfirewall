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
# Copyright (C) 2003-09-22 Darren Critchley <darrenc@telus.net>
# (c) 2008-2014, the Openfirewall Team
#
# $Id: addresses.cgi 7240 2014-02-18 22:08:00Z owes $
#
#  November 2004:
#       Achim Weber <dotzball@users.sourceforge.net>
#       I modified this file to work with BlockOutTraffic addon.
#       This is the advanced config-page.
#       You can define (IP-)networks, interfaces, and services.
#
#  Summer 2005:
#       Achim Weber <dotzball@users.sourceforge.net>
#       Added service grouping
#
# 6 May 2006 Achim Weber:
#       - Re-worked code to use it in Openfirewall 1.5, renamed all variables, keys, etc.
#         from "BOT" to "FW".
#       - Splited big fwadvconf.cgi to single pages for service, service grouping,
#         adresses, adress grouping and interfaces

# Add entry in menu
# MENUENTRY firewall 050 "addresses" "addresses"
#
# Make sure translation exists $Lang::tr{'addresses'}

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

my %cgiparams    = ();
my $errormessage = '';
my $error        = '';
$cgiparams{'ACTION'}     = '';
$cgiparams{'USED_COUNT'} = 0;
&General::getcgihash(\%cgiparams);

# Darren Critchley - vars for setting up sort order
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

my %custAddresses = ();
&DATA::readCustAddresses(\%custAddresses);

$cgiparams{'ADR_NAME'}     = '';
$cgiparams{'ADDRESS_TXT'}  = '';
$cgiparams{'NETMASK'}      = '';
$cgiparams{'ADDRESS_TYPE'} = 'ip';
&General::getcgihash(\%cgiparams);

$cgiparams{'ADR_NAME'} = &Header::cleanConfNames($cgiparams{'ADR_NAME'});

if ($cgiparams{'ACTION'} eq $Lang::tr{'add'}) {
    &validateAddressParams(\%custAddresses);

    unless ($errormessage) {
        $custAddresses{$cgiparams{'ADR_NAME'}}{'ADDRESS_TYPE'} = $cgiparams{'ADDRESS_TYPE'};
        $custAddresses{$cgiparams{'ADR_NAME'}}{'ADDRESS'}      = $cgiparams{'ADDRESS_TXT'};
        $custAddresses{$cgiparams{'ADR_NAME'}}{'NETMASK'}      = $cgiparams{'NETMASK'};
        $custAddresses{$cgiparams{'ADR_NAME'}}{'USED_COUNT'}   = 0;

        &DATA::saveCustAddresses(\%custAddresses);

        &General::log("$Lang::tr{'address added'}: $cgiparams{'ADR_NAME'}");
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'update'}) {
    &validateAddressParams(\%custAddresses);

    if ($errormessage) {
        $cgiparams{'ACTION'} = $Lang::tr{'edit'};
    }
    else {
        my $adrName    = $cgiparams{'ADR_NAME'};
        my $adrNameOld = $cgiparams{'OLD_ADR_NAME'};
        $custAddresses{$adrNameOld}{'ADDRESS_TYPE'} = $cgiparams{'ADDRESS_TYPE'};
        $custAddresses{$adrNameOld}{'ADDRESS'}      = $cgiparams{'ADDRESS_TXT'};
        $custAddresses{$adrNameOld}{'NETMASK'}      = $cgiparams{'NETMASK'};

        # if the name (==Key) has changed, we have to copy/move the old data to new key
        if ($adrName ne $adrNameOld) {
            $custAddresses{$adrName}{'ADDRESS_TYPE'} = $custAddresses{$adrNameOld}{'ADDRESS_TYPE'};
            $custAddresses{$adrName}{'ADDRESS'}      = $custAddresses{$adrNameOld}{'ADDRESS'};
            $custAddresses{$adrName}{'NETMASK'}      = $custAddresses{$adrNameOld}{'NETMASK'};
            $custAddresses{$adrName}{'USED_COUNT'}   = $custAddresses{$adrNameOld}{'USED_COUNT'};

            delete($custAddresses{$adrNameOld});
        }
        &DATA::saveCustAddresses(\%custAddresses);

        &General::log("$Lang::tr{'address updated'}: $cgiparams{'ADR_NAME'}");
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
        `/usr/local/bin/setfwrules --user < /dev/null > /dev/null 2>&1 &`;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {

    # on an update error we use the entered data, we do not re-read from stored config
    unless ($errormessage) {
        if (defined($custAddresses{$cgiparams{'ADR_NAME'}}{'ADDRESS'})) {
            $cgiparams{'ADDRESS_TYPE'} = $custAddresses{$cgiparams{'ADR_NAME'}}{'ADDRESS_TYPE'};
            $cgiparams{'ADDRESS_TXT'}  = $custAddresses{$cgiparams{'ADR_NAME'}}{'ADDRESS'};
            $cgiparams{'NETMASK'}      = $custAddresses{$cgiparams{'ADR_NAME'}}{'NETMASK'};
        }
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    delete($custAddresses{$cgiparams{'ADR_NAME'}});

    &DATA::saveCustAddresses(\%custAddresses);

    &General::log("$Lang::tr{'address removed'}: $cgiparams{'ADR_NAME'}");
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'reset'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

&Header::openpage($Lang::tr{'address settings'}, 1, '');
&Header::openbigbox('100%', 'left');

if ($cgiparams{'ACTION'} eq '') {
    $cgiparams{'ADDRESS_TXT'}  = '';
    $cgiparams{'NETMASK'}      = '';
    $cgiparams{'ADR_NAME'}     = '';
    $cgiparams{'ADDRESS_TYPE'} = 'ip';
}

# DEBUG DEBUG
#&Header::openbox('100%', 'left', 'DEBUG');
#foreach my $line (keys %cgiparams) {
#   print "$line = $cgiparams{$line}<br />\n";
#}
#print "$ENV{'QUERY_STRING'}\n";
#&Header::closebox();

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

my $disabled      = '';
my $hiddenAdrName = '';
if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
    &Header::openbox('100%', 'left', "$Lang::tr{'edit address'}:", $error);
    if ($cgiparams{'USED_COUNT'} > 0) {
        $disabled      = "disabled='disabled'";
        $hiddenAdrName = "<input type='hidden' name='ADR_NAME' value='$cgiparams{'ADR_NAME'}' />";
    }
}
else {
    &Header::openbox('100%', 'left', "$Lang::tr{'add address'}:", $error);
}

my %selected = ();
$selected{'ADDRESS_TYPE'}{'ip'}                       = '';
$selected{'ADDRESS_TYPE'}{'mac'}                      = '';
$selected{'ADDRESS_TYPE'}{$cgiparams{'ADDRESS_TYPE'}} = "selected='selected'";

print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<div align='center'>
<table width='100%'>
<tr>
    <td width='25%'>$Lang::tr{'name'}:&nbsp;</td>
    <td>
        <input type='text' name='ADR_NAME' value='$cgiparams{'ADR_NAME'}' size='20' maxlength='20' $disabled />
        $hiddenAdrName
    </td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr><tr>
    <td>$Lang::tr{'addressformat'}:&nbsp;</td>
    <td>
        <select name='ADDRESS_TYPE'>
            <option value='ip' $selected{'ADDRESS_TYPE'}{'ip'}>IP</option>
            <option value='mac' $selected{'ADDRESS_TYPE'}{'mac'}>MAC</option>
        </select>
    </td>
    <td colspan='2'>&nbsp;</td>
</tr><tr>
    <td>$Lang::tr{'address'}:&nbsp;</td>
    <td>
        <input type='text' name='ADDRESS_TXT' value='$cgiparams{'ADDRESS_TXT'}' size='19' maxlength='17' />
    </td>
    <td>$Lang::tr{'netmask'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td>
        <input type='text' name='NETMASK' value='$cgiparams{'NETMASK'}' size='19' maxlength='15' />
    </td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment2buttons'>
        <strong>$Lang::tr{'note'}</strong>:&nbsp;$Lang::tr{'mac adr not as dest'}
    </td>
    <td colspan='3'>&nbsp;</td>
</tr><tr>
    <td class='comment2buttons'>
        <img src='/blob.gif' alt='*' align='top' />&nbsp;$Lang::tr{'this field may be blank'}
    </td>
END

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {

    #   Darren Critchley - put in next release - author has authorized GPL inclusion
    #   print "<td align='center'><a href='ipcalc.cgi' target='_blank'>IP Calculator</a></td>\n";
    print "<td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'update'}' />\n";
    print "<input type='hidden' name='OLD_ADR_NAME' value='$cgiparams{'ADR_NAME'}' /></td>\n";
}
else {

    #   Darren Critchley - put in next release - author has authorized GPL inclusion
    #   print "<td align='center'><a href='ipcalc.cgi' target='_blank'>IP Calculator</a></td>\n";
    print "<td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'add'}' /></td>\n";
}
print <<END;
    <td class='button2buttons'>
        <input type='submit' name='ACTION' value='$Lang::tr{'reset'}' />
    </td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/firewall-addresses.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</div>
</form>
END

&Header::closebox();

&Header::openbox('100%', 'left', "$Lang::tr{'custom addresses'}:");
print <<END;
<div align='center'>
<table width='100%' align='center'>
<tr align="center">
    <td width='25%'><strong>$Lang::tr{'name'}</strong></td>
    <td width='25%'><strong>$Lang::tr{'address'}</strong></td>
    <td width='25%'><strong>$Lang::tr{'netmask'}</strong></td>
    <td width='25%'><strong>$Lang::tr{'used'}</strong></td>
    <td width='5%'>&nbsp;</td>
    <td width='5%'>&nbsp;</td>
</tr>
END

&display_custom_addresses(\%custAddresses);
print <<END;
</table>
</div>
END

&Header::closebox();

&Header::openbox('100%', 'left', "$Lang::tr{'default networks'}:");
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

# $addressesRef->{$adrName}{'ADDRESS_TYPE'}
# $addressesRef->{$adrName}{'ADDRESS'}
# $addressesRef->{$adrName}{'NETMASK'}
# $addressesRef->{$adrName}{'USED_COUNT'}
sub display_custom_addresses {
    my $addressesRef = shift;

    my $id = 0;
    foreach my $adrName (sort keys %$addressesRef) {

        # Darren Critchley highlight the row we are editing
        if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} && $cgiparams{'ADR_NAME'} eq $adrName) {
            print "<tr class='selectcolour'>\n";
        }
        else {
            print "<tr class='table".int(($id % 2) + 1)."colour'>";
        }
        print <<END;
    <td>$adrName</td>
    <td align='center'>$addressesRef->{$adrName}{'ADDRESS'}</td>
    <td align='center'>$addressesRef->{$adrName}{'NETMASK'}</td>
    <td align='center'>$addressesRef->{$adrName}{'USED_COUNT'}x</td>
    <td align='center'>
    <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
        <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}'/>
        <input type='hidden' name='ADR_NAME' value='$adrName' />
        <input type='hidden' name='USED_COUNT' value='$addressesRef->{$adrName}{'USED_COUNT'}' />
    </form>
    </td>
END
        if ($addressesRef->{$adrName}{'USED_COUNT'} > 0) {
            print "<td align='center'></td>";
        }
        else {
            print <<END;
    <td align='center'>
    <form method='post' name='frmb$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}'/>
        <input type='hidden' name='ADR_NAME' value='$adrName' />
    </form>
    </td>
END
        }
        print "</tr>\n";
        $id++;
    }
}

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

# Validate Field Entries
sub validateAddressParams {
    my $addressesRef = shift;

    if ($cgiparams{'ADR_NAME'} eq '') {
        $errormessage = $Lang::tr{'nonetworkname'};
        return;
    }

    # Strip out commas which will break CSV config file.
    $cgiparams{'ADR_NAME'} = &Header::cleanhtml($cgiparams{'ADR_NAME'});

    my $usedAsDest = &DATA::isUsedAsDestAdr($cgiparams{'ADR_NAME'});

    if ($cgiparams{'ADDRESS_TYPE'} eq 'ip') {
        unless (&General::validip($cgiparams{'ADDRESS_TXT'})) {
            $errormessage .= "$Lang::tr{'invalid ip'} <br />";
        }
        unless ($errormessage) {
            my @tmp = split(/\./, $cgiparams{'ADDRESS_TXT'});
            if ($cgiparams{'NETMASK'} eq '' && $tmp[3] ne '255' && $tmp[3] ne '0') {
                $cgiparams{'NETMASK'} = "255.255.255.255";
            }
        }
        unless (&General::validmask($cgiparams{'NETMASK'})) {
            $errormessage .= "$Lang::tr{'invalid netmask'} <br />";
        }

        # check if it is used in portforwardiing
        if($usedAsDest == 2) {
            if($cgiparams{'NETMASK'} ne '32' && $cgiparams{'NETMASK'} ne '255.255.255.255') {
                $errormessage .= "$Lang::tr{'adr is used in portfw'}:<br />";
                $errormessage .= "$Lang::tr{'only host ip adr allowed in portfw'}<br />";
            }
        }
    }
    elsif ($cgiparams{'ADDRESS_TYPE'} eq 'mac') {

        # change '-' in mac to ':'
        $cgiparams{'ADDRESS_TXT'} =~ s/-/:/g;

        unless (&General::validmac($cgiparams{'ADDRESS_TXT'})) {
            $errormessage .= "$Lang::tr{'invalid mac'} <br />";
        }

        # check if it is used as destination
        if($usedAsDest == 1) {
           $errormessage .= "$Lang::tr{'adr is used as dest'}:<br />";
           $errormessage .= "$Lang::tr{'mac adr not as dest'}<br />";
        }

        # we don't need a mask when MAC is selected
        $cgiparams{'NETMASK'} = '';
    }
    else {
        $errormessage .= "$Lang::tr{'none address type'} <br />";
    }

    # a new address has to have a different name
    if (defined($addressesRef->{$cgiparams{'ADR_NAME'}})) {

        # when this is an update, the old name is allowed
        unless ($cgiparams{'ACTION'} eq $Lang::tr{'update'}
            && $cgiparams{'ADR_NAME'} eq $cgiparams{'OLD_ADR_NAME'})
        {
            $errormessage .= "$Lang::tr{'duplicate name'} <br />";
        }
    }
}
