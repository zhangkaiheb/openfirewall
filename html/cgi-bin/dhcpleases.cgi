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
# (c) 2018-2019 The Openfirewall Team
#

# Add entry in menu
# MENUTHRDLVL "dhcp server" 020 "dhcp leases" "dhcp leases"

use strict;
use NetAddr::IP;

# enable only the following on debugging purpose
use warnings; no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

&Header::showhttpheaders();

my %dhcpsettings = ();
my %netsettings  = ();
my %mainsettings = ();
my %netaddressip = ();

my $errormessage     = '';
my $error_save_fixed = '';
my $warnmessage      = '';

my @INTERFACEs = ('GREEN', 'BLUE');
my $interface;
my $counter;
my $enabled_count = 0;
my $key;
my $line;
my %checked = ();
my $ic;
my $debug   = 0;

my $disable_main  = 0;          # 1 = only show (non-editable) some vital information in the main box
my $disable_fixed = 1;          # 1 = only show fixed leases, 0 = fields to add fixed lease become usable

# get Openfirewall settings
&General::readhash('/var/ofw/ethernet/settings', \%netsettings);
&General::readhash('/var/ofw/main/settings',     \%mainsettings);

# main settings
foreach $interface (@INTERFACEs) {
    for ($counter = 1; $counter <= $netsettings{"${interface}_COUNT"}; $counter++) {
        $ic = "${interface}_${counter}";
        $dhcpsettings{"ENABLED_${ic}"}            = 'off';
        $dhcpsettings{"ENABLED_BOOTP_${ic}"}      = 'off';
        $dhcpsettings{"START_ADDR_${ic}"}         = '';
        $dhcpsettings{"END_ADDR_${ic}"}           = '';
        $dhcpsettings{"DEFAULT_LEASE_TIME_${ic}"} = '60';
        $dhcpsettings{"DNS1_${ic}"}               = $netsettings{"${ic}_ADDRESS"};
        $dhcpsettings{"DNS2_${ic}"}               = '';
        $dhcpsettings{"WINS1_${ic}"}              = '';
        $dhcpsettings{"WINS2_${ic}"}              = '';
        $dhcpsettings{"NTP1_${ic}"}               = '';
        $dhcpsettings{"NTP2_${ic}"}               = '';

        $netaddressip{"${ic}"} = NetAddr::IP->new($netsettings{"${ic}_ADDRESS"}, $netsettings{"${ic}_NETMASK"});
    }
}
$dhcpsettings{'ACTION'}              = '';
$dhcpsettings{'SORT_FIXEDLEASELIST'} = '';
$dhcpsettings{'FIXED_ENABLED'}       = 'off';
$dhcpsettings{'FIXED_MAC'}           = '';
$dhcpsettings{'FIXED_IP'}            = '';
$dhcpsettings{'FIXED_REMARK'}        = '';
$dhcpsettings{'FIXED_HOSTNAME'}      = '';
$dhcpsettings{'FIXED_NEXTADDR'}      = '';
$dhcpsettings{'FIXED_FILENAME'}      = '';
$dhcpsettings{'FIXED_ROOTPATH'}      = '';
$dhcpsettings{'FIXED_ROUTER'}        = '';
$dhcpsettings{'FIXED_DNS'}           = '';
$dhcpsettings{'KEY_FIXED'}           = '';
$dhcpsettings{'ADD_FROM_LIST'}       = '';

our @fixedleases;
&readfixedleases();

&General::getcgihash(\%dhcpsettings);

# set default domainname if not configured
foreach $interface (@INTERFACEs) {
    for ($counter = 1; $counter <= $netsettings{"${interface}_COUNT"}; $counter++) {
        $ic = "${interface}_${counter}";
        if (!exists($dhcpsettings{"DOMAIN_NAME_${ic}"})) {
            $dhcpsettings{"DOMAIN_NAME_${ic}"} = $mainsettings{'DOMAINNAME'};
        }
    }
}

&Header::openpage($Lang::tr{'dhcp configuration'}, 1, '');

###############
# DEBUG DEBUG
if ($debug) {
    &Header::openbox('100%', 'left', 'DEBUG');
    my $debugCount = 0;
    foreach my $line (sort keys %dhcpsettings) {
        print "$line = $dhcpsettings{$line}<br />\n";
        $debugCount++;
    }
    print "&nbsp;Count: $debugCount\n";
    &Header::closebox();
}

#
# Sorting of fixed leases
#
if ($ENV{'QUERY_STRING'} =~ /^FIXEDMAC|^FIXEDIP/) {
    my $newsort = $ENV{'QUERY_STRING'};
    my $act     = $dhcpsettings{'SORT_FIXEDLEASELIST'};

    #Reverse actual sort ?
    if ($act =~ $newsort) {
        my $rev = '';
        if ($act !~ 'Rev') {
            $rev = 'Rev';
        }
        $newsort .= $rev;
    }
    $dhcpsettings{'SORT_FIXEDLEASELIST'} = $newsort;
    &writeconfig(0);
    &writefixedleases(0);
}

#
# display box with warnmessage in case of warning
#
if ($warnmessage) {
    &Header::openbox('100%', 'left', $Lang::tr{'capswarning'}, 'warning');
    print "<font class='base'>$warnmessage&nbsp;</font>\n";
    &Header::closebox();
}

#
# display box with errormessage in case of error
#
if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>\n";
    &Header::closebox();
}

#
# display box with main settings
#

print <<END
<table width='100%'>
END
;

#
# display box with fixed leases
#

if ($disable_fixed == 0) {
    $checked{'FIXED_ENABLED'}{'on'} = ($dhcpsettings{'FIXED_ENABLED'} ne 'on') ? '' : "checked='checked'";

    print <<END
<table width='100%' border='0'>
<tr>
    <td class='base'>$Lang::tr{'enabled'}:</td>
    <td><input type='checkbox' name='FIXED_ENABLED' $checked{'FIXED_ENABLED'}{'on'} /></td>
    <td colspan='2'>&nbsp;</td>
</tr><tr>
    <td width='25%' class='base'>$Lang::tr{'mac address'}:</td>
    <td width='25%'><input type='text' name='FIXED_MAC' value='$dhcpsettings{'FIXED_MAC'}' size='18' /></td>
    <td width='25%' class='base'>$Lang::tr{'ip address'}:</td>
    <td width='25%'><input type='text' name='FIXED_IP' value='$dhcpsettings{'FIXED_IP'}' size='18' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'hostname'} $Lang::tr{'or'} FQDN:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='3'><input type='text' name='FIXED_HOSTNAME' value='$dhcpsettings{'FIXED_HOSTNAME'}' size='40' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'router ip'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='FIXED_ROUTER' value='$dhcpsettings{'FIXED_ROUTER'}' size='18' /></td>
    <td class='base'>$Lang::tr{'dns server'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='FIXED_DNS' value='$dhcpsettings{'FIXED_DNS'}' size='18' /></td>
</tr><tr>
    <td width='25%' class='base'>$Lang::tr{'remark'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='3'><input type='text' name='FIXED_REMARK' value='$dhcpsettings{'FIXED_REMARK'}' size='40' /></td>
</tr><tr>
    <td colspan = '4'><b>$Lang::tr{'dhcp bootp pxe data'}</b></td>
</tr><tr>
    <td class='base'>filename:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='FIXED_FILENAME' value='$dhcpsettings{'FIXED_FILENAME'}' size='18' /></td>
    <td class='base'>root-path:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='FIXED_ROOTPATH' value='$dhcpsettings{'FIXED_ROOTPATH'}' size='18' /></td>
</tr><tr>
    <td class='base'>next-server:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='FIXED_NEXTADDR' value='$dhcpsettings{'FIXED_NEXTADDR'}' size='18' /></td>
    <td colspan='2'>&nbsp;</td>
</tr>
</table>
END
        ;
}


# Add visual indicators to column headings to show sort order - EO
my $sortarrow1 = '';
my $sortarrow2 = '';

if ($dhcpsettings{'SORT_FIXEDLEASELIST'} eq 'FIXEDMACRev') {
    $sortarrow1 = $Header::sortdn;
}
elsif ($dhcpsettings{'SORT_FIXEDLEASELIST'} eq 'FIXEDMAC') {
    $sortarrow1 = $Header::sortup;
}
elsif ($dhcpsettings{'SORT_FIXEDLEASELIST'} eq 'FIXEDIPRev') {
    $sortarrow2 = $Header::sortdn;
}
else {
    $sortarrow2 = $Header::sortup;
}

print <<END
<table width='100%'>
<tr class='headbar'>
    <td width='13%' align='center' nowrap='nowrap'><a href='$ENV{'SCRIPT_NAME'}?FIXEDMAC'><b>$Lang::tr{'mac address'}</b></a> $sortarrow1</td>
    <td width='13%' align='center' nowrap='nowrap'><a href='$ENV{'SCRIPT_NAME'}?FIXEDIP'><b>$Lang::tr{'ip address'}</b></a> $sortarrow2</td>
    <td width='14%' class='boldbase' align='center'><b>$Lang::tr{'hostname'}</b></td>
    <td width='15%' align='center'><b>$Lang::tr{'remark'}</b></td>
    <td width='15%' class='boldbase' align='center'><b>next-server</b></td>
    <td width='15%' class='boldbase' align='center'><b>filename</b></td>
    <td width='15%' class='boldbase' align='center'><b>root-path</b></td>
</tr>
END
    ;

for $key (0 .. $#fixedleases) {
    my $gif   = '';
    my $gdesc = '';

    if ($fixedleases[$key]{'ENABLED'} eq "on") {
        $gif   = 'on.gif';
        $gdesc = $Lang::tr{'click to disable'};
    }
    else {
        $gif   = 'off.gif';
        $gdesc = $Lang::tr{'click to enable'};
    }

    if ($dhcpsettings{'KEY_FIXED'} eq $key) {
        print "<tr class='selectcolour'>";
    }
    else {
        print "<tr class='table".int(($key % 2) + 1)."colour'>";
    }
    print <<END
<td align='center'>$fixedleases[$key]{'MAC'}</td>
<td align='center'>$fixedleases[$key]{'IP'}</td>
<td align='center'>$fixedleases[$key]{'HOSTNAME'}</td>
<td align='center'>$fixedleases[$key]{'REMARK'}</td>
<td align='center'>$fixedleases[$key]{'NEXTADDR'}</td>
<td align='center'>$fixedleases[$key]{'FILENAME'}</td>
<td align='center'>$fixedleases[$key]{'ROOTPATH'}</td>
</tr>
END
    ;
}    # for all fixed leases

print "</table>";

#&Header::closebox();

#
# display box with dynamic leases if we have one or more enabled interface(s)
#
$enabled_count = 0;
foreach $interface (@INTERFACEs) {
    for ($counter = 1; $counter <= $netsettings{"${interface}_COUNT"}; $counter++) {
        $ic = "${interface}_${counter}";
        if ($dhcpsettings{"ENABLED_${ic}"} eq 'on') {
            $enabled_count++;
        }
    }
}
if ($enabled_count > 0) {
    &General::CheckSortOrder;
    &General::PrintActualLeases($Lang::tr{'add new lease'});
}

&Header::closepage();

#
# write config files, dhcpd.conf etc.
#

sub readfixedleases
{
    @fixedleases = ();
    open(FILE, '/var/ofw/dhcp/fixedleases');
    my @tmpfile = <FILE>;
    close(FILE);

    foreach $line (@tmpfile) {
        chomp($line);
        my @tmp = split(/\,/, $line);

        # These can be empty, make sure they exist to avoid warning messages
        $tmp[0] = '' unless defined $tmp[0];
        $tmp[3] = '' unless defined $tmp[3];
        $tmp[4] = '' unless defined $tmp[4];
        $tmp[5] = '' unless defined $tmp[5];
        $tmp[6] = '' unless defined $tmp[6];
        $tmp[7] = '' unless defined $tmp[7];
        $tmp[8] = '' unless defined $tmp[8];
        $tmp[9] = '' unless defined $tmp[9];

        push @fixedleases, { MAC => $tmp[0], IP => $tmp[1], ENABLED => $tmp[2],
            NEXTADDR => $tmp[3], FILENAME => $tmp[4], ROOTPATH => $tmp[5],
            REMARK => $tmp[6], HOSTNAME => $tmp[7], ROUTER => $tmp[8], DNS => $tmp[9] };
    }
}

