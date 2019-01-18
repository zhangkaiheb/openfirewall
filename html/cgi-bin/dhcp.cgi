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
# MENUENTRY services 030 "dhcp server" "dhcp configuration"

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
my %timesettings = ();
my %netaddressip = ();

my $buttontext       = $Lang::tr{'add'};
my $errormessage     = '';
my $error_save_main  = '';
my $error_save_fixed = '';
my $warnmessage      = '';

my @INTERFACEs = ('GREEN', 'BLUE');
my $interface;
my $counter;
my $enabled_count = 0;
my $key;
my $key_fixed = 0;
my $line;
my %checked = ();
my $ic;
my $debug   = 0;

my $disable_main  = 0;          # 1 = only show (non-editable) some vital information in the main box
my $disable_fixed = 1;          # 1 = only show fixed leases, 0 = fields to add fixed lease become usable

# get Openfirewall settings
&General::readhash('/var/ofw/ethernet/settings', \%netsettings);
&General::readhash('/var/ofw/main/settings',     \%mainsettings);
&General::readhash('/var/ofw/time/settings',     \%timesettings);

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
$key_fixed = $dhcpsettings{'KEY_FIXED'};

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
&Header::openbigbox('100%', 'left', '', '');

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

# DEBUG DEBUG
###############

if ($dhcpsettings{'ACTION'} eq 'SAVE_MAIN') {

    # Verify the options before writing anything
    foreach $interface (@INTERFACEs) {

        # Limit to 1 interface for now
        for ($counter = 1; $counter <= $netsettings{"${interface}_COUNT"}; $counter++) {
            $ic = "${interface}_${counter}";

            if ($dhcpsettings{"ENABLED_${ic}"} eq 'on') {
                my $ipstart = 0;
                my $ipend   = 0;

                # define START and END or leave both empty (for static leases only)
                if ($dhcpsettings{"START_ADDR_${ic}"}) {
                    if (!&General::validip($dhcpsettings{"START_ADDR_${ic}"})) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid start address'};
                        goto ERROR_SAVE_MAIN;
                    }
                    if (!$dhcpsettings{"END_ADDR_${ic}"}) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid end address'};
                        goto ERROR_SAVE_MAIN;
                    }

                    $ipstart = NetAddr::IP->new($dhcpsettings{"START_ADDR_${ic}"});
                    unless ($netaddressip{"${ic}"}->contains($ipstart)) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid start address'};
                        goto ERROR_SAVE_MAIN;
                    }
                }

                if ($dhcpsettings{"END_ADDR_${ic}"}) {
                    if (!&General::validip($dhcpsettings{"END_ADDR_${ic}"})) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid end address'};
                        goto ERROR_SAVE_MAIN;
                    }
                    if (!$dhcpsettings{"START_ADDR_${ic}"}) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid start address'};
                        goto ERROR_SAVE_MAIN;
                    }

                    $ipend = NetAddr::IP->new($dhcpsettings{"END_ADDR_${ic}"});
                    unless ($netaddressip{"${ic}"}->contains($ipend)) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid end address'};
                        goto ERROR_SAVE_MAIN;
                    }
                }

                # Swap Start and End IF End is less than Start
                if ( $ipend < $ipstart ) {
                    ($dhcpsettings{"START_ADDR_${ic}"},$dhcpsettings{"END_ADDR_${ic}"}) =
                    ($dhcpsettings{"END_ADDR_${ic}"},$dhcpsettings{"START_ADDR_${ic}"});

                    ($ipstart,$ipend) = ($ipend,$ipstart);
                }

                # Lease time must be set and be numeric
                if (!($dhcpsettings{"DEFAULT_LEASE_TIME_${ic}"} =~ /^\d+$/)) {
                    $errormessage =
                          "DHCP on ${interface}: "
                        . $Lang::tr{'invalid default lease time'} . ' '
                        . $dhcpsettings{'DEFAULT_LEASE_TIME_${ic}'};
                    goto ERROR_SAVE_MAIN;
                }

                # Verify DNS1 and DNS2
                # DNS1 is required
                if (!&General::validip($dhcpsettings{"DNS1_${ic}"})) {
                    $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid primary dns'};
                    goto ERROR_SAVE_MAIN;
                }
                if ($dhcpsettings{"DNS2_${ic}"}) {
                    if (!&General::validip($dhcpsettings{"DNS2_${ic}"})) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid secondary dns'};
                        goto ERROR_SAVE_MAIN;
                    }
                    if (!$dhcpsettings{"DNS1_${ic}"}) {
                        $errormessage =
                            "DHCP on ${interface}: "
                            . $Lang::tr{'cannot specify secondary dns without specifying primary'};
                        goto ERROR_SAVE_MAIN;
                    }
                }

                # Verify WINS1 and WINS2
                if ($dhcpsettings{"WINS1_${ic}"}) {
                    if (!&General::validip($dhcpsettings{"WINS1_${ic}"})) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid wins address'};
                        goto ERROR_SAVE_MAIN;
                    }
                }
                if ($dhcpsettings{"WINS2_${ic}"}) {
                    if (!&General::validip($dhcpsettings{"WINS2_${ic}"})) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid wins address'};
                        goto ERROR_SAVE_MAIN;
                    }
                    if (!$dhcpsettings{"WINS1_${ic}"}) {
                        $errormessage =
                            "DHCP on ${interface}: "
                            . $Lang::tr{'cannot specify secondary wins without specifying primary'};
                        goto ERROR_SAVE_MAIN;
                    }
                }

                # Verify NTP1 and NTP2
                if ($dhcpsettings{"NTP1_${ic}"}) {
                    if (!&General::validip($dhcpsettings{"NTP1_${ic}"})) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid primary ntp'};
                        goto ERROR_SAVE_MAIN;
                    }
                    if (   ($dhcpsettings{"NTP1_${ic}"} eq $netsettings{"${ic}_ADDRESS"})
                        && ($timesettings{'ENABLED_NTP'} ne 'on'))
                    {
                        $warnmessage =
                            "DHCP on ${interface}: " . $Lang::tr{'local ntp server specified but not enabled'};
                    }
                }
                if ($dhcpsettings{"NTP2_${ic}"}) {
                    if (!&General::validip($dhcpsettings{"NTP2_${ic}"})) {
                        $errormessage = "DHCP on ${interface}: " . $Lang::tr{'invalid secondary ntp'};
                        goto ERROR_SAVE_MAIN;
                    }
                    if (   ($dhcpsettings{"NTP2_${ic}"} eq $netsettings{"${ic}_ADDRESS"})
                        && ($timesettings{'ENABLED_NTP'} ne 'on'))
                    {
                        $warnmessage =
                            "DHCP on ${interface}: " . $Lang::tr{'local ntp server specified but not enabled'};
                    }
                    if (!$dhcpsettings{"NTP1_${ic}"}) {
                        $errormessage =
                            "DHCP on ${interface}: "
                            . $Lang::tr{'cannot specify secondary ntp without specifying primary'};
                        goto ERROR_SAVE_MAIN;
                    }
                }
            }
        }    # interface count
    }    # foreach interface
    &writeconfig(1);
ERROR_SAVE_MAIN:
    $error_save_main = 'error' if ($errormessage);
}
else {
    &General::readhash('/var/ofw/dhcp/settings', \%dhcpsettings);
}

if ($dhcpsettings{'ACTION'} eq $Lang::tr{'toggle enable disable'} . '_fixed') {

    # Toggle enable/disable field on specified fixed lease
    if ($fixedleases[$key_fixed]{'ENABLED'} eq 'on') {
        $fixedleases[$key_fixed]{'ENABLED'} = 'off';
    }
    else {
        $fixedleases[$key_fixed]{'ENABLED'} = 'on';
    }

    # Test for duplicate IP address, we allow for multiple disabled IP addresses
    if ($fixedleases[$key_fixed]{'ENABLED'} eq 'on') {
        for my $id (0 .. $#fixedleases) {
            if (($fixedleases[$id]{'ENABLED'} eq 'on') && ($fixedleases[$key_fixed]{'IP'} eq $fixedleases[$id]{'IP'})) {
                next if ($key_fixed == $id);
                $errormessage = $Lang::tr{'duplicate ip'};
            }
        }
    }

    $dhcpsettings{'KEY_FIXED'} = '';    # forget we were editing something
    if ($errormessage eq '') {
        &General::log('dhcpd', $Lang::tr{'fixed ip lease modified'});
        &writefixedleases(1);
    }
    else {
        &readfixedleases();
    }
}

if ($dhcpsettings{'ACTION'} eq $Lang::tr{'edit'} . '_fixed') {

    # Edit fields on specified fixed lease

    $disable_main  = 1;
    $disable_fixed = 0;

    $dhcpsettings{'FIXED_ENABLED'}  = $fixedleases[$key_fixed]{'ENABLED'};
    $dhcpsettings{'FIXED_MAC'}      = $fixedleases[$key_fixed]{'MAC'};
    $dhcpsettings{'FIXED_IP'}       = $fixedleases[$key_fixed]{'IP'};
    $dhcpsettings{'FIXED_REMARK'}   = $fixedleases[$key_fixed]{'REMARK'};
    $dhcpsettings{'FIXED_HOSTNAME'} = $fixedleases[$key_fixed]{'HOSTNAME'};
    $dhcpsettings{'FIXED_NEXTADDR'} = $fixedleases[$key_fixed]{'NEXTADDR'};
    $dhcpsettings{'FIXED_FILENAME'} = $fixedleases[$key_fixed]{'FILENAME'};
    $dhcpsettings{'FIXED_ROOTPATH'} = $fixedleases[$key_fixed]{'ROOTPATH'};
    $dhcpsettings{'FIXED_ROUTER'}   = $fixedleases[$key_fixed]{'ROUTER'};
    $dhcpsettings{'FIXED_DNS'}      = $fixedleases[$key_fixed]{'DNS'};
}

if ($dhcpsettings{'ACTION'} eq $Lang::tr{'remove'} . '_fixed') {

    # simply set ENABLED to empty, writefixedleases will handle the gory details
    $fixedleases[$key_fixed]{'ENABLED'} = '';

    &General::log('dhcpd', $Lang::tr{'fixed ip lease removed'});
    $dhcpsettings{'KEY_FIXED'} = '';    # forget we were editing something
    &writefixedleases(1);
}

if ($dhcpsettings{'ACTION'} eq 'ADD_FIXED_LEASE') {

    # Button to add fixed lease was pressed

    $disable_main                  = 1;
    $disable_fixed                 = 0;
    $dhcpsettings{'FIXED_ENABLED'} = 'on';    # on per default
}

if ($dhcpsettings{'ACTION'} eq $Lang::tr{'add new lease'}) {

    # Add fixed lease from list of actual leases

    if ($dhcpsettings{'ADD_FROM_LIST'} =~ /^(\d+\.\d+\.\d+\.\d+)!([0-9a-fA-F:]+)!(.*)$/) {
        my $ip  = $1;
        my $mac = $2;
        my $hostname = ($3 ne '*') ? $3 : '';
        my $comment = 'imported';

        $dhcpsettings{'FIXED_MAC'}      = $mac;
        $dhcpsettings{'FIXED_REMARK'}   = $comment;
        $dhcpsettings{'FIXED_HOSTNAME'} = $hostname;

        # Button to add fixed lease from DHCP dynamic list was pressed

        $disable_main                  = 1;
        $disable_fixed                 = 0;
        $dhcpsettings{'FIXED_ENABLED'} = 'on';    # on per default
    }
}

if ($dhcpsettings{'ACTION'} eq 'SAVE_FIXED_LEASE') {

    # Verify the options before writing anything

    $dhcpsettings{'FIXED_REMARK'} = &Header::cleanhtml($dhcpsettings{'FIXED_REMARK'});

    # Remove some characters not allowed in filenames,
    # and commas which will break CSV config files.
    $dhcpsettings{'FIXED_FILENAME'} =~ s/[<">?|*;&`,]//g;
    $dhcpsettings{'FIXED_ROOTPATH'} =~ s/[<">?|*;&`,]//g;

    if (($dhcpsettings{'FIXED_MAC'} eq '') && ($dhcpsettings{'FIXED_HOSTNAME'} eq '')) {
        $errormessage = $Lang::tr{'dhcp fixed lease err1'};
        goto ERROR_SAVE_FIXED;
    }

    if ($dhcpsettings{'FIXED_MAC'}) {
        $dhcpsettings{'FIXED_MAC'} =~ tr/-/:/;
        if (!&General::validmac($dhcpsettings{'FIXED_MAC'})) {
            $errormessage = $Lang::tr{'invalid fixed mac address'};
            goto ERROR_SAVE_FIXED;
        }
    }

    if ($dhcpsettings{'FIXED_HOSTNAME'}) {
        # This could be a hostname, or a FQDN
        if (!&General::validhostname($dhcpsettings{'FIXED_HOSTNAME'}) &&
            !&General::validfqdn($dhcpsettings{'FIXED_HOSTNAME'})) {
            $errormessage = $Lang::tr{'invalid hostname'};
            goto ERROR_SAVE_FIXED;
        }
    }

    if ($dhcpsettings{'FIXED_ROUTER'}) {
        if (!&General::validip($dhcpsettings{'FIXED_ROUTER'})) {
            $errormessage = $Lang::tr{'invalid fixed ip address'} . " <b>router</b>";
            goto ERROR_SAVE_FIXED;
        }
    }
    if ($dhcpsettings{'FIXED_DNS'}) {
        if (!&General::validip($dhcpsettings{'FIXED_DNS'})) {
            $errormessage = $Lang::tr{'invalid fixed ip address'} . " <b>DNS server</b>";
            goto ERROR_SAVE_FIXED;
        }
    }

    if ($dhcpsettings{'FIXED_NEXTADDR'}) {
        if (!&General::validip($dhcpsettings{'FIXED_NEXTADDR'})) {
            $errormessage = $Lang::tr{'invalid fixed ip address'} . " <b>next-server</b>";
            goto ERROR_SAVE_FIXED;
        }
    }

    if (!&General::validip($dhcpsettings{'FIXED_IP'})) {
        $errormessage = $Lang::tr{'invalid fixed ip address'};
        goto ERROR_SAVE_FIXED;
    }

    my $insubnet = 0;
    # IP must be in green or blue network
    foreach $interface (@INTERFACEs) {
        for ($counter = 1; $counter <= $netsettings{"${interface}_COUNT"}; $counter++) {
            $ic = "${interface}_${counter}";
            # Don't test on DHCP enabled for now
            # next if ($dhcpsettings{"ENABLED_${ic}"} ne 'on');

            if ($netaddressip{"${ic}"}->contains(NetAddr::IP->new($dhcpsettings{'FIXED_IP'}))) {
                $insubnet++;
            }
        }
    }
    if ($insubnet == 0) {
        $errormessage = $Lang::tr{'invalid fixed ip address'};
        goto ERROR_SAVE_FIXED;
    }

    my $id;
    # TODO: test for duplicate MAC addresses
    # Duplicate MAC is OK, as long as the to be assigned IP addresses are in different networks

    # Test for duplicate IP address
    if ($dhcpsettings{'FIXED_ENABLED'} eq 'on') {
        for $id (0 .. $#fixedleases) {
            if (($fixedleases[$id]{'ENABLED'} eq 'on') && ($dhcpsettings{'FIXED_IP'} eq $fixedleases[$id]{'IP'})) {
                # If we are editing, is it our own entry?
                next if (($dhcpsettings{'KEY_FIXED'} ne '') && ($key_fixed == $id));

                $errormessage = $Lang::tr{'duplicate ip'};
                goto ERROR_SAVE_FIXED;
            }
        }
    }

    # If we add a lease, set the key to last lease+1
    if ($dhcpsettings{'KEY_FIXED'} eq '') {
        $key_fixed = $#fixedleases + 1;
        &General::log('dhcpd', $Lang::tr{'fixed ip lease added'});
    }
    else {
        &General::log('dhcpd', $Lang::tr{'fixed ip lease modified'});
    }

    $fixedleases[$key_fixed]{'ENABLED'}  = $dhcpsettings{'FIXED_ENABLED'};
    $fixedleases[$key_fixed]{'MAC'}      = lc($dhcpsettings{'FIXED_MAC'});
    $fixedleases[$key_fixed]{'IP'}       = $dhcpsettings{'FIXED_IP'};
    $fixedleases[$key_fixed]{'REMARK'}   = $dhcpsettings{'FIXED_REMARK'};
    $fixedleases[$key_fixed]{'HOSTNAME'} = $dhcpsettings{'FIXED_HOSTNAME'};
    $fixedleases[$key_fixed]{'NEXTADDR'} = $dhcpsettings{'FIXED_NEXTADDR'};
    $fixedleases[$key_fixed]{'FILENAME'} = $dhcpsettings{'FIXED_FILENAME'};
    $fixedleases[$key_fixed]{'ROOTPATH'} = $dhcpsettings{'FIXED_ROOTPATH'};
    $fixedleases[$key_fixed]{'ROUTER'}   = $dhcpsettings{'FIXED_ROUTER'};
    $fixedleases[$key_fixed]{'DNS'}      = $dhcpsettings{'FIXED_DNS'};

    $dhcpsettings{'KEY_FIXED'} = '';    # forget we were editing something
    &writefixedleases(1);

ERROR_SAVE_FIXED:
    if ($errormessage) {
        $error_save_fixed = 'error';
        $disable_main     = 1;
        $disable_fixed    = 0;
    }
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
&Header::openbox('100%', 'left', "$Lang::tr{'settings'}:", $error_save_main);
my $sactive = &General::isrunning('dhcpd', 'nosize');

print <<END
<form method='post' name='frm_main' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td width='25%'>$Lang::tr{'dhcp server'}:</td>
    $sactive
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr>
<tr>
    <td colspan='4'><hr /></td>
</tr>
END
;

foreach $interface (@INTERFACEs) {
    for ($counter = 1; $counter <= $netsettings{"${interface}_COUNT"}; $counter++) {
        my $lc_interface = lc($interface);
        $ic = "${interface}_${counter}";
        $checked{'ENABLED'}{'on'} = ($dhcpsettings{"ENABLED_${ic}"} ne 'on') ? '' : "checked='checked'";
        $checked{'ENABLED_BOOTP'}{'on'} = ($dhcpsettings{"ENABLED_BOOTP_${ic}"} ne 'on') ? '' : "checked='checked'";
        my $disable_text = '';
        $disable_text = "disabled='disabled'" if ($disable_main == 1);
        my $blob = "/blob.gif";
        $blob = "/images/null.gif" if ($disable_main == 1);

        print <<END
<tr>
    <td width='25%' class='boldbase'><span class='ipcop_iface_$lc_interface'>$Lang::tr{"$lc_interface"}</span></td>
    <td width='25%' class='base'>$Lang::tr{'enabled'}:<input type='checkbox' name='ENABLED_${ic}' $checked{'ENABLED'}{'on'} $disable_text /></td>
    <td width='25%' class='base'>$Lang::tr{'ip address'}/$Lang::tr{'netmask'}:</td>
    <td width='25%' class='base'><b>$netsettings{"${ic}_ADDRESS"}/$netsettings{"${ic}_NETMASK"}</b></td>
</tr><tr>
    <td width='25%' class='base'>$Lang::tr{'start address'}:&nbsp;<img src='$blob' alt='*' /></td>
    <td width='25%'><input type='text' name='START_ADDR_${ic}' value='$dhcpsettings{"START_ADDR_${ic}"}' $disable_text /></td>
    <td width='25%' class='base'>$Lang::tr{'end address'}:&nbsp;<img src='$blob' alt='*' /></td>
    <td width='25%'><input type='text' name='END_ADDR_${ic}' value='$dhcpsettings{"END_ADDR_${ic}"}' $disable_text /></td>
</tr>
END
        ;
        if ($disable_main == 0) {
            print <<END
<tr>
    <td class='base'>$Lang::tr{'default lease time'}:</td>
    <td><input type='text' name='DEFAULT_LEASE_TIME_${ic}' value='$dhcpsettings{"DEFAULT_LEASE_TIME_${ic}"}' size='5' /></td>
    <td class='base'>$Lang::tr{'domain name suffix'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='DOMAIN_NAME_${ic}' value='$dhcpsettings{"DOMAIN_NAME_${ic}"}' /></td>
</tr><tr>
    <td>$Lang::tr{'dhcp allow bootp'}:</td>
    <td><input type='checkbox' name='ENABLED_BOOTP_${ic}' $checked{'ENABLED_BOOTP'}{'on'} /></td>
    <td>&nbsp;</td><td>&nbsp;</td>
</tr><tr>
    <td class='base'>$Lang::tr{'primary dns'}:</td>
    <td><input type='text' name='DNS1_${ic}' value='$dhcpsettings{"DNS1_${ic}"}' /></td>
    <td class='base'>$Lang::tr{'secondary dns'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='DNS2_${ic}' value='$dhcpsettings{"DNS2_${ic}"}' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'primary ntp server'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='NTP1_${ic}' value='$dhcpsettings{"NTP1_${ic}"}' /></td>
    <td class='base'>$Lang::tr{'secondary ntp server'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='NTP2_${ic}' value='$dhcpsettings{"NTP2_${ic}"}' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'primary wins server address'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='WINS1_${ic}' value='$dhcpsettings{"WINS1_${ic}"}' /></td>
    <td class='base'>$Lang::tr{'secondary wins server address'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='WINS2_${ic}' value='$dhcpsettings{"WINS2_${ic}"}' /></td>
</tr>
END
            ;
        }
        print "<tr><td colspan='4'><hr /></td></tr>";
    }
}

print "</table>";

if ($disable_main == 1) {
    print "</form>";
}
else {
    print <<END
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' align='top' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button1button'><input type='hidden' class='commonbuttons' name='ACTION' value='SAVE_MAIN' /><input type='submit' name='SUBMIT' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-dhcp.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a></td>
</tr>
</table>
</form>
END
        ;
}
&Header::closebox();

#
# display box with fixed leases
#

if ($disable_fixed == 0) {
    $checked{'FIXED_ENABLED'}{'on'} = ($dhcpsettings{'FIXED_ENABLED'} ne 'on') ? '' : "checked='checked'";

    # if KEY_FIXED is set, this is edit/update not add

    if ($dhcpsettings{'KEY_FIXED'} ne '') {
        $buttontext  = $Lang::tr{'update'};
        &Header::openbox('100%', 'left', "$Lang::tr{'edit an existing lease'}:", $error_save_fixed);
    }
    else {
        &Header::openbox('100%', 'left', "$Lang::tr{'add new lease'}:", $error_save_fixed);
    }

    print <<END
<form method='post' name='frm_fixed' action='$ENV{'SCRIPT_NAME'}'>
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
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' align='top' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}
        &nbsp;&nbsp;$Lang::tr{'dhcp fixed lease help1'}</td>
    <td class='button1button'><input type='hidden' name='ACTION' value='SAVE_FIXED_LEASE' />
        <input type='hidden' class='commonbuttons' name='KEY_FIXED' value='$dhcpsettings{'KEY_FIXED'}' />
        <input type='submit' class='commonbuttons' name='SUBMIT' value='$buttontext' /></td>
    <td class='onlinehelp'>&nbsp;</td>
</tr>
</table>
</form>
END
        ;
}
else {
    &Header::openbox('100%', 'left', "$Lang::tr{'current fixed leases'}:", $error_save_fixed);

    print <<END
<form method='post' name='frm_fixed_add' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'>
        <img src='/images/null.gif' width='21' height='1' alt='' />
        <input type='hidden' class='commonbuttons' name='ACTION' value='ADD_FIXED_LEASE' />
        <input type='submit' class='commonbuttons' name='SUBMIT' value='$Lang::tr{'add new lease'}' />
    </td>
    <td class='onlinehelp'>&nbsp;</td>
</tr>
</table>
&nbsp;&nbsp;
</form>
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
<hr /><table width='100%'>
<tr>
    <td width='13%' align='center' nowrap='nowrap'><a href='$ENV{'SCRIPT_NAME'}?FIXEDMAC'><b>$Lang::tr{'mac address'}</b></a> $sortarrow1</td>
    <td width='13%' align='center' nowrap='nowrap'><a href='$ENV{'SCRIPT_NAME'}?FIXEDIP'><b>$Lang::tr{'ip address'}</b></a> $sortarrow2</td>
    <td width='14%' class='boldbase' align='center'><b>$Lang::tr{'hostname'}</b></td>
    <td width='15%' align='center'><b>$Lang::tr{'remark'}</b></td>
    <td width='15%' class='boldbase' align='center'><b>next-server</b></td>
    <td width='15%' class='boldbase' align='center'><b>filename</b></td>
    <td width='15%' class='boldbase' align='center'><b>root-path</b></td>
    <td colspan='3' class='boldbase' align='center'><b>$Lang::tr{'action'}</b></td>
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

<td align='center'>
    <form method='post' name='frm_fixed_ted_$key' action='$ENV{'SCRIPT_NAME'}'>
    <input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}_fixed' />
    <input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif' alt='$gdesc' title='$gdesc' />
    <input type='hidden' name='KEY_FIXED' value='$key' />
    </form>
</td>

<td align='center'>
    <form method='post' name='frm_fixed_e_$key' action='$ENV{'SCRIPT_NAME'}'>
    <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}_fixed' />
    <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
    <input type='hidden' name='KEY_FIXED' value='$key' />
    </form>
</td>

<td align='center'>
    <form method='post' name='frm_fixed_r_$key' action='$ENV{'SCRIPT_NAME'}'>
    <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}_fixed' />
    <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
    <input type='hidden' name='KEY_FIXED' value='$key' />
    </form>
</td>
</tr>
END
    ;
}    # for all fixed leases

print "</table>";

# If the fixed leases file contains entries, print a legend
if (defined($fixedleases[0]{'IP'}) && $disable_fixed) {
    print <<END
<table>
<tr>
    <td class='boldbase'>&nbsp;<b>$Lang::tr{'legend'}:&nbsp;</b></td>
    <td><img src='/images/on.gif' alt='$Lang::tr{'click to disable'}' /></td>
    <td class='base'>$Lang::tr{'click to disable'}</td>
    <td>&nbsp;&nbsp;</td>
    <td><img src='/images/off.gif' alt='$Lang::tr{'click to enable'}' /></td>
    <td class='base'>$Lang::tr{'click to enable'}</td>
    <td>&nbsp;&nbsp;</td>
    <td><img src='/images/edit.gif' alt='$Lang::tr{'edit'}' /></td>
    <td class='base'>$Lang::tr{'edit'}</td>
    <td>&nbsp;&nbsp;</td>
    <td><img src='/images/delete.gif' alt='$Lang::tr{'remove'}' /></td>
    <td class='base'>$Lang::tr{'remove'}</td>
</tr>
</table>
END
    ;
}

&Header::closebox();

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

&Header::closebigbox();
&Header::closepage();

#
# write config files, dhcpd.conf etc.
#
sub writeconfig {
    my %savesettings = ();
    # dnsmasq default value for max. number of leases is 150, too small for larger networks
    # we will set it to the max. number of possible IP addresses minus network and broadcast addresses
    my $leasemax = 0;

    # copy the relevant settings into a duplicate hash, otherwise we'd need to undef loads of stuff
    foreach $interface (@INTERFACEs) {
        for ($counter = 1; $counter <= $netsettings{"${interface}_COUNT"}; $counter++) {
            $ic = "${interface}_${counter}";
            $savesettings{"ENABLED_${ic}"}            = $dhcpsettings{"ENABLED_${ic}"};
            $savesettings{"ENABLED_BOOTP_${ic}"}      = $dhcpsettings{"ENABLED_BOOTP_${ic}"};
            $savesettings{"START_ADDR_${ic}"}         = $dhcpsettings{"START_ADDR_${ic}"};
            $savesettings{"END_ADDR_${ic}"}           = $dhcpsettings{"END_ADDR_${ic}"};
            $savesettings{"DOMAIN_NAME_${ic}"}        = $dhcpsettings{"DOMAIN_NAME_${ic}"};
            $savesettings{"DEFAULT_LEASE_TIME_${ic}"} = $dhcpsettings{"DEFAULT_LEASE_TIME_${ic}"};
            $savesettings{"DNS1_${ic}"}               = $dhcpsettings{"DNS1_${ic}"};
            $savesettings{"DNS2_${ic}"}               = $dhcpsettings{"DNS2_${ic}"};
            $savesettings{"WINS1_${ic}"}              = $dhcpsettings{"WINS1_${ic}"};
            $savesettings{"WINS2_${ic}"}              = $dhcpsettings{"WINS2_${ic}"};
            $savesettings{"NTP1_${ic}"}               = $dhcpsettings{"NTP1_${ic}"};
            $savesettings{"NTP2_${ic}"}               = $dhcpsettings{"NTP2_${ic}"};

            if ($savesettings{"ENABLED_${ic}"} eq 'on') {
                $leasemax += $netaddressip{"${ic}"}->num();
            }
        }
    }
    $savesettings{'SORT_FIXEDLEASELIST'} = $dhcpsettings{'SORT_FIXEDLEASELIST'};
    &General::writehash('/var/ofw/dhcp/settings', \%savesettings);

    # only wanted to change (and save) sort order, no need to touch the dnsmasq file
    return if ($_[0] == 0);

    open(FILE, ">/var/ofw/dhcp/dnsmasq.conf") or die "Unable to write dhcp server conf file";
    flock(FILE, 2);

    # Global settings
    print FILE <<END
# Do not modify '/var/ofw/dhcp/dnsmasq.conf' directly since any changes
# you make will be overwritten whenever you resave dhcp settings using the
# web interface!
# Instead modify the file '/var/ofw/dhcp/dnsmasq.local' and then restart
# the DHCP server using the web interface or restartdhcp.
# Changes made to the 'local' file will then propagate to the DHCP server.

# some global settings
pid-file=/var/run/dnsmasq/dnsmasq.pid
bind-interfaces
except-interface=wan-1
except-interface=ppp0
except-interface=dmz-1
no-poll
domain-needed
dhcp-authoritative
dhcp-lease-max=$leasemax
dhcp-leasefile=/var/run/dnsmasq/dnsmasq.leases
dhcp-hostsfile=/var/ofw/dhcp/dnsmasq.statichosts
dhcp-optsfile=/var/ofw/dhcp/dnsmasq.staticopts
conf-file=/var/ofw/dhcp/dnsmasq.local

# Enable this if you want to see DNS queries and results
# log-queries
# Enable this if you want to see all DHCP options sent to clients (lots of logging!)
# log-dhcp

END
    ;

    # Interface definitions
    foreach $interface (@INTERFACEs) {
        for ($counter = 1; $counter <= $netsettings{"${interface}_COUNT"}; $counter++) {
            $ic = "${interface}_${counter}";
            if ($savesettings{"ENABLED_${ic}"} eq 'on') {
                my $lease = $savesettings{"DEFAULT_LEASE_TIME_${ic}"} * 60;

                print FILE "# network: ${interface} - ${counter}, ".$netaddressip{"${ic}"}."\n";
                if ($savesettings{"START_ADDR_${ic}"}) {
                    print FILE "dhcp-range=${ic},"
                        . $savesettings{"START_ADDR_${ic}"} . ","
                        . $savesettings{"END_ADDR_${ic}"}
                        . ",$lease\n";
                }
                else {
                    print FILE "dhcp-range=${ic},"
                        . $netsettings{"${ic}_ADDRESS"}
                        . ",static,$lease\n";
                }
                if ($savesettings{"DOMAIN_NAME_${ic}"}) {
                    print FILE "dhcp-option=${ic},option:domain-name,"
                        . $savesettings{"DOMAIN_NAME_${ic}"} . "\n";
                }

                # bootp enabled
                if ($savesettings{"ENABLED_BOOTP_${ic}"} eq 'on') {
                    print FILE "bootp-dynamic=${ic}\n";
                }

                # DNS server(s)
                print FILE "dhcp-option=${ic},option:dns-server,"
                    . $savesettings{"DNS1_${ic}"};
                print FILE "," . $savesettings{"DNS2_${ic}"}
                    if ($savesettings{"DNS2_${ic}"});
                print FILE "\n";

                # WINS server(s)
                if ($savesettings{"WINS1_${ic}"}) {
                    print FILE "dhcp-option=${ic},option:netbios-ns,"
                        . $savesettings{"WINS1_${ic}"};
                    print FILE "," . $savesettings{"WINS2_${ic}"}
                        if ($savesettings{"WINS2_${ic}"});
                    print FILE "\n";
                }

                # NTP server(s)
                if ($savesettings{"NTP1_${ic}"}) {
                    print FILE "dhcp-option=${ic},option:ntp-server,"
                        . $savesettings{"NTP1_${ic}"};
                    print FILE "," . $savesettings{"NTP2_${ic}"}
                        if ($savesettings{"NTP2_${ic}"});
                    print FILE "\n";
                }

                print FILE "\n";

                &General::log('dhcpd', $netsettings{"${ic}_DEV"}.": ".$Lang::tr{'dhcp server enabled'});
            }
            else {
                &General::log('dhcpd', $netsettings{"${ic}_DEV"}.": ".$Lang::tr{'dhcp server disabled'});
            }
        }    # interface counter
    }    # for some interfaces
    close FILE;

    system '/usr/local/bin/restartdhcp';
}


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


sub writefixedleases {
    my $id;

    open(FILE, ">/var/ofw/dhcp/fixedleases") or die 'Unable to open fixed leases file.';
    for $id (0 .. $#fixedleases) {
        next if (($fixedleases[$id]{'ENABLED'} ne 'on') && ($fixedleases[$id]{'ENABLED'} ne 'off'));

        print FILE "$fixedleases[$id]{'MAC'},$fixedleases[$id]{'IP'},";
        print FILE "$fixedleases[$id]{'ENABLED'},$fixedleases[$id]{'NEXTADDR'},";
        print FILE "$fixedleases[$id]{'FILENAME'},$fixedleases[$id]{'ROOTPATH'},";
        print FILE "$fixedleases[$id]{'REMARK'},$fixedleases[$id]{'HOSTNAME'},";
        print FILE "$fixedleases[$id]{'ROUTER'},$fixedleases[$id]{'DNS'}\n";
    }
    close FILE;


    # sort
    if ($dhcpsettings{'SORT_FIXEDLEASELIST'} eq 'FIXEDMAC') {
        system "/usr/bin/sort -t ',' -k 1,1 /var/ofw/dhcp/fixedleases -o /var/ofw/dhcp/fixedleases";
    }
    elsif ($dhcpsettings{'SORT_FIXEDLEASELIST'} eq 'FIXEDMACRev') {
        system "/usr/bin/sort -r -t ',' -k 1,1 /var/ofw/dhcp/fixedleases -o /var/ofw/dhcp/fixedleases";
    }
    elsif ($dhcpsettings{'SORT_FIXEDLEASELIST'} eq 'FIXEDIPRev') {
        system "/usr/bin/sort -r -n -t '.' -k 1.18,1 -k 2,2 -k 3,3 -k 4,4 /var/ofw/dhcp/fixedleases -o /var/ofw/dhcp/fixedleases";
    }
    else {
        # FIXEDIP is also default when no sorting selected (yet)
        system "/usr/bin/sort -n -t '.' -k 1.18,1 -k 2,2 -k 3,3 -k 4,4 /var/ofw/dhcp/fixedleases -o /var/ofw/dhcp/fixedleases";
    }

    &readfixedleases();

    # only wanted to change (and save) sort order, no need to touch the dnsmasq file
    return if ($_[0] == 0);

    # now write the fixed leases file for dnsmasq
    open(FILEHOSTS, ">/var/ofw/dhcp/dnsmasq.statichosts") or die "Unable to write dhcp server hosts file";
    open(FILEOPTS, ">/var/ofw/dhcp/dnsmasq.staticopts") or die "Unable to write dhcp server opts file";
    for $id (0 .. $#fixedleases) {
        if ($fixedleases[$id]{'ENABLED'} eq "on") {
            my @fqdn = split(/\./, $fixedleases[$id]{'HOSTNAME'}, 2);

            if (!$fixedleases[$id]{'MAC'}) {
                print FILEHOSTS "$fqdn[0],$fixedleases[$id]{'IP'}\n";
            }
            else {
                print FILEHOSTS "$fixedleases[$id]{'MAC'},net:STATIC_$id,$fixedleases[$id]{'IP'}";
                print FILEHOSTS ",$fqdn[0]" if ($fqdn[0]);
                print FILEHOSTS "\n";
            }
            print FILEOPTS "net:STATIC_$id,option:bootfile-name,$fixedleases[$id]{'FILENAME'}\n" if ($fixedleases[$id]{'FILENAME'} ne '');
            print FILEOPTS "net:STATIC_$id,option:server-ip-address,$fixedleases[$id]{'NEXTADDR'}\n" if ($fixedleases[$id]{'NEXTADDR'} ne '');
            print FILEOPTS "net:STATIC_$id,option:root-path,$fixedleases[$id]{'ROOTPATH'}\n" if ($fixedleases[$id]{'ROOTPATH'} ne '');
            print FILEOPTS "net:STATIC_$id,option:router,$fixedleases[$id]{'ROUTER'}\n" if ($fixedleases[$id]{'ROUTER'} ne '');
            print FILEOPTS "net:STATIC_$id,option:dns-server,$fixedleases[$id]{'DNS'}\n" if ($fixedleases[$id]{'DNS'} ne '');
        }
    }
    close FILEHOSTS;
    close FILEOPTS;

    system '/usr/local/bin/restartdhcp --sighup';
}
