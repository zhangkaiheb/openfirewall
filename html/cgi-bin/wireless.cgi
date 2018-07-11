#!/usr/bin/perl
#
# This file is part of the IPCop Firewall.
#
# IPCop is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# IPCop is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IPCop.  If not, see <http://www.gnu.org/licenses/>.
#
# (c) 2003 Alan Hourihane <alanh@fairlite.demon.co.uk>
# (c) 2005 Eric Oberlander, Robert Kerr - Inline editing & DHCP leases
# (c) 2008-2014, the IPCop team
#
# $Id: wireless.cgi 7240 2014-02-18 22:08:00Z owes $
#

# Add entry in menu
# MENUENTRY firewall 020 "addressfilter" "addressfilter" haveBlue
#
# Make sure translation exists $Lang::tr{'addressfilter'}

use strict;
use Time::Local;

# enable only the following on debugging purpose
use warnings; no warnings 'once';# 'redefine', 'uninitialized';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

my $debug        = 0;
my %cgiparams    = ();
my %checked      = ();
my $errormessage = '';
my %dhcpsettings = ();
my %netsettings  = ();
our @wireless    = ();

my $counter;
my $line;
my $id;
my $key;

$cgiparams{'ENABLED'}    = 'on';
$cgiparams{'ACTION'}     = '';
$cgiparams{'VALID'}      = '';
$cgiparams{'SOURCE_IP'}  = '';
$cgiparams{'SOURCE_MAC'} = '';
$cgiparams{'REMARK'}     = '';
$cgiparams{'EDITING'}    = 'no';
$cgiparams{'ID'}         = -1;

&General::getcgihash(\%cgiparams);
$id = $cgiparams{'ID'};

&General::readhash('/var/ipcop/dhcp/settings',     \%dhcpsettings);
&General::readhash('/var/ipcop/ethernet/settings', \%netsettings);
&readSettings();

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'addressfilter'}, 1, '');

&Header::openbigbox('100%', 'left', '');

###############
# DEBUG DEBUG
if ($debug) {
    &Header::openbox('100%', 'left', 'DEBUG');
    my $debugCount = 0;
    foreach my $line (sort keys %cgiparams) {
        print "$line = $cgiparams{$line}<br />\n";
        $debugCount++;
    }
    print "&nbsp;Count: $debugCount\n";
    &Header::closebox();
}

# DEBUG DEBUG
###############

if ($cgiparams{'ACTION'} eq 'add') {

    # Verify the input data

    # An IP address or a MAC address, or both, are required.
    if ($cgiparams{'SOURCE_IP'} eq '' && $cgiparams{'SOURCE_MAC'} eq '') {
        $errormessage = $Lang::tr{'invalid ip'} . " " . $Lang::tr{'or'} . " " . $Lang::tr{'invalid mac'};
        goto ADDERROR;
    }

    $cgiparams{'SOURCE_MAC'} =~ tr/-/:/;

    for $key (0 .. $#wireless) {
        if ($wireless[$key]{'IP'} ne '' && $cgiparams{'SOURCE_IP'} eq $wireless[$key]{'IP'} && $cgiparams{'EDITING'} ne $key) {
            $errormessage = $Lang::tr{'duplicate ip'};
            goto ADDERROR;
        }
        if ($wireless[$key]{'MAC'} ne '' && lc($cgiparams{'SOURCE_MAC'}) eq lc($wireless[$key]{'MAC'}) && $cgiparams{'EDITING'} ne $key) {
            $errormessage = $Lang::tr{'duplicate mac'};
            goto ADDERROR;
        }
    }

    if ($cgiparams{'SOURCE_IP'} eq '') {
        $cgiparams{'SOURCE_IP'} = 'NONE';
    }
    else {
        unless (&General::validip($cgiparams{'SOURCE_IP'})) {
            $errormessage = $Lang::tr{'invalid ip'};
            goto ADDERROR;
        }
        else {
            my $insubnet = 0;

            # IP must be in a blue subnet
            for ($counter = 1; $counter <= $netsettings{'BLUE_COUNT'}; $counter++) {
                if (&General::IpInSubnet($cgiparams{'SOURCE_IP'},
                        $netsettings{"BLUE_${counter}_NETADDRESS"},
                        $netsettings{"BLUE_${counter}_NETMASK"})) {
                    $insubnet++;
                }
            }
            if ($insubnet == 0) {
                $errormessage = $Lang::tr{'invalid addressfilter ip blue'};
                goto ADDERROR;
            }
        }
    }

    if ($cgiparams{'SOURCE_MAC'} eq '') {
        $cgiparams{'SOURCE_MAC'} = 'NONE';
    }
    else {
        unless (&General::validmac($cgiparams{'SOURCE_MAC'})) {
            $errormessage = $Lang::tr{'invalid mac'};
        }
    }

ADDERROR:
    if ($errormessage) {
        $cgiparams{'SOURCE_MAC'} = '' if $cgiparams{'SOURCE_MAC'} eq 'NONE';
        $cgiparams{'SOURCE_IP'}  = '' if $cgiparams{'SOURCE_IP'}  eq 'NONE';
    }
    else {
        $cgiparams{'REMARK'} = &Header::cleanhtml($cgiparams{'REMARK'});
        if ($cgiparams{'EDITING'} eq 'no') {
            $key = $#wireless + 1;
            $wireless[$key]{'ID'} = 9999;
        }
        else {
            $key = $cgiparams{'EDITING'};
        }
        $wireless[$key]{'IP'} = $cgiparams{'SOURCE_IP'};
        $wireless[$key]{'MAC'} = $cgiparams{'SOURCE_MAC'};
        $wireless[$key]{'ENABLED'} = $cgiparams{'ENABLED'};
        $wireless[$key]{'REMARK'} = $cgiparams{'REMARK'};

        &writeSettings();
        if ($cgiparams{'EDITING'} eq 'no') {
            &General::log($Lang::tr{'wireless config added'});
        }
        else {
            &General::log($Lang::tr{'wireless config changed'});
        }
        `/usr/local/bin/setfwrules --wireless < /dev/null > /dev/null 2>&1 &`;

        # Restore defaults for next entry (if any)
        undef %cgiparams;
        $cgiparams{'ENABLED'} = 'on';
        $id = -1;
    }
ADDEXIT:
}

if ($cgiparams{'ACTION'} eq 'edit') {
    $cgiparams{'SOURCE_IP'}  = $wireless[$id]{'IP'};
    $cgiparams{'SOURCE_MAC'} = $wireless[$id]{'MAC'};
    $cgiparams{'ENABLED'}    = $wireless[$id]{'ENABLED'};
    $cgiparams{'REMARK'}     = $wireless[$id]{'REMARK'};
    $cgiparams{'SOURCE_IP'}  = '' if $cgiparams{'SOURCE_IP'} eq 'NONE';
    $cgiparams{'SOURCE_MAC'} = '' if $cgiparams{'SOURCE_MAC'} eq 'NONE';
}


if ($cgiparams{'ACTION'} eq 'toggle') {

    # Toggle enable/disable field on specified fixed lease
    if ($wireless[$id]{'ENABLED'} eq 'on') {
        $wireless[$id]{'ENABLED'} = 'off';
    }
    else {
        $wireless[$id]{'ENABLED'} = 'on';
    }

    &writeSettings();
    &General::log($Lang::tr{'wireless config changed'});
    `/usr/local/bin/setfwrules --wireless < /dev/null > /dev/null 2>&1 &`;
    $id = -1;
}


if ($cgiparams{'ACTION'} eq 'remove') {

    $wireless[$id]{'ENABLED'} = '';

    &writeSettings();
    &General::log($Lang::tr{'wireless config changed'});
    `/usr/local/bin/setfwrules --wireless < /dev/null > /dev/null 2>&1 &`;
    $id = -1;
}

$checked{'ENABLED'}{'off'}                 = '';
$checked{'ENABLED'}{'on'}                  = '';
$checked{'ENABLED'}{$cgiparams{'ENABLED'}} = "checked='checked'";

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();
}

print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";

my $buttontext = $Lang::tr{'add'};
if ($cgiparams{'ACTION'} eq 'edit') {
    &Header::openbox('100%', 'left', "$Lang::tr{'edit device'}");
    $buttontext = $Lang::tr{'update'};
}
else {
    &Header::openbox('100%', 'left', "$Lang::tr{'add device'}");
}

print <<END
<table width='100%'>
<tr>
<td width='25%' class='base'>$Lang::tr{'ip address'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
<td width='25%'><input type='text' name='SOURCE_IP' value='$cgiparams{'SOURCE_IP'}' size='20' /></td>
<td width='25%' align='right' class='base'>$Lang::tr{'mac address'}:&nbsp;<img src='/blob.gif' alt='*' />&nbsp;</td>
<td width='25%'><input type='text' name='SOURCE_MAC' value='$cgiparams{'SOURCE_MAC'}' size='20' /></td>
</tr>
<tr>
<td width='25%' class='base'>$Lang::tr{'remark'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
<td colspan='3'><input type='text' name='REMARK' value='$cgiparams{'REMARK'}' size='40' /></td>
</tr>
<tr>
<td width='25%' class='base'>$Lang::tr{'enabled'}:&nbsp;</td>
<td colspan='3'><input type='checkbox' name='ENABLED' $checked{'ENABLED'}{'on'} /></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><strong>$Lang::tr{'note'}:</strong>&nbsp;$Lang::tr{'addressfilter use hint'}</td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td class='comment1button'>
      <img src='/blob.gif' alt='*' />
      $Lang::tr{'this field may be blank'}</td>
    <td class='button1button'>
      <input type='hidden' name='ACTION' value='add' />
      <input type='submit' name='SUBMIT' value='$buttontext' />
    </td>
    <td class='onlinehelp'>
    <a href='${General::adminmanualurl}/firewall-blue-access.html' target='_blank'>
    <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a></td>
</tr>
</table>
END
    ;

if ($cgiparams{'ACTION'} eq 'edit') {
    print "<input type='hidden' name='EDITING' value='$cgiparams{'ID'}' />\n";
}
else {
    print "<input type='hidden' name='EDITING' value='no' />\n";
}

&Header::closebox();

print "</form>\n";

&Header::openbox('100%', 'left', "$Lang::tr{'devices on blue'}");
print <<END
<div align='center'>
END
;

print <<END
<table width='100%'>
<tr>
<td align='center' width='20%'><b>$Lang::tr{'ip address'}</b> $Header::sortup</td>
<td align='center' width='20%'><b>$Lang::tr{'mac address'}</b></td>
<td align='center' width='55%'><b>$Lang::tr{'remark'}</b></td>
<td align='center' colspan='3'><b>$Lang::tr{'action'}</b></td>
</tr>
END
    ;

for $key (0 .. $#wireless) {
    my $gif   = '';
    my $gdesc = '';

    if ($wireless[$key]{'ENABLED'} eq "on") {
        $gif   = 'on.gif';
        $gdesc = $Lang::tr{'click to disable'};
    }
    else {
        $gif   = 'off.gif';
        $gdesc = $Lang::tr{'click to enable'};
    }

    if ($id eq $key) {
        print "<tr class='selectcolour'>";
    }
    else {
        print "<tr class='table".int(($key % 2) + 1)."colour'>";
    }

    print <<END
<td align='center'>$wireless[$key]{IP}</td>
<td align='center'>$wireless[$key]{MAC}</td>
<td align='center'>$wireless[$key]{REMARK}</td>
<td align='center'>
	<form method='post' name='frma$key' action='$ENV{'SCRIPT_NAME'}'>
	<input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif' alt='$gdesc' title='$gdesc' />
	<input type='hidden' name='ACTION' value='toggle' />
	<input type='hidden' name='ID' value='$key' />
	</form>
</td>

<td align='center'>
	<form method='post' name='frmb$key' action='$ENV{'SCRIPT_NAME'}'>
	<input type='hidden' name='ACTION' value='edit' />
	<input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
	<input type='hidden' name='ID' value='$key' />
	</form>
</td>

<td align='center'>
	<form method='post' name='frmc$key' action='$ENV{'SCRIPT_NAME'}'>
	<input type='hidden' name='ACTION' value='remove' />
	<input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
	<input type='hidden' name='ID' value='$key' />
	</form>
</td>
END
        ;
    print "</tr>\n";
}
print "</table>\n";

print "</div>\n";

&Header::closebox();

my $haveBlueDHCP = 0;
for ($counter = 1; $counter <= $netsettings{'BLUE_COUNT'}; $counter++) {
    if ($dhcpsettings{"ENABLED_BLUE_${counter}"} eq 'on') {
        $haveBlueDHCP++;
    }
}

if ($haveBlueDHCP) {
    &printblueleases;
}

&Header::closebigbox();

&Header::closepage();

sub printblueleases {
    our %entries = ();

    sub blueleasesort {

        # Sort by IP address
        my $qs = 'IPADDR';
        my @a  = split(/\./, $entries{$a}->{$qs});
        my @b  = split(/\./, $entries{$b}->{$qs});
               ($a[0] <=> $b[0])
            || ($a[1] <=> $b[1])
            || ($a[2] <=> $b[2])
            || ($a[3] <=> $b[3]);
    }

    &Header::openbox('100%', 'left', "$Lang::tr{'current dhcp leases on blue'}");
    print <<END
<table width='100%'>
<tr>
<td width='25%' align='center'><b>$Lang::tr{'ip address'}</b> $Header::sortup</td>
<td width='25%' align='center'><b>$Lang::tr{'mac address'}</b></td>
<td width='20%' align='center'><b>$Lang::tr{'hostname'}</b></td>
<td width='30%' align='center'><b>$Lang::tr{'lease expires'} (local time d/m/y)</b></td>
</tr>
END
        ;

    my ($ip, $endtime, $ether, $hostname, @record, $record);
    open(LEASES, "/var/run/dnsmasq/dnsmasq.leases") or die "Can't open dhcpd.leases";
    while (my $line = <LEASES>) {
        next if ($line =~ /^\s*#/);
        chomp($line);
        my @temp = split(' ', $line);

        $endtime  = $temp[0];
        $ip       = $temp[2];
        $ether    = $temp[1];
        $hostname = $temp[3];

        # Select records in Blue subnet
        # TODO: prepare for multiple blues
        if (&General::IpInSubnet($ip, $netsettings{"BLUE_1_NETADDRESS"}, $netsettings{"BLUE_1_NETMASK"})) {
            @record = ('IPADDR', $ip, 'ENDTIME', $endtime, 'ETHER', $ether, 'HOSTNAME', $hostname);
            $record = {};    # create a reference to empty hash
            %{$record} = @record;    # populate that hash with @record
            $entries{$record->{'IPADDR'}} = $record;    # add this to a hash of hashes
        }
    }
    close(LEASES);

    my $id = 0;
    foreach my $key (sort blueleasesort keys %entries) {

        my $hostname = &Header::cleanhtml($entries{$key}->{HOSTNAME}, "y");
        my $tid = ($id % 2) + 1;

        print <<END
<tr class='table${tid}colour'>
<td align='center'>$entries{$key}->{IPADDR}</td>
<td align='center'>$entries{$key}->{ETHER}</td>
<td align='center'>&nbsp;$hostname </td>
<td align='center'>
END
            ;

        if ($entries{$key}->{ENDTIME} eq 'never') {
            print "$Lang::tr{'no time limit'}";
        }
        else {
            my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $dst);
            ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $dst) = localtime($entries{$key}->{ENDTIME});
            my $enddate = sprintf("%02d/%02d/%d %02d:%02d:%02d", $mday, $mon + 1, $year + 1900, $hour, $min, $sec);

            if ($entries{$key}->{ENDTIME} < time()) {
                print "<strike>$enddate</strike>";
            }
            else {
                print "$enddate";
            }
        }

        if ($hostname eq '') {
            $hostname = $Lang::tr{'device'};
        }

        # check if MAC address is already in list of devices
        my $macinlist = 0;
        for my $keywireless (0 .. $#wireless) {
            if (lc($wireless[$keywireless]{'MAC'}) eq lc($entries{$key}->{ETHER})) {

                # set flag to disable add device button
                $macinlist = 1;
                last;
            }
        }

        if ($macinlist < 1) {
            print <<END
</td>
<td align='center'>
	<form method='post' name='frmd$id' action='$ENV{'SCRIPT_NAME'}'>
	<input type='hidden' name='ACTION' value='add' />
	<input type='hidden' name='SOURCE_IP' value='' />
	<input type='hidden' name='SOURCE_MAC' value='$entries{$key}->{ETHER}' />
	<input type='hidden' name='REMARK' value='$hostname $Lang::tr{'added from dhcp lease list'}' />
	<input type='hidden' name='ENABLED' value='on' />
	<input type='hidden' name='EDITING' value='no' />
	<input type='image' name='$Lang::tr{'add device'}' src='/images/addblue.gif' alt='$Lang::tr{'add device'}' title='$Lang::tr{'add device'}' />
	</form>
</td></tr>
END
                ;
        }
        else {
            print <<END
</td>
<td>
	<img src='/images/addfaint.gif' alt='' width='20' />
</td></tr>
END
                ;
        }
        $id++;
    }

    print "</table>";
    &Header::closebox();
}


sub readSettings
{
    @wireless = ();
    open(FILE, '/var/ipcop/firewall/wireless');
    my @tmpfile = <FILE>;
    close(FILE);

    foreach $line (@tmpfile) {
        chomp($line);

        my @tmp = split(/\,/, $line);

        # These can be empty, make sure they exist to avoid warning messages
        $tmp[1] = '' unless defined $tmp[1];
        $tmp[2] = '' unless defined $tmp[2];
        $tmp[4] = '' unless defined $tmp[4];

        push @wireless, { ID => $tmp[0], IP => $tmp[1], MAC => $tmp[2],
            ENABLED => $tmp[3], REMARK => $tmp[4] };
    }
}


sub writeSettings {
    my $id;

    open(FILE, ">/var/ipcop/firewall/wireless") or die 'Unable to open Addressfilter file.';
    for $id (0 .. $#wireless) {
        next if (($wireless[$id]{'ENABLED'} ne 'on') && ($wireless[$id]{'ENABLED'} ne 'off'));

        print FILE "$id,$wireless[$id]{'IP'},$wireless[$id]{'MAC'},";
        print FILE "$wireless[$id]{'ENABLED'},$wireless[$id]{'REMARK'}\n";
    }
    close FILE;

    # sort wireless device list by IP address
    system "/usr/bin/sort -n -t '.' -k 2,2 -k 3,3 -k 4,4 /var/ipcop/firewall/wireless -o /var/ipcop/firewall/wireless";

    &readSettings();
}
