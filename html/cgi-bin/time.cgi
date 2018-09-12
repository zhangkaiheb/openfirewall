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
# (c) Darren Critchley June 2003 - added real time clock setting, etc
# (c) The Openfirewall Team January 2008 - redesigned for ntp-4.2.4
#
# $Id: time.cgi 7762 2014-12-29 08:13:26Z owes $
#

# Add entry in menu
# MENUENTRY services 060 "time server" "time server"
#
# Make sure translation exists $Lang::tr{'time server'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

our $conffile = '/var/ofw/time/ntp.conf';

my %timesettings=();
my %netsettings=();
my $errormessage = '';
my $error_settings ='';
my $error_instant = '';
my @ITFs=('GREEN','BLUE');

&Header::showhttpheaders();

$timesettings{'ACTION'} = '';
$timesettings{'NTP_VALID'} = '';

$timesettings{'ENABLED_NTP'} = 'off';
$timesettings{'ENABLED_NTP_REDIRECT'} = 'off';
$timesettings{'NTP_ADDR_1'} = '';
$timesettings{'NTP_ADDR_2'} = '';
$timesettings{'NTP_ADDR_3'} = '';
$timesettings{'SETHOUR'} = '';
$timesettings{'SETMINUTES'} = '';
$timesettings{'SETDAY'} = '';
$timesettings{'SETMONTH'} = '';
$timesettings{'SETYEAR'} = '';

&General::readhash('/var/ofw/ethernet/settings', \%netsettings);

&General::getcgihash(\%timesettings);

if ($timesettings{'ACTION'} eq $Lang::tr{'instant update'}) {
    if ($timesettings{'SETHOUR'} eq '' || $timesettings{'SETHOUR'} < 0 || $timesettings{'SETHOUR'} > 23) {
        $errormessage = $Lang::tr{'invalid time entered'};
        goto UPDTERROR;
    }
    if ($timesettings{'SETMINUTES'} eq '' || $timesettings{'SETMINUTES'} < 0 || $timesettings{'SETMINUTES'} > 59) {
        $errormessage = $Lang::tr{'invalid time entered'};
        goto UPDTERROR;
    }
    if ($timesettings{'SETDAY'} eq '' || $timesettings{'SETDAY'} < 1 || $timesettings{'SETDAY'} > 31) {
        $errormessage = $Lang::tr{'invalid date entered'};
        goto UPDTERROR;
    }
    if ($timesettings{'SETMONTH'} eq '' || $timesettings{'SETMONTH'} < 1 || $timesettings{'SETMONTH'} > 12) {
        $errormessage = $Lang::tr{'invalid date entered'};
        goto UPDTERROR;
    }
    if ($timesettings{'SETYEAR'} eq '' || $timesettings{'SETYEAR'} < 2008 || $timesettings{'SETYEAR'} > 2030) {
        $errormessage = $Lang::tr{'invalid date entered'};
        goto UPDTERROR;
    }

UPDTERROR:
    if ($errormessage) {
        $timesettings{'NTP_VALID'} = 'no'; }
    else {
        $timesettings{'NTP_VALID'} = 'yes'; }

    if ($timesettings{'NTP_VALID'} eq 'yes') {
        # we want date in YYYY-MM-DD HH:MM format for date command
        # EAO changed datestring to ISO 6801 format 2003-08-11
        my $datestring = "$timesettings{'SETYEAR'}-$timesettings{'SETMONTH'}-$timesettings{'SETDAY'}";
        my $timestring = "$timesettings{'SETHOUR'}:$timesettings{'SETMINUTES'}";
        # EAO setdate.c also revised for ISO 6801 date format 2003-08-11
        system ('/usr/local/bin/setdate', $datestring, $timestring);
        &General::log("$Lang::tr{'time date manually reset'} $datestring $timestring");
        # Restart service (if enabled etc.)
        system '/usr/local/bin/restartntpd';
    }
    else {
        $error_instant = 'error';
    }
    unless ($errormessage) {
        undef %timesettings;
    }
}

if ($timesettings{'ACTION'} eq $Lang::tr{'save'}) {
    if ($timesettings{'ENABLED_NTP'} eq "on") {
        # only do validation if NTP daemon is enabled

        if (!($timesettings{'NTP_ADDR_1'})) {
            $errormessage = $Lang::tr{'cannot enable ntp without specifying primary'};
            goto ERROR;
        }

        if (!($timesettings{'NTP_ADDR_1'}) && $timesettings{'NTP_ADDR_2'}) {
            $errormessage = $Lang::tr{'cannot specify secondary ntp without specifying primary'};
            goto ERROR;
        }

        if (!($timesettings{'NTP_ADDR_2'}) && $timesettings{'NTP_ADDR_3'}) {
            $errormessage = $Lang::tr{'cannot specify tertiary ntp without specifying secondary'};
            goto ERROR;
        }

        if (! (&General::validiporfqdn($timesettings{'NTP_ADDR_1'}))) {
            $errormessage = $Lang::tr{'invalid primary ntp'};
            goto ERROR;
        }

        if ($timesettings{'NTP_ADDR_2'} && ! (&General::validiporfqdn($timesettings{'NTP_ADDR_2'}))) {
            $errormessage = $Lang::tr{'invalid secondary ntp'};
            goto ERROR;
        }

        if ($timesettings{'NTP_ADDR_3'} && ! (&General::validiporfqdn($timesettings{'NTP_ADDR_3'}))) {
            $errormessage = $Lang::tr{'invalid tertiary ntp'};
            goto ERROR;
        }
    }

ERROR:
    if ($errormessage) {
        $timesettings{'NTP_VALID'} = 'no';
    }
    else {
        $timesettings{'NTP_VALID'} = 'yes';
    }

    &General::writehash('/var/ofw/time/settings', \%timesettings);

    if ($timesettings{'ENABLED_NTP'} eq 'on' && $timesettings{'NTP_VALID'} eq 'yes') {
        &General::log($Lang::tr{'ntp syncro enabled'});
    }
    else {
        &General::log($Lang::tr{'ntp syncro disabled'})
    }

    if (! $errormessage) {
        # Write changes to ntp.conf and restartntpd
        &buildConfFile;
    }
    else {
        $error_settings = 'error';
    }
}

# To enter an ' into a pushbutton solution is to use &#039; in it's definition
# but returned value when pressed is ' not the code. Cleanhtml recode the ' to enable comparison.
$timesettings{'ACTION'} = &Header::cleanhtml ($timesettings{'ACTION'});
if ($timesettings{'ACTION'} eq $Lang::tr{'set time now'} && $timesettings{'ENABLED_NTP'} eq 'on') {
    system ('/usr/local/bin/restartntpd syncnow');
}

&General::readhash('/var/ofw/time/settings', \%timesettings);

if ($timesettings{'NTP_VALID'} eq '') {
    $timesettings{'ENABLED_NTP'} = 'off';
    $timesettings{'NTP_ADDR_1'} = '0.openfirewall.pool.ntp.org';
    $timesettings{'NTP_ADDR_2'} = '1.openfirewall.pool.ntp.org';
    $timesettings{'NTP_ADDR_3'} = '2.openfirewall.pool.ntp.org';
}

unless ($errormessage) {
    ($timesettings{'SETYEAR'}, $timesettings{'SETMONTH'},
     $timesettings{'SETDAY'}, $timesettings{'SETHOUR'},
     $timesettings{'SETMINUTES'})= split(' ', `/bin/date +'%Y %m %d %H %M'`);
}

my %selected=();
my %checked=();

$checked{'ENABLED_NTP'}{'off'} = '';
$checked{'ENABLED_NTP'}{'on'} = '';
$checked{'ENABLED_NTP'}{$timesettings{'ENABLED_NTP'}} = "checked='checked'";
$checked{'ENABLED_NTP_REDIRECT'}{'off'} = '';
$checked{'ENABLED_NTP_REDIRECT'}{'on'} = '';
$checked{'ENABLED_NTP_REDIRECT'}{$timesettings{'ENABLED_NTP_REDIRECT'}} = "checked='checked'";

&Header::openpage($Lang::tr{'ntp configuration'}, 1, '');

&Header::openbigbox('100%', 'left', '');

# DPC move error message to top so it is seen!
if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>\n";
    &Header::closebox();
}

print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";

&Header::openbox('100%', 'left', "$Lang::tr{'settings'}:", $error_settings);
my $sactive = &General::isrunning('ntpd', 'nosize');

print <<END
<table width='100%' border='0'>
<tr>
    <td>$Lang::tr{'ntp server'}:</td>
    $sactive
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td colspan='4'><hr /></td>
</tr>
<tr>
    <td>$Lang::tr{'network time from'}:</td>
    <td><input type='checkbox' name='ENABLED_NTP' $checked{'ENABLED_NTP'}{'on'} /></td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'primary ntp server'}:</td>
    <td width='25%'><input type='text' name='NTP_ADDR_1' value='$timesettings{'NTP_ADDR_1'}' /></td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'secondary ntp server'}:&nbsp;<img src='/blob.gif' align='top' alt='*' /></td>
    <td width='25%'><input type='text' name='NTP_ADDR_2' value='$timesettings{'NTP_ADDR_2'}' /></td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'tertiary ntp server'}:&nbsp;<img src='/blob.gif' align='top' alt='*' /></td>
    <td width='25%'><input type='text' name='NTP_ADDR_3' value='$timesettings{'NTP_ADDR_3'}' /></td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr>
<tr>
    <td>$Lang::tr{'redirect ntp packets'}:</td>
    <td><input type='checkbox' name='ENABLED_NTP_REDIRECT' $checked{'ENABLED_NTP_REDIRECT'}{'on'} /></td>
    <td colspan='2'>&nbsp;</td>
</tr>
</table>
<br />
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' alt='*' /> $Lang::tr{'this field may be blank'}</td>
    <td class='button1button'><input type='submit' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-time.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
;

&Header::closebox();

&Header::openbox('100%', 'left', "$Lang::tr{'update time'}:", $error_instant);

print <<END
<table width='100%'>
<tr>
    <td class='comment1button'>
    <table>
    <tr>
        <td>$Lang::tr{'year'}:&nbsp;</td>
        <td><input type='text' name='SETYEAR' size='4' maxlength='4' value='$timesettings{'SETYEAR'}' /></td>
        <td>&nbsp;$Lang::tr{'month'}:&nbsp;</td>
        <td><input type='text' name='SETMONTH' size='2' maxlength='2' value='$timesettings{'SETMONTH'}' /></td>
        <td>&nbsp;$Lang::tr{'day'}:&nbsp;</td>
        <td><input type='text' name='SETDAY' size='2' maxlength='2' value='$timesettings{'SETDAY'}' /></td>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;$Lang::tr{'hours2'}:&nbsp;</td>
        <td><input type='text' name='SETHOUR' size='2' maxlength='2' value='$timesettings{'SETHOUR'}' /></td>
        <td>&nbsp;$Lang::tr{'minutes'}:&nbsp;</td>
        <td><input type='text' name='SETMINUTES' size='2' maxlength='2' value='$timesettings{'SETMINUTES'}' /></td>
    </tr>
    </table>
    </td>
    <td class='button1button'><input type='submit' name='ACTION' value='$Lang::tr{'instant update'}' /></td>
    <td class='onlinehelp'>&nbsp;</td>
</tr>
</table>
END
;
&Header::closebox();

print "</form>\n";

&Header::closebigbox();

&Header::closepage();

##
## Build the configuration file for ntpd
##
sub buildConfFile {
    open(FILE, ">/$conffile") or die "Unable to open ntp.conf file.";
    flock(FILE, 2);

    print FILE "# Configuration file for ntpd, created by time.cgi.\n";
    print FILE "# Do not edit manually.\n";
    print FILE "#\n";
    print FILE "restrict default kod limited nomodify nopeer noquery notrap\n";
    print FILE "restrict 127.0.0.1\n";

    print FILE "# Our networks\n";
    foreach my $itf (@ITFs) {
        my $icount = $netsettings{"${itf}_COUNT"};
        while ( $icount > 0 ) {
            print FILE "restrict " . $netsettings{"${itf}_${icount}_NETADDRESS"} . " mask " . $netsettings{"${itf}_${icount}_NETMASK"} . " nomodify noquery notrap\n" if ( $netsettings{"${itf}_${icount}_NETADDRESS"} );
            $icount--;
        }
    }

    print FILE "# Servers\n";
    for (my $iserver = 1; $iserver <= 3; $iserver++) {
        if ( $timesettings{"NTP_ADDR_${iserver}"} ) {
            print FILE "server " . $timesettings{"NTP_ADDR_${iserver}"} . " iburst\n" ;
        }
    }

    print FILE "# Local clock\n";
    print FILE "server 127.127.1.0\n";
    print FILE "fudge  127.127.1.0 stratum 7\n";

    print FILE "# Other settings\n";
    print FILE "driftfile /var/log/ntp/drift\n";
    print FILE "tinker panic 0\n";

    # Some basic loginfo
    print FILE "logconfig +allsync +allclock +allsys\n";
    # Include this if we want to know everything...
#    print FILE "logconfig +allsync +allclock +allpeer +allsys\n";
    close FILE;

    # Restart service
    system '/usr/local/bin/restartntpd';
}
