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
# along with IPCop. If not, see <http://www.gnu.org/licenses/>.
#
# (c) The SmoothWall Team
#
# Copyright (C) 03-Apr-2002 Guy Ellis <guy@traverse.com.au>
#              - ISDN DOV support
#              - ibod now an option
#              - PCI ADSL support added
#
# Copyright (c) 2002-2012 The IPCop Team
#
# $Id: pppsetup.cgi 6824 2012-11-02 17:52:29Z owes $
#

# Add entry in menu
# MENUENTRY network 010 "alt dialup" "dialup settings"
#
# Make sure translation exists $Lang::tr{'alt dialup'} $Lang::tr{'dialup settings'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

our %pppsettings = ();
my %temppppsettings = ();
our %netsettings   = ();
my %selected     = ();
my %checked      = ();
my @profilenames = ();
my $errormessage = '';
my $warningmessage = '';
my $maxprofiles  = 5;
my $kernel       = `/bin/uname -r | /usr/bin/tr -d '\012'`;
our $drivererror = '';

# read in the profile names into @profilenames.
my $c = 0;
$profilenames[0] = $Lang::tr{'no profile switch'};
for ($c = 1; $c <= $maxprofiles; $c++) {
    %temppppsettings = ();
    $temppppsettings{'PROFILENAME'} = $Lang::tr{'empty'};
    &General::readhash("/var/ipcop/ppp/settings-$c", \%temppppsettings);
    $profilenames[$c] = $temppppsettings{'PROFILENAME'};
}
for ($c = 1; $c <= $maxprofiles; $c++) {
    $selected{'PROFILE'}{$c} = '';
}

my @list_ttys = ('ttyS0','ttyS1','ttyS2','ttyS3','ttyS4',
            'ttyUSB0','ttyUSB1','ttyUSB2','ttyUSB3','ttyUSB4',
            'noz0','noz1','ttyHS0','ttyHS1','ttyHS2','ttyHS3',
            'usb/ttyACM0','usb/ttyACM1','usb/ttyACM2','usb/ttyACM3');

&Header::showhttpheaders();

$pppsettings{'ACTION'} = '';
&initprofile();
&General::getcgihash(\%pppsettings);

if (($pppsettings{'ACTION'} eq '') && (-e '/var/run/ppp-ipcop.pid' || -e "/var/ipcop/red/active")) {
    $warningmessage = $Lang::tr{'unable to alter profiles while red is active'};

    &General::readhash('/var/ipcop/ppp/settings', \%pppsettings);
}
elsif ($pppsettings{'ACTION'} ne ''
    && (-e '/var/run/ppp-ipcop.pid' || -e "/var/ipcop/red/active"))
{
    $errormessage = $Lang::tr{'unable to alter profiles while red is active'};

    # read in the current vars (could be different from actual user input)
    %pppsettings = ();
    # If RED is DHCP/Static we can have a connection without some sensible defaults in ppp/settings.
    # This messes up the screen: no box termination.
    &initprofile();
    &General::readhash("/var/ipcop/ppp/settings", \%pppsettings);
}
elsif ($pppsettings{'ACTION'} eq $Lang::tr{'refresh'}) {
    unless ($pppsettings{'TYPE'} =~
/^(modem|serial|isdn|pppoe|pptp|alcatelusb|amedynusbadsl|conexantusbadsl|conexantpciadsl|3cp4218usbadsl|pulsardsl|solosdsl|eciadsl|fritzdsl|bewanadsl|eagleusbadsl|wanpipe-adsl|wanpipe-serial)$/
        )
    {
        $errormessage = $Lang::tr{'invalid input'};
        goto ERROR;
    }
    my $type = $pppsettings{'TYPE'};
    &General::readhash("/var/ipcop/ppp/settings", \%pppsettings);
    $pppsettings{'TYPE'} = $type;
}
elsif ($pppsettings{'ACTION'} eq $Lang::tr{'save'}) {

    # TODO: do we need to check everything here, or do we simply trust the dropdownlists?

    if ($pppsettings{'TYPE'} =~ /^(modem|serial|isdn)$/) {
        my $ttyOK = 0;

        $ttyOK = 1 if (($pppsettings{'COMPORT'} eq 'isdn1') || ($pppsettings{'COMPORT'} eq 'isdn2'));
        for $c (0 .. $#list_ttys) {
            $ttyOK = 1 if ($pppsettings{'COMPORT'} eq $list_ttys[$c]);
        }
        
        if (! $ttyOK) {
            $errormessage = $Lang::tr{'invalid input'};
            goto ERROR;
        }
    }
    if (   $pppsettings{'TYPE'} =~ /^(modem|serial)$/
        && $pppsettings{'DTERATE'} !~ /^(9600|19200|38400|57600|115200|230400|460800|921600)$/)
    {
        $errormessage = $Lang::tr{'invalid input'};
        goto ERROR;
    }
    if ($pppsettings{'TYPE'} eq 'modem' && $pppsettings{'DIALMODE'} !~ /^(T|P)$/) {
        $errormessage = $Lang::tr{'invalid input'};
        goto ERROR;
    }
    if ($pppsettings{'AUTH'} !~ /^(pap-or-chap|pap|chap|standard-login-script|demon-login-script|other-login-script)$/)
    {
        $errormessage = $Lang::tr{'invalid input'};
        goto ERROR;
    }

    if ($pppsettings{'TYPE'} =~ /^(wanpipe-serial)$/) {
        if ($pppsettings{'COMPORT'} !~ /^(ttyWP0|ttyWP1|ttyWP2|ttyWP3|ttyWP4|ttyWP5|ttyWP6|ttyWP7)$/) {
            $errormessage = $Lang::tr{'invalid input'};
            goto ERROR;
        }
    }

    if ($pppsettings{'PROFILENAME'} eq '') {
        $errormessage = $Lang::tr{'profile name not given'};
        $pppsettings{'PROFILENAME'} = '';
        goto ERROR;
    }
    if ($pppsettings{'TYPE'} =~ /^(modem|isdn)$/) {
        if ($pppsettings{'TELEPHONE'} eq '') {
            $errormessage = $Lang::tr{'telephone not set'};
            goto ERROR;
        }
        if (!($pppsettings{'TELEPHONE'} =~ /^[\d\*\#\,]+$/)) {
            $errormessage = $Lang::tr{'bad characters in the telephone number field'};
            goto ERROR;
        }
    }
    unless (($pppsettings{'PROTOCOL'} eq 'RFC1483' && $pppsettings{'METHOD'} =~ /^(STATIC|DHCP)$/)) {
        if ($pppsettings{'USERNAME'} eq '') {
            $errormessage = $Lang::tr{'username not set'};
            goto ERROR;
        }
        if ($pppsettings{'PASSWORD'} eq '') {
            $errormessage = $Lang::tr{'password not set'};
            goto ERROR;
        }
    }

    if ($pppsettings{'TIMEOUT'} eq '') {
        $errormessage = $Lang::tr{'idle timeout not set'};
        goto ERROR;
    }
    if (!($pppsettings{'TIMEOUT'} =~ /^\d+$/)) {
        $errormessage = $Lang::tr{'only digits allowed in the idle timeout'};
        goto ERROR;
    }

    if ($pppsettings{'LOGINSCRIPT'} =~ /[.\/ ]/) {
        $errormessage = $Lang::tr{'bad characters in script field'};
        goto ERROR;
    }

    if ($pppsettings{'DNS1'}) {
        if (!(&General::validip($pppsettings{'DNS1'}))) {
            $errormessage = $Lang::tr{'invalid primary dns'};
            goto ERROR;
        }
    }
    if ($pppsettings{'DNS2'}) {
        if (!(&General::validip($pppsettings{'DNS2'}))) {
            $errormessage = $Lang::tr{'invalid secondary dns'};
            goto ERROR;
        }
    }

    if ($pppsettings{'MAXRETRIES'} eq '') {
        $errormessage = $Lang::tr{'max retries not set'};
        goto ERROR;
    }
    if (!($pppsettings{'MAXRETRIES'} =~ /^\d+$/)) {
        $errormessage = $Lang::tr{'only digits allowed in max retries field'};
        goto ERROR;
    }

    if (!($pppsettings{'HOLDOFF'} =~ /^\d+$/)) {
        $errormessage = $Lang::tr{'only digits allowed in holdoff field'};
        goto ERROR;
    }

    if ($pppsettings{'TYPE'} =~ /^(alcatelusb)$/) {
        my $modem      = '';
        my $speedtouch = &General::speedtouchversion;
        if ($speedtouch >= 0 && $speedtouch <= 4) {
            if   ($speedtouch == 4) { $modem = 'v4_b'; }
            else                    { $modem = 'v0123'; }
            $pppsettings{'MODEM'} = $modem;
        }
        else {
            $modem        = 'v0123';
            $errormessage = "$Lang::tr{'unknown'} Rev $speedtouch";
            goto ERROR;
        }
        if (!-e "/var/ipcop/alcatelusb/firmware.$modem.bin") {
            $errormessage = $Lang::tr{'no alcatelusb firmware'};
            $drivererror  = 1;
            goto ERROR;
        }
    }

    if ($pppsettings{'TYPE'} eq 'eciadsl' && (!(-e "/var/ipcop/eciadsl/synch.bin"))) {
        $errormessage = $Lang::tr{'no eciadsl synch.bin file'};
        $drivererror  = 1;
        goto ERROR;
    }

    if ($pppsettings{'TYPE'} eq 'fritzdsl' && (!(-e "/lib/modules/$kernel/extra/fcdsl.ko.gz"))) {
        $errormessage = $Lang::tr{'no fritzdsl driver'};
        $drivererror  = 1;
        goto ERROR;
    }

    if ($pppsettings{'USEIBOD'} eq 'on' && $pppsettings{'COMPORT'} eq 'isdn1') {
        $errormessage = $Lang::tr{'ibod for dual isdn only'};
        goto ERROR;
    }

    if ($pppsettings{'TYPE'} eq 'pptp') {
        $errormessage = '';
        if ($pppsettings{'METHOD'} eq 'STATIC') {
            if (!&General::validip($pppsettings{'ROUTERIP'})) {
                $errormessage = $Lang::tr{'router ip'} . ': ' . $Lang::tr{'invalid ip'};
            }
        }
        else {
            if (($pppsettings{'DHCP_HOSTNAME'} ne '') && (!&General::validfqdn($pppsettings{'DHCP_HOSTNAME'}))) {
                $errormessage = $errormessage . ' ' . $Lang::tr{'hostname'} . ' ' . $Lang::tr{'invalid hostname'};
            }
        }
        if ($errormessage ne '') {
            goto ERROR;
        }
    }

    if ($pppsettings{'TYPE'} =~
/^(alcatelusb|amedynusbadsl|conexantusbadsl|conexantpciadsl|3cp4218usbadsl|pulsardsl|solosdsl|eciadsl|fritzdsl|bewanadsl|eagleusbadsl|wanpipe-adsl)$/
        )
    {
        if (($pppsettings{'VPI'} eq '') || ($pppsettings{'VCI'} eq '')) {
            $errormessage = $Lang::tr{'invalid vpi vpci'};
            goto ERROR;
        }
        if ((!($pppsettings{'VPI'} =~ /^\d+$/)) || (!($pppsettings{'VCI'} =~ /^\d+$/))) {
            $errormessage = $Lang::tr{'invalid vpi vpci'};
            goto ERROR;
        }
        if (($pppsettings{'VPI'} eq '0') && ($pppsettings{'VCI'} eq '0')) {
            $errormessage = $Lang::tr{'invalid vpi vpci'};
            goto ERROR;
        }
        if ($pppsettings{'PROTOCOL'} eq '') {
            $errormessage = $Lang::tr{'invalid input'};
            goto ERROR;
        }
    }

    if (   ($pppsettings{'PROTOCOL'} eq 'RFC1483')
        && ($pppsettings{'METHOD'} eq '')
        && \($pppsettings{'TYPE'} !~ /^(fritzdsl)$/))
    {
        $errormessage = $Lang::tr{'invalid input'};
        goto ERROR;
    }

    if (($pppsettings{'PROTOCOL'} eq 'RFC1483' && $pppsettings{'METHOD'} eq 'DHCP')) {
        if ($pppsettings{'DHCP_HOSTNAME'} ne '') {
            if (!&General::validfqdn($pppsettings{'DHCP_HOSTNAME'})) {
                $errormessage = $errormessage . ' ' . $Lang::tr{'hostname'} . ': ' . $Lang::tr{'invalid hostname'};
            }
        }
    }

    if (($pppsettings{'PROTOCOL'} eq 'RFC1483' && $pppsettings{'METHOD'} eq 'STATIC')) {
        $errormessage = '';
        if (!&General::validip($pppsettings{'IP'})) {
            $errormessage = $Lang::tr{'static ip'} . ' ' . $Lang::tr{'invalid ip'};
        }
        if (!&General::validip($pppsettings{'GATEWAY'})) {
            $errormessage = $errormessage . ' ' . $Lang::tr{'gateway ip'} . ' ' . $Lang::tr{'invalid ip'};
        }
        if (!&General::validmask($pppsettings{'NETMASK'})) {
            $errormessage = $errormessage . ' ' . $Lang::tr{'netmask'} . ' ' . $Lang::tr{'invalid netmask'};
        }
        if ($pppsettings{'BROADCAST'} ne '') {
            if (!&General::validip($pppsettings{'BROADCAST'})) {
                $errormessage = $errormessage . ' ' . $Lang::tr{'broadcast'} . ' ' . $Lang::tr{'invalid broadcast ip'};
            }
        }
        if ($pppsettings{'DNS'} eq 'Automatic') {
            $errormessage = $Lang::tr{'invalid input'};
        }
        if ($errormessage ne '') {
            goto ERROR;
        }
    }

    if (   $pppsettings{'PROTOCOL'} eq 'RFC1483'
        && $pppsettings{'METHOD'} ne 'PPPOE'
        && \$pppsettings{'RECONNECTION'} eq 'dialondemand')
    {
        $errormessage = $Lang::tr{'invalid input'};
        goto ERROR;
    }

    if ($pppsettings{'RECONNECTION'} eq 'dialondemand' && `/bin/cat /var/ipcop/ddns/config` =~ /,on$/m) {
        $errormessage = $Lang::tr{'dod not compatible with ddns'};
        goto ERROR;
    }

    if (($pppsettings{'TYPE'} =~ /^(bewanadsl)$/) && $pppsettings{'MODEM'} eq '') {
        $errormessage = $Lang::tr{'no modem selected'};
        goto ERROR;
    }

    if ($pppsettings{'PROTOCOL'} eq 'RFC1483') {
        $pppsettings{'ENCAP'} = $pppsettings{'ENCAP_RFC1483'};
    }

    if ($pppsettings{'PROTOCOL'} eq 'RFC2364') {
        $pppsettings{'ENCAP'} = $pppsettings{'ENCAP_RFC2364'};
    }
    delete $pppsettings{'ENCAP_RFC1483'};
    delete $pppsettings{'ENCAP_RFC2364'};

    if ($pppsettings{'VDSL_TAG'} ne '') {
        if (!($pppsettings{'VDSL_TAG'} =~ /^\d+$/)) {
            $errormessage = $Lang::tr{'invalid vlan tag'};
            goto ERROR;
        }
        # According 802.1q valid VLAN tags are 1 .. 4096
        if (($pppsettings{'VDSL_TAG'} < 1) || ($pppsettings{'VDSL_TAG'} > 4096)) {
            $errormessage = $Lang::tr{'invalid vlan tag'};
            goto ERROR;
        }
    }

ERROR:
    if ($errormessage) {
        $pppsettings{'VALID'} = 'no';
    }
    else {
        $pppsettings{'VALID'} = 'yes';
    }

    # write cgi vars to the file.
    &General::writehash("/var/ipcop/ppp/settings-$pppsettings{'PROFILE'}", \%pppsettings);

    # Activate profile
    &General::SelectProfile($pppsettings{'PROFILE'});

    &General::log("$Lang::tr{'profile saved'}: $pppsettings{'PROFILENAME'}");
    $profilenames[$pppsettings{'PROFILE'}] = $pppsettings{'PROFILENAME'};
}
elsif ($pppsettings{'ACTION'} eq $Lang::tr{'select'}) {

    # save PROFILE, reset hash and recreate default values for empty profil
    my $profile = $pppsettings{'PROFILE'};    # from cgi
    %pppsettings            = ();
    $pppsettings{'PROFILE'} = $profile;       # to be written in file
    &initprofile();
    &General::readhash("/var/ipcop/ppp/settings-$profile", \%pppsettings);

    # need to write default values on disk when profile was empty
    &General::writehash("/var/ipcop/ppp/settings-$profile", \%pppsettings);

    # Activate profile
    &General::SelectProfile($profile);

    &General::log("$Lang::tr{'profile made current'}: $pppsettings{'PROFILENAME'}");
}
elsif ($pppsettings{'ACTION'} eq $Lang::tr{'delete'}) {
    my $profile = $pppsettings{'PROFILE'};
    &General::log("$Lang::tr{'profile deleted'}: $profilenames[$profile]");

    truncate("/var/ipcop/ppp/settings-$profile", 0);

    # save PROFILE, reset hash and recreate default values for empty profil
    %pppsettings = ();
    $pppsettings{'PROFILE'} = $profile;
    &initprofile();
    &General::writehash("/var/ipcop/ppp/settings-$profile", \%pppsettings);

    # Activate profile
    &General::SelectProfile($profile);
    $profilenames[$profile] = $pppsettings{'PROFILENAME'};
}
else {

    # no accepted action set, just read in the current vars
    &General::readhash('/var/ipcop/ppp/settings', \%pppsettings);
}

# For dropdown selection, we have profiles 1-5, profile 0 is special case
$selected{'PROFILE'}{$pppsettings{'PROFILE'}} = "selected='selected'";
for ($c = 0; $c <= $maxprofiles; $c++) {
    $selected{'BACKUPPROFILE'}{$c} = '';
}
$selected{'BACKUPPROFILE'}{$pppsettings{'BACKUPPROFILE'}} = "selected='selected'";

$selected{'TYPE'}{'modem'}              = '';
$selected{'TYPE'}{'serial'}             = '';
$selected{'TYPE'}{'isdn'}               = '';
$selected{'TYPE'}{'pppoe'}              = '';
$selected{'TYPE'}{'pptp'}               = '';
$selected{'TYPE'}{'alcatelusb'}         = '';
$selected{'TYPE'}{'pulsardsl'}          = '';
$selected{'TYPE'}{'solosdsl'}           = '';
$selected{'TYPE'}{'eciadsl'}            = '';
$selected{'TYPE'}{'fritzdsl'}           = '';
$selected{'TYPE'}{'bewanadsl'}          = '';
$selected{'TYPE'}{'eagleusbadsl'}       = '';
$selected{'TYPE'}{'conexantusbadsl'}    = '';
$selected{'TYPE'}{'conexantpciadsl'}    = '';
$selected{'TYPE'}{'amedynusbadsl'}      = '';
$selected{'TYPE'}{'3cp4218usbadsl'}     = '';
$selected{'TYPE'}{'wanpipe-adsl'}       = '';
$selected{'TYPE'}{'wanpipe-serial'}     = '';
$selected{'TYPE'}{$pppsettings{'TYPE'}} = "selected='selected'";

$checked{'DEBUG'}{'off'}                 = '';
$checked{'DEBUG'}{'on'}                  = '';
$checked{'DEBUG'}{$pppsettings{'DEBUG'}} = "checked='checked'";


for $c (0 .. $#list_ttys) {
    $selected{'COMPORT'}{"$list_ttys[$c]"} = '';
}
$selected{'COMPORT'}{'isdn1'}                 = '';
$selected{'COMPORT'}{'isdn2'}                 = '';
$selected{'COMPORT'}{'ttyWP0'}                = '';
$selected{'COMPORT'}{'ttyWP1'}                = '';
$selected{'COMPORT'}{'ttyWP2'}                = '';
$selected{'COMPORT'}{'ttyWP3'}                = '';
$selected{'COMPORT'}{'ttyWP4'}                = '';
$selected{'COMPORT'}{'ttyWP5'}                = '';
$selected{'COMPORT'}{'ttyWP6'}                = '';
$selected{'COMPORT'}{'ttyWP7'}                = '';
$selected{'COMPORT'}{$pppsettings{'COMPORT'}} = "selected='selected'";

$selected{'DTERATE'}{'9600'}                  = '';
$selected{'DTERATE'}{'19200'}                 = '';
$selected{'DTERATE'}{'38400'}                 = '';
$selected{'DTERATE'}{'57600'}                 = '';
$selected{'DTERATE'}{'115200'}                = '';
$selected{'DTERATE'}{'230400'}                = '';
$selected{'DTERATE'}{'460800'}                = '';
$selected{'DTERATE'}{'921600'}                = '';
$selected{'DTERATE'}{'sync'}                  = '';
$selected{'DTERATE'}{$pppsettings{'DTERATE'}} = "selected='selected'";

$checked{'SPEAKER'}{'off'}                   = '';
$checked{'SPEAKER'}{'on'}                    = '';
$checked{'SPEAKER'}{$pppsettings{'SPEAKER'}} = "checked='checked'";

$selected{'DIALMODE'}{'T'}                      = '';
$selected{'DIALMODE'}{'P'}                      = '';
$selected{'DIALMODE'}{$pppsettings{'DIALMODE'}} = "selected='selected'";

$checked{'RECONNECTION'}{'manual'}                     = '';
$checked{'RECONNECTION'}{'persistent'}                 = '';
$checked{'RECONNECTION'}{'dialondemand'}               = '';
$checked{'RECONNECTION'}{$pppsettings{'RECONNECTION'}} = "checked='checked'";

$checked{'DIALONDEMANDDNS'}{'off'}                           = '';
$checked{'DIALONDEMANDDNS'}{'on'}                            = '';
$checked{'DIALONDEMANDDNS'}{$pppsettings{'DIALONDEMANDDNS'}} = "checked='checked'";

my $disabledautoconnect = '';
$checked{'AUTOCONNECT'}{'off'}                       = '';
$checked{'AUTOCONNECT'}{'on'}                        = '';
if (   ($netsettings{'RED_COUNT'} >= 1)
    && ($netsettings{'RED_1_TYPE'} eq "DHCP" || $netsettings{'RED_1_TYPE'} eq "STATIC")) {

    $pppsettings{'AUTOCONNECT'} = 'on';
    $disabledautoconnect = "disabled='disabled'";
}
$checked{'AUTOCONNECT'}{$pppsettings{'AUTOCONNECT'}} = "checked='checked'";

$checked{'SENDCR'}{'off'}                    = '';
$checked{'SENDCR'}{'on'}                     = '';
$checked{'SENDCR'}{$pppsettings{'SENDCR'}}   = "checked='checked'";
$checked{'USEDOV'}{'off'}                    = '';
$checked{'USEDOV'}{'on'}                     = '';
$checked{'USEDOV'}{$pppsettings{'USEDOV'}}   = "checked='checked'";
$checked{'USEIBOD'}{'off'}                   = '';
$checked{'USEIBOD'}{'on'}                    = '';
$checked{'USEIBOD'}{$pppsettings{'USEIBOD'}} = "checked='checked'";

$checked{'MODEM'}{'PCIST'}               = '';
$checked{'MODEM'}{'USB'}                 = '';
$checked{'MODEM'}{$pppsettings{'MODEM'}} = "checked='checked'";

$selected{'LINE'}{'WO'}                 = '';
$selected{'LINE'}{'ES'}                 = '';
$selected{'LINE'}{'ES03'}               = '';
$selected{'LINE'}{'FR'}                 = '';
$selected{'LINE'}{'FR04'}               = '';
$selected{'LINE'}{'FR10'}               = '';
$selected{'LINE'}{'IT'}                 = '';
$selected{'LINE'}{$pppsettings{'LINE'}} = "selected='selected'";

$checked{'MODULATION'}{'GDMT'}                     = '';
$checked{'MODULATION'}{'ANSI'}                     = '';
$checked{'MODULATION'}{'GLITE'}                    = '';
$checked{'MODULATION'}{'AUTO'}                     = '';
$checked{'MODULATION'}{$pppsettings{'MODULATION'}} = "checked='checked'";

$checked{'PROTOCOL'}{'RFC1483'}                = '';
$checked{'PROTOCOL'}{'RFC2364'}                = '';
$checked{'PROTOCOL'}{$pppsettings{'PROTOCOL'}} = "checked='checked'";

$selected{'ENCAP'}{'0'}                    = '';
$selected{'ENCAP'}{'1'}                    = '';
$selected{'ENCAP'}{'2'}                    = '';
$selected{'ENCAP'}{'3'}                    = '';
$selected{'ENCAP'}{'4'}                    = '';
$selected{'ENCAP'}{$pppsettings{'ENCAP'}}  = "selected='selected'";
$checked{'METHOD'}{'STATIC'}               = '';
$checked{'METHOD'}{'PPPOE'}                = '';
$checked{'METHOD'}{'PPPOE_PLUGIN'}         = '';
$checked{'METHOD'}{'DHCP'}                 = '';
$checked{'METHOD'}{$pppsettings{'METHOD'}} = "checked='checked'";

$selected{'AUTH'}{'pap-or-chap'}           = '';
$selected{'AUTH'}{'pap'}                   = '';
$selected{'AUTH'}{'chap'}                  = '';
$selected{'AUTH'}{'standard-login-script'} = '';
$selected{'AUTH'}{'demon-login-script'}    = '';
$selected{'AUTH'}{'other-login-script'}    = '';
$selected{'AUTH'}{$pppsettings{'AUTH'}}    = "selected='selected'";

$checked{'DNS'}{'Automatic'}         = '';
$checked{'DNS'}{'Manual'}            = '';
$checked{'DNS'}{$pppsettings{'DNS'}} = "checked='checked'";

if ($drivererror) {
    &Header::openpage($Lang::tr{'upload'}, 0, "<meta http-equiv='refresh' content='2; URL=/cgi-bin/upload.cgi' />");
}
else {
    &Header::openpage($Lang::tr{'ppp setup'}, 1, '');
}

&Header::openbigbox('100%', 'left', '');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "$errormessage\n";
    &Header::closebox();
}
elsif ($warningmessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'warning messages'}:", 'warning');
    print "$warningmessage\n";
    &Header::closebox();
}

###
### Box for selecting profile
###
print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'profiles'}:");
print <<END
<table width='100%'>
<tr>
    <td align='right'>$Lang::tr{'profile'}:</td>
    <td>
    <select name='PROFILE'>
END
    ;
for ($c = 1; $c <= $maxprofiles; $c++) {
    print "\t<option value='$c' $selected{'PROFILE'}{$c}>$c. $profilenames[$c]</option>\n";
}
print <<END
    </select></td>
    <td><input type='submit' name='ACTION' value='$Lang::tr{'select'}' /></td>
    <td><input type='submit' name='ACTION' value='$Lang::tr{'delete'}' /></td>
    <td width='25%'><input type='submit' name='ACTION' value='$Lang::tr{'restore'}' /></td>
    <td width='5%' align='right'>
        <a href='${General::adminmanualurl}/network-ppp-settings.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
    ;
&Header::closebox();


###
### Box for connection type (the big one)
###
my $usb = $Lang::tr{'not running'};

&Header::openbox('100%', 'left', $Lang::tr{'connection'} . ':');
print <<END
<table width='100%'>
<tr>
    <td>$Lang::tr{'interface'}:</td>
    <td colspan='3'>
    <select name='TYPE'>
    <option value='modem' $selected{'TYPE'}{'modem'}>$Lang::tr{'modem'}</option>
    <option value='serial' $selected{'TYPE'}{'serial'}>$Lang::tr{'serial'}</option>
END
    ;
if ($netsettings{'RED_1_TYPE'} eq 'ISDN') {
    print "\t<option value='isdn' $selected{'TYPE'}{'isdn'}>$Lang::tr{'isdn'}</option>\n";
}
if ($netsettings{'RED_1_TYPE'} eq 'PPPOE') {
    print "\t<option value='pppoe' $selected{'TYPE'}{'pppoe'}>PPPoE</option>\n";
}
if ($netsettings{'RED_1_TYPE'} eq 'PPTP') {
    print "\t<option value='pptp' $selected{'TYPE'}{'pptp'}>PPTP</option>\n";
}
if (-e "/sys/bus/usb/devices/usb1") {
    print <<END
    <option value='eciadsl' $selected{'TYPE'}{'eciadsl'}>ECI USB ADSL</option>
    <option value='eagleusbadsl' $selected{'TYPE'}{'eagleusbadsl'}>Eagle USB ADSL (Acer Allied-Telesyn Comtrend D-Link Sagem USR)</option>
    <option value='conexantusbadsl' $selected{'TYPE'}{'conexantusbadsl'}>Conexant USB(Aetra Amigo Draytek Etec Mac Olitec Vitelcom Zoom)</option>
    <option value='amedynusbadsl' $selected{'TYPE'}{'amedynusbadsl'}>Zyxel 630-11 / Asus AAM6000UG USB ADSL</option>
    <option value='3cp4218usbadsl' $selected{'TYPE'}{'3cp4218usbadsl'}>3Com USB AccessRunner</option>
    <option value='alcatelusb' $selected{'TYPE'}{'alcatelusb'}>Speedtouch USB ADSL</option>
END
    ;

    my $usbmodules = `/bin/lsmod | /usr/bin/cut -d ' ' -f1 | /bin/grep -E '_hcd'`;
    $usb = $usbmodules if ($usbmodules ne '');
}
print <<END
    <option value='fritzdsl' $selected{'TYPE'}{'fritzdsl'}>Fritz!DSL</option>
    <option value='pulsardsl' $selected{'TYPE'}{'pulsardsl'}>Pulsar ADSL</option>
    <option value='solosdsl' $selected{'TYPE'}{'solosdsl'}>Solos PCI ADSL2+</option>
    <option value='bewanadsl' $selected{'TYPE'}{'bewanadsl'}>Bewan ADSL PCI st/USB st</option>
    <option value='conexantpciadsl' $selected{'TYPE'}{'conexantpciadsl'}>Conexant PCI ADSL</option>
    <option value='wanpipe-adsl' $selected{'TYPE'}{'wanpipe-adsl'}>Sangoma S518 adsl</option>
    <option value='wanpipe-serial' $selected{'TYPE'}{'wanpipe-serial'}>Sangoma S514 serial</option>
    </select>
    &nbsp;<input type='submit' name='ACTION' value='$Lang::tr{'refresh'}' /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td colspan='3'>USB: &nbsp;$usb</td>
</tr>
END
;

# Insert a visual seperation (and table column widths)
print <<END
<tr>
    <td width='25%'>&nbsp;</td><td width='25%'>&nbsp;</td><td width='25%'>&nbsp;</td><td width='25%'>&nbsp;</td>
</tr>
END
;

# TODO: How can TYPE not be set? Do we not do initprofile to avoid that, and also set TYPE for DHCP/STATIC?
#   If TYPE is not set can we not simply close box/page with an error message and bail out?
if ($pppsettings{'TYPE'}) {
    if ($pppsettings{'TYPE'} =~ /^(modem|serial|isdn|wanpipe-serial)$/) {
        print <<END
<tr>
    <td>$Lang::tr{'interface'}:</td>
    <td><select name='COMPORT'>
END
        ;
        if ($pppsettings{'TYPE'} =~ /^(modem|serial)$/) {
            for $c (0 .. $#list_ttys) {
                if ($list_ttys[$c] eq "ttyS$c") {
                    # Special tweak for serial interfaces, we have got translations for COM1 .. COM5
                    # Make sure translations exist $Lang::tr{'modem on com1'} $Lang::tr{'modem on com2'}
                    #   $Lang::tr{'modem on com3'} $Lang::tr{'modem on com4'} $Lang::tr{'modem on com5'}

                    my $modemtext = $Lang::tr{"modem on com".($c+1)};
                    print "<option value='$list_ttys[$c]' $selected{'COMPORT'}{$list_ttys[$c]}>$modemtext</option>\n";
                }
                else {
                    # There are all special USB interfaces, need a specialist to understand them
                    print "<option value='$list_ttys[$c]' $selected{'COMPORT'}{$list_ttys[$c]}>$list_ttys[$c]</option>\n";
                }
            }
        }
        elsif ($pppsettings{'TYPE'} eq 'isdn') {
            print <<END
        <option value='isdn1' $selected{'COMPORT'}{'isdn1'}>$Lang::tr{'isdn1'}</option>
        <option value='isdn2' $selected{'COMPORT'}{'isdn2'}>$Lang::tr{'isdn2'}</option>
END
            ;
        }
        elsif ($pppsettings{'TYPE'} eq 'wanpipe-serial') {
            print <<END
        <option value='ttyWP0' $selected{'COMPORT'}{'ttyWP0'}>ttyWP0</option>
        <option value='ttyWP1' $selected{'COMPORT'}{'ttyWP1'}>ttyWP1</option>
        <option value='ttyWP2' $selected{'COMPORT'}{'ttyWP2'}>ttyWP2</option>
        <option value='ttyWP3' $selected{'COMPORT'}{'ttyWP3'}>ttyWP3</option>
        <option value='ttyWP4' $selected{'COMPORT'}{'ttyWP4'}>ttyWP4</option>
        <option value='ttyWP5' $selected{'COMPORT'}{'ttyWP5'}>ttyWP5</option>
        <option value='ttyWP6' $selected{'COMPORT'}{'ttyWP6'}>ttyWP6</option>
        <option value='ttyWP7' $selected{'COMPORT'}{'ttyWP7'}>ttyWP7</option>
END
            ;
        }
        print "    </select></td>\n";

        if ($pppsettings{'TYPE'} =~ /^(modem|serial|wanpipe-serial)$/) {
            print <<END
    <td>$Lang::tr{'computer to modem rate'}:</td>
    <td><select name='DTERATE'>
        <option value='9600' $selected{'DTERATE'}{'9600'}>9600</option>
        <option value='19200' $selected{'DTERATE'}{'19200'}>19200</option>
        <option value='38400' $selected{'DTERATE'}{'38400'}>38400</option>
        <option value='57600' $selected{'DTERATE'}{'57600'}>57600</option>
        <option value='115200' $selected{'DTERATE'}{'115200'}>115200</option>
        <option value='230400' $selected{'DTERATE'}{'230400'}>230400</option>
        <option value='460800' $selected{'DTERATE'}{'460800'}>460800</option>
        <option value='921600' $selected{'DTERATE'}{'921600'}>921600</option>
END
            ;

            if ($pppsettings{'TYPE'} eq 'wanpipe-serial') {
                print "<option value='sync' $selected{'DTERATE'}{'sync'}>sync</option>";
            }
            print "</select></td></tr>";
        }
        else {
            print "<td colspan='2'>&nbsp;</td></tr>\n";
        }

        if ($pppsettings{'TYPE'} =~ /^(modem|isdn)$/) {
            print "<tr><td>$Lang::tr{'number'}:</td>\n";
            print "<td><input type='text' name='TELEPHONE' value='$pppsettings{'TELEPHONE'}' /></td>\n";
            if ($pppsettings{'TYPE'} eq 'modem') {
                print "<td>$Lang::tr{'modem speaker on'}:</td>\n";
                print "<td><input type='checkbox' name='SPEAKER' $checked{'SPEAKER'}{'on'} /></td></tr>\n";
            }
            else {
                print "<td colspan='2'>&nbsp;</td></tr>\n";
            }
        }
    }
    if ($pppsettings{'TYPE'} eq 'modem') {
        print <<END
<tr>
    <td>$Lang::tr{'dialing mode'}:</td>
    <td><select name='DIALMODE'>
        <option value='T' $selected{'DIALMODE'}{'T'}>$Lang::tr{'tone'}</option>
        <option value='P' $selected{'DIALMODE'}{'P'}>$Lang::tr{'pulse'}</option>
    </select></td>
    <td>$Lang::tr{'send cr'}:</td>
    <td><input type='checkbox' name='SENDCR' $checked{'SENDCR'}{'on'} /></td>
</tr>
END
        ;
    }

    if ($pppsettings{'TYPE'} eq 'modem') {
        print <<END
<tr>
    <td>$Lang::tr{'modem init for this profile'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='PROFILEMODEMINIT' value='$pppsettings{'PROFILEMODEMINIT'}' /></td>
    <td colspan='2'>&nbsp;</td>
</tr>
END
        ;
    }

    print <<END
<tr>
    <td>$Lang::tr{'idle timeout'}:</td>
    <td><input type='text' size='5' name='TIMEOUT' value='$pppsettings{'TIMEOUT'}' /></td>
    <td colspan='2'>&nbsp;</td>
</tr><tr>
    <td>$Lang::tr{'connect on ipcop restart'}:</td>
    <td><input type='checkbox' $disabledautoconnect name='AUTOCONNECT' value='on' $checked{'AUTOCONNECT'}{'on'} /></td>
    <td>$Lang::tr{'connection debugging'}:</td>
    <td><input type='checkbox' name='DEBUG' $checked{'DEBUG'}{'on'} /></td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td colspan='4' class='boldbase'>$Lang::tr{'reconnection'}:</td>
</tr><tr>
    <td colspan='4'><input type='radio' name='RECONNECTION' value='manual' $checked{'RECONNECTION'}{'manual'} />$Lang::tr{'manual'}</td>
</tr><tr>
    <td colspan='2'><input type='radio' name='RECONNECTION' value='persistent' $checked{'RECONNECTION'}{'persistent'} />$Lang::tr{'persistent'}</td>
    <td>$Lang::tr{'backupprofile'}:</td>
    <td>
    <select name='BACKUPPROFILE'>
END
    ;
    print "\t<option value='0' $selected{'BACKUPPROFILE'}{0}>$profilenames[0]</option>\n";
    for ($c = 1; $c <= $maxprofiles; $c++) {
        print "\t<option value='$c' $selected{'BACKUPPROFILE'}{$c}>$c. $profilenames[$c]</option>\n";
    }
    print <<END
    </select></td>
</tr>
<tr>
    <td colspan='2'><input type='radio' name='RECONNECTION' value='dialondemand' $checked{'RECONNECTION'}{'dialondemand'} />$Lang::tr{'dod'}</td>
    <td>$Lang::tr{'dod for dns'}:</td>
    <td><input type='checkbox' name='DIALONDEMANDDNS' $checked{'DIALONDEMANDDNS'}{'on'} /></td>
</tr><tr>
    <td>$Lang::tr{'holdoff'}:</td>
    <td><input type='text' size='5' name='HOLDOFF' value='$pppsettings{'HOLDOFF'}' /></td>
    <td>$Lang::tr{'maximum retries'}:</td>
    <td><input type='text' size='5' name='MAXRETRIES' value='$pppsettings{'MAXRETRIES'}' /></td>
</tr>
END
        ;

    if ($pppsettings{'TYPE'} eq 'isdn') {
        print <<END
<tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td colspan='4' class='boldbase'>$Lang::tr{'isdn settings'}:</td>
</tr><tr>
    <td>$Lang::tr{'use ibod'}:</td>
    <td><input type='checkbox' name='USEIBOD' $checked{'USEIBOD'}{'on'} /></td>
    <td>$Lang::tr{'use dov'}:</td>
    <td><input type='checkbox' name='USEDOV' $checked{'USEDOV'}{'on'} /></td>
</tr>
END
        ;
    }

    if ($pppsettings{'TYPE'} eq 'pptp') {
        print <<END
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td colspan='4' class='boldbase'>$Lang::tr{'pptp settings'}:</td>
</tr><tr>
    <td>$Lang::tr{'phonebook entry'}:</td>
    <td><input type='text' name='PHONEBOOK' value='$pppsettings{'PHONEBOOK'}' /></td>
    <td colspan='2'>&nbsp;</td>
</tr><tr>
    <td><input type='radio' name='METHOD' value='STATIC' $checked{'METHOD'}{'STATIC'} />$Lang::tr{'static ip'}</td>
    <td>$Lang::tr{'router ip'}:</td>
    <td><input type='text' name='ROUTERIP' value='$pppsettings{'ROUTERIP'}' /></td>
    <td>&nbsp;</td>
</tr><tr>
    <td>&nbsp;</td>
    <td colspan='3'><hr /></td>
</tr>
<tr>
    <td><input type='radio' name='METHOD' value='DHCP' $checked{'METHOD'}{'DHCP'} />$Lang::tr{'dhcp mode'}</td>
    <td>$Lang::tr{'hostname'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='DHCP_HOSTNAME' value='$pppsettings{'DHCP_HOSTNAME'}' /></td>
    <td>&nbsp;</td>
</tr>
END
            ;
    }

    if ($pppsettings{'TYPE'} eq 'pppoe') {
        print <<END
<tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td colspan='4' class='boldbase'>$Lang::tr{'pppoe settings'}:</td>
</tr>
END
        ;
    }

    if ($pppsettings{'TYPE'} =~
/^(alcatelusb|amedynusbadsl|conexantusbadsl|conexantpciadsl|3cp4218usbadsl|pulsardsl|solosdsl|eciadsl|fritzdsl|bewanadsl|eagleusbadsl|wanpipe-adsl)$/
        )
    {
        print <<END
<tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td colspan='4' class='boldbase'>$Lang::tr{'adsl settings'}:</td>
</tr><tr>
    <td nowrap='nowrap'>$Lang::tr{'vpi number'}:</td>
    <td><input type='text' size='5' name='VPI' value='$pppsettings{'VPI'}' /></td>
    <td>$Lang::tr{'vci number'}:</td>
    <td><input type='text' size='5' name='VCI' value='$pppsettings{'VCI'}' /></td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr>
END
            ;
    }

    if ($pppsettings{'TYPE'} eq 'bewanadsl') {
        print <<END
<tr>
    <td colspan='4'>$Lang::tr{'modem'}:</td>
</tr><tr>
    <td colspan='2'><input type='radio' name='MODEM' value='PCIST' $checked{'MODEM'}{'PCIST'} />Bewan ADSL PCI st</td>
    <td colspan='2'><input type='radio' name='MODEM' value='USB' $checked{'MODEM'}{'USB'} />Bewan ADSL USB st</td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr>
END
        ;
    }

    if ($pppsettings{'TYPE'} =~ /^(3cp4218usbadsl|bewanadsl)$/) {
        print <<END
<tr>
    <td colspan='4'>$Lang::tr{'modulation'}:</td>
</tr><tr>
    <td><input type='radio' name='MODULATION' value='AUTO' $checked{'MODULATION'}{'AUTO'} />$Lang::tr{'automatic'}</td>
    <td><input type='radio' name='MODULATION' value='ANSI' $checked{'MODULATION'}{'ANSI'} />ANSI T1.483</td>
    <td><input type='radio' name='MODULATION' value='GDMT' $checked{'MODULATION'}{'GDMT'} />G.DMT</td>
    <td><input type='radio' name='MODULATION' value='GLITE' $checked{'MODULATION'}{'GLITE'} />G.Lite</td>
</tr>
<tr>
    <td colspan='4'><hr /></td>
</tr>
END
        ;
    }

    if ($pppsettings{'TYPE'} eq 'eagleusbadsl') {
        print <<END
<tr>
    <td>$Lang::tr{'country'}:</td>
    <td>
    <select name='LINE'>
    <option value='WO' $selected{'LINE'}{'WO'}>$Lang::tr{'other countries'}</option>
    <option value='ES' $selected{'LINE'}{'ES'}>ESPANA</option>
    <option value='ES03' $selected{'LINE'}{'ES03'}>ESPANA03</option>
    <option value='FR' $selected{'LINE'}{'FR'}>FRANCE</option>
    <option value='FR04' $selected{'LINE'}{'FR04'}>FRANCE04</option>
    <option value='FR10' $selected{'LINE'}{'FR04'}>FRANCE10</option>
    <option value='IT' $selected{'LINE'}{'IT'}>ITALIA</option>
    </select></td>
    <td colspan='2'>&nbsp;</td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr>
END
        ;
    }

    if ($pppsettings{'TYPE'} eq 'eciadsl') {
        print <<END
<tr>
    <td>$Lang::tr{'modem'}:</td>
    <td colspan='3'>
        <select name='MODEM'>
END
            ;
        open(MODEMS, "/etc/eciadsl/modems.db") or die 'Unable to open modems database.';
        while (my $line = <MODEMS>) {
            $line =~ /^([\S\ ]+).*$/;
            my $modem = $1;
            $modem =~ s/^\s*(.*?)\s*$/$1/;
            print "<option value='$modem'";
            if ($pppsettings{'MODEM'} =~ /$modem/) {
                print " selected";
            }
            print ">$modem</option>\n";
        }
        close(MODEMS);

        print <<END
        </select>
    </td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr>
END
        ;
    }

    if ($pppsettings{'TYPE'} =~
/^(alcatelusb|amedynusbadsl|conexantusbadsl|conexantpciadsl|3cp4218usbadsl|pulsardsl|solosdsl|eciadsl|fritzdsl|bewanadsl|eagleusbadsl|wanpipe-adsl)$/
        )
    {
        print <<END
<tr>
    <td colspan='4'>$Lang::tr{'protocol'}:</td>
</tr><tr>
    <td valign='top' nowrap='nowrap'>
        <input type='radio' name='PROTOCOL' value='RFC2364' $checked{'PROTOCOL'}{'RFC2364'} />RFC2364 PPPoA</td>
END
            ;
    }

    if ($pppsettings{'TYPE'} eq 'alcatelusb') {
        print "<td colspan='3'>&nbsp;</td></tr>";
    }

    if ($pppsettings{'TYPE'} =~
/^(alcatelusb|amedynusbadsl|conexantusbadsl|conexantpciadsl|3cp4218usbadsl|pulsardsl|solosdsl|eciadsl|bewanadsl|eagleusbadsl|fritzdsl|wanpipe-adsl)$/
        )
    {
        print <<END
    <td>$Lang::tr{'encapsulation'}:</td>
    <td colspan='2'>
        <select name='ENCAP_RFC2364'>
        <option value='0' $selected{'ENCAP'}{'0'}>VCmux</option>
        <option value='1' $selected{'ENCAP'}{'1'}>LLC</option>
        </select>
    </td>
</tr>
END
        ;
    }

    if ($pppsettings{'TYPE'} =~
/^(alcatelusb|amedynusbadsl|conexantusbadsl|conexantpciadsl|3cp4218usbadsl|pulsardsl|solosdsl|eciadsl|fritzdsl|bewanadsl|eagleusbadsl|wanpipe-adsl)$/
        )
    {
        print <<END
<tr>
    <td>&nbsp;</td>
    <td colspan='3'><hr /></td>
</tr><tr>
    <td valign='top'>
        <input type='radio' name='PROTOCOL' value='RFC1483' $checked{'PROTOCOL'}{'RFC1483'} />RFC 1483 / 2684</td>
END
        ;
    }

    if ($pppsettings{'TYPE'} eq 'alcatelusb') {
        print "<td colspan='3'>&nbsp;</td></tr>";
    }

    if ($pppsettings{'TYPE'} =~
/^(alcatelusb|amedynusbadsl|conexantusbadsl|conexantpciadsl|3cp4218usbadsl|pulsardsl|eciadsl|bewanadsl|eagleusbadsl|fritzdsl|wanpipe-adsl)$/
        )
    {
        if ($pppsettings{'TYPE'} ne 'fritzdsl') {
            print <<END
    <td>$Lang::tr{'encapsulation'}:</td>
    <td colspan='3'>
        <select name='ENCAP_RFC1483'>
        <option value='0' $selected{'ENCAP'}{'0'}>BRIDGED_ETH_LLC</option>
        <option value='1' $selected{'ENCAP'}{'1'}>BRIDGED_ETH_VC</option>
        <option value='2' $selected{'ENCAP'}{'2'}>ROUTED_IP_LLC</option>
        <option value='3' $selected{'ENCAP'}{'3'}>ROUTED_IP_VC</option>
        </select>
    </td>
</tr><tr>
    <td colspan='2'>&nbsp;</td>
    <td colspan='2'><hr /></td>
</tr>
END
            ;
        }
        else {
            print <<END
    <td colspan='4'>PPPoE</td>
</tr>
END
                ;
        }
    }

    if ($pppsettings{'TYPE'} =~
/^(pppoe|alcatelusb|amedynusbadsl|conexantusbadsl|conexantpciadsl|3cp4218usbadsl|pulsardsl|solosdsl|eciadsl|bewanadsl|eagleusbadsl|wanpipe-adsl)$/
        )
    {
        print <<END
<tr>
    <td>&nbsp;</td>
    <td><input type='radio' name='METHOD' value='PPPOE_PLUGIN' $checked{'METHOD'}{'PPPOE_PLUGIN'} />PPPoE plugin</td>
    <td>$Lang::tr{'service name'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='SERVICENAME' value='$pppsettings{'SERVICENAME'}' /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td><input type='radio' name='METHOD' value='PPPOE' $checked{'METHOD'}{'PPPOE'} />$Lang::tr{'pppoe'}</td>
    <td>$Lang::tr{'concentrator name'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='CONCENTRATORNAME' value='$pppsettings{'CONCENTRATORNAME'}' /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
    <td>$Lang::tr{'vdsl using vlan tag'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' size='4' maxlength='4' name='VDSL_TAG' value='$pppsettings{'VDSL_TAG'}' /></td>
</tr>

END
        ;
    }

    if ($pppsettings{'TYPE'} =~
/^(alcatelusb|amedynusbadsl|conexantusbadsl|conexantpciadsl|3cp4218usbadsl|pulsardsl|eciadsl|bewanadsl|eagleusbadsl|wanpipe-adsl|wanpipe-serial)$/
        )
    {
        print <<END
<tr>
    <td colspan='2'>&nbsp;</td>
    <td colspan='2'><hr /></td>
</tr>
<tr>
    <td rowspan='4'>&nbsp;</td>
    <td valign='top' rowspan='4'><input type='radio' name='METHOD' value='STATIC' $checked{'METHOD'}{'STATIC'} />$Lang::tr{'static ip'}</td>
    <td>$Lang::tr{'static ip'}:</td>
    <td><input type='text' size='16' name='IP' value='$pppsettings{'IP'}' /></td>
</tr><tr>
    <td>$Lang::tr{'gateway ip'}:</td>
    <td><input type='text' size='16' name='GATEWAY' value='$pppsettings{'GATEWAY'}' /></td>
</tr><tr>
    <td>$Lang::tr{'netmask'}:</td>
    <td><input type='text' size='16' name='NETMASK' value='$pppsettings{'NETMASK'}' /></td>
</tr><tr>
    <td nowrap='nowrap'>$Lang::tr{'broadcast'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' size='16' name='BROADCAST' value='$pppsettings{'BROADCAST'}' /></td>
</tr>
END
        ;

        if ($pppsettings{'TYPE'} =~ /^(eciadsl|eagleusbadsl)$/) {
            print <<END
<tr>
    <td colspan='2'>&nbsp;</td>
    <td colspan='2'><hr /></td>
</tr>
<tr>
    <td>&nbsp;</td>
    <td><input type='radio' name='METHOD' value='DHCP' $checked{'METHOD'}{'DHCP'} />$Lang::tr{'dhcp mode'}</td>
    <td>$Lang::tr{'hostname'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='DHCP_HOSTNAME' value='$pppsettings{'DHCP_HOSTNAME'}' /></td>
</tr>
END
            ;
        }
    }

    #drivers that need a file upload
    if ($pppsettings{'TYPE'} =~ /^(alcatelusb|eciadsl|fritzdsl)$/) {
        print "<tr><td colspan='4'><hr /></td></tr>";
    }
    if ($pppsettings{'TYPE'} =~ /^(alcatelusb)$/) {
        my $speedtouch = &General::speedtouchversion;
        if (($speedtouch >= 0) && ($speedtouch <= 4)) {
            my $modem;
            if ($speedtouch == 4) {
                $modem = 'v4_b';
            }
            else {
                $modem = 'v0123';
            }
            print "<tr><td>$Lang::tr{'firmware'}:</td>";
            if (-e "/var/ipcop/alcatelusb/firmware.$modem.bin") {
                print "<td>$Lang::tr{'present'}</td><td colspan='2'>&nbsp;</td></tr>\n";
            }
            else {
                print "<td>$Lang::tr{'not present'}</td><td colspan='2'>&nbsp;</td></tr>\n";
            }
        }
        else {
            print "<tr><td colspan='4'>$Lang::tr{'unknown'} Rev $speedtouch</td></tr>";
        }
    }
    elsif ($pppsettings{'TYPE'} eq 'eciadsl') {
        print "<tr><td>$Lang::tr{'driver'}:</td>";
        if (-e "/var/ipcop/eciadsl/synch.bin") {
            print "<td>$Lang::tr{'present'}</td><td colspan='2'>&nbsp;</td></tr>\n";
        }
        else {
            print "<td>$Lang::tr{'not present'}</td><td colspan='2'>&nbsp;</td></tr>\n";
        }
    }
    elsif ($pppsettings{'TYPE'} eq 'fritzdsl') {
        print "<tr><td>$Lang::tr{'driver'}:</td>";
        if (-e "/lib/modules/$kernel/extra/fcdsl.ko.gz") {
            print "<td>$Lang::tr{'present'}</td><td colspan='2'>&nbsp;</td></tr>\n";
        }
        else {
            print "<td>$Lang::tr{'not present'}</td><td colspan='2'>&nbsp;</td></tr>\n";
        }
    }

    print <<END
<tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td colspan='4' class='boldbase'>$Lang::tr{'authentication'}:</td>
</tr><tr>
    <td>$Lang::tr{'username'}:</td>
    <td><input type='text' name='USERNAME' value='$pppsettings{'USERNAME'}' /></td>
    <td>$Lang::tr{'password'}:</td>
    <td><input type='password' name='PASSWORD' value='$pppsettings{'PASSWORD'}' /></td>
</tr><tr>
    <td>$Lang::tr{'method'}:</td>
    <td><select name='AUTH'>
        <option value='pap-or-chap' $selected{'AUTH'}{'pap-or-chap'}>$Lang::tr{'pap or chap'}</option>
        <option value='pap' $selected{'AUTH'}{'pap'}>PAP</option>
        <option value='chap' $selected{'AUTH'}{'chap'}>CHAP</option>
END
        ;

    if ($pppsettings{'TYPE'} eq 'modem') {
        print <<END
        <option value='standard-login-script' $selected{'AUTH'}{'standard-login-script'}>$Lang::tr{'standard login script'}</option>
        <option value='demon-login-script' $selected{'AUTH'}{'demon-login-script'}>$Lang::tr{'demon login script'}</option>
        <option value='other-login-script' $selected{'AUTH'}{'other-login-script'}>$Lang::tr{'other login script'}</option>
END
            ;
    }

    print <<END
    </select></td>
    <td>$Lang::tr{'script name'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td nowrap='nowrap'><input type='text' name='LOGINSCRIPT' value='$pppsettings{'LOGINSCRIPT'}' /></td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td colspan='4' class='boldbase'>DNS:</td>
</tr><tr>
    <td colspan='4'><input type='radio' name='DNS' value='Automatic' $checked{'DNS'}{'Automatic'} />$Lang::tr{'automatic'}</td>
</tr><tr>
    <td colspan='4'><input type='radio' name='DNS' value='Manual' $checked{'DNS'}{'Manual'} />$Lang::tr{'manual'}</td>
</tr><tr>
    <td>$Lang::tr{'primary dns'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' size='16' name='DNS1' value='$pppsettings{'DNS1'}' /></td>
    <td>$Lang::tr{'secondary dns'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' size='16' name='DNS2' value='$pppsettings{'DNS2'}' /></td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td>$Lang::tr{'profile name'}:</td>
    <td colspan='3'><input type='text' name='PROFILENAME' value='$pppsettings{'PROFILENAME'}' /></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' align='top' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button1button'><input type='submit' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/network-ppp-settings.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
    ;
    &Header::closebox();
}

print "</form>\n";

&Header::closebigbox();

&Header::closepage();


sub initprofile {

    # If we arrive for the first time, profile 1 is empty.
    # Other profiles are never empty, because they are selected.
    if (!defined($pppsettings{'PROFILE'})) {
        $pppsettings{'PROFILE'} = '1';
    }
    $pppsettings{'AUTH'}             = 'pap-or-chap';
    $pppsettings{'AUTOCONNECT'}      = 'off';
    $pppsettings{'BACKUPPROFILE'}    = '0';
    $pppsettings{'BROADCAST'}        = '';
    $pppsettings{'COMPORT'}          = 'ttyS0';
    $pppsettings{'CONCENTRATORNAME'} = '';
    $pppsettings{'DEBUG'}            = 'off';
    $pppsettings{'DHCP_HOSTNAME'}    = '';
    $pppsettings{'DIALONDEMANDDNS'}  = 'off';
    $pppsettings{'DIALMODE'}         = 'T';
    $pppsettings{'DNS'}              = 'Automatic';
    $pppsettings{'DNS1'}             = '';
    $pppsettings{'DNS2'}             = '';
    $pppsettings{'DTERATE'}          = 115200;
    $pppsettings{'ENCAP'}            = '0';
    $pppsettings{'GATEWAY'}          = '';
    $pppsettings{'HOLDOFF'}          = 30;
    $pppsettings{'IP'}               = '';
    $pppsettings{'LINE'}             = 'WO';
    $pppsettings{'LOGINSCRIPT'}      = '';
    $pppsettings{'MAXRETRIES'}       = 5;
    $pppsettings{'METHOD'}           = 'PPPOE_PLUGIN';
    $pppsettings{'MODEM'}            = 'PCIST';
    $pppsettings{'MODULATION'}       = 'AUTO';
    $pppsettings{'NETMASK'}          = '';
    $pppsettings{'PASSWORD'}         = '';
    $pppsettings{'PHONEBOOK'}        = 'RELAY_PPP1';
    $pppsettings{'PROFILENAME'}      = $Lang::tr{'unnamed'};
    $pppsettings{'PROFILEMODEMINIT'} = '';
    $pppsettings{'PROTOCOL'}         = 'RFC2364';
    $pppsettings{'RECONNECTION'}     = 'manual';
    $pppsettings{'ROUTERIP'}         = '';
    $pppsettings{'SENDCR'}           = 'off';
    $pppsettings{'SERVICENAME'}      = '';
    $pppsettings{'SPEAKER'}          = 'off';
    $pppsettings{'TELEPHONE'}        = '';
    $pppsettings{'TIMEOUT'}          = 15;
    $pppsettings{'USEDOV'}           = 'off';
    $pppsettings{'USEIBOD'}          = 'off';
    $pppsettings{'USERNAME'}         = '';
    $pppsettings{'VALID'}            = '';
    $pppsettings{'VCI'}              = '';
    $pppsettings{'VPI'}              = '';
    $pppsettings{'VDSL_TAG'}         = '';

    # Get PPPoE settings so we can see if PPPoE is enabled or not.
    $netsettings{'RED_1_TYPE'} = '';
    &General::readhash("/var/ipcop/ethernet/settings", \%netsettings);

    # empty profile partial pre-initialization
    if ($netsettings{'RED_COUNT'} >= 1) {
        $pppsettings{'TYPE'} = lc($netsettings{'RED_1_TYPE'});
    }
    elsif ($netsettings{'RED_1_TYPE'} eq 'ISDN') {
        $pppsettings{'TYPE'} = 'isdn';
    }
    else {
        $pppsettings{'TYPE'} = 'modem';
    }
}
