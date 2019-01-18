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
# along with Openfirewall. If not, see <http://www.gnu.org/licenses/>.
#
# Copyright (c) 2014-2019 The Openfirewall Team
#

# Add entry in menu
# MENUENTRY network 010 "alt dialup" "dialup settings"
#
# Make sure translation exists $Lang::tr{'alt dialup'} $Lang::tr{'dialup settings'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

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
    &General::readhash("/var/ofw/ppp/settings-$c", \%temppppsettings);
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

if (($pppsettings{'ACTION'} eq '') && (-e '/var/run/ppp-ofw.pid' || -e "/var/ofw/red/active")) {
    $warningmessage = $Lang::tr{'unable to alter profiles while red is active'};

    &General::readhash('/var/ofw/ppp/settings', \%pppsettings);
}
elsif ($pppsettings{'ACTION'} ne ''
    && (-e '/var/run/ppp-ofw.pid' || -e "/var/ofw/red/active"))
{
    $errormessage = $Lang::tr{'unable to alter profiles while red is active'};

    # read in the current vars (could be different from actual user input)
    %pppsettings = ();
    # If RED is DHCP/Static we can have a connection without some sensible defaults in ppp/settings.
    # This messes up the screen: no box termination.
    &initprofile();
    &General::readhash("/var/ofw/ppp/settings", \%pppsettings);
}
elsif ($pppsettings{'ACTION'} eq $Lang::tr{'refresh'}) {
    unless ($pppsettings{'TYPE'} =~
/^(modem|serial|pppoe|pptp)$/
        )
    {
        $errormessage = $Lang::tr{'invalid input'};
        goto ERROR;
    }
    my $type = $pppsettings{'TYPE'};
    &General::readhash("/var/ofw/ppp/settings", \%pppsettings);
    $pppsettings{'TYPE'} = $type;
}
elsif ($pppsettings{'ACTION'} eq $Lang::tr{'save'}) {

    # TODO: do we need to check everything here, or do we simply trust the dropdownlists?

    if ($pppsettings{'TYPE'} =~ /^(modem|serial)$/) {
        my $ttyOK = 0;

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

    if ($pppsettings{'PROFILENAME'} eq '') {
        $errormessage = $Lang::tr{'profile name not given'};
        $pppsettings{'PROFILENAME'} = '';
        goto ERROR;
    }
    if ($pppsettings{'TYPE'} =~ /^(modem)$/) {
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

    if (   ($pppsettings{'PROTOCOL'} eq 'RFC1483')
        && ($pppsettings{'METHOD'} eq ''))
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

    if ($pppsettings{'RECONNECTION'} eq 'dialondemand' && `/bin/cat /var/ofw/ddns/config` =~ /,on$/m) {
        $errormessage = $Lang::tr{'dod not compatible with ddns'};
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
    &General::writehash("/var/ofw/ppp/settings-$pppsettings{'PROFILE'}", \%pppsettings);

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
    &General::readhash("/var/ofw/ppp/settings-$profile", \%pppsettings);

    # need to write default values on disk when profile was empty
    &General::writehash("/var/ofw/ppp/settings-$profile", \%pppsettings);

    # Activate profile
    &General::SelectProfile($profile);

    &General::log("$Lang::tr{'profile made current'}: $pppsettings{'PROFILENAME'}");
}
elsif ($pppsettings{'ACTION'} eq $Lang::tr{'delete'}) {
    my $profile = $pppsettings{'PROFILE'};
    &General::log("$Lang::tr{'profile deleted'}: $profilenames[$profile]");

    truncate("/var/ofw/ppp/settings-$profile", 0);

    # save PROFILE, reset hash and recreate default values for empty profil
    %pppsettings = ();
    $pppsettings{'PROFILE'} = $profile;
    &initprofile();
    &General::writehash("/var/ofw/ppp/settings-$profile", \%pppsettings);

    # Activate profile
    &General::SelectProfile($profile);
    $profilenames[$profile] = $pppsettings{'PROFILENAME'};
}
else {

    # no accepted action set, just read in the current vars
    &General::readhash('/var/ofw/ppp/settings', \%pppsettings);
}

# For dropdown selection, we have profiles 1-5, profile 0 is special case
$selected{'PROFILE'}{$pppsettings{'PROFILE'}} = "selected='selected'";
for ($c = 0; $c <= $maxprofiles; $c++) {
    $selected{'BACKUPPROFILE'}{$c} = '';
}
$selected{'BACKUPPROFILE'}{$pppsettings{'BACKUPPROFILE'}} = "selected='selected'";

$selected{'TYPE'}{'modem'}              = '';
$selected{'TYPE'}{'serial'}             = '';
$selected{'TYPE'}{'pppoe'}              = '';
$selected{'TYPE'}{'pptp'}               = '';
$selected{'TYPE'}{$pppsettings{'TYPE'}} = "selected='selected'";

$checked{'DEBUG'}{'off'}                 = '';
$checked{'DEBUG'}{'on'}                  = '';
$checked{'DEBUG'}{$pppsettings{'DEBUG'}} = "checked='checked'";


for $c (0 .. $#list_ttys) {
    $selected{'COMPORT'}{"$list_ttys[$c]"} = '';
}
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
if ($netsettings{'RED_1_TYPE'} eq 'PPPOE') {
    print "\t<option value='pppoe' $selected{'TYPE'}{'pppoe'}>PPPoE</option>\n";
}
if ($netsettings{'RED_1_TYPE'} eq 'PPTP') {
    print "\t<option value='pptp' $selected{'TYPE'}{'pptp'}>PPTP</option>\n";
}

print <<END
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
    if ($pppsettings{'TYPE'} =~ /^(modem|serial)$/) {
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

        print "    </select></td>\n";

        if ($pppsettings{'TYPE'} =~ /^(modem|serial)$/) {
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

            print "</select></td></tr>";
        }
        else {
            print "<td colspan='2'>&nbsp;</td></tr>\n";
        }

        if ($pppsettings{'TYPE'} =~ /^(modem)$/) {
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
    <td>$Lang::tr{'connect on openfirewall restart'}:</td>
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

    if ($pppsettings{'TYPE'} =~ /^(pppoe)$/)
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
    <td class='button1button'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save'}' /></td>
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
    &General::readhash("/var/ofw/ethernet/settings", \%netsettings);

    # empty profile partial pre-initialization
    if ($netsettings{'RED_COUNT'} >= 1) {
        $pppsettings{'TYPE'} = lc($netsettings{'RED_1_TYPE'});
    }
    else {
        $pppsettings{'TYPE'} = 'modem';
    }
}
