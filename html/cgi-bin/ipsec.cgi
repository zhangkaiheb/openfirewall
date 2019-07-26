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
# (c) 2018-2020 The Openfirewall Team
#
#

# Add entry in menu
# MENUTHRDLVL "IPsec" 010 "IPsec settings" "IPsec settings"

use Net::DNS;
use File::Copy;
use File::Temp qw(tempfile tempdir);
use POSIX();
use Scalar::Util qw(blessed reftype);
use strict;

# enable only the following on debugging purpose
use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/vpn-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/countries.pl';
require '/usr/lib/ofw/firewall-lib.pl';

#workaround to suppress a warning when a variable is used only once
my @dummy = ( ${Header::sortup}, @{General::longMonths} );
undef (@dummy);

# $Lang::tr{'host'} # Dummy string variables included here
# $Lang::tr{'psk'}  # otherwise lang scripts will miss them
# $Lang::tr{'cert'}
# $Lang::tr{'net'}

###
### Initialize variables
###
my $sleepDelay = 4;     # small delay after call to ipsecctrl before reading status

my %netsettings=();
our %cgiparams=();
our %vpnsettings=();
our %rootcertsettings = ();
my %checked=();
my %confighash=();
my %cahash=();
my %selected=();
my $warnmessage = '';
my $errormessage = '';
my $error_advanced = '';
my $error_auth = '';
my $error_ca = '';
my $error_connection = '';
my $error_global = '';

&General::readhash("/var/ofw/ethernet/settings", \%netsettings);
$cgiparams{'ENABLED'} = 'off';
$cgiparams{'ENABLED_RED_1'} = 'off';
$cgiparams{'ENABLED_BLUE_1'} = 'off';
$cgiparams{'EDIT_ADVANCED'} = 'off';
$cgiparams{'ACTION'} = '';
$cgiparams{'CA_NAME'} = '';
$cgiparams{'DBG_CRYPT'} = 'off';
$cgiparams{'DBG_PARSING'} = 'off';
$cgiparams{'DBG_EMITTING'} = 'off';
$cgiparams{'DBG_CONTROL'} = 'off';
# we currently do not use KLIPS, keep the code in case we want to reuse KLIPS in the future
$cgiparams{'DBG_KLIPS'} = 'off';
$cgiparams{'DBG_DNS'} = 'off';
$cgiparams{'DBG_DPD'} = 'off';
$cgiparams{'DBG_NATT'} = 'off';
$cgiparams{'KEY'} = '';
$cgiparams{'TYPE'} = '';
$cgiparams{'ADVANCED'} = '';
$cgiparams{'INTERFACE'} = '';
$cgiparams{'NAME'} = '';
$cgiparams{'LOCAL_SUBNET'} = '';
$cgiparams{'REMOTE_SUBNET'} = '';
$cgiparams{'REMOTE'} = '';
$cgiparams{'LOCAL_ID'} = '';
$cgiparams{'REMOTE_ID'} = '';
$cgiparams{'REMARK'} = '';
$cgiparams{'PSK'} = '';
$cgiparams{'CERT_NAME'} = '';
$cgiparams{'CERT_EMAIL'} = '';
$cgiparams{'CERT_OU'} = '';
$cgiparams{'CERT_ORGANIZATION'} = '';
$cgiparams{'CERT_CITY'} = '';
$cgiparams{'CERT_STATE'} = '';
$cgiparams{'CERT_COUNTRY'} = '';
$cgiparams{'SUBJECTALTNAME'} = '';
$cgiparams{'CERT_PASS1'} = '';
$cgiparams{'CERT_PASS2'} = '';
$cgiparams{'P12_PASS'} = '';
$cgiparams{'ONLY_PROPOSED'} = 'off';
$cgiparams{'AGGRMODE'} = 'off';
$cgiparams{'PFS'} = 'off';
$cgiparams{'COMPRESSION'} = 'off';
$cgiparams{'VHOST'} = 'off';
$cgiparams{'VPN_WATCH'} = 'off';
my @now  = localtime();
$cgiparams{'DAY'}   = $now[3];
$cgiparams{'MONTH'} = $now[4];
my $this_year = $now[5] + 1900;
# default to 15 years valid
$cgiparams{'YEAR'}  = $now[5] + 1900 + 15;

# Those cgiparams are used as checkbox values have to be initalized with 'off' before reading %cgiparams
# If a checkbox is not select, there will be no such cgiparam.
&General::getcgihash(\%cgiparams, {'wantfile' => 1, 'filevar' => 'FH'});

###
### Save main settings
###
if ($cgiparams{'ACTION'} eq $Lang::tr{'save'} && $cgiparams{'TYPE'} eq '' && $cgiparams{'KEY'} eq '') {
    &General::readhash("/var/ofw/ipsec/settings", \%vpnsettings);
    unless (&General::validiporfqdn($cgiparams{'VPN_IP'}) || $cgiparams{'VPN_IP'} eq '%defaultroute') {
        $errormessage .= "$Lang::tr{'invalid input for hostname'}<br />";
        goto SAVE_ERROR;
    }

    unless ($cgiparams{'VPN_DELAYED_START'} =~ /^[0-9]{1,3}$/ ) { #allow 0-999 seconds !
        $errormessage .= "$Lang::tr{'invalid time period'}<br />";
        goto SAVE_ERROR;
    }

    unless ($cgiparams{'VPN_OVERRIDE_MTU'} =~ /^(|[0-9]{1,5})$/ ) { #allow 0-99999
        $errormessage .= "$Lang::tr{'vpn mtu invalid'}<br />";
        goto SAVE_ERROR;
    }

    unless ($cgiparams{'VPN_WATCH'} =~ /^(|off|on)$/ ) {
        $errormessage .= "$Lang::tr{'invalid input'}<br />";
        goto SAVE_ERROR;
    }

    map ($vpnsettings{$_} = $cgiparams{$_},
        ('ENABLED_BLUE_1','ENABLED_RED_1',
         'DBG_CRYPT','DBG_PARSING','DBG_EMITTING','DBG_CONTROL',
         'DBG_KLIPS','DBG_DNS','DBG_DPD','DBG_NATT'));

    $vpnsettings{'VPN_IP'} = $cgiparams{'VPN_IP'};
    $vpnsettings{'VPN_DELAYED_START'} = $cgiparams{'VPN_DELAYED_START'};
    $vpnsettings{'VPN_OVERRIDE_MTU'} = $cgiparams{'VPN_OVERRIDE_MTU'};
    $vpnsettings{'VPN_WATCH'} = $cgiparams{'VPN_WATCH'};

    if($errormessage) {
        $error_global = 'error';
    }
    else {
        &General::writehash("/var/ofw/ipsec/settings", \%vpnsettings);
        &VPN::writeipsecfiles();
        if (&VPN::ipsecenabled(\%vpnsettings)) {
            &General::log("ipsec", "Start ipsecctrl");
            system('/usr/local/bin/ipsecctrl', '--start');
        }
        else {
            &General::log("ipsec", "Stop ipsecctrl");
            system('/usr/local/bin/ipsecctrl', '--stop');
        }
        sleep $sleepDelay;
    }
}

##############################
#
# Box with global settings and status
#
##############################

%cgiparams = ();
%cahash = ();
%confighash = ();
&General::readhash("/var/ofw/ipsec/settings", \%cgiparams);
&General::readhasharray("/var/ofw/vpn/caconfig", \%cahash);
&General::readhasharray("/var/ofw/ipsec/config", \%confighash);
$cgiparams{'CA_NAME'} = '';

my @status = `/usr/local/bin/ipsecctrl --status`;
my $sactive = &General::isrunning('pluto/pluto', 'nosize');

# suggest a default name for this side
if ($cgiparams{'VPN_IP'} eq '' && -e "/var/ofw/red/active") {
    if (open(IPADDR, "/var/ofw/red/local-ipaddress")) {
        my $ipaddr = <IPADDR>;
        close IPADDR;
        chomp ($ipaddr);
        $cgiparams{'VPN_IP'} = (gethostbyaddr(pack("C4", split(/\./, $ipaddr)), 2))[0];
        if ($cgiparams{'VPN_IP'} eq '') {
            $cgiparams{'VPN_IP'} = $ipaddr;
        }
    }
}
# no IP found, use %defaultroute
$cgiparams{'VPN_IP'} ='%defaultroute' if ($cgiparams{'VPN_IP'} eq '');

$cgiparams{'VPN_DELAYED_START'} = 0 if (! defined ($cgiparams{'VPN_DELAYED_START'}));
$checked{'VPN_WATCH'} = $cgiparams{'VPN_WATCH'} eq 'on' ? "checked='checked'" : '' ;
$checked{'ENABLED_BLUE_1'}{'off'} = '';
$checked{'ENABLED_BLUE_1'}{'on'} = '';
$checked{'ENABLED_BLUE_1'}{$cgiparams{'ENABLED_BLUE_1'}} = "checked='checked'";
$checked{'ENABLED_RED_1'}{'off'} = '';
$checked{'ENABLED_RED_1'}{'on'} = '';
$checked{'ENABLED_RED_1'}{$cgiparams{'ENABLED_RED_1'}} = "checked='checked'";
map ($checked{$_} = $cgiparams{$_} eq 'on' ? "checked='checked'" : '',
    (   'DBG_CRYPT','DBG_PARSING','DBG_EMITTING','DBG_CONTROL',
        'DBG_KLIPS','DBG_DNS','DBG_DPD','DBG_NATT'));


&Header::showhttpheaders();
&Header::openpage($Lang::tr{'ipsec configuration main'}, 1, '');
&Header::openbigbox('100%', 'left', '', $errormessage);

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();
}

if ($warnmessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'warning messages'}:", 'warning');
    print "<font class='base'>$warnmessage&nbsp;</font>";
    &Header::closebox();
}

&Header::openbox('100%', 'left', $Lang::tr{'global settings'}, $error_global);
print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'><table width='100%'>
<tr>
    <td class='base' width='25%'>$Lang::tr{'ipsec server'}:</td>
    $sactive
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'ipsec on red'}:</td>
    <td colspan='3'><input type='checkbox' name='ENABLED_RED_1' $checked{'ENABLED_RED_1'}{'on'} /></td>
</tr>
END
;

if (&FW::haveBlueNet()) {
    print "<tr><td class='base'>$Lang::tr{'ipsec on blue'}:</td>";
    print "<td colspan='3'><input type='checkbox' name='ENABLED_BLUE_1' $checked{'ENABLED_BLUE_1'}{'on'} /></td></tr>";
}

# This text contains < and > characters, so use cleanhtml
my $ipsecredname = &Header::cleanhtml($Lang::tr{'vpn red name'});

print <<END
<tr>
    <td class='base'>$ipsecredname:</td>
    <td colspan='3'><input type='text' name='VPN_IP' value='$cgiparams{'VPN_IP'}' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'override mtu'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='3'><input type='text' name='VPN_OVERRIDE_MTU' value='$cgiparams{'VPN_OVERRIDE_MTU'}' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'vpn delayed start'}:&nbsp;<img src='/blob.gif' alt='*' /><img src='/blob.gif' alt='*' /></td>
    <td colspan='3'><input type='text' name='VPN_DELAYED_START' value='$cgiparams{'VPN_DELAYED_START'}' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'vpn watch'}:</td>
    <td colspan='3'><input type='checkbox' name='VPN_WATCH' $checked{'VPN_WATCH'} /></td>
</tr><tr>
    <td class='base'>PLUTO DEBUG</td>
    <td class='base' colspan='3'>
crypt:<input type='checkbox' name='DBG_CRYPT' $checked{'DBG_CRYPT'} />,&nbsp;
parsing:<input type='checkbox' name='DBG_PARSING' $checked{'DBG_PARSING'} />,&nbsp;
emitting:<input type='checkbox' name='DBG_EMITTING' $checked{'DBG_EMITTING'} />,&nbsp;
control:<input type='checkbox' name='DBG_CONTROL' $checked{'DBG_CONTROL'} />,&nbsp;
dns:<input type='checkbox' name='DBG_DNS' $checked{'DBG_DNS'} />,&nbsp;
dpd:<input type='checkbox' name='DBG_DPD' $checked{'DBG_DPD'} />,&nbsp;
nat-t:<input type='checkbox' name='DBG_NATT' $checked{'DBG_NATT'} />
    </td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td colspan='2'>&nbsp;</td>
</tr><tr>
    <td class='comment1button'><img src='/blob.gif' alt='*' /><img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'vpn delayed start help'}</td>
    <td class='button1button'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/vpns-ipsec.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table></form>
END
;
&Header::closebox();


&Header::closebigbox();
&Header::closepage();


