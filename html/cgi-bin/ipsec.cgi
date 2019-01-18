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
#

# Add entry in menu
# MENUENTRY vpn 010 "IPsec" "virtual private networking"

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
### Combine local subnet and connection name to make a unique name for each connection section
### (this sub is not used now)
###
sub makeconnname ($) {
    my $conn = shift;
    my $subnet = shift;

    $subnet =~ /^(.*?)\/(.*?)$/;    # $1=IP $2=mask
    my $ip = unpack('N', &Socket::inet_aton($1));
    if (length ($2) > 2) {
        my $mm =  unpack('N', &Socket::inet_aton($2));
        while ( ($mm & 1)==0 ) {
            $ip >>= 1;
            $mm >>= 1;
        }
    }
    else {
        $ip >>=  (32 - $2);
    }
    return sprintf ("%s-%X", $conn, $ip);
}
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
###
### Export ca certificate to browser
###
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'download ca certificate'}) {
    &General::readhasharray("/var/ofw/vpn/caconfig", \%cahash);

    if ( -f "/var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem" ) {
        print "Content-Type: application/force-download\n";
        print "Content-Type: application/octet-stream\r\n";
        print "Content-Disposition: attachment; filename=$cahash{$cgiparams{'KEY'}}[0]cert.pem\r\n\r\n";
        print `/usr/bin/openssl x509 -in /var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem`;
        exit(0);
    }
    else {
        $errormessage .= "$Lang::tr{'invalid key'}<br />";
    }
}
###
### Export PKCS12 file to browser
###
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'download pkcs12 file'}) {
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);
    print "Content-Type: application/force-download\n";
    print "Content-Disposition: attachment; filename=" . $confighash{$cgiparams{'KEY'}}[1] . ".p12\r\n";
    print "Content-Type: application/octet-stream\r\n\r\n";
    print `/bin/cat /var/ofw/certs/$confighash{$cgiparams{'KEY'}}[1].p12`;
    exit (0);
}
###
### Display certificate
###
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'show certificate'}) {
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);

    if ( -f "/var/ofw/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem") {
        &Header::showhttpheaders();
        &Header::openpage($Lang::tr{'ipsec configuration main'}, 1, '');
        &Header::openbigbox('100%', 'left', '', '');
        &Header::openbox('100%', 'left', "$Lang::tr{'certificate'}:");

        my $output = `/usr/bin/openssl x509 -text -in /var/ofw/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem`;
        $output = &Header::cleanhtml($output,"y");
        print <<END
<table width='100%'><tr>
    <td width='10%'><a href='$ENV{'SCRIPT_NAME'}'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
<hr />
<pre>$output</pre>
<hr />
<table width='100%'><tr>
    <td width='10%'><a href='$ENV{'SCRIPT_NAME'}'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END
        ;
        &Header::closebox();
        &Header::closebigbox();
        &Header::closepage();
        exit(0);
    }
}
###
### Export Certificate to browser
###
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'download certificate'}) {
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);

    if ( -f "/var/ofw/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem") {
        print "Content-Type: application/force-download\n";
        print "Content-Disposition: attachment; filename=" . $confighash{$cgiparams{'KEY'}}[1] . "cert.pem\n\n";
        print `/bin/cat /var/ofw/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem`;
        exit (0);
    }
}
###
### Enable/Disable connection
###
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'toggle enable disable'}) {

    &General::readhash("/var/ofw/ipsec/settings", \%vpnsettings);
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);

    if ($confighash{$cgiparams{'KEY'}}) {
        if ($confighash{$cgiparams{'KEY'}}[0] eq 'off') {
            $confighash{$cgiparams{'KEY'}}[0] = 'on';
            &General::writehasharray("/var/ofw/ipsec/config", \%confighash);
            &VPN::writeipsecfiles();
            if (&VPN::ipsecenabled(\%vpnsettings)) {
                &General::log("ipsec", "Activate connection #$cgiparams{'KEY'}");
                system("/usr/local/bin/ipsecctrl --start=$cgiparams{'KEY'}")
            }
        }
        else {
            if (&VPN::ipsecenabled(\%vpnsettings)) {
                &General::log("ipsec", "Deactivate connection #$cgiparams{'KEY'}");
                system("/usr/local/bin/ipsecctrl --stop=$cgiparams{'KEY'}")
            }
            $confighash{$cgiparams{'KEY'}}[0] = 'off';
            &General::writehasharray("/var/ofw/ipsec/config", \%confighash);
            &VPN::writeipsecfiles();
        }
        sleep $sleepDelay;
    }
    else {
        $errormessage .= "$Lang::tr{'invalid key'}<br />";
    }
}
###
### Restart connection
###
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'restart'}) {
    &General::readhash("/var/ofw/ipsec/settings", \%vpnsettings);
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);

    if ($confighash{$cgiparams{'KEY'}}) {
        if (&VPN::ipsecenabled(\%vpnsettings)) {
            &General::log("ipsec", "Restart connection #$cgiparams{'KEY'}");
            system("/usr/local/bin/ipsecctrl --start=$cgiparams{'KEY'}");
            sleep $sleepDelay;
        }
    }
    else {
        $errormessage .= "$Lang::tr{'invalid key'}<br />";
    }
}
###
### Remove connection
###
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    &General::readhash("/var/ofw/ipsec/settings", \%vpnsettings);
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);

    if ($confighash{$cgiparams{'KEY'}}) {
        if (&VPN::ipsecenabled(\%vpnsettings)) {
            &General::log("ipsec", "Remove connection #$cgiparams{'KEY'}");
            system("/usr/local/bin/ipsecctrl --stop=$cgiparams{'KEY'}")
        }
        unlink ("/var/ofw/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem");
        unlink ("/var/ofw/certs/$confighash{$cgiparams{'KEY'}}[1].p12");
        delete $confighash{$cgiparams{'KEY'}};
        &General::writehasharray("/var/ofw/ipsec/config", \%confighash);
        &VPN::writeipsecfiles();
    }
    else {
        $errormessage .= "$Lang::tr{'invalid key'}<br />";
    }
}
###
### Choose between adding a host-net or net-net connection
###
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'add'} && $cgiparams{'TYPE'} eq '') {
    &Header::showhttpheaders();
    &Header::openpage($Lang::tr{'ipsec configuration main'}, 1, '');
    &Header::openbigbox('100%', 'left', '', '');
    &Header::openbox('100%', 'left', $Lang::tr{'connection type'});
    print <<END
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <b>$Lang::tr{'connection type'}:</b><br />
        <table>
        <tr><td><input type='radio' name='TYPE' value='host' checked='checked' /></td>
        <td class='base'>$Lang::tr{'host to net vpn'}</td>
        </tr><tr>
        <td><input type='radio' name='TYPE' value='net' /></td>
        <td class='base'>$Lang::tr{'net to net vpn'}</td>
        </tr></table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' /></td>
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
    exit (0);
}
###
### Adding/Editing/Saving a  connection
###
elsif (($cgiparams{'ACTION'} eq $Lang::tr{'add'})
        || ($cgiparams{'ACTION'} eq $Lang::tr{'edit'})
        || ($cgiparams{'ACTION'} eq $Lang::tr{'save'} && $cgiparams{'ADVANCED'} eq '')) {

    &General::readhash("/var/ofw/ipsec/settings", \%vpnsettings);
    &General::readhasharray("/var/ofw/vpn/caconfig", \%cahash);
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);

    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        if (! $confighash{$cgiparams{'KEY'}}[0]) {
            $errormessage .= "$Lang::tr{'invalid key'}<br />";
            goto VPNCONF_END;
        }
        $cgiparams{'ENABLED'}       = $confighash{$cgiparams{'KEY'}}[0];
        $cgiparams{'NAME'}          = $confighash{$cgiparams{'KEY'}}[1];
        $cgiparams{'TYPE'}          = $confighash{$cgiparams{'KEY'}}[3];
        $cgiparams{'AUTH'}          = $confighash{$cgiparams{'KEY'}}[4];
        $cgiparams{'PSK'}           = $confighash{$cgiparams{'KEY'}}[5];
        $cgiparams{'TUNNELSTART'}   = $confighash{$cgiparams{'KEY'}}[6];
        $cgiparams{'LOCAL_ID'}      = $confighash{$cgiparams{'KEY'}}[7];
        $cgiparams{'LOCAL_SUBNET'}  = $confighash{$cgiparams{'KEY'}}[8];
        $cgiparams{'REMOTE_ID'}     = $confighash{$cgiparams{'KEY'}}[9];
        $cgiparams{'REMOTE'}        = $confighash{$cgiparams{'KEY'}}[10];
        $cgiparams{'REMOTE_SUBNET'} = $confighash{$cgiparams{'KEY'}}[11];
        $cgiparams{'REMARK'}        = $confighash{$cgiparams{'KEY'}}[25];
        $cgiparams{'INTERFACE'}     = $confighash{$cgiparams{'KEY'}}[26];
        $cgiparams{'DPD_ACTION'}    = $confighash{$cgiparams{'KEY'}}[27];
        $cgiparams{'IKE_ENCRYPTION'}= $confighash{$cgiparams{'KEY'}}[18];
        $cgiparams{'IKE_INTEGRITY'} = $confighash{$cgiparams{'KEY'}}[19];
        $cgiparams{'IKE_GROUPTYPE'} = $confighash{$cgiparams{'KEY'}}[20];
        $cgiparams{'IKE_LIFETIME'}  = $confighash{$cgiparams{'KEY'}}[16];
        $cgiparams{'ESP_ENCRYPTION'}= $confighash{$cgiparams{'KEY'}}[21];
        $cgiparams{'ESP_INTEGRITY'} = $confighash{$cgiparams{'KEY'}}[22];
        $cgiparams{'ESP_GROUPTYPE'} = $confighash{$cgiparams{'KEY'}}[23]; # pfsgroup removed from openswan 2.6.21
        $cgiparams{'ESP_KEYLIFE'}   = $confighash{$cgiparams{'KEY'}}[17];
        $cgiparams{'AGGRMODE'}      = $confighash{$cgiparams{'KEY'}}[12];
        $cgiparams{'COMPRESSION'}   = $confighash{$cgiparams{'KEY'}}[13];
        $cgiparams{'ONLY_PROPOSED'} = $confighash{$cgiparams{'KEY'}}[24];
        $cgiparams{'PFS'}           = $confighash{$cgiparams{'KEY'}}[28];
        $cgiparams{'VHOST'}         = $confighash{$cgiparams{'KEY'}}[14];
    }
    elsif ($cgiparams{'ACTION'} eq $Lang::tr{'save'}) {
        $cgiparams{'REMARK'} = &Header::cleanhtml($cgiparams{'REMARK'});
        if ($cgiparams{'TYPE'} !~ /^(host|net)$/) {
            $errormessage .= "$Lang::tr{'connection type is invalid'}<br />";
            goto VPNCONF_ERROR;
        }

        if ($cgiparams{'NAME'} !~ /^[a-zA-Z]+[a-zA-Z0-9]*$/) {
            $errormessage .= "$Lang::tr{'vpn name is invalid'}<br />";
            $error_connection = 'error';
            goto VPNCONF_ERROR;
        }

        if ($cgiparams{'NAME'} =~ /^(host|01|block|private|clear|packetdefault)$/) {
            $errormessage .= "$Lang::tr{'vpn name is invalid'}<br />";
            $error_connection = 'error';
            goto VPNCONF_ERROR;
        }

        if (length($cgiparams{'NAME'}) >60) {
            $errormessage .= "$Lang::tr{'vpn name is invalid'}<br />";
            $error_connection = 'error';
            goto VPNCONF_ERROR;
        }

        # Check if there is no other entry with this name
        if (! $cgiparams{'KEY'}) {  #only for add
            foreach my $key (keys %confighash) {
                if ($confighash{$key}[1] eq $cgiparams{'NAME'}) {
                    $errormessage .= "$Lang::tr{'a connection with this name already exists'}<br />";
                    $error_connection = 'error';
                    goto VPNCONF_ERROR;
                }
            }
        }

        if (($cgiparams{'TYPE'} eq 'net') && (! $cgiparams{'REMOTE'})) {
            $errormessage .= "$Lang::tr{'invalid input for remote host/ip'}<br />";
            goto VPNCONF_ERROR;
        }

        if ($cgiparams{'REMOTE'}) {
            if (! &General::validip($cgiparams{'REMOTE'})) {
                if (! &General::validfqdn ($cgiparams{'REMOTE'}))  {
                    $errormessage .= "$Lang::tr{'invalid input for remote host/ip'}<br />";
                    goto VPNCONF_ERROR;
                }
                else {
                    if (&General::validdnshost($cgiparams{'REMOTE'})) {
                        $warnmessage .= "$Lang::tr{'check vpn lr'} $cgiparams{'REMOTE'}. $Lang::tr{'dns check failed'}<br />";
                    }
                }
            }
        }

        unless (&General::validipandmask($cgiparams{'LOCAL_SUBNET'})) {
            $errormessage .= "$Lang::tr{'local subnet is invalid'}<br />";
            goto VPNCONF_ERROR;
        }

        # Allow only one roadwarrior/psk without remote IP-address
        if ($cgiparams{'REMOTE'} eq '' && $cgiparams{'AUTH'} eq 'psk') {
            foreach my $key (keys %confighash) {
                if ( ($cgiparams{'KEY'} ne $key) && ($confighash{$key}[4] eq 'psk') && ($confighash{$key}[10] eq '') ) {
                    $errormessage .= "$Lang::tr{'you can only define one roadwarrior connection when using pre-shared key authentication'}<br />";
                    goto VPNCONF_ERROR;
                }
            }
        }
        if (($cgiparams{'TYPE'} eq 'net') && (! &General::validipandmask($cgiparams{'REMOTE_SUBNET'}))) {
            $errormessage .= "$Lang::tr{'remote subnet is invalid'}<br />";
            goto VPNCONF_ERROR;
        }

        if ($cgiparams{'ENABLED'} !~ /^(on|off)$/) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto VPNCONF_ERROR;
        }
        if ($cgiparams{'EDIT_ADVANCED'} !~ /^(on|off)$/) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto VPNCONF_ERROR;
        }

        # Allow nothing or an IP or a string (DN,FDQN,) beginning with @
        # with no comma but slashes between RID eg @O=FR/C=Paris/OU=myhome/CN=franck
        if ( ($cgiparams{'LOCAL_ID'} !~ /^(|[\w.-]*@[\w. =*\/-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) ||
                ($cgiparams{'REMOTE_ID'} !~ /^(|[\w.-]*@[\w. =*\/-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) ||
                (($cgiparams{'REMOTE_ID'} eq $cgiparams{'LOCAL_ID'}) && ($cgiparams{'LOCAL_ID'} ne '')) ) {
            $errormessage .= "$Lang::tr{'invalid local-remote id'} <br />"
                                    . "DER_ASN1_DN: \@c=FR/ou=Paris/ou=Home/cn=*<br />"
                                    . "FQDN: \@example.com<br />"
                                    . "USER_FQDN: user\@example.com<br />"
                                    . "IPV4_ADDR: 123.123.123.123<br />";
            goto VPNCONF_ERROR;
        }
        # If Auth is DN, verify existance of Remote ID.
        if ( $cgiparams{'REMOTE_ID'} eq ''
                && ($cgiparams{'AUTH'} eq 'auth-dn'          # while creation
                    ||$confighash{$cgiparams{'KEY'}}[2] eq '%auth-dn')){ # while editing
            $errormessage .= "$Lang::tr{'vpn missing remote id'}<br />";
            goto VPNCONF_ERROR;
        }

        if ($cgiparams{'AUTH'} eq 'psk') {
            if (! length($cgiparams{'PSK'}) ) {
                $errormessage .= "$Lang::tr{'pre-shared key is too short'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'PSK'} =~ /'/) {
                $cgiparams{'PSK'} =~ tr/'/ /;
                $errormessage .= "$Lang::tr{'invalid characters found in pre-shared key'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
        }
        elsif ($cgiparams{'AUTH'} eq 'certreq') {
            if ($cgiparams{'KEY'}) {
                $errormessage .= "$Lang::tr{'cant change certificates'}<br />";
                goto VPNCONF_ERROR;
            }
            if (blessed($cgiparams{'FH'}) ne 'CGI::File::Temp') {
                $errormessage .= "$Lang::tr{'there was no file upload'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }

            # Move uploaded certificate request to a temporary file
            (my $fh, my $filename) = tempfile( );
            if (copy($cgiparams{'FH'}, $fh) != 1) {
                $errormessage .= "$!<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }

            # Sign the certificate request
            &General::log("ipsec", "Signing your cert $cgiparams{'NAME'}...");
            my  $opt  = " ca -days 999999";
            $opt .= " -batch -notext";
            $opt .= " -in $filename";
            $opt .= " -out /var/ofw/certs/$cgiparams{'NAME'}cert.pem";

            my $return = &VPN::callssl ($opt);
            unlink ($filename);
            &VPN::cleanssldatabase();
            if ($return) {
                $errormessage .= "$return<br />";
                $error_auth = 'error';
                unlink ("/var/ofw/certs/$cgiparams{'NAME'}cert.pem");
                goto VPNCONF_ERROR;
            }

            $cgiparams{'CERT_NAME'} = &VPN::getCNfromcert ("/var/ofw/certs/$cgiparams{'NAME'}cert.pem");
            if ($cgiparams{'CERT_NAME'} eq '') {
                $errormessage .= "$Lang::tr{'could not retrieve common name from certificate'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
        }
        elsif ($cgiparams{'AUTH'} eq 'pkcs12') {
            &General::log("ipsec", "Importing from p12...");

            if (blessed($cgiparams{'FH'}) ne 'CGI::File::Temp') {
                $errormessage .= "$Lang::tr{'there was no file upload'}<br />";
                $error_auth = 'error';
                goto ROOTCERT_ERROR;
            }

            # Move uploaded certificate request to a temporary file
            (my $fh, my $filename) = tempfile( );
            if (copy($cgiparams{'FH'}, $fh) != 1) {
                $errormessage .= "$!<br />";
                $error_auth = 'error';
                goto ROOTCERT_ERROR;
            }

            # Extract the CA certificate from the file
            &General::log("ipsec", "Extracting ca root from p12...");
            if (open(STDIN, "-|")) {
                my  $opt  = " pkcs12 -cacerts -nokeys";
                $opt .= " -in $filename";
                $opt .= " -out /tmp/newcacert";
                my $return = &VPN::callssl ($opt);
                if ($return) {
                    $errormessage .= "$return<br />";
                    $error_auth = 'error';
                }
            }
            else {    #child
                print "$cgiparams{'P12_PASS'}\n";
                exit (0);
            }

            # Extract the Host certificate from the file
            if (!$errormessage) {
                &General::log("ipsec", "Extracting host cert from p12...");
                if (open(STDIN, "-|")) {
                    my  $opt  = " pkcs12 -clcerts -nokeys";
                    $opt .= " -in $filename";
                    $opt .= " -out /tmp/newhostcert";
                    my $return = &VPN::callssl ($opt);
                    $errormessage .= "$return<br />" if ($return);
                }
                else {    #child
                    print "$cgiparams{'P12_PASS'}\n";
                    exit (0);
                }
            }

            if (!$errormessage) {
                &General::log("ipsec", "Moving cacert...");
                # If CA has new subject, add it to our list of CA
                my $casubject = &Header::cleanhtml(&VPN::getsubjectfromcert ('/tmp/newcacert'));
                my @names;
                foreach my $x (keys %cahash) {
                    $casubject = '' if ($cahash{$x}[1] eq $casubject);
                    unshift (@names,$cahash{$x}[0]);
                }
                if ($casubject) { # a new one!
                    my $temp = `/usr/bin/openssl x509 -text -in /tmp/newcacert`;
                    if ($temp !~ /CA:TRUE/i) {
                        $errormessage .= "$Lang::tr{'not a valid ca certificate'}<br />";
                        $error_auth = 'error';
                    }
                    else {
                        # compute a name for it
                        my $idx=0;
                        while (grep(/Imported-$idx/, @names) ) {
                            $idx++
                        };
                        $cgiparams{'CA_NAME'} = "Imported-$idx";
                        $cgiparams{'CERT_NAME'} = &Header::cleanhtml(&VPN::getCNfromcert ('/tmp/newhostcert'));
                        my $return = move("/tmp/newcacert", "/var/ofw/ca/$cgiparams{'CA_NAME'}cert.pem");
                        $errormessage .= "$Lang::tr{'certificate file move failed'}: $!<br />" if ($return ne 1);
                        if (!$errormessage) {
                            my $key = &General::findhasharraykey (\%cahash);
                            $cahash{$key}[0] = $cgiparams{'CA_NAME'};
                            $cahash{$key}[1] = $casubject;
                            &General::writehasharray("/var/ofw/vpn/caconfig", \%cahash);
                            &General::log("ipsec", "Reload certificates and secrets");
                            system("/usr/local/bin/ipsecctrl --reload");
                        }
                    }
                }
            }
            if (!$errormessage) {
                &General::log("ipsec", "Moving host cert...");
                my $return = move("/tmp/newhostcert", "/var/ofw/certs/$cgiparams{'NAME'}cert.pem");
                $errormessage .= "$Lang::tr{'certificate file move failed'}: $!<br />" if ($return ne 1);
            }

            #cleanup temp files
            unlink ($filename);
            unlink ('/tmp/newcacert');
            unlink ('/tmp/newhostcert');
            if ($errormessage) {
                unlink ("/var/ofw/ca/$cgiparams{'CA_NAME'}cert.pem");
                unlink ("/var/ofw/certs/$cgiparams{'NAME'}cert.pem");
                goto VPNCONF_ERROR;
            }
            &General::log("ipsec", "p12 import completed!");
        }
        elsif ($cgiparams{'AUTH'} eq 'certfile') {
            if ($cgiparams{'KEY'}) {
                $errormessage .= "$Lang::tr{'cant change certificates'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if (blessed($cgiparams{'FH'}) ne 'CGI::File::Temp') {
                $errormessage .= "$Lang::tr{'there was no file upload'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            # Move uploaded certificate to a temporary file
            (my $fh, my $filename) = tempfile( );
            if (copy($cgiparams{'FH'}, $fh) != 1) {
                $errormessage .= "$!<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }

            # Verify the certificate has a valid CA and move it
            &General::log("ipsec", "Validating imported cert against our known CA...");
            my $validca = 1;  #assume ok
            my $test = `/usr/bin/openssl verify -CAfile /var/ofw/ca/cacert.pem $filename`;

            if ($test !~ /: OK/) {
                my $validca = 0;
                foreach my $key (keys %cahash) {
                    $test = `/usr/bin/openssl verify -CAfile /var/ofw/ca/$cahash{$key}[0]cert.pem $filename`;
                    if ($test =~ /: OK/) {
                        $validca = 1;
                        last;
                    }
                }
            }

            if (! $validca) {
                $errormessage .= "$Lang::tr{'certificate does not have a valid ca associated with it'}<br />";
                $error_auth = 'error';
                unlink ($filename);
                goto VPNCONF_ERROR;
            }
            else {
                my $return = move($filename, "/var/ofw/certs/$cgiparams{'NAME'}cert.pem");
                if ($return ne 1) {
                    $errormessage .= "$Lang::tr{'certificate file move failed'}: $!<br />";
                    $error_auth = 'error';
                    unlink ($filename);
                    goto VPNCONF_ERROR;
                }
            }

            $cgiparams{'CERT_NAME'} = &VPN::getCNfromcert ("/var/ofw/certs/$cgiparams{'NAME'}cert.pem");
            if ($cgiparams{'CERT_NAME'} eq '') {
                unlink ("/var/ofw/certs/$cgiparams{'NAME'}cert.pem");
                $errormessage .= "$Lang::tr{'could not retrieve common name from certificate'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
        }
        elsif ($cgiparams{'AUTH'} eq 'certgen') {
            if ($cgiparams{'KEY'}) {
                $errormessage .= "$Lang::tr{'cant change certificates'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            # Validate input since the form was submitted
            if (length($cgiparams{'CERT_NAME'}) >60) {
                $errormessage .= "$Lang::tr{'name too long'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_NAME'} !~ /^[a-zA-Z0-9 ,\.\-_]+$/) {
                $errormessage .= "$Lang::tr{'invalid input for name'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_EMAIL'} ne '' && (! &General::validemail($cgiparams{'CERT_EMAIL'}))) {
                $errormessage .= "$Lang::tr{'invalid input for e-mail address'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if (length($cgiparams{'CERT_EMAIL'}) > 40) {
                $errormessage .= "$Lang::tr{'e-mail address too long'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_OU'} ne '' && $cgiparams{'CERT_OU'} !~ /^[a-zA-Z0-9 ,\.\-_]*$/) {
                $errormessage .= "$Lang::tr{'invalid input for department'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if (length($cgiparams{'CERT_ORGANIZATION'}) >60) {
                $errormessage .= $Lang::tr{'organization too long'};
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_ORGANIZATION'} !~ /^[a-zA-Z0-9 ,\.\-_]+$/) {
                $errormessage .= "$Lang::tr{'invalid input for organization'}<br />";
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_CITY'} ne '' && $cgiparams{'CERT_CITY'} !~ /^[a-zA-Z0-9 ,\.\-_]*$/) {
                $errormessage .= "$Lang::tr{'invalid input for city'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_STATE'} ne '' && $cgiparams{'CERT_STATE'} !~ /^[a-zA-Z0-9 ,\.\-_]*$/) {
                $errormessage .= "$Lang::tr{'invalid input for state or province'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_COUNTRY'} !~ /^[A-Z]*$/) {
                $errormessage .= "$Lang::tr{'invalid input for country'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            #the exact syntax is a list comma separated of
            #  email:any-validemail
            #   URI: a uniform resource indicator
            #   DNS: a DNS domain name
            #   RID: a registered OBJECT IDENTIFIER
            #   IP: an IP address
            # example: email:user@example.com,IP:10.0.0.10,DNS:user.example.com

            if ($cgiparams{'SUBJECTALTNAME'} ne '' && $cgiparams{'SUBJECTALTNAME'} !~ /^(email|URI|DNS|RID|IP):[a-zA-Z0-9 :\/,\.\-_@]*$/) {
                $errormessage .= "$Lang::tr{'vpn altname syntax'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }

            if (length($cgiparams{'CERT_PASS1'}) < 5) {
                $errormessage .= "$Lang::tr{'password too short'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_PASS1'} ne $cgiparams{'CERT_PASS2'}) {
                $errormessage .= "$Lang::tr{'passwords do not match'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }

            if (($cgiparams{'YEAR'} < $this_year)
                || (($cgiparams{'YEAR'} == $this_year) && ($cgiparams{'MONTH'} < $now[4]))
                || (($cgiparams{'YEAR'} == $this_year) && ($cgiparams{'MONTH'} == $now[4]) && ($cgiparams{'DAY'} < $now[3])) ) {
                $errormessage .= "$Lang::tr{'invalid date entered'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }
            my $certdays = (POSIX::mktime( 0, 0, 1, $cgiparams{'DAY'}, $cgiparams{'MONTH'}, $cgiparams{'YEAR'}-1900) - POSIX::mktime( 0, 0, 0, $now[3], $now[4], $now[5])) / 86400;
            if ($certdays <= 1) {
                $errormessage .= "$Lang::tr{'invalid date entered'}<br />";
                $error_auth = 'error';
                goto VPNCONF_ERROR;
            }

            # Replace empty strings with a .
            (my $ou = $cgiparams{'CERT_OU'}) =~ s/^\s*$/\./;
            (my $city = $cgiparams{'CERT_CITY'}) =~ s/^\s*$/\./;
            (my $state = $cgiparams{'CERT_STATE'}) =~ s/^\s*$/\./;

            # Create the Host certificate request
            &General::log("ipsec", "Creating a cert...");

            if (open(STDIN, "-|")) {
                my $opt  = " req -nodes -rand /proc/interrupts:/proc/net/rt_cache";
                $opt .= " -newkey rsa:1024";
                $opt .= " -keyout /var/ofw/certs/$cgiparams{'NAME'}key.pem";
                $opt .= " -out /var/ofw/certs/$cgiparams{'NAME'}req.pem";

                my $return = &VPN::callssl ($opt);
                if ($return) {
                    $errormessage .= "$return<br />";
                    $error_auth = 'error';
                    unlink ("/var/ofw/certs/$cgiparams{'NAME'}key.pem");
                    unlink ("/var/ofw/certs/$cgiparams{'NAME'}req.pem");
                    goto VPNCONF_ERROR;
                }
            }
            else {    #child
                print  "$cgiparams{'CERT_COUNTRY'}\n";
                print  "$state\n";
                print  "$city\n";
                print  "$cgiparams{'CERT_ORGANIZATION'}\n";
                print  "$ou\n";
                print  "$cgiparams{'CERT_NAME'}\n";
                print  "$cgiparams{'CERT_EMAIL'}\n";
                print  ".\n";
                print  ".\n";
                exit (0);
            }

            # Sign the host certificate request
            &General::log("ipsec", "Signing the cert $cgiparams{'NAME'}...");

            # No easy way for specifying the contain of subjectAltName without writing a config file...
            my ($fh, $v3extname) = tempfile ('/tmp/XXXXXXXX');
            print $fh <<END
basicConstraints=CA:FALSE
nsComment="OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always
END
;
            print $fh "subjectAltName=$cgiparams{'SUBJECTALTNAME'}" if ($cgiparams{'SUBJECTALTNAME'});
            close ($fh);

            my $opt  = " ca -days $certdays -batch -notext";
            $opt .= " -in /var/ofw/certs/$cgiparams{'NAME'}req.pem";
            $opt .= " -out /var/ofw/certs/$cgiparams{'NAME'}cert.pem";
            $opt .= " -extfile $v3extname";

            my $return = &VPN::callssl ($opt);
            unlink ($v3extname);
            unlink ("/var/ofw/certs/$cgiparams{'NAME'}req.pem");
            &VPN::cleanssldatabase();
            if ($return) {
                $errormessage .= "$return<br />";
                $error_auth = 'error';
                unlink ("/var/ofw/certs/$cgiparams{'NAME'}key.pem");
                unlink ("/var/ofw/certs/$cgiparams{'NAME'}cert.pem");
                goto VPNCONF_ERROR;
            }

            # Create the pkcs12 file
            &General::log("ipsec", "Packing a pkcs12 file...");
            $opt  = " pkcs12 -export";
            $opt .= " -inkey /var/ofw/certs/$cgiparams{'NAME'}key.pem";
            $opt .= " -in /var/ofw/certs/$cgiparams{'NAME'}cert.pem";
            $opt .= " -name \"$cgiparams{'NAME'}\"";
            $opt .= " -passout pass:" . &General::escape_shell($cgiparams{'CERT_PASS1'});
            $opt .= " -certfile /var/ofw/ca/cacert.pem";
            $opt .= " -caname \"$vpnsettings{'ROOTCERT_ORGANIZATION'} CA\"";
            $opt .= " -out /var/ofw/certs/$cgiparams{'NAME'}.p12";

            $return = &VPN::callssl ($opt);
            unlink ("/var/ofw/certs/$cgiparams{'NAME'}key.pem");
            if ($return) {
                $errormessage .= "$return<br />";
                $error_auth = 'error';
                unlink ("/var/ofw/certs/$cgiparams{'NAME'}cert.pem");
                unlink ("/var/ofw/certs/$cgiparams{'NAME'}.p12");
                goto VPNCONF_ERROR;
            }
        }
        elsif ($cgiparams{'AUTH'} eq 'cert') {
            ;# Nothing, just editing
        }
        elsif ($cgiparams{'AUTH'} eq 'auth-dn') {
            $cgiparams{'CERT_NAME'} = '%auth-dn';   # a special value saying 'no cert file'
        }
        else {
            $errormessage .= "$Lang::tr{'invalid input for authentication method'}<br />";
            $error_auth = 'error';
            goto VPNCONF_ERROR;
        }

        # 1) Error message here is not accurate.
        # 2) Test is superfluous, openswan can reference same cert multiple times
        # 3) Present since initial version (1.3.2.11), it isn't a bug correction
        # Check if there is no other entry with this certificate name
        #if ((! $cgiparams{'KEY'}) && ($cgiparams{'AUTH'} ne 'psk') && ($cgiparams{'AUTH'} ne 'auth-dn')) {
        #    foreach my $key (keys %confighash) {
        #   if ($confighash{$key}[2] eq $cgiparams{'CERT_NAME'}) {
        #       $errormessage .= "$Lang::tr{'a connection with this common name already exists'}<br />";
        #       goto VPNCONF_ERROR;
        #   }
        #    }
        #}
        # Save the config

        my $key = $cgiparams{'KEY'};
        if (! $key) {
            $key = &General::findhasharraykey (\%confighash);
            foreach my $i (0 .. 28) { $confighash{$key}[$i] = "";}
        }
        $confighash{$key}[0] = $cgiparams{'ENABLED'};
        $confighash{$key}[1] = $cgiparams{'NAME'};
        if ((! $cgiparams{'KEY'}) && $cgiparams{'AUTH'} ne 'psk') {
            $confighash{$key}[2] = $cgiparams{'CERT_NAME'};
        }
        $confighash{$key}[3] = $cgiparams{'TYPE'};
        if ($cgiparams{'AUTH'} eq 'psk') {
            $confighash{$key}[4] = 'psk';
            $confighash{$key}[5] = $cgiparams{'PSK'};
        }
        else {
            $confighash{$key}[4] = 'cert';
        }
        if ($cgiparams{'TYPE'} eq 'net') {
            $confighash{$key}[11] = $cgiparams{'REMOTE_SUBNET'};
        }
        $confighash{$key}[7] = $cgiparams{'LOCAL_ID'};
        $confighash{$key}[8] = $cgiparams{'LOCAL_SUBNET'};
        $confighash{$key}[9] = $cgiparams{'REMOTE_ID'};
        $confighash{$key}[10] = $cgiparams{'REMOTE'};
        $confighash{$key}[25] = $cgiparams{'REMARK'};
        $confighash{$key}[26] = $cgiparams{'INTERFACE'};
        $confighash{$key}[27] = $cgiparams{'DPD_ACTION'};
        $confighash{$key}[6] = $cgiparams{'TUNNELSTART'};

        # dont forget advanced value
        $confighash{$key}[18] = $cgiparams{'IKE_ENCRYPTION'};
        $confighash{$key}[19] = $cgiparams{'IKE_INTEGRITY'};
        $confighash{$key}[20] = $cgiparams{'IKE_GROUPTYPE'};
        $confighash{$key}[16] = $cgiparams{'IKE_LIFETIME'};
        $confighash{$key}[21] = $cgiparams{'ESP_ENCRYPTION'};
        $confighash{$key}[22] = $cgiparams{'ESP_INTEGRITY'};
        $confighash{$key}[23] = $cgiparams{'ESP_GROUPTYPE'};
        $confighash{$key}[17] = $cgiparams{'ESP_KEYLIFE'};
        $confighash{$key}[12] = $cgiparams{'AGGRMODE'};
        $confighash{$key}[13] = $cgiparams{'COMPRESSION'};
        $confighash{$key}[24] = $cgiparams{'ONLY_PROPOSED'};
        $confighash{$key}[28] = $cgiparams{'PFS'};
        $confighash{$key}[14] = $cgiparams{'VHOST'};

        # free unused fields!
        $confighash{$key}[15] = 'off';

        &General::writehasharray("/var/ofw/ipsec/config", \%confighash);
        &VPN::writeipsecfiles();
        if (&VPN::ipsecenabled(\%vpnsettings)) {
            &General::log("ipsec", "Add connection #$key");
            system("/usr/local/bin/ipsecctrl --start=$key");
            sleep $sleepDelay;
        }
        if ($cgiparams{'EDIT_ADVANCED'} eq 'on') {
            $cgiparams{'KEY'} = $key;
            $cgiparams{'ACTION'} = $Lang::tr{'advanced'};
        }
        goto VPNCONF_END;
    }
    else { # add new connection
        $cgiparams{'ENABLED'} = 'on';
        if ( ! -f "/var/ofw/private/cakey.pem" ) {
            $cgiparams{'AUTH'} = 'psk';
        }
        elsif ( ! -f "/var/ofw/ca/cacert.pem") {
            $cgiparams{'AUTH'} = 'certfile';
        }
        else {
            $cgiparams{'AUTH'} = 'certgen';
        }
        &General::readhash('/var/ofw/vpn/rootcertsettings', \%rootcertsettings) if (-f '/var/ofw/vpn/rootcertsettings');
        $cgiparams{'LOCAL_SUBNET'}      = "$netsettings{'GREEN_1_NETADDRESS'}/$netsettings{'GREEN_1_NETMASK'}";
        $cgiparams{'CERT_EMAIL'}        = $rootcertsettings{'ROOTCERT_EMAIL'};
        $cgiparams{'CERT_OU'}           = $rootcertsettings{'ROOTCERT_OU'};
        $cgiparams{'CERT_ORGANIZATION'} = $rootcertsettings{'ROOTCERT_ORGANIZATION'};
        $cgiparams{'CERT_CITY'}         = $rootcertsettings{'ROOTCERT_CITY'};
        $cgiparams{'CERT_STATE'}        = $rootcertsettings{'ROOTCERT_STATE'};
        $cgiparams{'CERT_COUNTRY'}      = $rootcertsettings{'ROOTCERT_COUNTRY'};

        # choose appropriate dpd action
        if ($cgiparams{'TYPE'} eq 'host') {
            $cgiparams{'DPD_ACTION'} = 'clear';
        }
        else {
            $cgiparams{'DPD_ACTION'} = 'restart';
        }
        # choose appropriate tunnel start action
        if ($cgiparams{'TYPE'} eq 'host') {
            $cgiparams{'TUNNELSTART'} = 'add';
        }
        else {
            $cgiparams{'TUNNELSTART'} = 'start';
        }

        # Default is yes for 'pfs'
        $cgiparams{'PFS'}     = 'on';

        # ID are empty
        $cgiparams{'LOCAL_ID'}  = '';
        $cgiparams{'REMOTE_ID'} = '';

        # use default advanced value
        $cgiparams{'IKE_ENCRYPTION'} = 'aes128|3des';   #[18];
        $cgiparams{'IKE_INTEGRITY'}  = 'sha|md5';       #[19];
        $cgiparams{'IKE_GROUPTYPE'}  = '1536|1024';     #[20];
        $cgiparams{'IKE_LIFETIME'}   = '1';             #[16];
        $cgiparams{'ESP_ENCRYPTION'} = 'aes128|3des';   #[21];
        $cgiparams{'ESP_INTEGRITY'}  = 'sha1|md5';      #[22];
        $cgiparams{'ESP_GROUPTYPE'}  = '';              #[23];
        $cgiparams{'ESP_KEYLIFE'}    = '8';             #[17];
        $cgiparams{'AGGRMODE'}       = 'off';           #[12];
        $cgiparams{'COMPRESSION'}    = 'off';           #[13];
        $cgiparams{'ONLY_PROPOSED'}  = 'off';           #[24];
        $cgiparams{'PFS'}            = 'on';            #[28];
        $cgiparams{'VHOST'}          = 'on';            #[14];
    }

    VPNCONF_ERROR:
    $checked{'ENABLED'}{'off'}  = '';
    $checked{'ENABLED'}{'on'}   = '';
    $checked{'ENABLED'}{$cgiparams{'ENABLED'}} = "checked='checked'";

    $checked{'EDIT_ADVANCED'}{'off'}    = '';
    $checked{'EDIT_ADVANCED'}{'on'}     = '';
    $checked{'EDIT_ADVANCED'}{$cgiparams{'EDIT_ADVANCED'}} = "checked='checked'";

    $checked{'AUTH'}{'psk'}         = '';
    $checked{'AUTH'}{'certreq'}     = '';
    $checked{'AUTH'}{'certgen'}     = '';
    $checked{'AUTH'}{'certfile'}    = '';
    $checked{'AUTH'}{'pkcs12'}      = '';
    $checked{'AUTH'}{'auth-dn'}     = '';
    $checked{'AUTH'}{$cgiparams{'AUTH'}} = "checked='checked'";

    $selected{'INTERFACE'}{'RED'}   = '';
    $selected{'INTERFACE'}{'BLUE'}  = '';
    $selected{'INTERFACE'}{$cgiparams{'INTERFACE'}} = "selected='selected'";

    $selected{'DPD_ACTION'}{'clear'}    = '';
    $selected{'DPD_ACTION'}{'hold'}     = '';
    $selected{'DPD_ACTION'}{'restart'}  = '';
    $selected{'DPD_ACTION'}{$cgiparams{'DPD_ACTION'}} = "selected='selected'";

    $selected{'TUNNELSTART'}{'add'}     = '';
    $selected{'TUNNELSTART'}{'route'}   = '';
    $selected{'TUNNELSTART'}{'start'}   = '';
    $selected{'TUNNELSTART'}{$cgiparams{'TUNNELSTART'}} = "selected='selected'";

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

    print<<END
<form method='post' enctype='multipart/form-data' action='$ENV{'SCRIPT_NAME'}'>
    <input type='hidden' name='TYPE' value='$cgiparams{'TYPE'}' />
    <input type='hidden' name='IKE_ENCRYPTION' value='$cgiparams{'IKE_ENCRYPTION'}' />
    <input type='hidden' name='IKE_INTEGRITY' value='$cgiparams{'IKE_INTEGRITY'}' />
    <input type='hidden' name='IKE_GROUPTYPE' value='$cgiparams{'IKE_GROUPTYPE'}' />
    <input type='hidden' name='IKE_LIFETIME' value='$cgiparams{'IKE_LIFETIME'}' />
    <input type='hidden' name='ESP_ENCRYPTION' value='$cgiparams{'ESP_ENCRYPTION'}' />
    <input type='hidden' name='ESP_INTEGRITY' value='$cgiparams{'ESP_INTEGRITY'}' />
    <input type='hidden' name='ESP_GROUPTYPE' value='$cgiparams{'ESP_GROUPTYPE'}' />
    <input type='hidden' name='ESP_KEYLIFE' value='$cgiparams{'ESP_KEYLIFE'}' />
    <input type='hidden' name='AGGRMODE' value='$cgiparams{'AGGRMODE'}' />
    <input type='hidden' name='COMPRESSION' value='$cgiparams{'COMPRESSION'}' />
    <input type='hidden' name='ONLY_PROPOSED' value='$cgiparams{'ONLY_PROPOSED'}' />
    <input type='hidden' name='PFS' value='$cgiparams{'PFS'}' />
    <input type='hidden' name='VHOST' value='$cgiparams{'VHOST'}' />
END
    ;
    if ($cgiparams{'KEY'}) {
        print "<input type='hidden' name='KEY' value='$cgiparams{'KEY'}' />";
        print "<input type='hidden' name='AUTH' value='$cgiparams{'AUTH'}' />";
    }

    &Header::openbox('100%', 'left', "$Lang::tr{'connection'}:", $error_connection);
    print "<table width='100%'>";
    print "<tr><td width='25%' class='base'>$Lang::tr{'name'}:</td>";
    if ($cgiparams{'KEY'}) {
        print "<td width='25%' class='base'><input type='hidden' name='NAME' value='$cgiparams{'NAME'}' /><b>$cgiparams{'NAME'}</b></td>";
    }
    else {
        print "<td width='25%'><input type='text' name='NAME' value='$cgiparams{'NAME'}' size='30' /></td>";
    }
    print "<td width='25%'>$Lang::tr{'enabled'}:</td><td><input type='checkbox' name='ENABLED' $checked{'ENABLED'}{'on'} /></td>";
    print "</tr><tr><td colspan='4'><br /></td></tr>";

    my $disabled = '';
    my $blob = '';
    if ($cgiparams{'TYPE'} eq 'host') {
        $disabled = "disabled='disabled'";
        $blob = "<img src='/blob.gif' alt='*' />";
    };

    print "<tr><td>$Lang::tr{'host ip'}:</td>";
    print "<td><select name='INTERFACE'>";
    print "<option value='RED' $selected{'INTERFACE'}{'RED'}>RED ($vpnsettings{'VPN_IP'})</option>";
    print "<option value='BLUE' $selected{'INTERFACE'}{'BLUE'}>BLUE ($netsettings{'BLUE_1_ADDRESS'})</option>" if (&FW::haveBlueNet());
    print "</select></td>";
    print <<END
    <td class='base'>$Lang::tr{'remote host/ip'}:&nbsp;$blob</td>
    <td><input type='text' name='REMOTE' value='$cgiparams{'REMOTE'}' size='30' /></td>
</tr><tr>
    <td class='base' nowrap='nowrap'>$Lang::tr{'local subnet'}:</td>
    <td><input type='text' name='LOCAL_SUBNET' value='$cgiparams{'LOCAL_SUBNET'}' size='30' /></td>
    <td class='base' nowrap='nowrap'>$Lang::tr{'remote subnet'}:</td>
    <td><input $disabled type='text' name='REMOTE_SUBNET' value='$cgiparams{'REMOTE_SUBNET'}' size='30' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'vpn local id'}:&nbsp;<img src='/blob.gif' alt='*' />
    <br />($Lang::tr{'eg'}: <tt>&#64;xy.example.com</tt>)</td>
    <td><input type='text' name='LOCAL_ID' value='$cgiparams{'LOCAL_ID'}' /></td>
    <td class='base'>$Lang::tr{'vpn remote id'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='REMOTE_ID' value='$cgiparams{'REMOTE_ID'}' /></td>
</tr><tr>
    <td colspan='4'><br /></td>
</tr><tr>
    <td>$Lang::tr{'dpd action'}:</td>
    <td colspan='3'><select name='DPD_ACTION'>
        <option value='clear' $selected{'DPD_ACTION'}{'clear'}>clear</option>
        <option value='hold' $selected{'DPD_ACTION'}{'hold'}>hold</option>
        <option value='restart' $selected{'DPD_ACTION'}{'restart'}>restart</option>
    </select></td>
</tr><tr>
<!--http://www.openswan.com/docs/local/README.DPD
    http://bugs.xelerance.com/view.php?id=156
    restart = clear + reinitiate connection
-->
END
    ;
    if ($cgiparams{'TYPE'} ne 'host') {
        print <<END
    <td>$Lang::tr{'operation at ipsec startup'}:</td>
    <td colspan='3'><select name='TUNNELSTART'>
        <option value='add' $selected{'TUNNELSTART'}{'add'}>add</option>
        <option value='route' $selected{'TUNNELSTART'}{'route'}>route</option>
        <option value='start' $selected{'TUNNELSTART'}{'start'}>start</option>
    </select>
    </td>
</tr><tr>
END
        ;
    }
    print <<END
    <td class='base'>$Lang::tr{'remark'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='3'><input type='text' name='REMARK' value='$cgiparams{'REMARK'}' size='55' maxlength='50' /></td>
</tr>
END
    ;
    my $advancedbutton = "&nbsp;";
    if (!$cgiparams{'KEY'}) {
        print "<tr><td colspan='4'><input type='checkbox' name='EDIT_ADVANCED' $checked{'EDIT_ADVANCED'}{'on'} /> $Lang::tr{'edit advanced settings when done'}</td></tr>";
    }
    else {
        $advancedbutton = "<input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'advanced'}' />";
    }
    print "</table>";
    print <<END
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button1button'>$advancedbutton</td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/vpns-ipsec.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
    ;
    &Header::closebox();

    my $commentblob = "&nbsp;";
    &Header::openbox('100%', 'left', "$Lang::tr{'authentication'}:", $error_auth);
    if ($cgiparams{'KEY'} && $cgiparams{'AUTH'} eq 'psk') {
        print <<END
<table width='100%' cellpadding='0' cellspacing='5' border='0'><tr>
    <td class='base' width='50%'>$Lang::tr{'use a pre-shared key'}:</td>
    <td class='base' width='50%'><input type='text' name='PSK' size='30' value='$cgiparams{'PSK'}' /></td>
</tr></table>
<hr />
END
        ;
    }
    elsif (! $cgiparams{'KEY'}) {
        # Using %defaultroute in ipsec.secrets produces an error during openswan start
        # strangely a roadwarrior using PSK can still connect, so we'll allow %defaultroute for RW with PSK for now.
        # my $pskdisabled = ($vpnsettings{'VPN_IP'} eq '%defaultroute') ? "disabled='disabled'" : '' ;
        my $pskdisabled = '' ;
        $cgiparams{'PSK'} =  $Lang::tr{'vpn incompatible use of defaultroute'} if ($pskdisabled);
        my $cakeydisabled = ( ! -f "/var/ofw/private/cakey.pem" ) ? "disabled='disabled'" : '';
        $cgiparams{'CERT_NAME'} = $Lang::tr{'vpn no full pki'} if ($cakeydisabled);
        my $cacrtdisabled = ( ! -f "/var/ofw/ca/cacert.pem" ) ? "disabled='disabled'" : '';

        $commentblob = "<img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}" if ($cakeydisabled eq '');

        print <<END
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td width='5%'><input type='radio' name='AUTH' value='psk' $checked{'AUTH'}{'psk'} $pskdisabled/></td>
    <td class='base' width='55%'>$Lang::tr{'use a pre-shared key'}:</td>
    <td class='base' width='40%'><input type='text' name='PSK' size='30' value='$cgiparams{'PSK'}' $pskdisabled/></td>
</tr><tr>
    <td colspan='3' bgcolor='#000000'></td>
</tr><tr>
    <td><input type='radio' name='AUTH' value='certreq' $checked{'AUTH'}{'certreq'} $cakeydisabled /></td>
    <td class='base'><hr />$Lang::tr{'upload a certificate request'}:</td>
    <td class='base' rowspan='3' valign='middle'><input type='file' name='FH' size='30' $cacrtdisabled /></td>
</tr><tr>
    <td><input type='radio' name='AUTH' value='certfile' $checked{'AUTH'}{'certfile'} $cacrtdisabled /></td>
    <td class='base'>$Lang::tr{'upload a certificate'}:</td>
</tr><tr>
    <td><input type='radio' name='AUTH' value='pkcs12' $cacrtdisabled /></td>
    <td class='base'>$Lang::tr{'upload p12 file'} $Lang::tr{'pkcs12 file password'}:<input type='password' name='P12_PASS'/></td>
</tr><tr>
    <td><input type='radio' name='AUTH' value='auth-dn' $checked{'AUTH'}{'auth-dn'} $cacrtdisabled /></td>
    <td class='base'><hr />$Lang::tr{'vpn auth-dn'}</td>
</tr><tr>
    <td colspan='3' bgcolor='#000000'></td>
</tr><tr>
    <td><input type='radio' name='AUTH' value='certgen' $checked{'AUTH'}{'certgen'} $cakeydisabled /></td>
    <td class='base'><hr />$Lang::tr{'generate a certificate'}:</td><td>&nbsp;</td>
</tr><tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'users fullname or system hostname'}:</td>
    <td class='base' nowrap='nowrap'><input type='text' name='CERT_NAME' value='$cgiparams{'CERT_NAME'}' size='32' $cakeydisabled /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'users email'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td class='base' nowrap='nowrap'><input type='text' name='CERT_EMAIL' value='$cgiparams{'CERT_EMAIL'}' size='32' $cakeydisabled /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'users department'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td class='base' nowrap='nowrap'><input type='text' name='CERT_OU' value='$cgiparams{'CERT_OU'}' size='32' $cakeydisabled /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'organization name'}:</td>
    <td class='base' nowrap='nowrap'><input type='text' name='CERT_ORGANIZATION' value='$cgiparams{'CERT_ORGANIZATION'}' size='32' $cakeydisabled /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'city'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td class='base' nowrap='nowrap'><input type='text' name='CERT_CITY' value='$cgiparams{'CERT_CITY'}' size='32' $cakeydisabled /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'state or province'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td class='base' nowrap='nowrap'><input type='text' name='CERT_STATE' value='$cgiparams{'CERT_STATE'}' size='32' $cakeydisabled /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'country'}:</td>
    <td class='base'><select name='CERT_COUNTRY' $cakeydisabled>
END
        ;
        foreach my $country (sort keys %{Countries::countries}) {
            print "\t\t\t<option value='$Countries::countries{$country}'";
            if ( $Countries::countries{$country} eq $cgiparams{'CERT_COUNTRY'} ) {
                print " selected='selected'";
            }
            print ">$country</option>\n";
        }
        print <<END
        </select></td>

</tr><tr>
    <td>&nbsp;</td><td class='base'>$Lang::tr{'vpn subjectaltname'} (subjectAltName=email:*,URI:*,DNS:*,RID:*)<img src='/blob.gif' alt='*' /></td>
    <td class='base' nowrap='nowrap'><input type='text' name='SUBJECTALTNAME' value='$cgiparams{'SUBJECTALTNAME'}' size='32' $cakeydisabled /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'pkcs12 file password'}:</td>
    <td class='base' nowrap='nowrap'><input type='password' name='CERT_PASS1' value='$cgiparams{'CERT_PASS1'}' size='32' $cakeydisabled /></td>
</tr><tr>
    <td>&nbsp;</td><td class='base'>$Lang::tr{'pkcs12 file password'}:($Lang::tr{'confirmation'})</td>
    <td class='base' nowrap='nowrap'><input type='password' name='CERT_PASS2' value='$cgiparams{'CERT_PASS2'}' size='32' $cakeydisabled /></td>
</tr><tr>
    <td>&nbsp;</td><td class='base'>$Lang::tr{'valid until'}:</td>
    <td class='base' nowrap='nowrap'>
    <select name='YEAR'>
END
    ;
    for (my $year = $this_year; $year <= $this_year + 25; $year++) {
        print "\t<option ";
        print "selected='selected' " if ($year == $cgiparams{'YEAR'});
        print "value='$year'>$year</option>\n";
    }
    print "</select>&nbsp;<select name='MONTH'>";
    for (my $month = 0; $month < 12; $month++) {
        print "\t<option ";
        print "selected='selected' " if ($month == $cgiparams{'MONTH'});
        print "value='$month'>$Lang::tr{$General::longMonths[$month]}</option>\n";
    }
    print "</select>&nbsp;<select name='DAY'>";
    for (my $day = 1; $day <= 31; $day++) {
        print "\t<option ";
        print "selected='selected' " if ($day == $cgiparams{'DAY'});
        print "value='$day'>$day</option>\n";
    }
    print <<END
    </select>
    </td>
</tr></table>
<hr />
END
        ;
    }

    print <<END
<table width='100%'>
<tr>
    <td class='comment2button'>$commentblob</td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'cancel'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/vpns-ipsec.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
    ;
    &Header::closebox();
    print "</form>";
    &Header::closebigbox();
    &Header::closepage();
    exit (0);

    VPNCONF_END:
}

###
### Advanced settings
###
if(($cgiparams{'ACTION'} eq $Lang::tr{'advanced'})
    || ($cgiparams{'ACTION'} eq $Lang::tr{'save'} && $cgiparams{'ADVANCED'} eq 'yes')) {

    &General::readhash("/var/ofw/ipsec/settings", \%vpnsettings);
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);

    if (! $confighash{$cgiparams{'KEY'}}) {
        $errormessage .= "$Lang::tr{'invalid key'}<br />";
        goto ADVANCED_END;
    }

    if ($cgiparams{'ACTION'} eq $Lang::tr{'save'}) {
        # I didn't read any incompatibilities here....
        #if ($cgiparams{'VHOST'} eq 'on' && $cgiparams{'COMPRESSION'} eq 'on') {
        #    $errormessage .= "$Lang::tr{'cannot enable both nat traversal and compression'}<br />";
        #    goto ADVANCED_ERROR;
        #}
        my @temp = split('\|', $cgiparams{'IKE_ENCRYPTION'});
        if ($#temp < 0) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
        }
        foreach my $val (@temp) {
            if ($val !~ /^(aes256|aes128|3des|twofish256|twofish128|serpent256|serpent128|blowfish256|blowfish128|cast128)$/) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
            }
        }
        @temp = split('\|', $cgiparams{'IKE_INTEGRITY'});
        if ($#temp < 0) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
        }
        foreach my $val (@temp) {
            if ($val !~ /^(sha2_512|sha2_256|sha|md5)$/) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
            }
        }
        @temp = split('\|', $cgiparams{'IKE_GROUPTYPE'});
        if ($#temp < 0) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
        }
        foreach my $val (@temp) {
            if ($val !~ /^(768|1024|1536|2048|3072|4096|6144|8192)$/) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
            }
        }
        if ($cgiparams{'IKE_LIFETIME'} !~ /^\d+$/) {
            $errormessage .= "$Lang::tr{'invalid input for ike lifetime'}<br />";
            goto ADVANCED_ERROR;
        }
        if ($cgiparams{'IKE_LIFETIME'} < 1 || $cgiparams{'IKE_LIFETIME'} > 8) {
            $errormessage .= "$Lang::tr{'ike lifetime should be between 1 and 8 hours'}<br />";
            goto ADVANCED_ERROR;
        }
        @temp = split('\|', $cgiparams{'ESP_ENCRYPTION'});
        if ($#temp < 0) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
        }
        foreach my $val (@temp) {
            if ($val !~ /^(aes256|aes128|3des|twofish256|twofish128|serpent256|serpent128|blowfish256|blowfish128)$/) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
            }
        }
        @temp = split('\|', $cgiparams{'ESP_INTEGRITY'});
        if ($#temp < 0) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
        }
        foreach my $val (@temp) {
            if ($val !~ /^(sha2_512|sha2_256|sha1|md5)$/) {
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
            }
        }
        # pfsgroup removed from openswan 2.6.21
        # if ($cgiparams{'ESP_GROUPTYPE'} ne '' &&
        #     $cgiparams{'ESP_GROUPTYPE'} !~  /^modp(768|1024|1536|2048|3072|4096)$/) {
        #     $errormessage .= "$Lang::tr{'invalid input'}<br />";
        #     goto ADVANCED_ERROR;
        # }

        if ($cgiparams{'ESP_KEYLIFE'} !~ /^\d+$/) {
            $errormessage .= "$Lang::tr{'invalid input for esp keylife'}<br />";
            goto ADVANCED_ERROR;
        }
        if ($cgiparams{'ESP_KEYLIFE'} < 1 || $cgiparams{'ESP_KEYLIFE'} > 24) {
            $errormessage .= "$Lang::tr{'esp keylife should be between 1 and 24 hours'}<br />";
            goto ADVANCED_ERROR;
        }

        # Achim Weber: Don't allow empty values, otherwise the configfile can break.
        # If the last entry is empty there would be a comma as last char, if you edit
        # another entry that last comma of the first entry will be forgotten.
        # When a checkbox is not selected, there is no cgiparam send.
        # To avoid this don't allow empty values, and init those parameters (which
        # are used as checkbox value) with 'off' before reading %cgiparams.
        if (
            ($cgiparams{'AGGRMODE'} !~ /^(on|off)$/) ||
            ($cgiparams{'COMPRESSION'} !~ /^(on|off)$/) ||
            ($cgiparams{'ONLY_PROPOSED'} !~ /^(on|off)$/) ||
            ($cgiparams{'PFS'} !~ /^(on|off)$/) ||
            ($cgiparams{'VHOST'} !~ /^(on|off)$/)
        ){
            $errormessage .= "$Lang::tr{'invalid input'}<br />";
            goto ADVANCED_ERROR;
        }

        $confighash{$cgiparams{'KEY'}}[18] = $cgiparams{'IKE_ENCRYPTION'};
        $confighash{$cgiparams{'KEY'}}[19] = $cgiparams{'IKE_INTEGRITY'};
        $confighash{$cgiparams{'KEY'}}[20] = $cgiparams{'IKE_GROUPTYPE'};
        $confighash{$cgiparams{'KEY'}}[16] = $cgiparams{'IKE_LIFETIME'};
        $confighash{$cgiparams{'KEY'}}[21] = $cgiparams{'ESP_ENCRYPTION'};
        $confighash{$cgiparams{'KEY'}}[22] = $cgiparams{'ESP_INTEGRITY'};
        $confighash{$cgiparams{'KEY'}}[23] = $cgiparams{'ESP_GROUPTYPE'};
        $confighash{$cgiparams{'KEY'}}[17] = $cgiparams{'ESP_KEYLIFE'};
        $confighash{$cgiparams{'KEY'}}[12] = $cgiparams{'AGGRMODE'};
        $confighash{$cgiparams{'KEY'}}[13] = $cgiparams{'COMPRESSION'};
        $confighash{$cgiparams{'KEY'}}[24] = $cgiparams{'ONLY_PROPOSED'};
        $confighash{$cgiparams{'KEY'}}[28] = $cgiparams{'PFS'};
        $confighash{$cgiparams{'KEY'}}[14] = $cgiparams{'VHOST'};

        &General::writehasharray("/var/ofw/ipsec/config", \%confighash);
        &VPN::writeipsecfiles();

        if (&VPN::ipsecenabled(\%vpnsettings)) {
            &General::log("ipsec", "Start connection #$cgiparams{'KEY'}");
            system("/usr/local/bin/ipsecctrl --start=$cgiparams{'KEY'}");
            sleep $sleepDelay;
        }
        goto ADVANCED_END;
    }
    else {
        $cgiparams{'IKE_ENCRYPTION'} = $confighash{$cgiparams{'KEY'}}[18];
        $cgiparams{'IKE_INTEGRITY'}  = $confighash{$cgiparams{'KEY'}}[19];
        $cgiparams{'IKE_GROUPTYPE'}  = $confighash{$cgiparams{'KEY'}}[20];
        $cgiparams{'IKE_LIFETIME'}   = $confighash{$cgiparams{'KEY'}}[16];
        $cgiparams{'ESP_ENCRYPTION'} = $confighash{$cgiparams{'KEY'}}[21];
        $cgiparams{'ESP_INTEGRITY'}  = $confighash{$cgiparams{'KEY'}}[22];
        $cgiparams{'ESP_GROUPTYPE'}  = $confighash{$cgiparams{'KEY'}}[23];
        $cgiparams{'ESP_KEYLIFE'}    = $confighash{$cgiparams{'KEY'}}[17];
        $cgiparams{'AGGRMODE'}       = $confighash{$cgiparams{'KEY'}}[12];
        $cgiparams{'COMPRESSION'}    = $confighash{$cgiparams{'KEY'}}[13];
        $cgiparams{'ONLY_PROPOSED'}  = $confighash{$cgiparams{'KEY'}}[24];
        $cgiparams{'PFS'}            = $confighash{$cgiparams{'KEY'}}[28];
        $cgiparams{'VHOST'}          = $confighash{$cgiparams{'KEY'}}[14];

        if ($confighash{$cgiparams{'KEY'}}[3] eq 'net' || $confighash{$cgiparams{'KEY'}}[10]) {
            $cgiparams{'VHOST'} = 'off';
        }
    }

    ADVANCED_ERROR:
    $error_advanced = 'error' if ($errormessage);

    $checked{'IKE_ENCRYPTION'}{'aes256'} = '';
    $checked{'IKE_ENCRYPTION'}{'aes128'} = '';
    $checked{'IKE_ENCRYPTION'}{'3des'} = '';
    $checked{'IKE_ENCRYPTION'}{'twofish256'} = '';
    $checked{'IKE_ENCRYPTION'}{'twofish128'} = '';
    $checked{'IKE_ENCRYPTION'}{'serpent256'} = '';
    $checked{'IKE_ENCRYPTION'}{'serpent128'} = '';
    $checked{'IKE_ENCRYPTION'}{'blowfish256'} = '';
    $checked{'IKE_ENCRYPTION'}{'blowfish128'} = '';
    $checked{'IKE_ENCRYPTION'}{'cast128'} = '';
    my @temp = split('\|', $cgiparams{'IKE_ENCRYPTION'});
    foreach my $key (@temp) {$checked{'IKE_ENCRYPTION'}{$key} = "selected='selected'"; }

    $checked{'IKE_INTEGRITY'}{'sha2_512'} = '';
    $checked{'IKE_INTEGRITY'}{'sha2_256'} = '';
    $checked{'IKE_INTEGRITY'}{'sha'} = '';
    $checked{'IKE_INTEGRITY'}{'md5'} = '';
    @temp = split('\|', $cgiparams{'IKE_INTEGRITY'});
    foreach my $key (@temp) {$checked{'IKE_INTEGRITY'}{$key} = "selected='selected'"; }

    $checked{'IKE_GROUPTYPE'}{'768'} = '';
    $checked{'IKE_GROUPTYPE'}{'1024'} = '';
    $checked{'IKE_GROUPTYPE'}{'1536'} = '';
    $checked{'IKE_GROUPTYPE'}{'2048'} = '';
    $checked{'IKE_GROUPTYPE'}{'3072'} = '';
    $checked{'IKE_GROUPTYPE'}{'4096'} = '';
    $checked{'IKE_GROUPTYPE'}{'6144'} = '';
    $checked{'IKE_GROUPTYPE'}{'8192'} = '';
    @temp = split('\|', $cgiparams{'IKE_GROUPTYPE'});
    foreach my $key (@temp) {$checked{'IKE_GROUPTYPE'}{$key} = "selected='selected'"; }

    $checked{'ESP_ENCRYPTION'}{'aes256'} = '';
    $checked{'ESP_ENCRYPTION'}{'aes128'} = '';
    $checked{'ESP_ENCRYPTION'}{'3des'} = '';
    $checked{'ESP_ENCRYPTION'}{'twofish256'} = '';
    $checked{'ESP_ENCRYPTION'}{'twofish128'} = '';
    $checked{'ESP_ENCRYPTION'}{'serpent256'} = '';
    $checked{'ESP_ENCRYPTION'}{'serpent128'} = '';
    $checked{'ESP_ENCRYPTION'}{'blowfish256'} = '';
    $checked{'ESP_ENCRYPTION'}{'blowfish128'} = '';
    @temp = split('\|', $cgiparams{'ESP_ENCRYPTION'});
    foreach my $key (@temp) {$checked{'ESP_ENCRYPTION'}{$key} = "selected='selected'"; }

    $checked{'ESP_INTEGRITY'}{'sha2_512'} = '';
    $checked{'ESP_INTEGRITY'}{'sha2_256'} = '';
    $checked{'ESP_INTEGRITY'}{'sha1'} = '';
    $checked{'ESP_INTEGRITY'}{'md5'} = '';
    @temp = split('\|', $cgiparams{'ESP_INTEGRITY'});
    foreach my $key (@temp) {$checked{'ESP_INTEGRITY'}{$key} = "selected='selected'"; }

    $checked{'ESP_GROUPTYPE'}{'modp768'} = '';
    $checked{'ESP_GROUPTYPE'}{'modp1024'} = '';
    $checked{'ESP_GROUPTYPE'}{'modp1536'} = '';
    $checked{'ESP_GROUPTYPE'}{'modp2048'} = '';
    $checked{'ESP_GROUPTYPE'}{'modp3072'} = '';
    $checked{'ESP_GROUPTYPE'}{'modp4096'} = '';
    $checked{'ESP_GROUPTYPE'}{$cgiparams{'ESP_GROUPTYPE'}} = "selected='selected'";

    $checked{'AGGRMODE'} = $cgiparams{'AGGRMODE'} eq 'on' ? "checked='checked'" : '' ;
    $checked{'COMPRESSION'} = $cgiparams{'COMPRESSION'} eq 'on' ? "checked='checked'" : '' ;
    $checked{'ONLY_PROPOSED'} = $cgiparams{'ONLY_PROPOSED'} eq 'on' ? "checked='checked'" : '' ;
    $checked{'PFS'} = $cgiparams{'PFS'} eq 'on' ? "checked='checked'" : '' ;
    $checked{'VHOST'} = $cgiparams{'VHOST'} eq 'on' ? "checked='checked'" : '' ;

    &Header::showhttpheaders();
    &Header::openpage($Lang::tr{'ipsec configuration main'}, 1, '');
    &Header::openbigbox('100%', 'left', '', $errormessage);

    if ($errormessage) {
        &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
        print "<font class='base'>$errormessage&nbsp;</font>";
        &Header::closebox();
    }

    if ($warnmessage) {
        &Header::openbox('100%', 'left', $Lang::tr{'warning messages'}, 'warning');
        print "<font class='base'>$warnmessage&nbsp;</font>";
        &Header::closebox();
    }

    &Header::openbox('100%', 'left', "$Lang::tr{'advanced'}:", $error_advanced);
    print <<END
    <form method='post' enctype='multipart/form-data' action='$ENV{'SCRIPT_NAME'}'>
    <input type='hidden' name='ADVANCED' value='yes' />
    <input type='hidden' name='KEY' value='$cgiparams{'KEY'}' />

    <table width='100%' border='0'>
    <tr><td class='base' align='right' valign='top'>$Lang::tr{'ike encryption'}:</td><td class='base' valign='top'>
        <select name='IKE_ENCRYPTION' multiple='multiple' size='4'>
        <option value='aes256' $checked{'IKE_ENCRYPTION'}{'aes256'}>AES (256 bit)</option>
        <option value='aes128' $checked{'IKE_ENCRYPTION'}{'aes128'}>AES (128 bit)</option>
        <option value='3des' $checked{'IKE_ENCRYPTION'}{'3des'}>3DES</option>
        <option value='twofish256' $checked{'IKE_ENCRYPTION'}{'twofish256'}>Twofish (256 bit)</option>
        <option value='twofish128' $checked{'IKE_ENCRYPTION'}{'twofish128'}>Twofish (128 bit)</option>
        <option value='serpent256' $checked{'IKE_ENCRYPTION'}{'serpent256'}>Serpent (256 bit)</option>
        <option value='serpent128' $checked{'IKE_ENCRYPTION'}{'serpent128'}>Serpent (128 bit)</option>
        <option value='blowfish256' $checked{'IKE_ENCRYPTION'}{'blowfish256'}>Blowfish (256 bit)</option>
        <option value='blowfish128' $checked{'IKE_ENCRYPTION'}{'blowfish128'}>Blowfish (128 bit)</option>
        <option value='cast128' $checked{'IKE_ENCRYPTION'}{'cast128'}>Cast (128 bit)</option>
        </select></td>

        <td class='base' align='right' valign='top'>$Lang::tr{'ike integrity'}:</td><td class='base' valign='top'>
        <select name='IKE_INTEGRITY' multiple='multiple' size='4'>
        <option value='sha2_512' $checked{'IKE_INTEGRITY'}{'sha2_512'}>SHA2 (512)</option>
        <option value='sha2_256' $checked{'IKE_INTEGRITY'}{'sha2_256'}>SHA2 (256)</option>
        <option value='sha' $checked{'IKE_INTEGRITY'}{'sha'}>SHA</option>
        <option value='md5' $checked{'IKE_INTEGRITY'}{'md5'}>MD5</option>
        </select></td>

        <td class='base' align='right' valign='top'>$Lang::tr{'ike grouptype'}:</td><td class='base' valign='top'>
        <select name='IKE_GROUPTYPE' multiple='multiple' size='4'>
        <option value='8192' $checked{'IKE_GROUPTYPE'}{'8192'}>MODP-8192</option>
        <option value='6144' $checked{'IKE_GROUPTYPE'}{'6144'}>MODP-6144</option>
        <option value='4096' $checked{'IKE_GROUPTYPE'}{'4096'}>MODP-4096</option>
        <option value='3072' $checked{'IKE_GROUPTYPE'}{'3072'}>MODP-3072</option>
        <option value='2048' $checked{'IKE_GROUPTYPE'}{'2048'}>MODP-2048</option>
        <option value='1536' $checked{'IKE_GROUPTYPE'}{'1536'}>MODP-1536</option>
        <option value='1024' $checked{'IKE_GROUPTYPE'}{'1024'}>MODP-1024</option>
        <option value='768'  $checked{'IKE_GROUPTYPE'}{'768'}>MODP-768</option>
        </select></td>
    </tr><tr>
        <td class='base' align='right'>$Lang::tr{'ike lifetime'}:</td><td class='base'>
        <input type='text' name='IKE_LIFETIME' value='$cgiparams{'IKE_LIFETIME'}' size='5' /> $Lang::tr{'hours'}</td>

    </tr><tr>
        <td colspan='6'><hr /></td>
    </tr><tr>
        <td class='base' align='right' valign='top'>$Lang::tr{'esp encryption'}:</td><td class='base' valign='top'>
        <select name='ESP_ENCRYPTION' multiple='multiple' size='4'>
        <option value='aes256' $checked{'ESP_ENCRYPTION'}{'aes256'}>AES (256 bit)</option>
        <option value='aes128' $checked{'ESP_ENCRYPTION'}{'aes128'}>AES (128 bit)</option>
        <option value='3des' $checked{'ESP_ENCRYPTION'}{'3des'}>3DES</option>
        <option value='twofish256' $checked{'ESP_ENCRYPTION'}{'twofish256'}>Twofish (256 bit)</option>
        <option value='twofish128' $checked{'ESP_ENCRYPTION'}{'twofish128'}>Twofish (128 bit)</option>
        <option value='serpent256' $checked{'ESP_ENCRYPTION'}{'serpent256'}>Serpent (256 bit)</option>
        <option value='serpent128' $checked{'ESP_ENCRYPTION'}{'serpent128'}>Serpent (128 bit)</option>
        <option value='blowfish256' $checked{'ESP_ENCRYPTION'}{'blowfish256'}>Blowfish (256 bit)</option>
        <option value='blowfish128' $checked{'ESP_ENCRYPTION'}{'blowfish128'}>Blowfish (128 bit)</option></select></td>

        <td class='base' align='right' valign='top'>$Lang::tr{'esp integrity'}:</td><td class='base' valign='top'>
        <select name='ESP_INTEGRITY' multiple='multiple' size='4'>
        <option value='sha2_512' $checked{'ESP_INTEGRITY'}{'sha2_512'}>SHA2 (512)</option>
        <option value='sha2_256' $checked{'ESP_INTEGRITY'}{'sha2_256'}>SHA2 (256)</option>
        <option value='sha1' $checked{'ESP_INTEGRITY'}{'sha1'}>SHA1</option>
        <option value='md5' $checked{'ESP_INTEGRITY'}{'md5'}>MD5</option></select></td>

<!-- pfsgroup removed from openswan 2.6.21
        <td class='base' align='right' valign='top'>$Lang::tr{'esp grouptype'}:</td><td class='base' valign='top'>
        <select name='ESP_GROUPTYPE'>
        <option value=''>$Lang::tr{'phase1 group'}</option>
        <option value='modp4096' $checked{'ESP_GROUPTYPE'}{'modp4096'}>MODP-4096</option>
        <option value='modp3072' $checked{'ESP_GROUPTYPE'}{'modp3072'}>MODP-3072</option>
        <option value='modp2048' $checked{'ESP_GROUPTYPE'}{'modp2048'}>MODP-2048</option>
        <option value='modp1536' $checked{'ESP_GROUPTYPE'}{'modp1536'}>MODP-1536</option>
        <option value='modp1024' $checked{'ESP_GROUPTYPE'}{'modp1024'}>MODP-1024</option>
        <option value='modp768'  $checked{'ESP_GROUPTYPE'}{'modp768'}>MODP-768</option></select></td>
pfsgroup -->
    </tr><tr>
        <td class='base' align='right'>$Lang::tr{'esp keylife'}:</td><td class='base'>
        <input type='text' name='ESP_KEYLIFE' value='$cgiparams{'ESP_KEYLIFE'}' size='5' /> $Lang::tr{'hours'}</td>
    </tr><tr>
        <td colspan='6'><hr /></td>
    </tr><tr>
        <td colspan='5'><input type='checkbox' name='ONLY_PROPOSED' $checked{'ONLY_PROPOSED'} />
        IKE+ESP: $Lang::tr{'use only proposed settings'}</td>
    </tr><tr>
        <td colspan='6'><input type='checkbox' name='AGGRMODE' $checked{'AGGRMODE'} />
        $Lang::tr{'vpn aggrmode'}</td>
    </tr><tr>
        <td colspan='6'><input type='checkbox' name='PFS' $checked{'PFS'} />
        $Lang::tr{'pfs yes no'}</td>
    </tr><tr>
        <td colspan='6'><input type='checkbox' name='COMPRESSION' $checked{'COMPRESSION'} />
        $Lang::tr{'vpn payload compression'}</td>
    </tr>
END
    ;
    if ($confighash{$cgiparams{'KEY'}}[3] eq 'net') {
        print "<tr><td><input type='hidden' name='VHOST' value='off' /></td></tr>";
    }
    elsif ($confighash{$cgiparams{'KEY'}}[10]) {
        print "<tr><td colspan='5'><input type='checkbox' name='VHOST' $checked{'VHOST'} disabled='disabled' />";
        print " $Lang::tr{'vpn vhost'}</td></tr>";
    }
    else {
        print "<tr><td colspan='5'><input type='checkbox' name='VHOST' $checked{'VHOST'} />";
        print " $Lang::tr{'vpn vhost'}</td></tr>";
    }

    print <<END
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment2button'>&nbsp;</td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'cancel'}' /></td>
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
    exit(0);

    ADVANCED_END:
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


##############################
#
# Box with connections
#
##############################

&Header::openbox('100%', 'left', "$Lang::tr{'connection status and controlc'}:");
print <<END
<table width='100%' border='0' cellspacing='1' cellpadding='0'>
<tr>
    <td width='10%' class='boldbase' align='center'><b>$Lang::tr{'name'}</b> $Header::sortup</td>
    <td width='15%' class='boldbase' align='center'><b>$Lang::tr{'type'}</b></td>
    <td width='15%' class='boldbase' align='center'><b>$Lang::tr{'common name'}</b></td>
    <td width='20%' class='boldbase' align='center'><b>$Lang::tr{'valid until'}</b></td>
    <td width='20%' class='boldbase' align='center'><b>$Lang::tr{'remark'}</b></td>
    <td width='10%' class='boldbase' align='center'><b>$Lang::tr{'status'}</b></td>
    <td width='10%' class='boldbase' align='center' colspan='6'><b>$Lang::tr{'action'}</b></td>
</tr>
END
;
my $id = 0;
my $gif;

foreach my $key (sort SortConfigHashByTunnelName (keys(%confighash))) {
    if ($confighash{$key}[0] eq 'on') {
        $gif = 'on.gif'; }
    else {
        $gif = 'off.gif';
    }

    my $tid = ($id % 2) + 1;
    print "<tr class='table${tid}colour'>";
    print "<td align='center' nowrap='nowrap'>$confighash{$key}[1]</td>";
    print "<td align='center' nowrap='nowrap'>" . $Lang::tr{"$confighash{$key}[3]"} . " (" . $Lang::tr{"$confighash{$key}[4]"} . ")</td>";
    if ($confighash{$key}[2] eq '%auth-dn') {
        print "<td align='center' nowrap='nowrap'>$confighash{$key}[9]</td>";
    }
    elsif ($confighash{$key}[4] eq 'cert') {
        print "<td align='center' nowrap='nowrap'>$confighash{$key}[2]</td>";
    }
    else {
        print "<td align='center'>$confighash{$key}[8]";
        print "<br />[$confighash{$key}[10]]" if ($confighash{$key}[10] ne '');
        print "<br />$confighash{$key}[11]" if ($confighash{$key}[11] ne '');
        print "</td>";
    }

    my $cavalid = `/usr/bin/openssl x509 -text -in /var/ofw/certs/$confighash{$key}[1]cert.pem`;
    $cavalid    =~ /Not After : (.*)[\n]/;
    $cavalid    = $1;
    print "<td align='center'>$cavalid</td>";
    print "<td align='center'>$confighash{$key}[25]</td>";

    #
    my $active = "";
    if ($confighash{$key}[0] eq 'off') {
        $active = "<table class='ofw_closed' cellpadding='2' cellspacing='0' width='100%'><tr><td align='center'>$Lang::tr{'capsclosed'}</td></tr></table>";
    }
    else {
        $active = "<table class='ofw_stopped' cellpadding='2' cellspacing='0' width='100%'><tr><td align='center'>$Lang::tr{'capserror'}</td></tr></table>";
    }
    foreach my $line (@status) {
        if ($line =~ /Pluto is not running/) {
            $active = "<table class='ofw_closed' cellpadding='2' cellspacing='0' width='100%'><tr><td align='center'>$Lang::tr{'capsclosed'}</td></tr></table>";
            last;
        }
        if ($line =~ /\"$confighash{$key}[1]\".*IPsec SA established/) {
            $active = "<table class='ofw_running' cellpadding='2' cellspacing='0' width='100%'><tr><td align='center'>$Lang::tr{'capsopen'}</td></tr></table>";
            last;
        }
        if ($line =~ /\"$confighash{$key}[1]\".*policy/) {
            $active = "<table class='ofw_stopped' cellpadding='2' cellspacing='0' width='100%'><tr><td align='center'>$Lang::tr{'capsclosed'}</td></tr></table>";
        }
    }
    print <<END
    <td align='center'>$active</td>
    <td align='center'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image'  name='$Lang::tr{'restart'}' src='/images/reload.gif' alt='$Lang::tr{'restart'}' title='$Lang::tr{'restart'}' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'restart'}' />
        <input type='hidden' name='KEY' value='$key' />
        </form>
    </td>
END
    ;
    if (($confighash{$key}[4] eq 'cert') && ($confighash{$key}[2] ne '%auth-dn')) {
        print <<END
    <td align='center'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'show certificate'}' src='/images/info.gif' alt='$Lang::tr{'show certificate'}' title='$Lang::tr{'show certificate'}' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'show certificate'}' />
        <input type='hidden' name='KEY' value='$key' />
        </form>
    </td>
END
        ;
    }
    else {
        print "<td width='2%'>&nbsp;</td>";
    }

    if ($confighash{$key}[4] eq 'cert' && -f "/var/ofw/certs/$confighash{$key}[1].p12") {
        print <<END
    <td align='center'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'download pkcs12 file'}' src='/images/floppy.gif' alt='$Lang::tr{'download pkcs12 file'}' title='$Lang::tr{'download pkcs12 file'}' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'download pkcs12 file'}' />
        <input type='hidden' name='KEY' value='$key' />
        </form>
    </td>
END
        ;
    }
    elsif (($confighash{$key}[4] eq 'cert') && ($confighash{$key}[2] ne '%auth-dn')) {
        print <<END
    <td align='center'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'download certificate'}' src='/images/floppy.gif' alt='$Lang::tr{'download certificate'}' title='$Lang::tr{'download certificate'}' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'download certificate'}' />
        <input type='hidden' name='KEY' value='$key' />
        </form>
    </td>
END
        ;
    }
    else {
        print "<td width='2%'>&nbsp;</td>";
    }

    print <<END
    <td align='center'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif' alt='$Lang::tr{'toggle enable disable'}' title='$Lang::tr{'toggle enable disable'}' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
        <input type='hidden' name='KEY' value='$key' />
        </form>
    </td>

    <td align='center'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
        <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
        <input type='hidden' name='KEY' value='$key' />
        </form>
    </td>
    <td align='center' >
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        <input type='image'  name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
        <input type='hidden' name='KEY' value='$key' />
        </form>
    </td>
</tr>
END
    ;
    $id++;
}
print "</table>";

# If the config file contains entries, print Key to action icons
if ( $id ) {
    print <<END
<table>
<tr>
    <td class='boldbase'>&nbsp; <b>$Lang::tr{'legend'}:</b></td>
    <td>&nbsp; <img src='/images/on.gif' alt='$Lang::tr{'click to disable'}' /></td>
    <td class='base'>$Lang::tr{'click to disable'}</td>
    <td>&nbsp; &nbsp; <img src='/images/info.gif' alt='$Lang::tr{'show certificate'}' /></td>
    <td class='base'>$Lang::tr{'show certificate'}</td>
    <td>&nbsp; &nbsp; <img src='/images/edit.gif' alt='$Lang::tr{'edit'}' /></td>
    <td class='base'>$Lang::tr{'edit'}</td>
    <td>&nbsp; &nbsp; <img src='/images/delete.gif' alt='$Lang::tr{'remove'}' /></td>
    <td class='base'>$Lang::tr{'remove'}</td>
</tr><tr>
    <td>&nbsp; </td>
    <td>&nbsp; <img src='/images/off.gif' alt='?OFF' /></td>
    <td class='base'>$Lang::tr{'click to enable'}</td>
    <td>&nbsp; &nbsp; <img src='/images/floppy.gif' alt='?FLOPPY' /></td>
    <td class='base'>$Lang::tr{'download certificate'}</td>
    <td>&nbsp; &nbsp; <img src='/images/reload.gif' alt='?RELOAD'/></td>
    <td class='base'>$Lang::tr{'restart'}</td>
</tr>
</table>
<hr />
END
    ;
}

print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'><table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' /></td>
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



sub SortConfigHashByTunnelName
{
    if ($confighash{$a}[1] lt $confighash{$b}[1]) {
        return -1;
    }
    elsif ($confighash{$a}[1] gt $confighash{$b}[1]) {
        return 1;
    }
    else {
        return 0;
    }
}
