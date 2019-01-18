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
#
# (c) 2018-2019 The Openfirewall Team
#
#

# Add entry in menu
# MENUENTRY vpn 020 "OpenVPN" "virtual private networking"

use CGI;
use CGI qw/:standard/;
use File::Copy;
use File::Temp qw/ tempfile tempdir /;
use strict;
use Archive::Zip qw(:ERROR_CODES :CONSTANTS);
use NetAddr::IP;
use POSIX();

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/vpn-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/countries.pl';
require '/usr/lib/ofw/firewall-lib.pl';

# enable only the following on debugging purpose
#use warnings; no warnings 'once';
#use CGI::Carp 'fatalsToBrowser';


###
### Initialize variables
###
my %netsettings=();
my %cgiparams=();
my %vpnsettings=();
our %rootcertsettings = ();
my %checked=();
my %confighash=();
my %cahash=();
my %selected=();
my $warnmessage = '';
my $errormessage = '';
my %settings=();
my %roadwarriorips = ();
&General::readhash("/var/ofw/ethernet/settings", \%netsettings);
$cgiparams{'ENABLED'} = 'off';
$cgiparams{'ENABLED_RED_1'} = 'off';
$cgiparams{'ENABLED_BLUE_1'} = 'off';
$cgiparams{'EDIT_ADVANCED'} = 'off';
$cgiparams{'NAT'} = 'off';
$cgiparams{'COMPRESSION'} = 'off';
$cgiparams{'ONLY_PROPOSED'} = 'off';
$cgiparams{'ACTION'} = '';
$cgiparams{'CA_NAME'} = '';
$cgiparams{'DHCP_DOMAIN'} = '';
$cgiparams{'DHCP_DNS1'} = '';
$cgiparams{'DHCP_DNS2'} = '';
$cgiparams{'DHCP_NTP1'} = '';
$cgiparams{'DHCP_NTP2'} = '';
$cgiparams{'DHCP_WINS1'} = '';
$cgiparams{'DHCP_WINS2'} = '';
$cgiparams{'NOBIND'} = 'off';
$cgiparams{'FASTIO'} = 'off';
$cgiparams{'MTUDISC'} = 'off';
$cgiparams{'DCOMPLZO'} = 'off';
$cgiparams{'ACTION'} = '';
$cgiparams{'RADIUS_ENABLED'}= 'off';
$cgiparams{'RADIUS_HOST'} = '';
$cgiparams{'RADIUS_AUTHPORT'} = '';
$cgiparams{'RADIUS_ACCTPORT'} = '';
$cgiparams{'RADIUS_RETRY'} = '';
$cgiparams{'RADIUS_TIMEOUT'} = '';
$cgiparams{'RADIUS_PASS1'} = '';
$cgiparams{'PUSH_GREEN_1'} = 'off';
$cgiparams{'PUSH_BLUE_1'} = 'off';
$cgiparams{'PUSH_ORANGE_1'} = 'off';
$cgiparams{'TYPE'} = '';
$cgiparams{'KEY'} = '';
my @now  = localtime();
$cgiparams{'DAY'}   = $now[3];
$cgiparams{'MONTH'} = $now[4];
my $this_year = $now[5] + 1900;
# default to 15 years valid
$cgiparams{'YEAR'}  = $now[5] + 1900 + 15;
$cgiparams{'CERT_BITS'} = 2048;

&General::getcgihash(\%cgiparams, {'wantfile' => 1, 'filevar' => 'FH'});
&General::readhash('/var/ofw/openvpn/settings', \%vpnsettings);
&General::readhasharray('/var/ofw/openvpn/config', \%confighash);

foreach my $key (keys %confighash) {
    # Avoid uninitialized value in Remark field
    $confighash{$key}[25] = '' unless (defined($confighash{$key}[25]));
}

my @serverstatus = `/usr/local/bin/restartopenvpn --status`;

# prepare openvpn config file
###
### Useful functions
###
sub sizeformat {
    my $bytesize = shift;
    my $i = 0;

    while(abs($bytesize) >= 1024) {
        $bytesize=$bytesize/1024;
        $i++;
        last if($i==6);
    }

    my @units = ("Bytes","KB","MB","GB","TB","PB","EB");
    my $newsize=(int($bytesize*100 +0.5))/100;
    return("$newsize $units[$i]");
}

sub deletebackupcert {
    if (open(FILE, '/var/ofw/openvpn/certs/serial.old')) {
        my $hexvalue = <FILE>;
        chomp $hexvalue;
        close FILE;
        unlink ('/var/ofw/openvpn/certs/$hexvalue.pem');
    }
}

sub emptyserverlog{
    if (open(FILE, ">/var/log/openvpnserver.log")) {
        flock FILE, 2;
        print FILE "";
        close FILE;
    }
}

sub writeclientconf {
    my $key = shift;

    return unless ($vpnsettings{'STATICIP'} eq 'on');
    my $filename = "/var/ofw/openvpn/ccd/$confighash{$key}[2]";

    open(CONF, ">$filename") or die "Unable to open $filename $!";
    print CONF "# $confighash{$key}[2]\n";
    my $serverip = NetAddr::IP->new("$confighash{$key}[32]/30")->first()->addr();
    print CONF "ifconfig-push $confighash{$key}[32] $serverip\n";
    close(CONF);
}

sub removeclientconf {
    my $key = shift;
    return unless ($vpnsettings{'STATICIP'} eq 'on');
    my $filename = "/var/ofw/openvpn/ccd/$confighash{$key}[2]";
    unlink($filename) if (-e $filename);
    # In older Openfirewall versions we needed to replace ' ' by '_', so an 'old' ccd file might still be around.
    $filename =~ tr/ /_/;
    unlink($filename) if (-e $filename);
}

sub getroadwarriorips {
    my $thisip = shift;
    my $ovpnnet = NetAddr::IP->new($vpnsettings{'DOVPN_SUBNET'});
    my $index = 5;

    while ($index < $ovpnnet->num()) {
        my $ip = $ovpnnet->nth($index)->addr();
        $roadwarriorips{$ip} = '';
        $roadwarriorips{$ip} = "selected='selected'" if ($ip eq $thisip);
        $index += 4;
    }

    # TODO: remove already assigned IPs from list
    foreach my $key (keys %confighash) {
        delete($roadwarriorips{"$confighash{$key}[32]"}) unless ($confighash{$key}[32] eq $thisip);
    }
}

###
### OpenVPN Server Control
###
if ($cgiparams{'ACTION'} eq $Lang::tr{'start openvpn server'} ||
    $cgiparams{'ACTION'} eq $Lang::tr{'stop openvpn server'} ||
    $cgiparams{'ACTION'} eq $Lang::tr{'restart openvpn server'}) {

    #start openvpn server
    if ($cgiparams{'ACTION'} eq $Lang::tr{'start openvpn server'}) {
        &emptyserverlog();
        system('/usr/local/bin/restartopenvpn', '--start');
    }

    #stop openvpn server
    if ($cgiparams{'ACTION'} eq $Lang::tr{'stop openvpn server'}) {
        system('/usr/local/bin/restartopenvpn', '--stop');
        &emptyserverlog();
    }

    #restart openvpn server
    if ($cgiparams{'ACTION'} eq $Lang::tr{'restart openvpn server'}) {
        system('/usr/local/bin/restartopenvpn', '--restart');
        &emptyserverlog();
    }
}

###
### Save Advanced options
###
if ($cgiparams{'ACTION'} eq $Lang::tr{'save-adv-options'}) {
    map($vpnsettings{$_} = $cgiparams{$_},
        ('LOG_VERB', 'KEEPALIVE_1', 'KEEPALIVE_2', 'MAX_CLIENTS', 'REDIRECT_GW_DEF1', 'STATICIP', 'CLIENT2CLIENT',
         'DHCP_DOMAIN', 'DHCP_DNS1', 'DHCP_DNS2', 'DHCP_NTP1', 'DHCP_NTP2', 'DHCP_WINS1', 'DHCP_WINS2',
         'NOBIND', 'FASTIO', 'MTUDISC', 'LOG_MUTE_REPLAY',
         'RADIUS_ENABLED', 'RADIUS_HOST', 'RADIUS_AUTHPORT', 'RADIUS_ACCTPORT', 'RADIUS_RETRY', 'RADIUS_TIMEOUT', 'RADIUS_PASS1',
         'PUSH_GREEN_1', 'PUSH_BLUE_1', 'PUSH_ORANGE_1'));

    if ($cgiparams{'DHCP_DOMAIN'} ne '') {
        unless (&General::validdomainname($cgiparams{'DHCP_DOMAIN'})) {
            $errormessage = $Lang::tr{'invalid input for dhcp domain'};
            goto ADV_ERROR;
        }
    }
    if ($cgiparams{'DHCP_DNS1'} ne '') {
        unless (&General::validip($cgiparams{'DHCP_DNS1'})) {
            $errormessage = $Lang::tr{'invalid primary dns'};
            goto ADV_ERROR;
        }
    }
    if ($cgiparams{'DHCP_DNS2'} ne '') {
        unless (&General::validip($cgiparams{'DHCP_DNS2'})) {
            $errormessage = $Lang::tr{'invalid secondary dns'};
            goto ADV_ERROR;
        }
        if ($cgiparams{'DHCP_DNS1'} eq '') {
            $errormessage = $Lang::tr{'cannot specify secondary dns without specifying primary'};
            goto ADV_ERROR;
        }
    }
    if ($cgiparams{'DHCP_NTP1'} ne '') {
        unless (&General::validip($cgiparams{'DHCP_NTP1'})) {
            $errormessage = $Lang::tr{'invalid primary ntp'};
            goto ADV_ERROR;
        }
    }
    if ($cgiparams{'DHCP_NTP2'} ne '') {
        unless (&General::validip($cgiparams{'DHCP_NTP2'})) {
            $errormessage = $Lang::tr{'invalid secondary ntp'};
            goto ADV_ERROR;
        }
        if ($cgiparams{'DHCP_NTP1'} eq '') {
            $errormessage = $Lang::tr{'cannot specify secondary ntp without specifying primary'};
            goto ADV_ERROR;
        }
    }
    if ($cgiparams{'DHCP_WINS1'} ne '') {
        unless (&General::validip($cgiparams{'DHCP_WINS1'})) {
            $errormessage = $Lang::tr{'invalid wins address'};
            goto ADV_ERROR;
        }
    }
    if ($cgiparams{'DHCP_WINS2'} ne '') {
        unless (&General::validip($cgiparams{'DHCP_WINS2'})) {
            $errormessage = $Lang::tr{'invalid wins address'};
            goto ADV_ERROR;
        }
        if ($cgiparams{'DHCP_WINS1'} eq '') {
            $errormessage = $Lang::tr{'cannot specify secondary wins without specifying primary'};
            goto ADV_ERROR;
        }
    }
    if ((length($cgiparams{'MAX_CLIENTS'}) == 0) || (($cgiparams{'MAX_CLIENTS'}) < 1 ) || (($cgiparams{'MAX_CLIENTS'}) > 255 )) {
        $errormessage = $Lang::tr{'invalid input for max clients'};
        goto ADV_ERROR;
    }
    if ($cgiparams{'KEEPALIVE_1'} ne '') {
        if ($cgiparams{'KEEPALIVE_1'} !~ /^[0-9]+$/) {
            $errormessage = $Lang::tr{'invalid input for keepalive 1'};
            goto ADV_ERROR;
        }
    }
    if ($cgiparams{'KEEPALIVE_2'} ne '') {
        if ($cgiparams{'KEEPALIVE_2'} !~ /^[0-9]+$/) {
            $errormessage = $Lang::tr{'invalid input for keepalive 2'};
            goto ADV_ERROR;
        }
    }
    if ($cgiparams{'KEEPALIVE_2'} < ($cgiparams{'KEEPALIVE_1'} * 2)) {
        $errormessage = $Lang::tr{'invalid input for keepalive 1:2'};
        goto ADV_ERROR;
    }
    if ($cgiparams{'RADIUS_ENABLED'} eq 'on') {
        if ($cgiparams{'RADIUS_HOST'} ne '') {
            unless (&General::validiporfqdn($cgiparams{'RADIUS_HOST'})) {
                $errormessage = $Lang::tr{'invalid input for radius hostname'};
                goto ADV_ERROR;
            }
        }
        if ($cgiparams{'RADIUS_AUTHPORT'} ne '') {
            unless (&General::validport($cgiparams{'RADIUS_AUTHPORT'})) {
                $errormessage = $Lang::tr{'invalid input for radius authport'};
                goto ADV_ERROR;
            }
        }
        if ($cgiparams{'RADIUS_ACCTPORT'} ne '') {
            unless (&General::validport($cgiparams{'RADIUS_ACCTPORT'})) {
                $errormessage = $Lang::tr{'invalid input for radius acctport'};
                goto ADV_ERROR;
            }
        }
        if ($cgiparams{'RADIUS_AUTHPORT'} eq ($cgiparams{'RADIUS_ACCTPORT'})) {
            $errormessage = $Lang::tr{'invalid input for radius auth acct'};
            goto ADV_ERROR;
        }
        if ($cgiparams{'RADIUS_RETRY'} ne '') {
            if ($cgiparams{'RADIUS_RETRY'} !~ /^[0-9]+$/) {
                $errormessage = $Lang::tr{'invalid input for radius retry'};
                goto ADV_ERROR;
            }
        }
        if ($cgiparams{'RADIUS_TIMEOUT'} ne '') {
            if ($cgiparams{'RADIUS_TIMEOUT'} !~ /^[0-9]+$/) {
                $errormessage = $Lang::tr{'invalid input for radius timeout'};
                goto ADV_ERROR;
            }
        }
#       if ($cgiparams{'RADIUS_PASS1'} ne $cgiparams{'RADIUS_PASS2'}) {
#           $errormessage = $Lang::tr{'passwords do not match'};
#           goto ADV_ERROR;
#       }
    }
    &General::writehash('/var/ofw/openvpn/settings', \%vpnsettings);
    &VPN::writeovpnserverconf();
}


###
### Save main settings
###
if ($cgiparams{'ACTION'} eq $Lang::tr{'save'} && $cgiparams{'TYPE'} eq '' && $cgiparams{'KEY'} eq '') {
    if ($cgiparams{'ENABLED_RED_1'} eq 'on') {
        unless (&General::validiporfqdn($cgiparams{'VPN_IP'})) {
            $errormessage = $Lang::tr{'invalid input for hostname'};
            goto SETTINGS_ERROR;
        }
    }
    if (($cgiparams{'DPROTOCOL'} ne $vpnsettings{'DPROTOCOL'}) || ($cgiparams{'DDEST_PORT'} ne $vpnsettings{'DDEST_PORT'})) {
        # Verify port (usually udp/1994) only if want to change it.
        if (&DATA::isReservedPort($cgiparams{'DPROTOCOL'},$cgiparams{'DDEST_PORT'})) {
            $errormessage = $Lang::tr{'reserved dst port'};
            goto SETTINGS_ERROR;
        }
    }

    # TODO: checking for portforwards will need to be done differently.

    if (! &General::validipandmask($cgiparams{'DOVPN_SUBNET'})) {
        $errormessage = $Lang::tr{'openvpn subnet is invalid'};
        goto SETTINGS_ERROR;
    }
    my $tmpnetaddr = NetAddr::IP->new($cgiparams{'DOVPN_SUBNET'});
    if ($tmpnetaddr->masklen() > 29) {
        # We need at least two /30 networks, one for the server and minimal one for client
        $errormessage = $Lang::tr{'openvpn subnet is invalid'};
        goto SETTINGS_ERROR;
    }

    if (&General::validip($netsettings{'RED_1_ADDRESS'}) && $tmpnetaddr->contains(NetAddr::IP->new($netsettings{'RED_1_ADDRESS'}))) {
        $errormessage = "$Lang::tr{'openvpn subnet overlap'}: Openfirewall RED Network $netsettings{'RED_1_ADDRESS'}";
        goto SETTINGS_ERROR;
    }

    if ($tmpnetaddr->contains(NetAddr::IP->new($netsettings{'GREEN_1_ADDRESS'}))) {
        $errormessage = "$Lang::tr{'openvpn subnet overlap'}: Openfirewall Green Network $netsettings{'GREEN_1_ADDRESS'}";
        goto SETTINGS_ERROR;
    }

    if (&General::validip($netsettings{'BLUE_1_ADDRESS'}) && $tmpnetaddr->contains(NetAddr::IP->new($netsettings{'BLUE_1_ADDRESS'}))) {
        $errormessage = "$Lang::tr{'openvpn subnet overlap'}: Openfirewall Blue Network $netsettings{'BLUE_1_ADDRESS'}";
        goto SETTINGS_ERROR;
    }

    if (&General::validip($netsettings{'ORANGE_1_ADDRESS'}) && $tmpnetaddr->contains(NetAddr::IP->new($netsettings{'ORANGE_1_ADDRESS'}))) {
        $errormessage = "$Lang::tr{'openvpn subnet overlap'}: Openfirewall Orange Network $netsettings{'ORANGE_1_ADDRESS'}";
        goto SETTINGS_ERROR;
    }
    open(ALIASES, '/var/ofw/ethernet/aliases') or die 'Unable to open aliases file.';
    while (<ALIASES>) {
        chomp($_);
        my @tempalias = split(/\,/,$_);
        if ($tempalias[1] eq 'on') {
            if (&General::validip($tempalias[0]) && $tmpnetaddr->contains(NetAddr::IP->new($tempalias[0]))) {
                $errormessage = "$Lang::tr{'openvpn subnet overlap'}: Openfirewall alias entry $tempalias[0]";
            }
        }
    }
    close(ALIASES);
    if ($errormessage ne '') {
        goto SETTINGS_ERROR;
    }

    if ($cgiparams{'ENABLED_RED_1'} !~ /^(on|off)$/) {
        $errormessage = $Lang::tr{'invalid input'};
        goto SETTINGS_ERROR;
    }
    if ((length($cgiparams{'DMTU'})==0) || (($cgiparams{'DMTU'}) < 1000 )) {
        $errormessage = $Lang::tr{'invalid mtu input'};
        goto SETTINGS_ERROR;
    }

    unless (&General::validport($cgiparams{'DDEST_PORT'})) {
        $errormessage = $Lang::tr{'invalid port'};
        goto SETTINGS_ERROR;
    }

    map($vpnsettings{$_} = $cgiparams{$_},
        ('ENABLED_BLUE_1', 'ENABLED_RED_1', 'VPN_IP', 'DOVPN_SUBNET', 'DDEVICE', 'DPROTOCOL', 'DDEST_PORT', 'DMTU', 'DCOMPLZO', 'DCIPHER'));
    &General::writehash('/var/ofw/openvpn/settings', \%vpnsettings);
    &VPN::writeovpnserverconf();
SETTINGS_ERROR:

###
### Enable/Disable connection
###
}
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'toggle enable disable'}) {
    if ($confighash{$cgiparams{'KEY'}}) {
        if ($confighash{$cgiparams{'KEY'}}[0] eq 'off') {
            $confighash{$cgiparams{'KEY'}}[0] = 'on';
            &General::writehasharray('/var/ofw/openvpn/config', \%confighash);
            &writeclientconf($cgiparams{'KEY'});
        }
        else {
            $confighash{$cgiparams{'KEY'}}[0] = 'off';
            &General::writehasharray('/var/ofw/openvpn/config', \%confighash);
            &removeclientconf($cgiparams{'KEY'});
        }
    }
    else {
        $errormessage = $Lang::tr{'invalid key'};
    }

###
### Download OpenVPN client package
###
}
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'dl client arch'}) {
    my $file = '';
    my $clientovpn = '';
    my @fileholder;
    my $tempdir = tempdir( CLEANUP => 1 );
    my $zippath = "$tempdir/";
    my $zipname = "$confighash{$cgiparams{'KEY'}}[1]-TO-IPCop.zip";
    my $zippathname = "$zippath$zipname";
    $clientovpn = "$confighash{$cgiparams{'KEY'}}[1]-TO-IPCop.ovpn";
    open(CLIENTCONF, ">$tempdir/$clientovpn") or die "Unable to open tempfile: $!";
    flock CLIENTCONF, 2;

    my $zip = Archive::Zip->new();

    print CLIENTCONF "#OpenVPN Server conf\r\n";
    if ( $vpnsettings{'RADIUS_ENABLED'} eq 'on') {
        print CLIENTCONF "auth-user-pass\r\n";
    }
    print CLIENTCONF "tls-client\r\n";
    print CLIENTCONF "client\r\n";
    print CLIENTCONF "dev $vpnsettings{'DDEVICE'}\r\n";
    print CLIENTCONF "proto $vpnsettings{'DPROTOCOL'}\r\n";
    print CLIENTCONF "$vpnsettings{'DDEVICE'}-mtu $vpnsettings{'DMTU'}\r\n";
    if ($vpnsettings{'NOBIND'} eq 'on') {
        print CLIENTCONF "nobind\r\n";
    }
    if ( $vpnsettings{'ENABLED_RED_1'} eq 'on') {
        print CLIENTCONF "remote $vpnsettings{'VPN_IP'} $vpnsettings{'DDEST_PORT'}\r\n";

        if ($vpnsettings{'ENABLED_BLUE_1'} eq 'on' && (&FW::haveBlueNet())) {
            print CLIENTCONF "#Comment the above line and uncomment the next line, if you want to connect on the Blue interface\r\n";
            print CLIENTCONF ";remote $netsettings{'BLUE_1_ADDRESS'} $vpnsettings{'DDEST_PORT'}\r\n";
        }
    }
    elsif ($vpnsettings{'ENABLED_BLUE_1'} eq 'on' && (&FW::haveBlueNet())) {
        print CLIENTCONF "remote $netsettings{'BLUE_1_ADDRESS'} $vpnsettings{'DDEST_PORT'}\r\n";
    }

    if ($confighash{$cgiparams{'KEY'}}[4] eq 'cert' && -f "/var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1].p12") {
        print CLIENTCONF "pkcs12 $confighash{$cgiparams{'KEY'}}[1].p12\r\n";
        $zip->addFile("/var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1].p12", "$confighash{$cgiparams{'KEY'}}[1].p12") or die "Can't add file $confighash{$cgiparams{'KEY'}}[1].p12\n";
    }
    else {
        print CLIENTCONF "ca cacert.pem\r\n";
        print CLIENTCONF "cert $confighash{$cgiparams{'KEY'}}[1]cert.pem\r\n";
        print CLIENTCONF "key $confighash{$cgiparams{'KEY'}}[1].key\r\n";
        $zip->addFile("/var/ofw/ca/cacert.pem", "cacert.pem")  or die "Can't add file cacert.pem\n";
        $zip->addFile("/var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem", "$confighash{$cgiparams{'KEY'}}[1]cert.pem") or die "Can't add file $confighash{$cgiparams{'KEY'}}[1]cert.pem\n";
    }
    print CLIENTCONF "cipher $vpnsettings{DCIPHER}\r\n";
    if ($vpnsettings{DCOMPLZO} eq 'on') {
        print CLIENTCONF "comp-lzo\r\n";
    }
    print CLIENTCONF "verb 3\r\n";
    print CLIENTCONF "ns-cert-type server\r\n";
    close(CLIENTCONF);
    $zip->addFile( "$tempdir/$clientovpn", $clientovpn) or die "Can't add file $clientovpn\n";
    my $status = $zip->writeToFileNamed($zippathname);

    open(DLFILE, "<$zippathname") or die "Unable to open $zippathname: $!";
    @fileholder = <DLFILE>;
    print "Content-Type:application/x-download\n";
    print "Content-Disposition:attachment;filename=$zipname\n\n";
    print @fileholder;
    exit (0);

###
### Remove connection
###
}
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    if ($confighash{$cgiparams{'KEY'}}) {
        system("/usr/bin/openssl ca -revoke /var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem");
        unlink ("/var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem");
        unlink ("/var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1].p12");
        &removeclientconf($cgiparams{'KEY'});
        delete $confighash{$cgiparams{'KEY'}};
        system("/usr/bin/openssl ca -gencrl -out /var/ofw/crls/cacrl.pem");
        &General::writehasharray('/var/ofw/openvpn/config', \%confighash);
    }
    else {
        $errormessage = $Lang::tr{'invalid key'};
    }

###
### Download PKCS12 file
###
}
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'download pkcs12 file'}) {
    print "Content-Disposition: filename=" . $confighash{$cgiparams{'KEY'}}[1] . ".p12\r\n";
    print "Content-Type: application/octet-stream\r\n\r\n";
    print `/bin/cat /var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1].p12`;
    exit (0);

###
### Display certificate
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'show certificate'}) {
    if ( -f "/var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem") {
        &Header::showhttpheaders();
        &Header::openpage($Lang::tr{'openvpn configuration main'}, 1, '');
        &Header::openbigbox('100%', 'left', '', '');
        &Header::openbox('100%', 'left', "$Lang::tr{'certificate'}:");
        my $output = `/usr/bin/openssl x509 -text -in /var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem`;
        $output = &Header::cleanhtml($output,"y");
        print <<END
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/openvpn.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
<hr />
<pre>$output</pre>
<hr />
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/openvpn.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END
        ;
        &Header::closebox();
        &Header::closebigbox();
        &Header::closepage();
        exit(0);
    }

###
### Display Certificate Revoke List
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'show crl'}) {

    if ( -f '/var/ofw/crls/cacrl.pem') {
        &Header::showhttpheaders();
        &Header::openpage($Lang::tr{'openvpn configuration main'}, 1, '');
        &Header::openbigbox('100%', 'left', '', '');
        &Header::openbox('100%', 'left', "$Lang::tr{'crl'}:");
        my $output = `/usr/bin/openssl crl -text -noout -in /var/ofw/crls/cacrl.pem`;
        $output = &Header::cleanhtml($output,"y");
        print <<END
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/openvpn.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
<hr />
<pre>$output</pre>
<hr />
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/openvpn.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END
        ;
        &Header::closebox();
        &Header::closebigbox();
        &Header::closepage();
        exit(0);
    }

###
### Advanced Server Settings
###

}
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'advanced server'}) {
    %cgiparams = ();
    %cahash = ();
    &General::readhash('/var/ofw/openvpn/settings', \%cgiparams);

ADV_ERROR:
    if ($cgiparams{'MAX_CLIENTS'} eq '') {
        $cgiparams{'MAX_CLIENTS'} =  '100';
    }

    if ($cgiparams{'KEEPALIVE_1'} eq '') {
        $cgiparams{'KEEPALIVE_1'} =  '10';
    }
    if ($cgiparams{'KEEPALIVE_2'} eq '') {
        $cgiparams{'KEEPALIVE_2'} =  '60';
    }
    if ($cgiparams{'LOG_VERB'} eq '') {
        $cgiparams{'LOG_VERB'} =  '3';
    }
    $checked{'STATICIP'}{'off'} = '';
    $checked{'STATICIP'}{'on'} = '';
    $checked{'STATICIP'}{$cgiparams{'STATICIP'}} = "checked='checked'";
    $checked{'CLIENT2CLIENT'}{'off'} = '';
    $checked{'CLIENT2CLIENT'}{'on'} = '';
    $checked{'CLIENT2CLIENT'}{$cgiparams{'CLIENT2CLIENT'}} = "checked='checked'";
    $checked{'REDIRECT_GW_DEF1'}{'off'} = '';
    $checked{'REDIRECT_GW_DEF1'}{'on'} = '';
    $checked{'REDIRECT_GW_DEF1'}{$cgiparams{'REDIRECT_GW_DEF1'}} = "checked='checked'";
    $checked{'PUSH_GREEN_1'}{'off'} = '';
    $checked{'PUSH_GREEN_1'}{'on'} = '';
    $checked{'PUSH_GREEN_1'}{$cgiparams{'PUSH_GREEN_1'}} = "checked='checked'";
    $checked{'PUSH_BLUE_1'}{'off'} = '';
    $checked{'PUSH_BLUE_1'}{'on'} = '';
    $checked{'PUSH_BLUE_1'}{$cgiparams{'PUSH_BLUE_1'}} = "checked='checked'";
    $checked{'PUSH_ORANGE_1'}{'off'} = '';
    $checked{'PUSH_ORANGE_1'}{'on'} = '';
    $checked{'PUSH_ORANGE_1'}{$cgiparams{'PUSH_ORANGE_1'}} = "checked='checked'";
    $checked{'NOBIND'}{'off'} = '';
    $checked{'NOBIND'}{'on'} = '';
    $checked{'NOBIND'}{$cgiparams{'NOBIND'}} = "checked='checked'";
    $checked{'FASTIO'}{'off'} = '';
    $checked{'FASTIO'}{'on'} = '';
    $checked{'FASTIO'}{$cgiparams{'FASTIO'}} = "checked='checked'";
    # fast-io only useable if proto is udp
    $checked{'FASTIO'}{'on'} = $checked{'FASTIO'}{'on'}." disabled='disabled'" unless ($cgiparams{'DPROTOCOL'} eq 'udp');
    $checked{'MTUDISC'}{'off'} = '';
    $checked{'MTUDISC'}{'on'} = '';
    $checked{'MTUDISC'}{$cgiparams{'MTUDISC'}} = "checked='checked'";
    $selected{'LOG_VERB'}{'1'} = '';
    $selected{'LOG_VERB'}{'2'} = '';
    $selected{'LOG_VERB'}{'3'} = '';
    $selected{'LOG_VERB'}{'4'} = '';
    $selected{'LOG_VERB'}{'5'} = '';
    $selected{'LOG_VERB'}{'6'} = '';
    $selected{'LOG_VERB'}{'7'} = '';
    $selected{'LOG_VERB'}{'8'} = '';
    $selected{'LOG_VERB'}{'9'} = '';
    $selected{'LOG_VERB'}{'10'} = '';
    $selected{'LOG_VERB'}{'11'} = '';
    $selected{'LOG_VERB'}{'0'} = '';
    $selected{'LOG_VERB'}{$cgiparams{'LOG_VERB'}} = "selected='selected'";
    $checked{'LOG_MUTE_REPLAY'}{'off'} = '';
    $checked{'LOG_MUTE_REPLAY'}{'on'} = '';
    $checked{'LOG_MUTE_REPLAY'}{$cgiparams{'LOG_MUTE_REPLAY'}} = "checked='checked'";

    $checked{'RADIUS_ENABLED'}{'off'} = '';
    $checked{'RADIUS_ENABLED'}{'on'} = '';
    $checked{'RADIUS_ENABLED'}{$cgiparams{'RADIUS_ENABLED'}} = "checked='checked'";

    &Header::showhttpheaders();
    &Header::openpage($Lang::tr{'openvpn configuration main'}, 1, '');
    &Header::openbigbox('100%', 'left', '');
    if ($errormessage) {
        &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
        print "<font class='base'>$errormessage&nbsp;</font>";
        &Header::closebox();
    }
    &Header::openbox('100%', 'left', "$Lang::tr{'advanced server'}:");
    print <<END
<form method='post' enctype='multipart/form-data' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td class='boldbase' colspan='4'>$Lang::tr{'dhcp-options'}</td>
</tr><tr>
    <td width='25%' class='base'>$Lang::tr{'domain name suffix'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='3'><input type='text' name='DHCP_DOMAIN' value='$cgiparams{'DHCP_DOMAIN'}' size='30' /></td>
</tr><tr>
    <td width='25%' class='base'>$Lang::tr{'primary dns'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td width='25%'><input type='text' name='DHCP_DNS1' value='$cgiparams{'DHCP_DNS1'}' /></td>
    <td width='25%' class='base'>$Lang::tr{'secondary dns'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td width='25%'><input type='text' name='DHCP_DNS2' value='$cgiparams{'DHCP_DNS2'}' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'primary ntp server'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='DHCP_NTP1' value='$cgiparams{'DHCP_NTP1'}' /></td>
    <td class='base'>$Lang::tr{'secondary ntp server'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='DHCP_NTP2' value='$cgiparams{'DHCP_NTP2'}' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'primary wins server address'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='DHCP_WINS1' value='$cgiparams{'DHCP_WINS1'}' /></td>
    <td class='base'>$Lang::tr{'secondary wins server address'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='DHCP_WINS2' value='$cgiparams{'DHCP_WINS2'}' /></td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td class='boldbase' colspan='4'>$Lang::tr{'push-routes'}</td>
</tr><tr>
    <td class='base'>$Lang::tr{'redirect traffic'}:</td>
    <td colspan='3'><input type='checkbox' name='REDIRECT_GW_DEF1' $checked{'REDIRECT_GW_DEF1'}{'on'} /> (<tt>redirect-gateway def1</tt>)</td>
</tr><tr>
    <td class='base'>Green Network:</td>
    <td colspan='3'><input type='checkbox' name='PUSH_GREEN_1' $checked{'PUSH_GREEN_1'}{'on'} /></td>
</tr><tr>
END
    ;
    if (&FW::haveBlueNet()) {
        print <<END
    <td class='base'>Blue Network:</td>
    <td colspan='3'><input type='checkbox' name='PUSH_BLUE_1' $checked{'PUSH_BLUE_1'}{'on'} /></td>
</tr><tr>
END
        ;
    }
    if (&FW::haveOrangeNet()) {
        print <<END
    <td class='base'>Orange Network:</td>
    <td colspan='3'><input type='checkbox' name='PUSH_ORANGE_1' $checked{'PUSH_ORANGE_1'}{'on'} /></td>
</tr><tr>
END
        ;
    }
    print <<END
    <td colspan='4'><hr /></td>
</tr><tr>
    <td class='boldbase' colspan='4'>$Lang::tr{'misc-options'}</td>
</tr><tr>
    <td class='base'>$Lang::tr{'static ip'}:</td>
    <td><input type='checkbox' name='STATICIP' $checked{'STATICIP'}{'on'} /></td>
    <td class='base'>Fast IO:</td>
    <td><input type='checkbox' name='FASTIO' $checked{'FASTIO'}{'on'} /></td>
</tr><tr>
    <td class='base'>Client-To-Client:</td>
    <td><input type='checkbox' name='CLIENT2CLIENT' $checked{'CLIENT2CLIENT'}{'on'} /></td>
    <td class='base'>MTU discovery:</td>
    <td><input type='checkbox' name='MTUDISC' $checked{'MTUDISC'}{'on'} /></td>
</tr><tr>
    <td class='base'>Nobind:</td>
    <td colspan='3'><input type='checkbox' name='NOBIND' $checked{'NOBIND'}{'on'} /></td>
</tr><tr>
    <td class='base'>Max-Clients:</td>
    <td colspan='3'><input type='text' name='MAX_CLIENTS' value='$cgiparams{'MAX_CLIENTS'}' size='10' /></td>
</tr><tr>
    <td class='base'>Keepalive (ping/ping-restart):</td>
    <td colspan='3'><input type='text' name='KEEPALIVE_1' value='$cgiparams{'KEEPALIVE_1'}' size='10' />&nbsp;
        <input type='text' name='KEEPALIVE_2' value='$cgiparams{'KEEPALIVE_2'}' size='10' /></td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td class='boldbase' colspan='4'>$Lang::tr{'log-options'}</td>
</tr><tr>
    <td class='base'>$Lang::tr{'detail level'}:</td>
    <td><select name='LOG_VERB'>
        <option value='1'  $selected{'LOG_VERB'}{'1'}>1</option>
        <option value='2'  $selected{'LOG_VERB'}{'2'}>2</option>
        <option value='3'  $selected{'LOG_VERB'}{'3'}>3</option>
        <option value='4'  $selected{'LOG_VERB'}{'4'}>4</option>
        <option value='5'  $selected{'LOG_VERB'}{'5'}>5</option>
        <option value='6'  $selected{'LOG_VERB'}{'6'}>6</option>
        <option value='7'  $selected{'LOG_VERB'}{'7'}>7</option>
        <option value='8'  $selected{'LOG_VERB'}{'8'}>8</option>
        <option value='9'  $selected{'LOG_VERB'}{'9'}>9</option>
        <option value='10' $selected{'LOG_VERB'}{'10'}>10</option>
        <option value='11' $selected{'LOG_VERB'}{'11'}>11</option>
        <option value='0'  $selected{'LOG_VERB'}{'0'}>0</option></select>
    </td>
    <td class='base'>mute-replay-warnings:</td>
    <td><input type='checkbox' name='LOG_MUTE_REPLAY' $checked{'LOG_MUTE_REPLAY'}{'on'} /></td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td class='boldbase' colspan='4'>$Lang::tr{'radius server settings'}</td>
</tr><tr>
    <td class='base'>$Lang::tr{'radius enable'}:</td>
    <td colspan='3'><input type='checkbox' name='RADIUS_ENABLED' $checked{'RADIUS_ENABLED'}{'on'} /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'radius servername'}:</td>
    <td colspan='3'><input type='text' name='RADIUS_HOST' value='$cgiparams{'RADIUS_HOST'}' size='30' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'radius authport'}:</td>
    <td colspan='3'><input type='text' name='RADIUS_AUTHPORT' value='$cgiparams{'RADIUS_AUTHPORT'}' size='10' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'radius acctport'}:</td>
    <td colspan='3'><input type='text' name='RADIUS_ACCTPORT' value='$cgiparams{'RADIUS_ACCTPORT'}' size='10' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'maximum retries'}:</td>
    <td colspan='3'><input type='text' name='RADIUS_RETRY' value='$cgiparams{'RADIUS_RETRY'}' size='10' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'radius wait'}:</td>
    <td colspan='3'><input type='text' name='RADIUS_TIMEOUT' value='$cgiparams{'RADIUS_TIMEOUT'}' size='10' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'radius sharedsecret'}:</td>
    <td colspan='3'><input type='password' name='RADIUS_PASS1' value='$cgiparams{'RADIUS_PASS1'}' size='32' /></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment2buttons'><img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save-adv-options'}' /></td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'cancel'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/vpns-openvpn.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
END
;

    &Header::closebox();
    &Header::closebigbox();
    &Header::closepage();
    exit(0);

###
### Openvpn Connections Statistics
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'openvpn con stat'}) {
    &Header::showhttpheaders();
    &Header::openpage($Lang::tr{'openvpn configuration main'}, 1, '');
    &Header::openbigbox('100%', 'left', '', '');
    &Header::openbox('100%', 'left', "$Lang::tr{'openvpn con stat'}:");

    print <<END
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/openvpn.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
<hr />
<table width='100%' border='0' cellpadding='2' cellspacing='0'>
<tr>
    <td><b>$Lang::tr{'common name'}</b></td>
    <td><b>$Lang::tr{'real address'}</b></td>
    <td><b>$Lang::tr{'virtual address'}</b></td>
    <td><b>$Lang::tr{'loged in at'}</b></td>
    <td><b>$Lang::tr{'bytes sent'}</b></td>
    <td><b>$Lang::tr{'bytes received'}</b></td>
    <td><b>$Lang::tr{'last activity'}</b></td>
</tr>
END
;

    my @users =();
    my $status;
    my $uid = 0;
    my $cn;
    my @match = ();
    my $proto = "udp";
    my $address;
    my %userlookup = ();
    foreach my $line (@serverstatus) {
        chomp($line);
        if ( $line =~ /^Updated,(.+)/) {
            @match = split( /^Updated,(.+)/, $line);
            $status = $match[1];
        }
        if ( $line =~ /^(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(\d+),(\d+),(.+)/) {
            @match = split(m/^(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(\d+),(\d+),(.+)/, $line);
            if ($match[1] ne "Common Name") {
                $cn = $match[1];
                $userlookup{$match[2]} = $uid;
                $users[$uid]{'CommonName'} = $match[1];
                $users[$uid]{'RealAddress'} = $match[2];
                $users[$uid]{'BytesReceived'} = &sizeformat($match[3]);
                $users[$uid]{'BytesSent'} = &sizeformat($match[4]);
                $users[$uid]{'Since'} = $match[5];
                $users[$uid]{'Proto'} = $proto;
                $uid++;
            }
        }
        if ( $line =~ /^(\d+\.\d+\.\d+\.\d+),(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(.+)/) {
            @match = split(m/^(\d+\.\d+\.\d+\.\d+),(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(.+)/, $line);
            if ($match[1] ne "Virtual Address") {
                $address = $match[3];
                #find the uid in the lookup table
                $uid = $userlookup{$address};
                $users[$uid]{'VirtualAddress'} = $match[1];
                $users[$uid]{'LastRef'} = $match[4];
            }
        }
    }
    my $user2 = @users;
    if ($user2 >= 1) {
        for (my $idx = 1; $idx <= $user2; $idx++){
            print "<tr class='table".int($idx % 2)."colour'>";
            print "<td align='left'>$users[$idx-1]{'CommonName'}</td>";
            print "<td align='left'>$users[$idx-1]{'RealAddress'}</td>";
            print "<td align='left'>$users[$idx-1]{'VirtualAddress'}</td>";
            print "<td align='left'>$users[$idx-1]{'Since'}</td>";
            print "<td align='left'>$users[$idx-1]{'BytesSent'}</td>";
            print "<td align='left'>$users[$idx-1]{'BytesReceived'}</td>";
            print "<td align='left'>$users[$idx-1]{'LastRef'}</td>";
            print "</tr>";
        }
    }

    print <<END
</table>
<hr />
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/openvpn.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td align='center' >$Lang::tr{'the statistics were last updated at'} <b>$status</b></td>
</tr></table>
END
;
    &Header::closebox();
    &Header::closebigbox();
    &Header::closepage();
    exit(0);

###
### Download Certificate
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'download certificate'}) {
    if ( -f "/var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem") {
        print "Content-Disposition: filename=" . $confighash{$cgiparams{'KEY'}}[1] . "cert.pem\r\n";
        print "Content-Type: application/octet-stream\r\n\r\n";
        print `/bin/cat /var/ofw/openvpn/certs/$confighash{$cgiparams{'KEY'}}[1]cert.pem`;
        exit (0);
    }

###
### Restart connection
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'restart'}) {
    # TODO: populate with some code?
    if ($confighash{$cgiparams{'KEY'}}) {
    }
    else {
        $errormessage = $Lang::tr{'invalid key'};
    }

###
### Choose between adding a host-net or net-net connection
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'add'} && $cgiparams{'TYPE'} eq '') {

    &Header::showhttpheaders();
    &Header::openpage($Lang::tr{'openvpn configuration main'}, 1, '');
    &Header::openbigbox('100%', 'left', '', '');
    &Header::openbox('100%', 'left', "$Lang::tr{'connection type'}:");
    print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'><table>
<tr>
    <td><input type='radio' name='TYPE' value='host' checked='checked' /></td>
    <td class='base'>$Lang::tr{'host to net vpn'}</td>
</tr><tr>
    <td><input type='radio' name='TYPE' value='net' disabled='disabled' /></td>
    <td class='base'>$Lang::tr{'net to net vpn'}</td>
</tr></table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/vpns-openvpn.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table></form>
END
    ;
    &Header::closebox();
    &Header::closebigbox();
    &Header::closepage();
    exit (0);

###
### Adding a new connection
###
} elsif (($cgiparams{'ACTION'} eq $Lang::tr{'add'}) ||
     ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) ||
     ($cgiparams{'ACTION'} eq $Lang::tr{'save'} && $cgiparams{'ADVANCED'} eq '')) {

    &General::readhash('/var/ofw/vpn/rootcertsettings', \%rootcertsettings) if (-f '/var/ofw/vpn/rootcertsettings');
    &General::readhasharray('/var/ofw/vpn/caconfig', \%cahash);

    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        if (! $confighash{$cgiparams{'KEY'}}[0]) {
            $errormessage = $Lang::tr{'invalid key'};
            goto VPNCONF_END;
        }
        $cgiparams{'ENABLED'}   = $confighash{$cgiparams{'KEY'}}[0];
        $cgiparams{'NAME'}  = $confighash{$cgiparams{'KEY'}}[1];
        $cgiparams{'TYPE'}  = $confighash{$cgiparams{'KEY'}}[3];
        $cgiparams{'AUTH'}  = $confighash{$cgiparams{'KEY'}}[4];
        $cgiparams{'PSK'}   = $confighash{$cgiparams{'KEY'}}[5];
        $cgiparams{'SIDE'}  = $confighash{$cgiparams{'KEY'}}[6];
        $cgiparams{'LOCAL_SUBNET'} = $confighash{$cgiparams{'KEY'}}[8];
        $cgiparams{'REMOTE'}    = $confighash{$cgiparams{'KEY'}}[10];
        $cgiparams{'REMOTE_SUBNET'} = $confighash{$cgiparams{'KEY'}}[11];
        $cgiparams{'REMARK'}    = $confighash{$cgiparams{'KEY'}}[25];
        $cgiparams{'INTERFACE'} = $confighash{$cgiparams{'KEY'}}[26];
        $cgiparams{'OVPN_SUBNET'} = $confighash{$cgiparams{'KEY'}}[27];
        $cgiparams{'PROTOCOL'}    = $confighash{$cgiparams{'KEY'}}[28];
        $cgiparams{'DEST_PORT'}   = $confighash{$cgiparams{'KEY'}}[29];
        $cgiparams{'COMPLZO'}     = $confighash{$cgiparams{'KEY'}}[30];
        $cgiparams{'MTU'}     = $confighash{$cgiparams{'KEY'}}[31];
        $cgiparams{'ROADWARRIORIP'} = $confighash{$cgiparams{'KEY'}}[32];
    }
    elsif ($cgiparams{'ACTION'} eq $Lang::tr{'save'}) {
        $cgiparams{'REMARK'} = &Header::cleanhtml($cgiparams{'REMARK'});
        if ($cgiparams{'TYPE'} !~ /^(host|net)$/) {
            $errormessage = $Lang::tr{'connection type is invalid'};
            goto VPNCONF_ERROR;
        }


        if ($cgiparams{'NAME'} !~ /^[a-zA-Z0-9]+$/) {
            $errormessage = $Lang::tr{'name must only contain characters'};
            goto VPNCONF_ERROR;
        }

        if ($cgiparams{'NAME'} =~ /^(host|01|block|private|clear|packetdefault)$/) {
            $errormessage = $Lang::tr{'name is invalid'};
            goto VPNCONF_ERROR;
        }

        if (length($cgiparams{'NAME'}) >60) {
            $errormessage = $Lang::tr{'name too long'};
            goto VPNCONF_ERROR;
        }

        # Check if there is no other entry with this name
        if (! $cgiparams{'KEY'}) {
            foreach my $key (keys %confighash) {
            if ($confighash{$key}[1] eq $cgiparams{'NAME'}) {
                $errormessage = $Lang::tr{'a connection with this name already exists'};
                goto VPNCONF_ERROR;
            }
            }
        }

        if (($cgiparams{'TYPE'} eq 'net') && (! $cgiparams{'REMOTE'})) {
            $errormessage = $Lang::tr{'invalid input for remote host/ip'};
            goto VPNCONF_ERROR;
        }

        if ($cgiparams{'REMOTE'}) {
            if (! &General::validip($cgiparams{'REMOTE'})) {
                if (! &General::validfqdn ($cgiparams{'REMOTE'}))  {
                    $errormessage = $Lang::tr{'invalid input for remote host/ip'};
                    goto VPNCONF_ERROR;
                } else {
                    if (&General::validdnshost($cgiparams{'REMOTE'})) {
                    $warnmessage = "$Lang::tr{'check vpn lr'} $cgiparams{'REMOTE'}. $Lang::tr{'dns check failed'}";
                    }
                }
            }
        }
        if ($cgiparams{'TYPE'} ne 'host') {
                unless (&General::validipandmask($cgiparams{'LOCAL_SUBNET'})) {
                    $errormessage = $Lang::tr{'local subnet is invalid'};
                goto VPNCONF_ERROR;}
        }
        # Check if there is no other entry without IP-address and PSK
        if ($cgiparams{'REMOTE'} eq '') {
            foreach my $key (keys %confighash) {
            if(($cgiparams{'KEY'} ne $key) &&
               ($confighash{$key}[4] eq 'psk' || $cgiparams{'AUTH'} eq 'psk') &&
                $confighash{$key}[10] eq '') {
                $errormessage = $Lang::tr{'you can only define one roadwarrior connection when using pre-shared key authentication'};
                goto VPNCONF_ERROR;
            }
            }
        }
        if (($cgiparams{'TYPE'} eq 'net') && (! &General::validipandmask($cgiparams{'REMOTE_SUBNET'}))) {
                    $errormessage = $Lang::tr{'remote subnet is invalid'};
            goto VPNCONF_ERROR;
        }

        if ($cgiparams{'ENABLED'} !~ /^(on|off)$/) {
            $errormessage = $Lang::tr{'invalid input'};
            goto VPNCONF_ERROR;
        }
        if ($cgiparams{'EDIT_ADVANCED'} !~ /^(on|off)$/) {
            $errormessage = $Lang::tr{'invalid input'};
            goto VPNCONF_ERROR;
        }

        if ($cgiparams{'AUTH'} eq 'psk')  {
        }
        elsif ($cgiparams{'AUTH'} eq 'certreq') {
            if ($cgiparams{'KEY'}) {
                $errormessage = $Lang::tr{'cant change certificates'};
                goto VPNCONF_ERROR;
            }
            if (blessed($cgiparams{'FH'}) ne 'CGI::File::Temp') {
                $errormessage = $Lang::tr{'there was no file upload'};
                goto VPNCONF_ERROR;
            }

            # Move uploaded certificate request to a temporary file
            (my $fh, my $filename) = tempfile( );
            if (copy ($cgiparams{'FH'}, $fh) != 1) {
                $errormessage = $!;
                goto VPNCONF_ERROR;
            }

            # Sign the certificate request and move it
            # Sign the host certificate request
            &General::log("openvpn", "Signing your cert $cgiparams{'NAME'}...");
            my  $opt  = " ca -days 999999";
            $opt .= " -batch -notext";
            $opt .= " -in $filename";
            $opt .= " -out /var/ofw/openvpn/certs/$cgiparams{'NAME'}cert.pem";
            if ( $errormessage = &VPN::callssl ($opt) ) {
                unlink ($filename);
                unlink ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}cert.pem");
                &VPN::newcleanssldatabase();
                goto VPNCONF_ERROR;
            }
            else {
                unlink ($filename);
                &deletebackupcert();
            }

            $cgiparams{'CERT_NAME'} = &VPN::getCNfromcert ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}cert.pem");
            if ($cgiparams{'CERT_NAME'} eq '') {
                $errormessage = $Lang::tr{'could not retrieve common name from certificate'};
                goto VPNCONF_ERROR;
            }
        }
        elsif ($cgiparams{'AUTH'} eq 'certfile') {
            if ($cgiparams{'KEY'}) {
                $errormessage = $Lang::tr{'cant change certificates'};
                goto VPNCONF_ERROR;
            }
            if (blessed($cgiparams{'FH'}) ne 'CGI::File::Temp') {
                $errormessage = $Lang::tr{'there was no file upload'};
                goto VPNCONF_ERROR;
            }
            # Move uploaded certificate to a temporary file
            (my $fh, my $filename) = tempfile( );
            if (copy ($cgiparams{'FH'}, $fh) != 1) {
                $errormessage = $!;
                goto VPNCONF_ERROR;
            }

            # Verify the certificate has a valid CA and move it
            my $validca = 0;
            my $test = `/usr/bin/openssl verify -CAfile /var/ofw/ca/cacert.pem $filename`;
            if ($test =~ /: OK/) {
                $validca = 1;
            }
            else {
                foreach my $key (keys %cahash) {
                    $test = `/usr/bin/openssl verify -CAfile /var/ofw/ca/$cahash{$key}[0]cert.pem $filename`;
                    if ($test =~ /: OK/) {
                        $validca = 1;
                    }
                }
            }
            if (! $validca) {
                $errormessage = $Lang::tr{'certificate does not have a valid ca associated with it'};
                unlink ($filename);
                goto VPNCONF_ERROR;
            }
            else {
                move($filename, "/var/ofw/openvpn/certs/$cgiparams{'NAME'}cert.pem");
                if ($? ne 0) {
                    $errormessage = "$Lang::tr{'certificate file move failed'}: $!";
                    unlink ($filename);
                    goto VPNCONF_ERROR;
                }
            }

            $cgiparams{'CERT_NAME'} = &VPN::getCNfromcert ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}cert.pem");
            if ($cgiparams{'CERT_NAME'} eq '') {
                unlink ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}cert.pem");
                $errormessage = $Lang::tr{'could not retrieve common name from certificate'};
                goto VPNCONF_ERROR;
            }
        }
        elsif ($cgiparams{'AUTH'} eq 'certgen') {
            if ($cgiparams{'KEY'}) {
                $errormessage = $Lang::tr{'cant change certificates'};
                goto VPNCONF_ERROR;
            }
            # Validate input since the form was submitted
            if (length($cgiparams{'CERT_NAME'}) >60) {
                $errormessage = $Lang::tr{'name too long'};
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_NAME'} !~ /^[a-zA-Z0-9 ,\.\-_]+$/) {
                $errormessage = $Lang::tr{'invalid input for name'};
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_EMAIL'} ne '' && (! &General::validemail($cgiparams{'CERT_EMAIL'}))) {
                $errormessage = $Lang::tr{'invalid input for e-mail address'};
                goto VPNCONF_ERROR;
            }
            if (length($cgiparams{'CERT_EMAIL'}) > 40) {
                $errormessage = $Lang::tr{'e-mail address too long'};
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_OU'} ne '' && $cgiparams{'CERT_OU'} !~ /^[a-zA-Z0-9 ,\.\-_]*$/) {
                $errormessage = $Lang::tr{'invalid input for department'};
                goto VPNCONF_ERROR;
            }
            if (length($cgiparams{'CERT_ORGANIZATION'}) >60) {
                $errormessage = $Lang::tr{'organization too long'};
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_ORGANIZATION'} !~ /^[a-zA-Z0-9 ,\.\-_]+$/) {
                $errormessage = $Lang::tr{'invalid input for organization'};
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_CITY'} ne '' && $cgiparams{'CERT_CITY'} !~ /^[a-zA-Z0-9 ,\.\-_]*$/) {
                $errormessage = $Lang::tr{'invalid input for city'};
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_STATE'} ne '' && $cgiparams{'CERT_STATE'} !~ /^[a-zA-Z0-9 ,\.\-_]*$/) {
                $errormessage = $Lang::tr{'invalid input for state or province'};
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_COUNTRY'} !~ /^[A-Z]*$/) {
                $errormessage = $Lang::tr{'invalid input for country'};
                goto VPNCONF_ERROR;
            }
            if ($cgiparams{'CERT_PASS1'} ne '' && $cgiparams{'CERT_PASS2'} ne ''){
                if (length($cgiparams{'CERT_PASS1'}) < 5) {
                    $errormessage = $Lang::tr{'password too short'};
                    goto VPNCONF_ERROR;
                }
            }
            if ($cgiparams{'CERT_PASS1'} ne $cgiparams{'CERT_PASS2'}) {
                $errormessage = $Lang::tr{'passwords do not match'};
                goto VPNCONF_ERROR;
            }

            if (($cgiparams{'YEAR'} < $this_year)
                || (($cgiparams{'YEAR'} == $this_year) && ($cgiparams{'MONTH'} < $now[4]))
                || (($cgiparams{'YEAR'} == $this_year) && ($cgiparams{'MONTH'} == $now[4]) && ($cgiparams{'DAY'} < $now[3])) ) {
                $errormessage = $Lang::tr{'invalid date entered'};
                goto VPNCONF_ERROR;
            }
            my $certdays = (POSIX::mktime( 0, 0, 1, $cgiparams{'DAY'}, $cgiparams{'MONTH'}, $cgiparams{'YEAR'}-1900) - POSIX::mktime( 0, 0, 0, $now[3], $now[4], $now[5])) / 86400;
            if ($certdays <= 1) {
                $errormessage = $Lang::tr{'invalid date entered'};
                goto VPNCONF_ERROR;
            }

            # Replace empty strings with a .
            (my $ou = $cgiparams{'CERT_OU'}) =~ s/^\s*$/\./;
            (my $city = $cgiparams{'CERT_CITY'}) =~ s/^\s*$/\./;
            (my $state = $cgiparams{'CERT_STATE'}) =~ s/^\s*$/\./;

            # Create the Host certificate request client
            &General::log("openvpn", "Creating a cert...");

            if (open(STDIN, "-|")) {
                my $opt  = " req -nodes -rand /proc/interrupts:/proc/net/rt_cache";
                $opt .= " -newkey rsa:$cgiparams{'CERT_BITS'} -sha256";
                $opt .= " -keyout /var/ofw/openvpn/certs/$cgiparams{'NAME'}key.pem";
                $opt .= " -out /var/ofw/openvpn/certs/$cgiparams{'NAME'}req.pem";

                if ( $errormessage = &VPN::callssl ($opt) ) {
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
            &General::log("openvpn", "Signing the cert $cgiparams{'NAME'}...");

            my $opt  = " ca -days $certdays -batch -notext -md sha256";
            $opt .= " -in /var/ofw/openvpn/certs/$cgiparams{'NAME'}req.pem";
            $opt .= " -out /var/ofw/openvpn/certs/$cgiparams{'NAME'}cert.pem";

            if ($errormessage = &VPN::callssl($opt)) {
                unlink ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}key.pem");
                unlink ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}req.pem");
                unlink ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}cert.pem");
                &VPN::newcleanssldatabase();
                goto VPNCONF_ERROR;
            }
            else {
                unlink ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}req.pem");
                &deletebackupcert();
            }

            # Create the pkcs12 file
            &General::log("openvpn", "Packing a pkcs12 file...");
            $opt  = " pkcs12 -export";
            $opt .= " -inkey /var/ofw/openvpn/certs/$cgiparams{'NAME'}key.pem";
            $opt .= " -in /var/ofw/openvpn/certs/$cgiparams{'NAME'}cert.pem";
            $opt .= " -name \"$cgiparams{'NAME'}\"";
            $opt .= " -passout pass:" . &General::escape_shell($cgiparams{'CERT_PASS1'});
            $opt .= " -certfile /var/ofw/ca/cacert.pem";
            $opt .= " -caname \"$rootcertsettings{'ROOTCERT_ORGANIZATION'} CA\"";
            $opt .= " -out /var/ofw/openvpn/certs/$cgiparams{'NAME'}.p12";

            if ($errormessage = &VPN::callssl($opt)) {
                unlink ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}key.pem");
                unlink ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}cert.pem");
                unlink ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}.p12");
                goto VPNCONF_ERROR;
            }
            else {
                unlink ("/var/ofw/openvpn/certs/$cgiparams{'NAME'}key.pem");
            }
        }
        elsif ($cgiparams{'AUTH'} eq 'cert') {
            ;# Nothing, just editing
        }
        else {
            $errormessage = $Lang::tr{'invalid input for authentication method'};
            goto VPNCONF_ERROR;
        }

        # Check if there is no other entry with this common name
        if ((! $cgiparams{'KEY'}) && ($cgiparams{'AUTH'} ne 'psk')) {
            foreach my $key (keys %confighash) {
                if ($confighash{$key}[2] eq $cgiparams{'CERT_NAME'}) {
                    $errormessage = $Lang::tr{'a connection with this common name already exists'};
                    goto VPNCONF_ERROR;
                }
            }
        }

        # Save the config
        my $key = $cgiparams{'KEY'};
        if (! $key) {
            $key = &General::findhasharraykey (\%confighash);
            foreach my $i (0 .. 31) { $confighash{$key}[$i] = "";}
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
            $confighash{$key}[6] = $cgiparams{'SIDE'};
            $confighash{$key}[11] = $cgiparams{'REMOTE_SUBNET'};
        }
        $confighash{$key}[8] = $cgiparams{'LOCAL_SUBNET'};
        $confighash{$key}[10] = $cgiparams{'REMOTE'};
        $confighash{$key}[25] = $cgiparams{'REMARK'};
        $confighash{$key}[26] = $cgiparams{'INTERFACE'};
        $confighash{$key}[27] = $cgiparams{'OVPN_SUBNET'};
        $confighash{$key}[28] = $cgiparams{'PROTOCOL'};
        $confighash{$key}[29] = $cgiparams{'DEST_PORT'};
        $confighash{$key}[30] = $cgiparams{'COMPLZO'};
        $confighash{$key}[31] = $cgiparams{'MTU'};
        $confighash{$key}[32] = $cgiparams{'ROADWARRIORIP'};
        &General::writehasharray('/var/ofw/openvpn/config', \%confighash);
        &writeclientconf($key);
        if ($cgiparams{'EDIT_ADVANCED'} eq 'on') {
            $cgiparams{'KEY'} = $key;
            $cgiparams{'ACTION'} = $Lang::tr{'advanced'};
        }
        goto VPNCONF_END;
    }
    else {
        $cgiparams{'ENABLED'} = 'on';
        $cgiparams{'SIDE'} = 'left';
        if ( ! -f '/var/ofw/private/cakey.pem' ) {
            $cgiparams{'AUTH'} = 'psk';
        }
        elsif ( ! -f '/var/ofw/ca/cacert.pem') {
            $cgiparams{'AUTH'} = 'certfile';
        }
        else {
            $cgiparams{'AUTH'} = 'certgen';
        }
        $cgiparams{'LOCAL_SUBNET'}      ="$netsettings{'GREEN_1_NETADDRESS'}/$netsettings{'GREEN_1_NETMASK'}";
        $cgiparams{'CERT_ORGANIZATION'} = $rootcertsettings{'ROOTCERT_ORGANIZATION'};
        $cgiparams{'CERT_CITY'}         = $rootcertsettings{'ROOTCERT_CITY'};
        $cgiparams{'CERT_STATE'}        = $rootcertsettings{'ROOTCERT_STATE'};
        $cgiparams{'CERT_COUNTRY'}      = $rootcertsettings{'ROOTCERT_COUNTRY'};
    }

    VPNCONF_ERROR:
    $checked{'ENABLED'}{'off'} = '';
    $checked{'ENABLED'}{'on'} = '';
    $checked{'ENABLED'}{$cgiparams{'ENABLED'}} = "checked='checked'";

    $checked{'EDIT_ADVANCED'}{'off'} = '';
    $checked{'EDIT_ADVANCED'}{'on'} = '';
    $checked{'EDIT_ADVANCED'}{$cgiparams{'EDIT_ADVANCED'}} = "checked='checked'";

    $selected{'SIDE'}{'server'} = '';
    $selected{'SIDE'}{'client'} = '';
    $selected{'SIDE'}{$cgiparams{'SIDE'}} = 'SELECTED';

    $checked{'AUTH'}{'psk'} = '';
    $checked{'AUTH'}{'certreq'} = '';
    $checked{'AUTH'}{'certgen'} = '';
    $checked{'AUTH'}{'certfile'} = '';
    $checked{'AUTH'}{$cgiparams{'AUTH'}} = "checked='checked'";

    $selected{'INTERFACE'}{$cgiparams{'INTERFACE'}} = 'SELECTED';

    $checked{'COMPLZO'}{'off'} = '';
    $checked{'COMPLZO'}{'on'} = '';
    $checked{'COMPLZO'}{$cgiparams{'COMPLZO'}} = "checked='checked'";

    &getroadwarriorips($cgiparams{'ROADWARRIORIP'});

    &Header::showhttpheaders();
    &Header::openpage($Lang::tr{'openvpn configuration main'}, 1, '');
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

    print "<form method='post' enctype='multipart/form-data' action='$ENV{'SCRIPT_NAME'}'>";
    print "<input type='hidden' name='TYPE' value='$cgiparams{'TYPE'}' />";

    if ($cgiparams{'KEY'}) {
        print "<input type='hidden' name='KEY' value='$cgiparams{'KEY'}' />";
        print "<input type='hidden' name='AUTH' value='$cgiparams{'AUTH'}' />";
    }

    &Header::openbox('100%', 'left', "$Lang::tr{'connection'}:");
    print "<table width='100%'>\n";
    print "<tr><td width='25%' class='base'>$Lang::tr{'name'}:</td>";
    if ($cgiparams{'TYPE'} eq 'host') {
        if ($cgiparams{'KEY'}) {
            print "<td width='25%' class='base'><input type='hidden' name='NAME' value='$cgiparams{'NAME'}' />$cgiparams{'NAME'}</td>\n";
        }
        else {
            print "<td width='25%'><input type='text' name='NAME' value='$cgiparams{'NAME'}' maxlength='20' size='30' /></td>";
        }
    }
    print <<END
    <td class='base' width='25%'>$Lang::tr{'enabled'}:</td>
    <td width='25%'><input type='checkbox' name='ENABLED' $checked{'ENABLED'}{'on'} /></td>
</tr><tr>
END
    ;
    if ($vpnsettings{'STATICIP'} eq 'on') {
        print <<END
    <td class='base'>$Lang::tr{'static ip'}:</td>
    <td colspan='3'><select name='ROADWARRIORIP'>
END
        ;

        my @rwipsunsorted =  keys %roadwarriorips;
        my @rwips = sort {
            my @a = $a =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
            my @b = $b =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
            $a[0] <=> $b[0]
            || $a[1] <=> $b[1]
            || $a[2] <=> $b[2]
            || $a[3] <=> $b[3]

        } @rwipsunsorted;

        foreach my $rwip (@rwips) {
            print "<option value='$rwip' $roadwarriorips{$rwip} >$rwip</option>\n";
        }
        print <<END
        </select></td>
</tr><tr>
END
        ;
    }
    print <<END
    <td class='base'>$Lang::tr{'remark'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='3'><input type='text' name='REMARK' value='$cgiparams{'REMARK'}' size='55' maxlength='50' /></td>
</tr></table>
END
    ;
    if ($cgiparams{'KEY'} && $cgiparams{'AUTH'} eq 'psk') {
END
    }
    elsif (! $cgiparams{'KEY'}) {
        my $cakeydisabled='';
        my $cacrtdisabled='';
        $cakeydisabled = "disabled='disabled'" if ( ! -f '/var/ofw/private/cakey.pem' );
        $cacrtdisabled = "disabled='disabled'" if ( ! -f '/var/ofw/ca/cacert.pem' );

        $selected{'CERT_BITS'}{'1024'} = '';
        $selected{'CERT_BITS'}{'2048'} = '';
        $selected{'CERT_BITS'}{'4096'} = '';
        $selected{'CERT_BITS'}{$cgiparams{'CERT_BITS'}} = "selected='selected'";

        # Close the previous box
        &Header::closebox();

        &Header::openbox('100%', 'left', "$Lang::tr{'authentication'}:");
        print <<END
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td><input type='radio' name='AUTH' value='certreq' $checked{'AUTH'}{'certreq'} $cakeydisabled /></td>
    <td class='base'>$Lang::tr{'upload a certificate request'}:</td>
    <td class='base' rowspan='2'><input type='file' name='FH' size='30' $cacrtdisabled /></td>
</tr><tr>
    <td><input type='radio' name='AUTH' value='certfile' $checked{'AUTH'}{'certfile'} $cacrtdisabled /></td>
    <td class='base'>$Lang::tr{'upload a certificate'}:</td>
</tr><tr>
    <td colspan='3'><hr /></td>
</tr><tr>
    <td><input type='radio' name='AUTH' value='certgen' $checked{'AUTH'}{'certgen'} $cakeydisabled /></td>
    <td class='base'>$Lang::tr{'generate a certificate'}:</td><td>&nbsp;</td>
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
            print "<option value='$Countries::countries{$country}'";
            if ( $Countries::countries{$country} eq $cgiparams{'CERT_COUNTRY'} ) {
                print " selected='selected'";
            }
            print ">$country</option>";
        }
        print <<END
        </select></td>
</tr><tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'pkcs12 file password'}:</td>
    <td class='base' nowrap='nowrap'><input type='password' name='CERT_PASS1' value='$cgiparams{'CERT_PASS1'}' size='32' $cakeydisabled /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'pkcs12 file password'}:<br />($Lang::tr{'confirmation'})</td>
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
</tr><tr>
    <td>&nbsp;</td><td class='base'>$Lang::tr{'certificate'}:</td>
    <td class='base' nowrap='nowrap'>
    <select name='CERT_BITS'>
        <option value='1024' $selected{'CERT_BITS'}{'1024'}>1024 bits</option>
        <option value='2048' $selected{'CERT_BITS'}{'2048'}>2048 bits</option>
        <option value='4096' $selected{'CERT_BITS'}{'4096'}>4096 bits</option>
    </select>
    </td>
</tr></table>
END
        ;
    }

    print <<END
<hr />
<table width='100%'>
<tr>
    <td class='comment2buttons'><img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'cancel'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/vpns-openvpn.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
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

#    SETTINGS_ERROR:
###
### Default status page
###
%cgiparams = ();
$cgiparams{'ENABLED_RED_1'} = 'off';
$cgiparams{'ENABLED_BLUE_1'} = 'off';
$cgiparams{'DDEVICE'} =  'tun';
%cahash = ();
&General::readhash('/var/ofw/openvpn/settings', \%cgiparams);
&General::readhasharray('/var/ofw/vpn/caconfig', \%cahash);

my $disableadvanced = '';

# Defaults for several settings
if ((!defined($cgiparams{'VPN_IP'}) || ($cgiparams{'VPN_IP'} eq '')) && -e '/var/ofw/red/active') {
    if (open(IPADDR, '/var/ofw/red/local-ipaddress')) {
        my $ipaddr = <IPADDR>;
        close IPADDR;
        chomp ($ipaddr);
        $cgiparams{'VPN_IP'} = (gethostbyaddr(pack("C4", split(/\./, $ipaddr)), 2))[0];
        if ($cgiparams{'VPN_IP'} eq '') {
            $cgiparams{'VPN_IP'} = $ipaddr;
        }
    }
}

if (!defined($cgiparams{'DCOMPLZO'}) || ($cgiparams{'DCIPHER'} eq '')) {
    $cgiparams{'DCIPHER'} =  'BF-CBC';
}
if (!defined($cgiparams{'DCOMPLZO'}) || ($cgiparams{'DCOMPLZO'} eq '')) {
    $cgiparams{'DCOMPLZO'} =  'off';
}
if (!defined($cgiparams{'DDEST_PORT'}) || ($cgiparams{'DDEST_PORT'} eq '')) {
    $cgiparams{'DDEST_PORT'} =  '1194';
}
if (!defined($cgiparams{'DMTU'}) || ($cgiparams{'DMTU'} eq '')) {
    $cgiparams{'DMTU'} =  '1400';
}
if (!defined($cgiparams{'DOVPN_SUBNET'}) || ($cgiparams{'DOVPN_SUBNET'} eq '')) {
    $cgiparams{'DOVPN_SUBNET'} = '10.' . int(rand(256)) . '.' . int(rand(256)) . '.0/255.255.255.0';

    # We need at least OpenVPN subnet to be able to modifiy/store advanced settings
    $disableadvanced = "disabled='disabled'";
}

$checked{'ENABLED_RED_1'}{'off'} = '';
$checked{'ENABLED_RED_1'}{'on'} = '';
$checked{'ENABLED_RED_1'}{$cgiparams{'ENABLED_RED_1'}} = "checked='checked'";
$checked{'ENABLED_BLUE_1'}{'off'} = '';
$checked{'ENABLED_BLUE_1'}{'on'} = '';
$checked{'ENABLED_BLUE_1'}{$cgiparams{'ENABLED_BLUE_1'}} = "checked='checked'";
$selected{'DDEVICE'}{'tun'} = '';
$selected{'DDEVICE'}{'tap'} = '';
$selected{'DDEVICE'}{$cgiparams{'DDEVICE'}} = "selected='selected'";

$selected{'DPROTOCOL'}{'udp'} = '';
$selected{'DPROTOCOL'}{'tcp'} = '';
$selected{'DPROTOCOL'}{$cgiparams{'DPROTOCOL'}} = "selected='selected'";

$selected{'DCIPHER'}{'DES-CBC'} = '';
$selected{'DCIPHER'}{'DES-EDE-CBC'} = '';
$selected{'DCIPHER'}{'DES-EDE3-CBC'} = '';
$selected{'DCIPHER'}{'DESX-CBC'} = '';
$selected{'DCIPHER'}{'RC2-CBC'} = '';
$selected{'DCIPHER'}{'RC2-40-CBC'} = '';
$selected{'DCIPHER'}{'RC2-64-CBC'} = '';
$selected{'DCIPHER'}{'BF-CBC'} = '';
$selected{'DCIPHER'}{'CAST5-CBC'} = '';
$selected{'DCIPHER'}{'AES-128-CBC'} = '';
$selected{'DCIPHER'}{'AES-192-CBC'} = '';
$selected{'DCIPHER'}{'AES-256-CBC'} = '';
$selected{'DCIPHER'}{$cgiparams{'DCIPHER'}} = "selected='selected'";
$checked{'DCOMPLZO'}{'off'} = '';
$checked{'DCOMPLZO'}{'on'} = '';
$checked{'DCOMPLZO'}{$cgiparams{'DCOMPLZO'}} = "checked='checked'";


&Header::showhttpheaders();
&Header::openpage($Lang::tr{'openvpn configuration main'}, 1, '');
&Header::openbigbox('100%', 'left', '', $errormessage);

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();
}

my $sactive = &General::isrunning('openvpn', 'nosize');
my $srunning = "no";
my $addclient = "";
my $activeonrun = "";
if (-e "/var/run/openvpn.pid") {
    $srunning ="yes";
    $activeonrun = "";
}
else {
    $activeonrun = "disabled='disabled'";
}

##############################
#
# Box with global settings and status
#
##############################

&Header::openbox('100%', 'left', "$Lang::tr{'global settings'}:");
print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'><table width='100%'>
<tr>
    <td class='base' width='25%'>$Lang::tr{'openvpn server'}:</td>
    $sactive
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'openvpn on red'}:</td>
    <td colspan='3'><input type='checkbox' name='ENABLED_RED_1' $checked{'ENABLED_RED_1'}{'on'} /></td>
</tr>
END
;

if (&FW::haveBlueNet()) {
    print "<tr><td class='base'>$Lang::tr{'openvpn on blue'}:</td>";
    print "<td colspan='3'><input type='checkbox' name='ENABLED_BLUE_1' $checked{'ENABLED_BLUE_1'}{'on'} /></td></tr>";
}

print <<END
<tr>
    <td class='base' nowrap='nowrap'>$Lang::tr{'local vpn hostname/ip'}:</td>
    <td><input type='text' name='VPN_IP' value='$cgiparams{'VPN_IP'}' size='30' /></td>
    <td class='base' nowrap='nowrap'>$Lang::tr{'openvpn subnet'}:<br />
        ($Lang::tr{'eg'}: <tt>10.0.10.0/255.255.255.0</tt>)</td>
    <td><input type='text' name='DOVPN_SUBNET' value='$cgiparams{'DOVPN_SUBNET'}' size='30' /></td>
</tr><tr>
    <!-- TODO Do we really need to offer TAP device? Do we support that? -->
    <!--     <td class='base' nowrap='nowrap'>$Lang::tr{'openvpn device'}:</td> -->
    <!--     <td colspan='3'><select name='DDEVICE' ><option value='tun' $selected{'DDEVICE'}{'tun'}>TUN</option> -->
    <!--                         <option value='tap' $selected{'DDEVICE'}{'tap'}>TAP</option></select></td> -->
    <td colspan='3'><input type='hidden' name='DDEVICE' value='tun' /></td>
</tr><tr>

    <td class='base' nowrap='nowrap'>$Lang::tr{'protocol'}:</td>
    <td><select name='DPROTOCOL'><option value='udp' $selected{'DPROTOCOL'}{'udp'}>UDP</option>
            <option value='tcp' $selected{'DPROTOCOL'}{'tcp'}>TCP</option></select></td>
    <td class='base'>$Lang::tr{'destination port'}:</td>
    <td><input type='text' name='DDEST_PORT' value='$cgiparams{'DDEST_PORT'}' size='5' /></td>
</tr><tr>
    <td class='base' nowrap='nowrap'>$Lang::tr{'mtu size'}:&nbsp;</td>
        <td colspan='3'><input type='text' name='DMTU' value='$cgiparams{'DMTU'}' size='5' /></td></tr>
    <tr><td class='base' nowrap='nowrap'>$Lang::tr{'comp-lzo'}:</td>
        <td><input type='checkbox' name='DCOMPLZO' $checked{'DCOMPLZO'}{'on'} /></td>
        <td class='base' nowrap='nowrap'>$Lang::tr{'cipher'}:</td>
        <td><select name='DCIPHER'>
            <option value='DES-CBC' $selected{'DCIPHER'}{'DES-CBC'}>DES-CBC</option>
            <option value='DES-EDE-CBC' $selected{'DCIPHER'}{'DES-EDE-CBC'}>DES-EDE-CBC</option>
            <option value='DES-EDE3-CBC' $selected{'DCIPHER'}{'DES-EDE3-CBC'}>DES-EDE3-CBC</option>
            <option value='DESX-CBC' $selected{'DCIPHER'}{'DESX-CBC'}>DESX-CBC</option>
            <option value='RC2-CBC' $selected{'DCIPHER'}{'RC2-CBC'}>RC2-CBC</option>
            <option value='RC2-40-CBC' $selected{'DCIPHER'}{'RC2-40-CBC'}>RC2-40-CBC</option>
            <option value='RC2-64-CBC' $selected{'DCIPHER'}{'RC2-64-CBC'}>RC2-64-CBC</option>
            <option value='BF-CBC' $selected{'DCIPHER'}{'BF-CBC'}>BF-CBC</option>
            <option value='CAST5-CBC' $selected{'DCIPHER'}{'CAST5-CBC'}>CAST5-CBC</option>
            <option value='AES-128-CBC' $selected{'DCIPHER'}{'AES-128-CBC'}>AES-128-CBC</option>
            <option value='AES-192-CBC' $selected{'DCIPHER'}{'AES-192-CBC'}>AES-192-CBC</option>
            <option value='AES-256-CBC' $selected{'DCIPHER'}{'AES-256-CBC'}>AES-256-CBC</option>
        </select></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
END
;

if ( $srunning eq "yes" ) {
    print "<td width='25%' align='left'><input type='submit' name='ACTION' value='$Lang::tr{'save'}' disabled='disabled' /></td>";
    print "<td width='25%'><input type='submit' name='ACTION' value='$Lang::tr{'advanced server'}' disabled='disabled'/></td>";
    print "<td width='25%'><input type='submit' name='ACTION' value='$Lang::tr{'stop openvpn server'}' /></td>";
    print "<td width='20%'><input type='submit' name='ACTION' value='$Lang::tr{'restart openvpn server'}' /></td>";
} else{
    print "<td width='25%' align='left'><input type='submit' name='ACTION' value='$Lang::tr{'save'}' /></td>";
    print "<td width='25%'><input type='submit' name='ACTION' value='$Lang::tr{'advanced server'}' $disableadvanced /></td>";
    if (( -e '/var/ofw/ca/cacert.pem' &&
          -e '/var/ofw/private/dh1024.pem' &&
          -e '/var/ofw/certs/hostcert.pem' &&
          -e '/var/ofw/certs/hostkey.pem') &&
        ( ($cgiparams{'ENABLED_RED_1'} eq 'on') || ($cgiparams{'ENABLED_BLUE_1'} eq 'on'))) {
        print "<td width='25%'><input type='submit' name='ACTION' value='$Lang::tr{'start openvpn server'}' /></td>";
        print "<td width='20%'><input type='submit' name='ACTION' value='$Lang::tr{'restart openvpn server'}' /></td>";
    } else {
        print "<td width='25%'><input type='submit' name='ACTION' value='$Lang::tr{'start openvpn server'}' disabled='disabled' /></td>";
        print "<td width='20%'><input type='submit' name='ACTION' value='$Lang::tr{'restart openvpn server'}' disabled='disabled' /></td>";
        $addclient = "disabled='disabled'";
    }
}

print <<END
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/vpns-openvpn.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr></table></form>
END
;
&Header::closebox();


##############################
#
# Box with .....
#
##############################

if ( -f '/var/ofw/ca/cacert.pem' ) {
    &Header::openbox('100%', 'left', "$Lang::tr{'connection status and controlc'}:");
    print <<END
<table width='100%' border='0' cellspacing='1' cellpadding='0'>
<tr valign='bottom'>
    <td width='10%' class='boldbase' align='center'><b>$Lang::tr{'name'}</b> $Header::sortup</td>
    <td width='15%' class='boldbase' align='center'><b>$Lang::tr{'type'}</b></td>
    <td width='15%' class='boldbase' align='center'><b>$Lang::tr{'common name'}</b></td>
    <td width='20%' class='boldbase' align='center'><b>$Lang::tr{'valid until'}</b></td>
    <td width='20%' class='boldbase' align='center'><b>$Lang::tr{'remark'}</b></td>
    <td width='10%' class='boldbase' align='center'><b>$Lang::tr{'status'}</b></td>
    <td width='10%' class='boldbase' colspan='6' align='center'><b>$Lang::tr{'action'}</b></td>
</tr>
END
    ;
    my $id = 0;
    my $gif;
    foreach my $key (sort SortConfigHashByName (keys(%confighash))) {
        if ($confighash{$key}[0] eq 'on') {
            $gif = 'on.gif';
        }
        else {
            $gif = 'off.gif';
        }

        print "<tr class='table".int(($id % 2) + 1)."colour'>";
        print "<td align='center' nowrap='nowrap'>$confighash{$key}[1]</td>";
        print "<td align='center' nowrap='nowrap'>" . $Lang::tr{"$confighash{$key}[3]"} . " (" . $Lang::tr{"$confighash{$key}[4]"} . ")</td>";
        if ($confighash{$key}[4] eq 'cert') {
            print "<td align='center' nowrap='nowrap'>$confighash{$key}[2]</td>";
        }
        else {
            print "<td align='left'>&nbsp;</td>";
        }

        my $cavalid = `/usr/bin/openssl x509 -text -in /var/ofw/openvpn/certs/$confighash{$key}[1]cert.pem`;
        $cavalid    =~ /Not After : (.*)[\n]/;
        $cavalid    = $1;
        print "<td align='center'>$cavalid</td>";
        print "<td align='center'>$confighash{$key}[25]</td>";
        my $active = "<table cellpadding='2' cellspacing='0' class='ofw_stopped' width='100%'><tr><td align='center'>$Lang::tr{'capsclosed'}</td></tr></table>";
        if ($confighash{$key}[0] eq 'off') {
            $active = "<table cellpadding='2' cellspacing='0' class='ofw_closed' width='100%'><tr><td align='center'>$Lang::tr{'capsclosed'}</td></tr></table>";
        }
        else {
            my $cn;
            my @match = ();
            foreach my $line (@serverstatus) {
                chomp($line);
                if ( $line =~ /^(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(\d+),(\d+),(.+)/) {
                    @match = split(m/^(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(\d+),(\d+),(.+)/, $line);
                    if ($match[1] ne "Common Name") {
                        $cn = $match[1];
                    }
                    $cn =~ s/[_]/ /g;
                    if ($cn eq "$confighash{$key}[2]") {
                        $active = "<table cellpadding='2' cellspacing='0' class='ofw_running' width='100%'><tr><td align='center'>$Lang::tr{'capsopen'}</td></tr></table>";
                    }
                }
            }
        }

        print <<END
<td align='center'>$active</td>
<td align='center'><form method='post' name='frm${key}a' action='$ENV{'SCRIPT_NAME'}'>
    <input type='image'  name='$Lang::tr{'dl client arch'}' $addclient src='/images/openvpnzip.gif' alt='$Lang::tr{'dl client arch'}' title='$Lang::tr{'dl client arch'}' />
    <input type='hidden' name='ACTION' value='$Lang::tr{'dl client arch'}' $addclient />
    <input type='hidden' name='KEY' value='$key' $addclient />
</form></td>
END
        ;
        if ($confighash{$key}[4] eq 'cert') {
            print <<END
<td align='center'><form method='post' name='frm${key}b' action='$ENV{'SCRIPT_NAME'}'>
    <input type='image' name='$Lang::tr{'show certificate'}' src='/images/info.gif' alt='$Lang::tr{'show certificate'}' title='$Lang::tr{'show certificate'}' />
    <input type='hidden' name='ACTION' value='$Lang::tr{'show certificate'}' />
    <input type='hidden' name='KEY' value='$key' />
</form></td>
END
    ;
        }
        else {
            print "<td>&nbsp;</td>";
        }
        if ($confighash{$key}[4] eq 'cert' && -f "/var/ofw/openvpn/certs/$confighash{$key}[1].p12") {
            print <<END
<td align='center'><form method='post' name='frm${key}c' action='$ENV{'SCRIPT_NAME'}'>
    <input type='image' name='$Lang::tr{'download pkcs12 file'}' src='/images/floppy.gif' alt='$Lang::tr{'download pkcs12 file'}' title='$Lang::tr{'download pkcs12 file'}' />
    <input type='hidden' name='ACTION' value='$Lang::tr{'download pkcs12 file'}' />
    <input type='hidden' name='KEY' value='$key' />
</form></td>
END
            ;
        }
        elsif ($confighash{$key}[4] eq 'cert') {
            print <<END
<td align='center'><form method='post' name='frm${key}c' action='$ENV{'SCRIPT_NAME'}'>
    <input type='image' name='$Lang::tr{'download certificate'}' src='/images/floppy.gif' alt='$Lang::tr{'download certificate'}' title='$Lang::tr{'download certificate'}' />
    <input type='hidden' name='ACTION' value='$Lang::tr{'download certificate'}' />
    <input type='hidden' name='KEY' value='$key' />
</form></td>
END
            ;
        }
        else {
            print "<td>&nbsp;</td>";
        }
        print <<END
<td align='center'><form method='post' name='frm${key}d' action='$ENV{'SCRIPT_NAME'}'>
    <input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif' alt='$Lang::tr{'toggle enable disable'}' title='$Lang::tr{'toggle enable disable'}' />
    <input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
    <input type='hidden' name='KEY' value='$key' />
</form></td>

<td align='center'><form method='post' name='frm${key}e' action='$ENV{'SCRIPT_NAME'}'>
    <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
    <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
    <input type='hidden' name='KEY' value='$key' />
</form></td>
<td align='center'><form method='post' name='frm${key}f' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        <input type='image'  name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
        <input type='hidden' name='KEY' value='$key' />
</form></td>
</tr>
END
        ;
        $id++;
    }
    ;
    print "</table>\n";

    # If the config file contains entries, print Key to action icons
    if ( $id ) {
        print <<END
<table><tr>
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
    <td>&nbsp; &nbsp; <img src='/images/openvpnzip.gif' alt='?RELOAD'/></td>
    <td class='base'>$Lang::tr{'dl client arch'}</td>
</tr></table><hr />
END
        ;
    }

    print <<END

<form method='post' action='$ENV{'SCRIPT_NAME'}'><table width='100%'>
<tr>
    <td class='comment2buttons'>&nbsp;</td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' $addclient /></td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'openvpn con stat'}' $activeonrun /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/vpns-openvpn.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table></form>
END
    ;
    &Header::closebox();
}

&Header::closebigbox();
&Header::closepage();



sub SortConfigHashByName
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
