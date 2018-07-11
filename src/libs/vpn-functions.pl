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
# (c) 2009-2015 The IPCop Team
#
# $Id: vpn-functions.pl 7885 2015-02-09 17:09:40Z owes $
#

package VPN;

use strict;

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/header.pl';


# netsettings required in several places, read once here for all functions
my %netsettings = ();
&General::readhash("/var/ipcop/ethernet/settings", \%netsettings);


###
### old version: maintain serial number to one, without explication.
### this         : let the counter go, so that each cert is numbered.
###
sub cleanssldatabase {
    if (open(FILE, '>/var/ipcop/certs/serial')) {
        print FILE '01';
        close FILE;
    }
    if (open(FILE, '>/var/ipcop/certs/index.txt')) {
        print FILE '';
        close FILE;
    }
    unlink('/var/ipcop/certs/index.txt.old');
    unlink('/var/ipcop/certs/serial.old');
    unlink('/var/ipcop/certs/01.pem');

    if (open(FILE, '>/var/ipcop/openvpn/certs/serial')) {
        print FILE '01';
        close FILE;
    }
    if (open(FILE, '>/var/ipcop/openvpn/certs/index.txt')) {
        print FILE '';
        close FILE;
    }
    unlink('/var/ipcop/openvpn/certs/index.txt.old');
    unlink('/var/ipcop/openvpn/certs/serial.old');
    unlink('/var/ipcop/openvpn/certs/01.pem');
}

sub newcleanssldatabase {
    if (! -s '/var/ipcop/certs/serial' ) {
        open(FILE, '>/var/ipcop/certs/serial');
        print FILE '01';
        close FILE;
    }
    if (! -s '>/var/ipcop/certs/index.txt') {
        system('touch /var/ipcop/certs/index.txt');
    }
    unlink('/var/ipcop/certs/index.txt.old');
    unlink('/var/ipcop/certs/serial.old');

    if (! -s '/var/ipcop/openvpn/certs/serial' ) {
        open(FILE, '>/var/ipcop/openvpn/certs/serial');
        print FILE '01';
        close FILE;
    }
    if (! -s '>/var/ipcop/openvpn/certs/index.txt') {
        system('touch /var/ipcop/openvpn/certs/index.txt');
    }
    unlink('/var/ipcop/openvpn/certs/index.txt.old');
    unlink('/var/ipcop/openvpn/certs/serial.old');
}

###
### Obtain Subject from given cert
###
sub getsubjectfromcert ($) {
    #&General::log("vpn", "Extracting subject from $_[0]...");
    my $temp = `/usr/bin/openssl x509 -text -in $_[0]`;
    $temp =~ /Subject: (.*)[\n]/;
    $temp = $1;
    $temp =~ s+/Email+, E+;
    $temp =~ s/ ST=/ S=/;
    return $temp;
}

###
### Obtain a CN from given cert
###
sub getCNfromcert ($) {
    #&General::log("ipsec", "Extracting name from $_[0]...");
    my $temp = `/usr/bin/openssl x509 -text -in $_[0]`;
    $temp =~ /Subject:.*CN=(.*)[\n]/;
    $temp = $1;
    $temp =~ s+/Email+, E+;
    $temp =~ s/ ST=/ S=/;
    $temp =~ s/,//g;
    $temp =~ s/\'//g;
    return $temp;
}

###
### Call openssl and return errormessage if any
###
sub callssl ($) {
    my $opt = shift;
    my $retssl =  `/usr/bin/openssl $opt 2>&1`; #redirect stderr
    my $ret = '';
    foreach my $line (split (/\n/, $retssl)) {
        &General::log("vpn", "$line") if (0);     # 1 for verbose logging
        if ( $line =~ /error|unknown/ ) {
            $ret .= '<br />'.&Header::cleanhtml($line);
        }
    }
    return $ret ? "$Lang::tr{'openssl produced an error'}: $ret" : '' ;
}


###
### Just return true is one interface is IPsec enabled
###
sub ipsecenabled {
    my $settings;

    if (defined($_[0])) {
        $settings = shift;
        return (($settings->{'ENABLED_RED_1'} eq 'on') || ($settings->{'ENABLED_BLUE_1'} eq 'on'));
    }
    else {
        my %vpnsettings = ();
        &General::readhash("/var/ipcop/ipsec/settings", \%vpnsettings);
        return (($vpnsettings{'ENABLED_RED_1'} eq 'on') || ($vpnsettings{'ENABLED_BLUE_1'} eq 'on'));
    }
}


###
### Write IPsec config files.
###
###Type=Host : GUI can choose the interface used (RED,GREEN,BLUE) and
###     the side is always defined as 'left'.
###     configihash[14]: 'VHOST' is allowed
###

sub writeipsecfiles {
    my %lconfighash = ();
    my %lvpnsettings = ();

    # klips or netkey
    my $protostack = (system('/sbin/modinfo ipsec 2>/dev/null')) ? 'netkey' : 'klips';

    &General::readhasharray("/var/ipcop/ipsec/config", \%lconfighash);
    &General::readhash("/var/ipcop/ipsec/settings", \%lvpnsettings);
    &General::readhash("/var/ipcop/ethernet/settings", \%netsettings);

    open(CONF,    ">/var/ipcop/ipsec/ipsec.conf") or die "Unable to open /var/ipcop/ipsec/ipsec.conf: $!";
    open(SECRETS, ">/var/ipcop/ipsec/ipsec.secrets") or die "Unable to open /var/ipcop/ipsec/ipsec.secrets: $!";
    flock CONF, 2;
    flock SECRETS, 2;
    print CONF <<END
# Do not modify 'ipsec.conf' directly since any changes you make will be
# overwritten whenever you change IPsec settings using the web interface!
#

version 2.0

config setup
	protostack=$protostack
END
    ;
    # Create an ipsec interface for each 'enabled' interface
    my $interfaces = "\tinterfaces=\"";
    my $ipsec_counter = 0;

    if ($lvpnsettings{"ENABLED_RED_1"} eq 'on') {
        # Since we do not always know what device real red is, use defaultroute for RED
        $interfaces .= "%defaultroute "; 
        $ipsec_counter++;
    }
    for my $iface ('BLUE') {
        if ($lvpnsettings{"ENABLED_${iface}_1"} eq 'on') {
            $interfaces .= "ipsec$ipsec_counter=".$netsettings{"${iface}_1_DEV"}." ";
            $ipsec_counter++;
        }
    }
    print CONF $interfaces . "\"\n" if ($protostack eq 'klips');

    my $plutodebug = '';            # build debug list
    map ($plutodebug .= $lvpnsettings{$_} eq 'on' ? lc (substr($_,4)).' ' : '',
        ('DBG_CRYPT','DBG_PARSING','DBG_EMITTING','DBG_CONTROL',
         'DBG_KLIPS','DBG_DNS','DBG_DPD','DBG_NATT'));
    $plutodebug = 'none' if $plutodebug eq '';  # if nothing selected, use 'none'.
    print CONF "\tklipsdebug=\"none\"\n";
    print CONF "\tplutodebug=\"$plutodebug\"\n";
    print CONF "\tuniqueids=yes\n";
    print CONF "\tnat_traversal=yes\n";
    print CONF "\toverridemtu=$lvpnsettings{'VPN_OVERRIDE_MTU'}\n" if ($lvpnsettings{'VPN_OVERRIDE_MTU'} ne '');
    print CONF "\tvirtual_private=%v4:10.0.0.0/8,%v4:172.16.0.0/12,%v4:192.168.0.0/16";
    # TODO: could prepare for multiple networks here
    print CONF ",%v4:!$netsettings{'GREEN_1_NETADDRESS'}/$netsettings{'GREEN_1_NETMASK'}";
    if ($netsettings{'ORANGE_COUNT'} > 0) {
        print CONF ",%v4:!$netsettings{'ORANGE_1_NETADDRESS'}/$netsettings{'ORANGE_1_NETMASK'}";
    }
    if ($netsettings{'BLUE_COUNT'} > 0) {
        print CONF ",%v4:!$netsettings{'BLUE_1_NETADDRESS'}/$netsettings{'BLUE_1_NETMASK'}";
    }
    foreach my $key (keys %lconfighash) {
        if ($lconfighash{$key}[3] eq 'net') {
            print CONF ",%v4:!$lconfighash{$key}[11]";
        }
    }
    print CONF "\n\n";
    print CONF "conn %default\n";
    print CONF "\tkeyingtries=0\n";
    print CONF "\tdisablearrivalcheck=no\n";
    print CONF "\tleftupdown=/usr/local/bin/ipsecupdown.sh\n" if ($protostack eq 'netkey');
    print CONF "\n";

    if (-f "/var/ipcop/certs/hostkey.pem") {
        print SECRETS ": RSA /var/ipcop/certs/hostkey.pem\n"
    }
    my $last_secrets = ''; # old the less specifics connections

    foreach my $key (keys %lconfighash) {
        next if ($lconfighash{$key}[0] ne 'on');

        #remote peer is not set? => use '%any'
        $lconfighash{$key}[10] = '%any' if ($lconfighash{$key}[10] eq '');

        my $localside;
        if ($lconfighash{$key}[26] eq 'BLUE') {
            $localside = $netsettings{'BLUE_1_ADDRESS'};
        }
        else {
            $localside = $lvpnsettings{'VPN_IP'};
        }

        my $comment = "net-2-net";
        $comment = "roadwarrior" if ($lconfighash{$key}[3] eq 'host');
        print CONF "# $lconfighash{$key}[25]\n# $comment to $lconfighash{$key}[26]\n";
        print CONF "conn $lconfighash{$key}[1]\n";
        if (($lconfighash{$key}[3] eq 'host') && ($lconfighash{$key}[4] eq 'psk') && ($lconfighash{$key}[26] eq 'RED')) {
            # Force left=%defaultroute for RW using PSK on RED. Openswan complains about the FQDN in this special case, probably because right=%any
            print CONF "\tleft=%defaultroute\n";
        }
        else {
            print CONF "\tleft=$localside\n";
        }
        # TODO: openswan 2.6 does not seem to need nexthop
        #print CONF "\tleftnexthop=%defaultroute\n" if ($lconfighash{$key}[26] eq 'RED' && $lvpnsettings{'VPN_IP'} ne '%defaultroute');
        print CONF "\tleftsubnet=$lconfighash{$key}[8]\n";

        print CONF "\tright=$lconfighash{$key}[10]\n";
        if ($lconfighash{$key}[3] eq 'net') {
            print CONF "\trightsubnet=$lconfighash{$key}[11]\n";
            # TODO: openswan 2.6 does not seem to need nexthop
            #print CONF "\trightnexthop=%defaultroute\n";
        } 
        elsif ($lconfighash{$key}[10] eq '%any' && $lconfighash{$key}[14] eq 'on') { #vhost allowed for roadwarriors?
            print CONF "\trightsubnet=vhost:%no,%priv\n";
        }

        # Local Cert and Remote Cert (unless auth is DN dn-auth)
        if ($lconfighash{$key}[4] eq 'cert') {
            print CONF "\tleftcert=/var/ipcop/certs/hostcert.pem\n";
            print CONF "\trightcert=/var/ipcop/certs/$lconfighash{$key}[1]cert.pem\n" if ($lconfighash{$key}[2] ne '%auth-dn');
        }

        # Local and Remote IDs
        print CONF "\tleftid=\"$lconfighash{$key}[7]\"\n" if ($lconfighash{$key}[7]);
        print CONF "\trightid=\"$lconfighash{$key}[9]\"\n" if ($lconfighash{$key}[9]);

        # Algorithms
        if ($lconfighash{$key}[18] && $lconfighash{$key}[19] && $lconfighash{$key}[20]) {
            print CONF "\tike=";
            my @encs   = split('\|', $lconfighash{$key}[18]);
            my @ints   = split('\|', $lconfighash{$key}[19]);
            my @groups = split('\|', $lconfighash{$key}[20]);
            my $comma = 0;
            foreach my $i (@encs) {
                foreach my $j (@ints) {
                    foreach my $k (@groups) {
                        if ($comma != 0) { print CONF ","; } else { $comma = 1; }
                        print CONF "$i-$j-modp$k";
                    }
                }
            }
            if ($lconfighash{$key}[24] eq 'on') {   #only proposed algorythms?
                print CONF "!\n";
            } 
            else {
                print CONF "\n";
            }
        }
        if ($lconfighash{$key}[21] && $lconfighash{$key}[22]) {
            print CONF "\tesp=";
            my @encs   = split('\|', $lconfighash{$key}[21]);
            my @ints   = split('\|', $lconfighash{$key}[22]);
            my $comma = 0;
            foreach my $i (@encs) {
                foreach my $j (@ints) {
                    if ($comma != 0) { print CONF ","; } else { $comma = 1; }
                    print CONF "$i-$j";
                }
            }
            if ($lconfighash{$key}[24] eq 'on') {   #only proposed algorythms?
                print CONF "!\n";
            } 
            else {
                print CONF "\n";
            }
        }

        # Lifetimes
        print CONF "\tikelifetime=$lconfighash{$key}[16]h\n" if ($lconfighash{$key}[16]);
        print CONF "\tkeylife=$lconfighash{$key}[17]h\n" if ($lconfighash{$key}[17]);

        # Aggresive mode
        print CONF "\taggrmode=yes\n" if ($lconfighash{$key}[12] eq 'on');

        # Compression
        print CONF "\tcompress=yes\n" if ($lconfighash{$key}[13] eq 'on');

        # Dead Peer Detection
        print CONF "\tdpddelay=30\n";
        print CONF "\tdpdtimeout=120\n";
        print CONF "\tdpdaction=$lconfighash{$key}[27]\n";

        # Disable pfs ?
        print CONF "\tpfs=". ($lconfighash{$key}[28] eq 'on' ? "yes\n" : "no\n");

        # Build Authentication details:  LEFTid RIGHTid : PSK psk
        my $psk_line;
        if ($lconfighash{$key}[4] eq 'psk') {
            $psk_line = ($lconfighash{$key}[7] ? $lconfighash{$key}[7] : $localside) . " " ;
            $psk_line .= $lconfighash{$key}[9] ? $lconfighash{$key}[9] : $lconfighash{$key}[10];  #remoteid or remote address?
            $psk_line .= " : PSK '$lconfighash{$key}[5]'\n";
            # if the line contains %any, it is less specific than two IP or ID, so move it at end of file.
            if ($psk_line =~ /%any/) {
                $last_secrets .= $psk_line;
            } 
            else {
                print SECRETS $psk_line;
            }
            print CONF "\tauthby=secret\n";
        } 
        else {
            print CONF "\tauthby=rsasig\n";
            print CONF "\tleftrsasigkey=%cert\n";
            print CONF "\trightrsasigkey=%cert\n";
        }

        if ($lconfighash{$key}[3] eq 'host') {
            # don't start tunnel, that is RoadWarrior job
            print CONF "\tauto=add\n";
            print CONF "\tkeyingtries=3\n";
        } 
        else {
            # start according to tunnel config
            print CONF "\tauto=$lconfighash{$key}[6]\n";
        }
        print CONF "\n";
    }#foreach key
    print SECRETS $last_secrets if ($last_secrets);
    close(CONF);
    close(SECRETS);
}


sub writeovpnradiusconf {
    my %radiussettings = ();
    &General::readhash('/var/ipcop/openvpn/settings', \%radiussettings);

    open(CONF, ">/var/ipcop/openvpn/radiusplugin.cnf") or die "Unable to open /var/ipcop/openvpn/radiusplugin.cnf: $!";
    flock CONF, 2;
    print CONF "NAS-Identifier=OpenVPN\n";
    print CONF "\n";
    print CONF "Service-Type=5\n";
    print CONF "\n";
    print CONF "Framed-Protocol=1\n";
    print CONF "\n";
    print CONF "NAS-Port-Type=5\n";
    print CONF "\n";
    print CONF "NAS-IP-Address=$netsettings{'GREEN_1_ADDRESS'}\n";
    print CONF "\n";
    print CONF "OpenVPNConfig=/var/ipcop/openvpn/server.conf\n";
    print CONF "\n";
    print CONF "overwriteccfiles=false\n";
    print CONF "\n";
    print CONF "server\n";
    print CONF "{\n";
    print CONF "   acctport=$radiussettings{RADIUS_ACCTPORT}\n";
    print CONF "   authport=$radiussettings{RADIUS_AUTHPORT}\n";
    print CONF "   name=$radiussettings{RADIUS_HOST}\n";
    print CONF "   retry=$radiussettings{RADIUS_RETRY}\n";
    print CONF "   wait=$radiussettings{RADIUS_TIMEOUT}\n";
    print CONF "   sharedsecret=$radiussettings{RADIUS_PASS1}\n";
    print CONF "}\n";
    print CONF "\n";
    close(CONF);
}


###
### Write OpenVPN server config
###
sub writeovpnserverconf {
    my %sovpnsettings = ();
    &General::readhash('/var/ipcop/openvpn/settings', \%sovpnsettings);

    open(CONF, ">/var/ipcop/openvpn/server.conf") or die "Unable to open /var/ipcop/openvpn/server.conf: $!";
    flock CONF, 2;
    print CONF <<END
# OpenVPN server configuration
# Do not modify '/var/ipcop/openvpn/server.conf' directly since any changes
# you make will be overwritten whenever you resave openvpn settings using the
# web interface!

daemon openvpnserver
writepid /var/run/openvpn.pid
dev $sovpnsettings{'DDEVICE'}
$sovpnsettings{'DDEVICE'}-mtu $sovpnsettings{'DMTU'}
proto $sovpnsettings{'DPROTOCOL'}
port $sovpnsettings{'DDEST_PORT'}
tls-server
ca /var/ipcop/ca/cacert.pem
cert /var/ipcop/certs/hostcert.pem
key /var/ipcop/certs/hostkey.pem
dh /var/ipcop/private/dh1024.pem
script-security 2
END
    ;
    if ($sovpnsettings{RADIUS_ENABLED} eq 'on') {
        print CONF "plugin /usr/lib/radiusplugin.so /var/ipcop/openvpn/radiusplugin.cnf\n";
    }
    # Make sure server IP settings are written as: server 10.0.10.0 255.255.255.0
    my $tmpnetaddr = NetAddr::IP->new($sovpnsettings{'DOVPN_SUBNET'});
    printf CONF sprintf("server %s %s\n",$tmpnetaddr->network()->addr(),$tmpnetaddr->mask());
    print CONF "push \"route $netsettings{'GREEN_1_NETADDRESS'} $netsettings{'GREEN_1_NETMASK'}\"\n" if ($sovpnsettings{'PUSH_GREEN_1'} eq 'on');
    print CONF "push \"route $netsettings{'BLUE_1_NETADDRESS'} $netsettings{'BLUE_1_NETMASK'}\"\n" if ($sovpnsettings{'PUSH_BLUE_1'} eq 'on');
    print CONF "push \"route $netsettings{'ORANGE_1_NETADDRESS'} $netsettings{'ORANGE_1_NETMASK'}\"\n" if ($sovpnsettings{'PUSH_ORANGE_1'} eq 'on');
    if ($sovpnsettings{CLIENT2CLIENT} eq 'on') {
        print CONF "client-to-client\n";
    }
    if (($sovpnsettings{'FASTIO'} eq 'on') && ($sovpnsettings{'DPROTOCOL'} eq 'udp')) {
        print CONF "fast-io\n";
    }
    if ($sovpnsettings{'MTUDISC'} eq 'on') {
        print CONF "mtu-disc yes\n";
    }
    if ($sovpnsettings{KEEPALIVE_1} > 0 && $sovpnsettings{KEEPALIVE_2} > 0) {
        print CONF "keepalive $sovpnsettings{'KEEPALIVE_1'} $sovpnsettings{'KEEPALIVE_2'}\n";
    }
    if ($sovpnsettings{'STATICIP'} eq 'on') {
        print CONF "client-config-dir /var/ipcop/openvpn/ccd\n";
        print CONF "ccd-exclusive\n";
    }
    print CONF "client-connect /usr/local/bin/openvpn.sh\n";
    print CONF "client-disconnect /usr/local/bin/openvpn.sh\n";
    print CONF "status-version 1\n";
    print CONF "status /var/log/openvpnserver.log 30\n";
    print CONF "cipher $sovpnsettings{DCIPHER}\n";
    if ($sovpnsettings{DCOMPLZO} eq 'on') {
        print CONF "comp-lzo\n";
    }
    if ($sovpnsettings{REDIRECT_GW_DEF1} eq 'on') {
        print CONF "push \"redirect-gateway def1\"\n";
    }
    if ($sovpnsettings{DHCP_DOMAIN} ne '') {
        print CONF "push \"dhcp-option DOMAIN $sovpnsettings{DHCP_DOMAIN}\"\n";
    }
    if ($sovpnsettings{DHCP_DNS1} ne '') {
        print CONF "push \"dhcp-option DNS $sovpnsettings{DHCP_DNS1}\"\n";
    }
    if ($sovpnsettings{DHCP_DNS2} ne '') {
        print CONF "push \"dhcp-option DNS $sovpnsettings{DHCP_DNS2}\"\n";
    }
    if ($sovpnsettings{DHCP_NTP1} ne '') {
        print CONF "push \"dhcp-option NTP $sovpnsettings{DHCP_NTP1}\"\n";
    }
    if ($sovpnsettings{DHCP_NTP2} ne '') {
        print CONF "push \"dhcp-option NTP $sovpnsettings{DHCP_NTP2}\"\n";
    }
    if ($sovpnsettings{DHCP_WINS1} ne '') {
        print CONF "push \"dhcp-option WINS $sovpnsettings{DHCP_WINS1}\"\n";
    }
    if ($sovpnsettings{DHCP_WINS2} ne '') {
        print CONF "push \"dhcp-option WINS $sovpnsettings{DHCP_WINS2}\"\n";
    }

    if ($sovpnsettings{MAX_CLIENTS} eq '') {
        print CONF "max-clients 100\n";
    }
    else {
        print CONF "max-clients $sovpnsettings{MAX_CLIENTS}\n";
    }
    print CONF "tls-verify /usr/local/bin/openvpnverify\n";
    print CONF "crl-verify /var/ipcop/crls/cacrl.pem\n";
    print CONF "user nobody\n";
    print CONF "group nobody\n";
    print CONF "persist-key\n";
    print CONF "persist-tun\n";
    if ($sovpnsettings{LOG_VERB} ne '') {
        print CONF "verb $sovpnsettings{LOG_VERB}\n";
    }
    else {
        print CONF "verb 3\n";
    }
    if ($sovpnsettings{LOG_MUTE_REPLAY} eq 'on') {
        print CONF "mute-replay-warnings\n";
    }
    print CONF "\n";

    close(CONF);

    if ($sovpnsettings{'RADIUS_ENABLED'} eq 'on') {
        &VPN::writeovpnradiusconf();
    }
}


1;
