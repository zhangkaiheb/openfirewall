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
# Copyright (C) 2005 Achim Weber <dotzball@users.sourceforge.net>
# (c) 2007-2014, the IPCop team
#
# $Id: DataAccess.pl 7534 2014-05-14 14:34:12Z owes $
#
# 6 May 2006 Achim Weber:
#       Re-worked code to use it in IPCop 1.5, renamed all variables, keys, etc.
#       from "BOT" to "FW".

package DATA;

use strict;

require '/usr/lib/ipcop/general-functions.pl';

$| = 1;    # line buffering

$DATA::customServicesFile  = "/var/ipcop/firewall/customservices";
$DATA::defaultServicesFile = "/var/ipcop/firewall/defaultservices";
$DATA::customNetworkFile   = "/var/ipcop/firewall/customnetworks";
$DATA::customIFaceFile     = "/var/ipcop/firewall/custominterfaces";
$DATA::serviceGroupFile    = "/var/ipcop/firewall/serviceGroups";
$DATA::addressGroupFile    = "/var/ipcop/firewall/addressGroups";
$DATA::blueAdressesFile    = "/var/ipcop/firewall/wireless";
$DATA::configfile          = "/var/ipcop/firewall/config";
$DATA::policyFile          = "/var/ipcop/firewall/policy";

@DATA::ruleKeys_unique = (
    'SRC_NET_TYPE', 'SRC_NET',      'SRC_ADR_TYPE', 'SRC_ADR',      'INV_SRC_ADR',  'SRC_PORT',     'INV_SRC_PORT', 
    'PORTFW_EXT_ADR', 'PORTFW_SERVICE_TYPE','PORTFW_SERVICE',
    'DST_NET_TYPE', 'DST_NET',      'DST_IP_TYPE',  'DST_IP',       'INV_DST_IP',   
    'SERVICE_TYPE', 'SERVICE',      
    'LOG_ENABLED',  'LIMIT_FOR',    'LIMIT_TYPE',   
    'MATCH_LIMIT',  'MATCH_STRING_ON', 'MATCH_STRING', 'INV_MATCH_STRING', 
    'RULEACTION'
);
@DATA::ruleKeys_all = ('ENABLED', 'RULEMODE', @DATA::ruleKeys_unique, 'TIMEFRAME_ENABLED', 'REMARK');

@DATA::weekDays = ('SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT');
@DATA::timeKeys_all = (
    'DAY_TYPE', 'START_DAY_MONTH', 'END_DAY_MONTH', @DATA::weekDays, 'START_HOUR', 'START_MINUTE', 'END_HOUR',
    'END_MINUTE'
);

my %netsettings = ();
&General::readhash("/var/ipcop/ethernet/settings", \%netsettings);

#######################################################
# Default Services
#######################################################
# my %defaultServices;
sub readDefaultServices
{
    my $dServices = shift;

    open(SERVICE, "$DATA::defaultServicesFile") or die 'Unable to open default services file.';
    my @service = <SERVICE>;
    close(SERVICE);
    my $tmpline;
    foreach $tmpline (@service) {
        chomp($tmpline);

        # remove unwanted characters
        $tmpline = &FW::cleanService($tmpline);
        my @tmp = split(/\,/, $tmpline);

        $dServices->{$tmp[0]}{'PORT_IPT'} = "--dport $tmp[1]";
        $dServices->{$tmp[0]}{'PORT_NR'}  = $tmp[1];
        $dServices->{$tmp[0]}{'PROTOCOL'} = $tmp[2];
    }

    # One special service: 'Ping', limit to icmp echo-request only
    $dServices->{'Ping'}{'PORT_IPT'} = '--icmp-type 8';
    $dServices->{'Ping'}{'PORT_NR'}  = '-';
    $dServices->{'Ping'}{'PROTOCOL'} = 'icmp';
}

#######################################################
# IPCop Services
#######################################################
# my %ipcopServices;
sub readIPCopServices
{
    my $dServices = shift;

    $dServices->{'IPCop dhcp'}{'PORT_IPT'} = "--sport 68 --dport 67";
    $dServices->{'IPCop dhcp'}{'PORT_NR'}  = '67';
    $dServices->{'IPCop dhcp'}{'PROTOCOL'} = 'udp';

    $dServices->{'IPCop dns'}{'PORT_IPT'} = "--dport 53";
    $dServices->{'IPCop dns'}{'PORT_NR'}  = '53';
    $dServices->{'IPCop dns'}{'PROTOCOL'} = 'tcpudp';

    my $https = '8443';
    my %mainsettings = ();
    &General::readhash("/var/ipcop/main/settings", \%mainsettings);
    $https = $mainsettings{'GUIPORT'} if (defined($mainsettings{'GUIPORT'}));

    $dServices->{'IPCop https'}{'PORT_IPT'} = "--dport $https";
    $dServices->{'IPCop https'}{'PORT_NR'}  = $https;
    $dServices->{'IPCop https'}{'PROTOCOL'} = 'tcp';

    $dServices->{'IPCop ntp'}{'PORT_IPT'} = "--dport 123";
    $dServices->{'IPCop ntp'}{'PORT_NR'}  = '123';
    $dServices->{'IPCop ntp'}{'PROTOCOL'} = 'udp';

    my %proxysettings = ();
    &General::readhash("/var/ipcop/proxy/settings", \%proxysettings);
    my $proxy = '8080';
    if ($proxysettings{'PROXY_PORT'} =~ /^(\d+)$/) {
        $proxy = $1;
    }
    $dServices->{'IPCop proxy'}{'PORT_IPT'} = "--dport $proxy";
    $dServices->{'IPCop proxy'}{'PORT_NR'}  = $proxy;
    $dServices->{'IPCop proxy'}{'PROTOCOL'} = 'tcp';
    # (our) Squid error messages use tcp/81 for images
    $dServices->{'IPCop http'}{'PORT_IPT'} = "--dport 81";
    $dServices->{'IPCop http'}{'PORT_NR'}  = '81';
    $dServices->{'IPCop http'}{'PROTOCOL'} = 'tcp';
    # use tcp/82 as intercept proxy port
    $dServices->{'IPCop proxy-int-1'}{'PORT_IPT'} = "--dport 82";
    $dServices->{'IPCop proxy-int-1'}{'PORT_NR'}  = '82';
    $dServices->{'IPCop proxy-int-1'}{'PROTOCOL'} = 'tcp';
    # reserve tcp/83 for proxy future use
    $dServices->{'IPCop proxy-int-2'}{'PORT_IPT'} = "--dport 83";
    $dServices->{'IPCop proxy-int-2'}{'PORT_NR'}  = '83';
    $dServices->{'IPCop proxy-int-2'}{'PROTOCOL'} = 'tcp';

    my $ssh = '8022';
    if (defined($mainsettings{'SSHPORT'})) {
        $ssh = $mainsettings{'SSHPORT'};
    }
    else {
        if (-e "/etc/ssh/sshd_config") {
            open(FILE, "/etc/ssh/sshd_config") or die 'Unable to open sshd_config file.';
            my @current = <FILE>;
            close(FILE);
            foreach my $line (@current) {

                #Port 8022

                if ($line =~ /^Port (\d+)\s*$/) {
                    $ssh = $1;
                    last;
                }
            }
        }
    }
    $dServices->{'IPCop ssh'}{'PORT_IPT'} = "--dport $ssh";
    $dServices->{'IPCop ssh'}{'PORT_NR'}  = $ssh;
    $dServices->{'IPCop ssh'}{'PROTOCOL'} = 'tcp';

    $dServices->{'IPCop IPsec'}{'PORT_IPT'} = "";
    $dServices->{'IPCop IPsec'}{'PORT_NR'}  = '-';
    $dServices->{'IPCop IPsec'}{'PROTOCOL'} = 'AH,ESP,IKE';

    if (-e "/var/ipcop/openvpn/settings") {
        my %ovpnSettings = ();
        &General::readhash("/var/ipcop/openvpn/settings", \%ovpnSettings);

        my $ovpnport = '1194';
        my $ovpnproto = 'udp';
        if ($ovpnSettings{'DDEST_PORT'} =~ /^(\d+)$/) {
          $ovpnport = $1;
        }
        if ($ovpnSettings{'DPROTOCOL'} =~ /^(tcp|udp)$/) {
          $ovpnproto = $1;
        }
        $dServices->{'IPCop OpenVPN'}{'PORT_IPT'} = "--dport $ovpnport";
        $dServices->{'IPCop OpenVPN'}{'PORT_NR'}  = $ovpnport;
        $dServices->{'IPCop OpenVPN'}{'PROTOCOL'} = $ovpnproto;

        # TODO: find the ports for OpenVPN net-2-net
    }

}

#######################################################
# ICMP Types
# Gets a hash-ref and additionaly returns a array
#######################################################
sub read_icmptypes
{
    my $hashRef = shift;

    my $fname   = "/var/ipcop/firewall/icmptypes";
    my $newline = "";
    my @newarray;

    open(FILE, "$fname") or die 'Unable to open icmp file.';
    my @current = <FILE>;
    close(FILE);

    foreach $newline (@current) {
        chomp($newline);
        if (substr($newline, 0, 1) ne "#") {
            my @tmp = split(/\,/, $newline);
            $hashRef->{$tmp[1]} = $tmp[0];
            push(@newarray, $tmp[1]);
        }
    }
    return (@newarray);
}

#######################################################
# Custom Services
#######################################################
# my %custServices;
sub readCustServices
{
    my $cServices = shift;

    open(SERVICE, "$DATA::customServicesFile") or die 'Unable to open custom services file.';
    my @service = <SERVICE>;
    close(SERVICE);
    my $tmpline;
    foreach $tmpline (@service) {
        chomp($tmpline);

        # remove unwanted characters
        $tmpline = &FW::cleanService($tmpline);
        my @tmp = split(/\,/, $tmpline);
        $cServices->{$tmp[0]}{'PORT_NR'}         = $tmp[1];
        $cServices->{$tmp[0]}{'PROTOCOL'}        = $tmp[2];
        $cServices->{$tmp[0]}{'PORT_INVERT'}     = $tmp[3];
        $cServices->{$tmp[0]}{'PROTOCOL_INVERT'} = $tmp[4];
        $cServices->{$tmp[0]}{'ICMP_TYPE'}       = $tmp[5];
        $cServices->{$tmp[0]}{'USED_COUNT'}      = $tmp[6];

        # iptables port
        my $port = '';
        if ($cServices->{$tmp[0]}{'PORT_NR'} ne '') {
            $port = "--dport $cServices->{$tmp[0]}{'PORT_NR'}";

            # when protocol is tcp or udp and proto is inverted
            # we have to invert the destination port(s)
            if (   $cServices->{$tmp[0]}{'PORT_INVERT'} eq 'on'
                || $cServices->{$tmp[0]}{'PROTOCOL_INVERT'} eq 'on')
            {
                $port = "--dport ! $cServices->{$tmp[0]}{'PORT_NR'}";
            }
        }

        $cServices->{$tmp[0]}{'PORT_IPT'} = $port;
    }
}

sub saveCustServices
{
    my $cServices = shift;

    my $line;
    open(FILE, ">$DATA::customServicesFile") or die 'Unable to open custom services file.';
    flock FILE, 2;
    foreach my $serviceName (sort keys %$cServices) {
        print FILE "$serviceName,";
        print FILE "$cServices->{$serviceName}{'PORT_NR'},";
        print FILE "$cServices->{$serviceName}{'PROTOCOL'},";
        print FILE "$cServices->{$serviceName}{'PORT_INVERT'},";
        print FILE "$cServices->{$serviceName}{'PROTOCOL_INVERT'},";
        print FILE "$cServices->{$serviceName}{'ICMP_TYPE'},";
        print FILE "$cServices->{$serviceName}{'USED_COUNT'}\n";
    }
    close(FILE);
}

#######################################################
# Service Groups
#######################################################
sub readServiceGroupConf
{
    my $conf = shift;
    %$conf = ();

    if (-e $DATA::serviceGroupFile) {
        open(FILE, $DATA::serviceGroupFile) or die 'Unable to open service group file.';
        my @current = <FILE>;
        close(FILE);

        foreach my $line (@current) {
            chomp($line);
            my @temp = split(/\,/, $line);
            my $key = $temp[1];
            if ($temp[0] eq "GROUP") {
                $conf->{$key}{'USED_COUNT'} = $temp[2];
                $conf->{$key}{'REMARK'}     = $temp[3];
                $conf->{$key}{'SERVICES'}   = ();

                #               print FILE "KEY,$key,$conf->{$key}{'USED_COUNT'},$conf->{$key}{'REMARK'}\n";
            }
            else {
                my %entry = ();
                $entry{'SERVICE_NAME'} = $temp[2];
                $entry{'SERVICE_TYP'}  = $temp[3];
                $entry{'ENABLED'}      = $temp[4];
                push(@{$conf->{$key}{'SERVICES'}}, \%entry);

#               print FILE "SERVICE,$key,$conf->{$key}{'SERVICE_NAME'},$conf->{$key}{'SERVICE_TYP'},$conf->{$key}{'ENABLED'}\n";
            }
        }
    }
}

sub saveServiceGroupConf
{
    my $conf = shift;

    open(FILE, ">$DATA::serviceGroupFile") or die 'Unable to open service group file.';
    flock FILE, 2;
    foreach my $key (sort keys %$conf) {
        print FILE "GROUP,$key,$conf->{$key}{'USED_COUNT'},$conf->{$key}{'REMARK'}\n";

        foreach my $entry (@{$conf->{$key}{'SERVICES'}}) {
            print FILE "SERVICE,$key,$entry->{'SERVICE_NAME'},$entry->{'SERVICE_TYP'},$entry->{'ENABLED'}\n";
        }
    }
    close(FILE);
}

#######################################################
# Address Groups
#######################################################
sub readAddressGroupConf
{
    my $conf = shift;
    %$conf = ();

    if (-e $DATA::addressGroupFile) {
        open(FILE, $DATA::addressGroupFile) or die 'Unable to open address group file.';
        my @current = <FILE>;
        close(FILE);

        foreach my $line (@current) {
            chomp($line);
            my @temp = split(/\,/, $line);
            my $key = $temp[1];
            if ($temp[0] eq "GROUP") {
                $conf->{$key}{'USED_COUNT'} = $temp[2];
                $conf->{$key}{'REMARK'}     = $temp[3];
                $conf->{$key}{'ADDRESSES'}  = ();

                #               print FILE "KEY,$key,$conf->{$key}{'USED_COUNT'},$conf->{$key}{'REMARK'}\n";
            }
            else {
                my %entry = ();
                $entry{'ADDRESS_NAME'} = $temp[2];
                $entry{'ADDRESS_TYP'}  = $temp[3];
                $entry{'ENABLED'}      = $temp[4];
                push(@{$conf->{$key}{'ADDRESSES'}}, \%entry);

#               print FILE "ADDRESS,$key,$conf->{$key}{'ADDRESS_NAME'},$conf->{$key}{'ADDRESS_TYP'},$conf->{$key}{'ENABLED'}\n";
            }
        }
    }
}

sub saveAddressGroupConf
{
    my $conf = shift;

    open(FILE, ">$DATA::addressGroupFile") or die 'Unable to open address group file.';
    flock FILE, 2;
    foreach my $key (sort keys %$conf) {
        print FILE "GROUP,$key,$conf->{$key}{'USED_COUNT'},$conf->{$key}{'REMARK'}\n";

        foreach my $entry (@{$conf->{$key}{'ADDRESSES'}}) {
            print FILE "ADDRESS,$key,$entry->{'ADDRESS_NAME'},$entry->{'ADDRESS_TYP'},$entry->{'ENABLED'}\n";
        }
    }
    close(FILE);
}

#######################################################
# Custom Interfaces
#######################################################
# my %custIfaces;
sub readCustIfaces
{
    my $ifaces = shift;
    my %ifacesCount = ();
    $ifacesCount{'NUM_EXTERNAL'} = 0;
    $ifacesCount{'NUM_INTERNAL'} = 0;

    open(IFACE, "$DATA::customIFaceFile") or die 'Unable to open custom iface file.';
    my @iface = <IFACE>;
    close(IFACE);
    my $tmpline;
    foreach $tmpline (@iface) {
        chomp($tmpline);
        my @tmp = split(/\,/, $tmpline);
        $ifaces->{$tmp[0]}{'IFACE'}      = $tmp[1];
        $ifaces->{$tmp[0]}{'EXTERNAL'} = $tmp[2];
        $ifaces->{$tmp[0]}{'USED_COUNT'} = $tmp[3];

        if($ifaces->{$tmp[0]}{'EXTERNAL'} eq 'on') {
            $ifacesCount{'NUM_EXTERNAL'}++;
        }
       else {
            $ifacesCount{'NUM_INTERNAL'}++;
        }
    }

    return %ifacesCount;
}

sub saveCustIfaces
{
    my $ifaces = shift;

    open(FILE, ">$DATA::customIFaceFile") or die 'Unable to open custom iface file.';
    flock FILE, 2;
    foreach my $ifaceName (sort keys %$ifaces) {
        print FILE "$ifaceName,$ifaces->{$ifaceName}{'IFACE'},$ifaces->{$ifaceName}{'EXTERNAL'},$ifaces->{$ifaceName}{'USED_COUNT'}\n";
    }
    close(FILE);
}

#######################################################
# Default Interfaces
#######################################################
sub setup_default_interfaces
{
    my $ifaces      = shift;
    my $ifaceCounts = shift;

    $ifaceCounts->{'GREEN'}   = 0;
    $ifaceCounts->{'BLUE'}    = 0;
    $ifaceCounts->{'ORANGE'}  = 0;
    $ifaceCounts->{'RED'}     = 0;
    $ifaceCounts->{'IPSEC'}   = 0;
    $ifaceCounts->{'OPENVPN'} = 0;

    my %netsettings = ();
    &General::readhash("/var/ipcop/ethernet/settings", \%netsettings);

    # Get current defined networks (Red, Green, Blue, Orange)
    $ifaces->{'Green'}{'IFACE'} = $netsettings{'GREEN_1_DEV'};
    $ifaces->{'Green'}{'ID'}    = 'GREEN_1';
    $ifaces->{'Green'}{'COLOR'} = 'GREEN_COLOR';
    $ifaces->{'Green'}{'ACTIV'} = 'yes';
    $ifaceCounts->{'GREEN'}++;

    if ($netsettings{'BLUE_1_DEV'} ne '') {
        $ifaces->{'Blue'}{'IFACE'} = $netsettings{'BLUE_1_DEV'};
        $ifaces->{'Blue'}{'ID'}    = 'BLUE_1';
        $ifaces->{'Blue'}{'COLOR'} = 'BLUE_COLOR';
        $ifaces->{'Blue'}{'ACTIV'} = 'yes';
        $ifaceCounts->{'BLUE'}++;
    }

    if ($netsettings{'ORANGE_1_DEV'} ne '') {
        $ifaces->{'Orange'}{'IFACE'} = $netsettings{'ORANGE_1_DEV'};
        $ifaces->{'Orange'}{'ID'}    = 'ORANGE_1';
        $ifaces->{'Orange'}{'COLOR'} = 'ORANGE_COLOR';
        $ifaces->{'Orange'}{'ACTIV'} = 'yes';
        $ifaceCounts->{'ORANGE'}++;
    }

    my $red_iface = &General::getredinterface();
    $ifaces->{'Red'}{'IFACE'} = $red_iface;
    $ifaces->{'Red'}{'ID'}    = 'RED_1';
    $ifaces->{'Red'}{'COLOR'} = 'RED_COLOR';
    if (-e "/var/ipcop/red/active" && $red_iface ne '') {
        $ifaces->{'Red'}{'ACTIV'} = 'yes';
    }
    else {
        $ifaces->{'Red'}{'ACTIV'} = 'no';
    }
    $ifaceCounts->{'RED'}++;

    ####
    ## setup VPN interfaces
    ####
    # IPsec
    if (-e "/var/ipcop/ipsec/ipsec.conf") {
        open(FILE, "/var/ipcop/ipsec/ipsec.conf") or die 'Unable to open ipsec.conf file.';
        my @current = <FILE>;
        close(FILE);
        foreach my $line (@current) {

            if ($line =~ /^\s*protostack=netkey/) {
                # using NETKEY
                if (-e "/var/ipcop/ipsec/settings") {
                    my %ipsecSettings = ();
                    &General::readhash("/var/ipcop/ipsec/settings", \%ipsecSettings);

                    if (($red_iface ne '') && (defined($ipsecSettings{'ENABLED_RED_1'}) && $ipsecSettings{'ENABLED_RED_1'} eq 'on')) {
                        # ipsec-red is a temporary interface
                        $ifaces->{"IPsec-Red"}{'IFACE'} = 'ipsec-red';
                        $ifaces->{"IPsec-Red"}{'ID'}    = 'IPSEC-RED';
                        $ifaces->{"IPsec-Red"}{'COLOR'} = 'IPSEC_COLOR';
                        $ifaces->{"IPsec-Red"}{'ACTIV'} = $ifaces->{'Red'}{'ACTIV'};
                        $ifaceCounts->{'IPSEC'}++;
                    }
                    if (defined($ipsecSettings{'ENABLED_BLUE_1'}) && $ipsecSettings{'ENABLED_BLUE_1'} eq 'on') {
                        # ipsec-blue is a temporary interface
                        $ifaces->{"IPsec-Blue"}{'IFACE'} = 'ipsec-blue';
                        $ifaces->{"IPsec-Blue"}{'ID'}    = 'IPSEC-BLUE';
                        $ifaces->{"IPsec-Blue"}{'COLOR'} = 'IPSEC_COLOR';
                        $ifaces->{"IPsec-Blue"}{'ACTIV'} = 'yes';
                        $ifaceCounts->{'IPSEC'}++;
                    }
                }
                last;
            }

            if ($line =~ /^\s*interfaces="(.*)"$/) {
                # using KLIPS
                my @ifaces = split(/ /, $1);
                my $count  = @ifaces;
                my $id     = 0;
                foreach my $match (@ifaces) {
                    if ($match =~ /^(ipsec\d+)=(.*?)$/) {
                        my $ipsec = $1;
                        my $eth   = $2;

                        foreach my $iface (keys %{$ifaces}) {
                            if ($ifaces->{$iface}{'IFACE'} eq $eth) {
                                $ifaces->{"IPsec-$iface"}{'IFACE'} = $ipsec;
                                $ifaces->{"IPsec-$iface"}{'ID'}    = uc("IPsec-$iface");
                                $ifaces->{"IPsec-$iface"}{'COLOR'} = 'IPSEC_COLOR';
                                $ifaces->{"IPsec-$iface"}{'ACTIV'} = 'yes';
                                $ifaceCounts->{'IPSEC'}++;
                            }
                        }
                    }
                    elsif ($match =~ /\%defaultroute/) {

                        # VPN on red
                        $ifaces->{"IPsec-Red"}{'IFACE'} = 'ipsec0';
                        $ifaces->{"IPsec-Red"}{'ID'}    = 'IPSEC-RED';
                        $ifaces->{"IPsec-Red"}{'COLOR'} = 'IPSEC_COLOR';
                        $ifaces->{"IPsec-Red"}{'ACTIV'} = 'yes';
                        $ifaceCounts->{'IPSEC'}++;
                    }
                }
                last;
            }
        }
    }    # end IPsec

    # OpenVPN
    if (-e "/var/ipcop/openvpn/settings") {
        my %ovpnSettings = ();
        &General::readhash("/var/ipcop/openvpn/settings", \%ovpnSettings);

        # We add only 1 interface here, since the OpenVPN server only creates 1 tunnel interface
        # This will probably change as soon as we add OpenVPN net-2-net

        # TODO: find the tunX interface used by the OpenVPN server and not fix to tun0

        if ((defined($ovpnSettings{'ENABLED_RED_1'}) && $ovpnSettings{'ENABLED_RED_1'} eq 'on')
            || (defined($ovpnSettings{'ENABLED_BLUE_1'}) && $ovpnSettings{'ENABLED_BLUE_1'} eq 'on')){
            $ifaces->{"OpenVPN-RW"}{'IFACE'} = 'tun0';
            $ifaces->{"OpenVPN-RW"}{'ID'}    = 'OPENVPN-RW';
            $ifaces->{"OpenVPN-RW"}{'COLOR'} = 'OVPN_COLOR';
            $ifaces->{"OpenVPN-RW"}{'ACTIV'} = 'yes';
            $ifaceCounts->{'OPENVPN'}++;
        }
    }    # end OpenVPN

}

#######################################################
# Default Networks
#######################################################
# Achim Weber: borrowed and modified from IPCop code:
sub setup_default_networks
{
    my $defaultNetworks = shift;
    my $netsettings     = shift;

    # Special mark(s) for accessing portforwards from internal
    # start at 11h to enough leave room for IPsec marks on red and blue.
    my $portFWMark = 17;

    # Get current defined networks (Red, Green, Blue, Orange)
    $defaultNetworks->{'Any'}{'IPT'}      = "0.0.0.0/0.0.0.0";
    $defaultNetworks->{'Any'}{'ADR'}      = "0.0.0.0";
    $defaultNetworks->{'Any'}{'MASK'}     = "0.0.0.0";
    $defaultNetworks->{'Any'}{'LOCATION'} = "OTHER";
    $defaultNetworks->{'Any'}{'COLOR'}    = "ANY_COLOR";

    $defaultNetworks->{'localhost'}{'IPT'}      = "127.0.0.1/255.255.255.255";
    $defaultNetworks->{'localhost'}{'ADR'}      = "127.0.0.1";
    $defaultNetworks->{'localhost'}{'MASK'}     = "255.255.255.255";
    $defaultNetworks->{'localhost'}{'LOCATION'} = "IPCOP";
    $defaultNetworks->{'localhost'}{'COLOR'}    = "LOCAL_COLOR";

    $defaultNetworks->{'localnet'}{'IPT'}      = "127.0.0.0/255.0.0.0";
    $defaultNetworks->{'localnet'}{'ADR'}      = "127.0.0.0";
    $defaultNetworks->{'localnet'}{'MASK'}     = "255.0.0.0";
    $defaultNetworks->{'localnet'}{'LOCATION'} = "OTHER";
    $defaultNetworks->{'localnet'}{'COLOR'}    = "LOCAL_COLOR";

    $defaultNetworks->{'Private Network 10.0.0.0'}{'IPT'}      = "10.0.0.0/255.0.0.0";
    $defaultNetworks->{'Private Network 10.0.0.0'}{'ADR'}      = "10.0.0.0";
    $defaultNetworks->{'Private Network 10.0.0.0'}{'MASK'}     = "255.0.0.0";
    $defaultNetworks->{'Private Network 10.0.0.0'}{'LOCATION'} = "OTHER";
    $defaultNetworks->{'Private Network 10.0.0.0'}{'COLOR'}    = "PRIVATE_COLOR";

    $defaultNetworks->{'Private Network 172.16.0.0'}{'IPT'}      = "172.16.0.0/255.240.0.0";
    $defaultNetworks->{'Private Network 172.16.0.0'}{'ADR'}      = "172.16.0.0";
    $defaultNetworks->{'Private Network 172.16.0.0'}{'MASK'}     = "255.240.0.0";
    $defaultNetworks->{'Private Network 172.16.0.0'}{'LOCATION'} = "OTHER";
    $defaultNetworks->{'Private Network 172.16.0.0'}{'COLOR'}    = "PRIVATE_COLOR";

    $defaultNetworks->{'Private Network 192.168.0.0'}{'IPT'}      = "192.168.0.0/255.255.0.0";
    $defaultNetworks->{'Private Network 192.168.0.0'}{'ADR'}      = "192.168.0.0";
    $defaultNetworks->{'Private Network 192.168.0.0'}{'MASK'}     = "255.255.0.0";
    $defaultNetworks->{'Private Network 192.168.0.0'}{'LOCATION'} = "OTHER";
    $defaultNetworks->{'Private Network 192.168.0.0'}{'COLOR'}    = "PRIVATE_COLOR";

    # init with a dummy value
    my $red_address = 'N/A';
    if (-e "/var/ipcop/red/local-ipaddress") {
        $red_address = `cat /var/ipcop/red/local-ipaddress`;
        chomp($red_address);
    }
    $defaultNetworks->{'Red Address'}{'IPT'}      = "$red_address";
    $defaultNetworks->{'Red Address'}{'ADR'}      = "$red_address";
    $defaultNetworks->{'Red Address'}{'MASK'}     = "";
    $defaultNetworks->{'Red Address'}{'LOCATION'} = "IPCOP";
    $defaultNetworks->{'Red Address'}{'COLOR'}    = "RED_COLOR";

    $defaultNetworks->{'Green Address'}{'IPT'}      = "$netsettings{'GREEN_1_ADDRESS'}/255.255.255.255";
    $defaultNetworks->{'Green Address'}{'ADR'}      = $netsettings{'GREEN_1_ADDRESS'};
    $defaultNetworks->{'Green Address'}{'MASK'}     = "255.255.255.255";
    $defaultNetworks->{'Green Address'}{'LOCATION'} = "IPCOP";
    $defaultNetworks->{'Green Address'}{'COLOR'}    = "GREEN_COLOR";

    $defaultNetworks->{'Green Network'}{'IPT'}  = "$netsettings{'GREEN_1_NETADDRESS'}/$netsettings{'GREEN_1_NETMASK'}";
    $defaultNetworks->{'Green Network'}{'ADR'}  = $netsettings{'GREEN_1_NETADDRESS'};
    $defaultNetworks->{'Green Network'}{'MASK'} = $netsettings{'GREEN_1_NETMASK'};
    $defaultNetworks->{'Green Network'}{'LOCATION'} = "OTHER";
    $defaultNetworks->{'Green Network'}{'COLOR'}    = "GREEN_COLOR";
    $defaultNetworks->{'Green Network'}{'PFWMARK'}  = $portFWMark++;
    $defaultNetworks->{'Green Network'}{'N2A'}      = "Green Address";

    if ($netsettings{'ORANGE_1_DEV'} ne '') {
        $defaultNetworks->{'Orange Address'}{'IPT'}      = "$netsettings{'ORANGE_1_ADDRESS'}/255.255.255.255";
        $defaultNetworks->{'Orange Address'}{'ADR'}      = $netsettings{'ORANGE_1_ADDRESS'};
        $defaultNetworks->{'Orange Address'}{'MASK'}     = "255.255.255.255";
        $defaultNetworks->{'Orange Address'}{'LOCATION'} = "IPCOP";
        $defaultNetworks->{'Orange Address'}{'COLOR'}    = "ORANGE_COLOR";

        $defaultNetworks->{'Orange Network'}{'IPT'} =
            "$netsettings{'ORANGE_1_NETADDRESS'}/$netsettings{'ORANGE_1_NETMASK'}";
        $defaultNetworks->{'Orange Network'}{'ADR'}      = $netsettings{'ORANGE_1_NETADDRESS'};
        $defaultNetworks->{'Orange Network'}{'MASK'}     = $netsettings{'ORANGE_1_NETMASK'};
        $defaultNetworks->{'Orange Network'}{'LOCATION'} = "OTHER";
        $defaultNetworks->{'Orange Network'}{'COLOR'}    = "ORANGE_COLOR";
        $defaultNetworks->{'Orange Network'}{'PFWMARK'}  = $portFWMark++;
        $defaultNetworks->{'Orange Network'}{'N2A'}      = "Orange Address";
    }

    if ($netsettings{'BLUE_1_DEV'} ne '') {
        $defaultNetworks->{'Blue Address'}{'IPT'}      = "$netsettings{'BLUE_1_ADDRESS'}/255.255.255.255";
        $defaultNetworks->{'Blue Address'}{'ADR'}      = $netsettings{'BLUE_1_ADDRESS'};
        $defaultNetworks->{'Blue Address'}{'MASK'}     = "255.255.255.255";
        $defaultNetworks->{'Blue Address'}{'LOCATION'} = "IPCOP";
        $defaultNetworks->{'Blue Address'}{'COLOR'}    = "BLUE_COLOR";

        $defaultNetworks->{'Blue Network'}{'IPT'}  = "$netsettings{'BLUE_1_NETADDRESS'}/$netsettings{'BLUE_1_NETMASK'}";
        $defaultNetworks->{'Blue Network'}{'ADR'}  = $netsettings{'BLUE_1_NETADDRESS'};
        $defaultNetworks->{'Blue Network'}{'MASK'} = $netsettings{'BLUE_1_NETMASK'};
        $defaultNetworks->{'Blue Network'}{'LOCATION'} = "OTHER";
        $defaultNetworks->{'Blue Network'}{'COLOR'}    = "BLUE_COLOR";
        $defaultNetworks->{'Blue Network'}{'PFWMARK'}  = $portFWMark++;
        $defaultNetworks->{'Blue Network'}{'N2A'}      = "Blue Address";
    }

    # OpenVPN
    if (-e "/var/ipcop/openvpn/settings") {
        my %ovpnSettings = ();
        &General::readhash("/var/ipcop/openvpn/settings", \%ovpnSettings);

        # OpenVPN on Red?
        if (defined($ovpnSettings{'DOVPN_SUBNET'})) {
            $defaultNetworks->{'OpenVPN Network'}{'IPT'} = $ovpnSettings{'DOVPN_SUBNET'};
            my @tempovpnsubnet = split("\/", $ovpnSettings{'DOVPN_SUBNET'});
            $defaultNetworks->{'OpenVPN Network'}{'ADR'}      = $tempovpnsubnet[0];
            $defaultNetworks->{'OpenVPN Network'}{'MASK'}     = $tempovpnsubnet[1];
            $defaultNetworks->{'OpenVPN Network'}{'LOCATION'} = "OTHER";
            $defaultNetworks->{'OpenVPN Network'}{'COLOR'}    = "OVPN_COLOR";

            # TODO: do we also want to do the portforward automagic for OpenVPN ?
            # We would need to find the server IP in that case.
            #$defaultNetworks->{'OpenVPN Network'}{'PFWMARK'}  = $portFWMark++;
            #$defaultNetworks->{'OpenVPN Network'}{'N2A'}      = "OpenVPN Address";
            #$defaultNetworks->{'OpenVPN Address'}{'ADR'}      = "2.2.2.2";
        }
    }    # end OpenVPN

    open(FILE, "/var/ipcop/ethernet/aliases") or die 'Unable to open aliases file.';
    my @current = <FILE>;
    close(FILE);
    my $ctr = 0;
    foreach my $line (@current) {
        if ($line ne '') {
            chomp($line);
            my @temp = split(/\,/, $line);
            if ($temp[2] eq '') {
                $temp[2] = "Alias $ctr : $temp[0]";
            }
            $defaultNetworks->{$temp[2]}{'IPT'}      = "$temp[0]";
            $defaultNetworks->{$temp[2]}{'ADR'}      = "$temp[0]";
            $defaultNetworks->{$temp[2]}{'MASK'}     = "";
            $defaultNetworks->{$temp[2]}{'LOCATION'} = "IPCOP";
            $defaultNetworks->{$temp[2]}{'COLOR'}    = "RED_COLOR";
            $ctr++;
        }
    }
}

#######################################################
# Custom Addresses
#######################################################
# my %custAddresses;
sub readCustAddresses
{
    my $addressesRef = shift;
    open(NET, "$DATA::customNetworkFile") or die 'Unable to open custom address file.';
    my @net = <NET>;
    close(NET);
    my $tmpline;
    foreach $tmpline (@net) {
        chomp($tmpline);
        my @tmp = split(/\,/, $tmpline);
        $addressesRef->{$tmp[0]}{'ADDRESS_TYPE'} = "$tmp[1]";
        $addressesRef->{$tmp[0]}{'ADDRESS'}      = "$tmp[2]";
        $addressesRef->{$tmp[0]}{'NETMASK'}      = "$tmp[3]";
        $addressesRef->{$tmp[0]}{'USED_COUNT'}   = "$tmp[4]";
    }
}

sub saveCustAddresses
{
    my $addressesRef = shift;

    open(FILE, ">$DATA::customNetworkFile") or die 'Unable to open custom address file.';
    flock FILE, 2;
    foreach my $adrName (sort keys %$addressesRef) {
        print FILE "$adrName,$addressesRef->{$adrName}{'ADDRESS_TYPE'},$addressesRef->{$adrName}{'ADDRESS'},";
        print FILE "$addressesRef->{$adrName}{'NETMASK'},$addressesRef->{$adrName}{'USED_COUNT'}\n";
    }
    close(FILE);
}

#######################################################
# Rule config
#######################################################
sub readRuleConfig
{
    my $configRef = shift;

    open(FILE, $DATA::configfile) or die 'Unable to open config file.';
    my @current = <FILE>;
    close(FILE);

    $configRef->{'INPUT'}    = ();
    $configRef->{'EXTERNAL'} = ();
    $configRef->{'OUTGOING'}  = ();
    $configRef->{'PINHOLES'} = ();
    $configRef->{'PORTFW'} = ();

    foreach my $line (@current) {
        chomp($line);
        my @tmp = split(/\,/, $line);

        if ($tmp[0] eq 'RULE') {
            my %rule     = ();
            my $keyCount = @DATA::ruleKeys_all;
            my $i        = 0;
            for (; $i < $keyCount; $i++) {

                # the rule config starts in 3th postion of each line
                $rule{$DATA::ruleKeys_all[$i]} = $tmp[ $i + 2 ];
            }

            push(@{$configRef->{$tmp[1]}}, \%rule);
        }
        elsif ($tmp[0] eq 'TIME') {
            my $rule = $configRef->{$tmp[1]}[ $tmp[2] ];

            my $keyCount = @DATA::timeKeys_all;
            my $i        = 0;
            for (; $i < $keyCount; $i++) {

                # the rule config starts in 4th postion of each line
                $rule->{$DATA::timeKeys_all[$i]} = $tmp[ $i + 3 ];
            }

            ## the time config starts in 4th postion of each line
            #$rule->{'DAY_TYPE'} = $tmp[3];
            #$rule->{'START_DAY_MONTH'} = $tmp[4];
            #$rule->{'END_DAY_MONTH'} = $tmp[5];
            #$rule->{'MON'} = $tmp[6];
            #$rule->{'TUE'} = $tmp[7];
            #$rule->{'WED'} = $tmp[8];
            #$rule->{'THU'} = $tmp[9];
            #$rule->{'FRI'} = $tmp[10];
            #$rule->{'SAT'} = $tmp[11];
            #$rule->{'SUN'} = $tmp[12];
            #$rule->{'START_HOUR'} = $tmp[13];
            #$rule->{'START_MINUTE'} = $tmp[14];
            #$rule->{'END_HOUR'} = $tmp[15];
            #$rule->{'END_MINUTE'} = $tmp[16];
        }
        else {

            # something is wrong with this config
            next;
        }
    }
}

sub saveRuleConfig
{
    my $configRef = shift;

    open(FILE, ">$DATA::configfile") or die 'Unable to open config file.';
    flock FILE, 2;

    foreach my $type (("INPUT", "OUTGOING", "EXTERNAL", "PINHOLES", "PORTFW")) {
        my $id = 0;
        foreach my $rule (@{$configRef->{$type}}) {
            print FILE "RULE,$type,";

            my $keyCount = @DATA::ruleKeys_all;
            my $i        = 0;
            for (; $i < $keyCount - 1; $i++) {
                print FILE "$rule->{$DATA::ruleKeys_all[$i]},";
            }
            print FILE "$rule->{$DATA::ruleKeys_all[$i]}\n";

            if ($rule->{'TIMEFRAME_ENABLED'} eq 'on') {
                print FILE "TIME,$type,$id,";

                my $keyCount = @DATA::timeKeys_all;
                my $j        = 0;
                for (; $j < $keyCount - 1; $j++) {
                    print FILE "$rule->{$DATA::timeKeys_all[$j]},";
                }
                print FILE "$rule->{$DATA::timeKeys_all[$j]}\n";
            }
            $id++;
        }
    }

    close(FILE);
}

#######################################################
# Interface policies
#######################################################
sub readReadPolicies
{
    my $ifaces     = shift;
    my $policygRef = shift;

    foreach my $iface (sort keys %$ifaces) {
        my $policy = 'open';
        my $action = 'reject';
        my $addressfilter = '-';
        if ($ifaces->{$iface}{'COLOR'} =~ /^GREEN_COLOR|IPSEC_COLOR|OVPN_COLOR$/) {
            $policy = 'open';
        }
        elsif ($ifaces->{$iface}{'COLOR'} =~ /^BLUE_COLOR$/) {

            # everything is open on blue but has to be allowed per IP/MAC address
            $policy = 'open';
            $addressfilter = 'on';
        }
        elsif ($ifaces->{$iface}{'COLOR'} =~ /^ORANGE_COLOR$/) {

            # orange is allowed to connect to the internet but no
            # access to IPCop
            $policy = 'open';
        }
        elsif ($ifaces->{$iface}{'COLOR'} =~ /^RED_COLOR$/) {

            # everything is closed on red
            $policy = 'closed';
            $action = 'drop';
        }
        else {
            next;
        }

        $policygRef->{$iface}                   = ();
        $policygRef->{$iface}{'POLICY'}         = $policy;
        $policygRef->{$iface}{'DEFAULT_LOG'}    = 'on';
        $policygRef->{$iface}{'DEFAULT_ACTION'} = $action;
        $policygRef->{$iface}{'ADDRESSFILTER'}  = $addressfilter;
        $policygRef->{$iface}{'DEFAULT_LOGBC'}  = 'off';
    }

    my %custIfaces = ();
    &DATA::readCustIfaces(\%custIfaces);
    foreach my $iface (sort keys %custIfaces) {
        $policygRef->{$iface}                   = ();
        $policygRef->{$iface}{'POLICY'}         = 'closed';
        $policygRef->{$iface}{'DEFAULT_LOG'}    = 'on';
        $policygRef->{$iface}{'DEFAULT_ACTION'} = 'drop';
        $policygRef->{$iface}{'ADDRESSFILTER'}  = '-';
        $policygRef->{$iface}{'DEFAULT_LOGBC'}  = 'off';
    }

    open(FILE, $DATA::policyFile) or die 'Unable to open policy file.';
    my @current = <FILE>;
    close(FILE);

    foreach my $line (@current) {
        chomp($line);
        my @tmp = split(/\,/, $line);

        $policygRef->{$tmp[0]}{'POLICY'}         = $tmp[1];
        $policygRef->{$tmp[0]}{'DEFAULT_LOG'}    = $tmp[2];
        $policygRef->{$tmp[0]}{'DEFAULT_ACTION'} = $tmp[3];
        $policygRef->{$tmp[0]}{'ADDRESSFILTER'}  = $tmp[4];
        $policygRef->{$tmp[0]}{'DEFAULT_LOGBC'}  = $tmp[5] if (defined($tmp[5]));
    }
}

sub savePolicies
{
    my $policygRef = shift;

    open(FILE, ">$DATA::policyFile") or die 'Unable to open policy file.';
    flock FILE, 2;

    foreach my $iface (sort keys %$policygRef) {
        print FILE "$iface,";
        print FILE "$policygRef->{$iface}{'POLICY'},";
        print FILE "$policygRef->{$iface}{'DEFAULT_LOG'},";
        print FILE "$policygRef->{$iface}{'DEFAULT_ACTION'},";
        print FILE "$policygRef->{$iface}{'ADDRESSFILTER'},";
        print FILE "$policygRef->{$iface}{'DEFAULT_LOGBC'}\n";
    }

    close(FILE);
    &General::log($Lang::tr{'firewall interface policy changed'});
}

#######################################################
# Wireless/blue addresses (Addressfilter)
#######################################################
# my %blueAddresses;
sub readBlueAddresses
{
    my $addressesRef = shift;
    open(ADR, "$DATA::blueAdressesFile") or die 'Unable to open blue addresses file.';
    my @addresses = <ADR>;
    my $count = 0;
    close(ADR);
    foreach my $tmpline (@addresses) {
        chomp($tmpline);
        my @tmp = split(/\,/, $tmpline);

        next if ($tmp[3] ne 'on');

        $addressesRef->{$count}{'SOURCE_IP'}  = "$tmp[1]";
        $addressesRef->{$count}{'SOURCE_MAC'} = "$tmp[2]";

        $addressesRef->{$count}{'SOURCE_ADR_IPT'} = '';

        if (&General::validmac($addressesRef->{$count}{'SOURCE_MAC'})) {
            $addressesRef->{$count}{'SOURCE_ADR_IPT'} = " -m mac --mac-source $addressesRef->{$count}{'SOURCE_MAC'} ";
        }

        if (&General::validip($addressesRef->{$count}{'SOURCE_IP'})) {
            $addressesRef->{$count}{'SOURCE_ADR_IPT'} .= " -s $addressesRef->{$count}{'SOURCE_IP'} ";
        }

        $count++;
    }
}



#######################################################
# Check if a protocol+port combination is reserved for IPCop itself
#######################################################
sub isReservedPort
{
    my $proto = shift;
    my $port = shift;

    my %ipcopServices = ();
    &DATA::readIPCopServices(\%ipcopServices);

    my $isRange = 0;
    my @range = ();
    if($port =~ /:/) {
        @range = split(/\:/, $port);
        $isRange = 1;
    }

    foreach my $key (keys %ipcopServices)
    {
        my $proto_ipcop = $ipcopServices{$key}{'PROTOCOL'};
        my $port_ipcop =  $ipcopServices{$key}{'PORT_NR'};

        if((index($proto_ipcop, $proto) != -1) || (index($proto, $proto_ipcop) != -1)) {
            if($isRange) {
                if($range[0] <= $port_ipcop && $port_ipcop <= $range[1]){
                   return 1;
                }
            }
            else {
                if($port_ipcop eq $port){
                   return 1;
                }
            }
        }
    }

    return 0;
}

#######################################################
# Check if an address is used as destination
# Returns
#       2 - if used as destination in portforwarding
#       1 - if used as destination (not portforwarding)
#       0 - if not used as destination
#######################################################
sub isUsedAsDestAdr
{
    my $adr = shift;

    my %ruleConfig = ();
    &DATA::readRuleConfig(\%ruleConfig);

    my $usedAsDest = 0;
    my $usedInPfw = 0;
    foreach my $type (keys %ruleConfig) {
        foreach my $rule (@{$ruleConfig{$type}}) {

            if($rule->{'DST_IP_TYPE'} eq 'custDestIP' && $rule->{'DST_IP'} eq $adr) {
                $usedAsDest = 1;
                if($type eq 'PORTFW') {
                    $usedInPfw = 2;
                }
            }
        }
    }

    if($usedInPfw == 2) {
        return 2;
    }
    elsif( $usedAsDest == 1) {
        return 1;
    }

    # not used as dest
    return 0;
}

#######################################################
# Returns the service parameters of a given servicename
#######################################################
sub getServiceParams
{
    my $type = shift;
    my $customName = shift;
    my $defaultName = shift;
    my $serviceRef = shift;

    $serviceRef->{'PROTOCOL'} = '';
    $serviceRef->{'PORT_INVERT'} = 'off';
    $serviceRef->{'PROTOCOL_INVERT'} = 'off';
    $serviceRef->{'PORT'} = 0;
    $serviceRef->{'IS_RANGE'} = 0;

    my %customSrv = ();
    &DATA::readCustServices(\%customSrv);
    my %defaultServices = ();
    &DATA::readDefaultServices(\%defaultServices);


    if($type eq 'custom') {
        $serviceRef->{'PORT_INVERT'} = $customSrv{$customName}{'PORT_INVERT'};
        $serviceRef->{'PROTOCOL_INVERT'} = $customSrv{$customName}{'PROTOCOL_INVERT'};
        $serviceRef->{'PROTOCOL'} = $customSrv{$customName}{'PROTOCOL'};
        $serviceRef->{'PORT'} =  $customSrv{$customName}{'PORT_NR'};
    }
    else {
        # default service
        $serviceRef->{'PROTOCOL'} = $defaultServices{$defaultName}{'PROTOCOL'};
        $serviceRef->{'PORT'} =  $defaultServices{$defaultName}{'PORT_NR'};
    }


    if($serviceRef->{'PORT'}=~ /^(\d+)\:(\d+)$/) {
        $serviceRef->{'IS_RANGE'} = 1;
    }

}

#######################################################
# Check if a service is used in portforwarding
# Returns
#       errormessage - if used in portforwarding and proto or portrange does not match with the other service
#       empty string   - if not used in portforwarding or if using it with the given params is ok
#######################################################
sub isUsedInPortfwOk
{
    my $servicename = shift;
    my $serviceRef = shift;

    my %ruleConfig = ();
    &DATA::readRuleConfig(\%ruleConfig);

    my $usedExternal = 0;
    my $errorReserved = 0;
    my $errorProto = 0;
    my $errorRange = 0;
    #DEBUG: print "service: <br />- Proto: $serviceRef->{'PROTOCOL'}<br />- PORT: $serviceRef->{'PORT'}<br />- IS_RANGE: $serviceRef->{'IS_RANGE'}<br />\n";

    foreach my $rule (@{$ruleConfig{'PORTFW'}}) {

        my %other = ();

        if($rule->{'PORTFW_SERVICE_TYPE'} eq 'custom' && $rule->{'PORTFW_SERVICE'} eq $servicename) {
            # the given service is used as external service
             $usedExternal = 1;

            if($rule->{'SERVICE_TYPE'} eq 'custom' && $rule->{'SERVICE'} eq $servicename){
                # external and internal are the same, all is fine
                next;
            }

            &DATA::getServiceParams($rule->{'SERVICE_TYPE'}, $rule->{'SERVICE'}, $rule->{'SERVICE'}, \%other);

        }
        elsif($rule->{'SERVICE_TYPE'} eq 'custom' && $rule->{'SERVICE'} eq $servicename)
        {
            # the given service is used internal but not external

            &DATA::getServiceParams($rule->{'PORTFW_SERVICE_TYPE'}, $rule->{'PORTFW_SERVICE'}, $rule->{'PORTFW_SERVICE'}, \%other);

        }
        else {
            # not used in this rule
            next;
        }

        #DEBUG: print "other: <br />- Proto: $other{'PROTOCOL'}<br />- PORT: $other{'PORT'}<br />- IS_RANGE: $other{'IS_RANGE'}<br />\n";

        if( ($serviceRef->{'IS_RANGE'} || $other{'IS_RANGE'}) && ($serviceRef->{'PORT'} ne $other{'PORT'})) {
            $errorRange = 1;
        }
        if($serviceRef->{'PROTOCOL'} ne $other{'PROTOCOL'}) {
            $errorProto = 1;
        }
    }

    if ($usedExternal && &DATA::isReservedPort($serviceRef->{'PROTOCOL'}, $serviceRef->{'PORT'})) {
        $errorReserved = 1;
    }


    my $msg = '';

    if($errorRange || $errorProto || $errorReserved) {
        $msg .= "$Lang::tr{'service is used in portfw'}:<br />";
    }
    if($errorRange) {
        $msg .= "$Lang::tr{'using portrange in portfw'}<br />";
    }
    if($errorProto) {
        $msg .= "$Lang::tr{'same proto in portfw'}<br />";
    }
    if($errorReserved) {
        if($serviceRef->{'IS_RANGE'} ) {
            $msg .= "$Lang::tr{'reserved external portrange'}<br />";
        }
        else {
            $msg .= "$Lang::tr{'reserved external port'}<br />";
        }
    }

    return $msg;
}

#EOF


