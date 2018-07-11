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
# firewall-lib.pl was created for the BlockOutTraffic Addon.
# Copyright (C) 2004 Achim Weber <dotzball@users.sourceforge.net>
#
# 6 May 2006 Achim Weber:
#       Re-worked code to use it in IPCop 1.5, renamed all variables, keys, etc.
#       from "BOT" to "FW".
#
# (c) 2007-2014, the IPCop team
#
# $Id: firewall-lib.pl 7340 2014-03-17 06:57:10Z owes $
#

package FW;

use strict;

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';
require '/usr/lib/ipcop/DataAccess.pl';

$| = 1;    # line buffering

%FW::fwSettings;
%FW::defaultNetworks;
%FW::interfaces = ();
my %ifaceCounts = ();

$ifaceCounts{'GREEN'}  = 0;
$ifaceCounts{'BLUE'}   = 0;
$ifaceCounts{'ORANGE'} = 0;
$ifaceCounts{'RED'}    = 0;

&DATA::setup_default_interfaces(\%FW::interfaces, \%ifaceCounts);

$FW::settingsfile     = '/var/ipcop/firewall/settings';
$FW::settingsCGI      = '/cgi-bin/fwrulesadm.cgi';
$FW::configCGI        = '/cgi-bin/fwrules.cgi';
$FW::advConfCGI       = '/cgi-bin/fwadvconf.cgi';
$FW::timeframeLogfile = '/var/log/fw_timeframe_log';

sub readValidSettings
{
    &General::readhash($FW::settingsfile, \%FW::fwSettings);

    my $haveAdminNetwork = 0;
    foreach my $iface (sort keys %FW::interfaces) {
        next if ($FW::interfaces{$iface}{'COLOR'} eq 'RED_COLOR');

        my $key = 'ADMIN_' . $FW::interfaces{$iface}{'ID'};
        if (defined($FW::fwSettings{$key}) && $FW::fwSettings{$key} eq 'on') {
            $haveAdminNetwork++;
        }
        else {
            $FW::fwSettings{$key} = 'off';
        }
    }
    if ($haveAdminNetwork == 0) {

        # hardcode GREEN_1 in case there was nothing selected yet
        # FIXME:
        # As soon as it is possible to install IPCop without GREEN
        # this needs to be fixed.
        $FW::fwSettings{'ADMIN_GREEN_1'} = 'on';
    }

    if ($FW::fwSettings{'USE_ADMIN_MAC'} eq 'on' && (!&General::validmac($FW::fwSettings{'ADMIN_MAC'}))) {
        $FW::fwSettings{'USE_ADMIN_MAC'} = 'off';
    }

    if ($FW::fwSettings{'ADV_MODE_ENABLE'} ne 'on' && $FW::fwSettings{'ADV_MODE_ENABLE'} ne 'off') {
        $FW::fwSettings{'ADV_MODE_ENABLE'} = 'off';
    }
    return 0;
}

sub haveRedNet
{
    if ($ifaceCounts{'RED'} > 0) {
        return 1;
    }
    else {
        return 0;
    }
}

sub haveOrangeNet
{
    if ($ifaceCounts{'ORANGE'} > 0) {
        return 1;
    }
    else {
        return 0;
    }
}

sub haveBlueNet
{
    if ($ifaceCounts{'BLUE'} > 0) {
        return 1;
    }
    else {
        return 0;
    }
}

sub haveGreenNet
{
    if ($ifaceCounts{'GREEN'} > 0) {
        return 1;
    }
    else {
        return 0;
    }
}

sub haveIPsecNet
{
    if ($ifaceCounts{'IPSEC'} > 0) {
        return 1;
    }
    else {
        return 0;
    }
}

sub haveOpenVPNNet
{
    if ($ifaceCounts{'OPENVPN'} > 0) {
        return 1;
    }
    else {
        return 0;
    }
}

sub haveInternalNet
{
    my %customIfaces = ();
    my %customifacesCount = &DATA::readCustIfaces(\%customIfaces);

    if (&haveBlueNet() || &haveOrangeNet() || &haveIPsecNet() || &haveOpenVPNNet() || $customifacesCount{'NUM_INTERNAL'} > 0) {
        return 1;
    }
    else {
        return 0;
    }
}

sub cleanService
{
    my $service = $_[0];

    # remove unwanted characters
    $service =~ s/ /<BLANK>/g;
    $service =~ s/\s//g;
    $service =~ s/<BLANK>/ /g;

    return $service;
}

sub changeUsedCountInRule
{
    my $rule          = shift;
    my $action        = shift;    #'remove' or 'add'
    my $custSrcNet    = '';
    my $custSrcAdr    = '';
    my $customService_pfw = '';
    my $custDestNet   = '';
    my $custDestIP    = '';
    my $customService = '';
    my $serviceGroup  = '';
    my $srcAdrGroup   = '';
    my $destAdrGroup  = '';

    if ($rule->{'SRC_NET_TYPE'} eq 'custSrcNet') {
        $custSrcNet = $rule->{'SRC_NET'};
    }
    if ($rule->{'SRC_ADR_TYPE'} eq 'custSrcAdr') {
        $custSrcAdr = $rule->{'SRC_ADR'};
    }

    if ($rule->{'PORTFW_SERVICE_TYPE'} eq 'custom') {
        $customService_pfw = $rule->{'PORTFW_SERVICE'};
    }

    if ($rule->{'DST_NET_TYPE'} eq 'custDestNet') {
        $custDestNet = $rule->{'DST_NET'};
    }
    if ($rule->{'DST_IP_TYPE'} eq 'custDestIP') {
        $custDestIP = $rule->{'DST_IP'};
    }
    if ($rule->{'SERVICE_TYPE'} eq 'custom') {
        $customService = $rule->{'SERVICE'};
    }
    if ($rule->{'SERVICE_TYPE'} eq 'serviceGroup') {
        $serviceGroup = $rule->{'SERVICE'};
    }

    if ($rule->{'SRC_ADR_TYPE'} eq 'groupSrcAdr') {
        $srcAdrGroup = $rule->{'SRC_ADR'};
    }
    if ($rule->{'DST_IP_TYPE'} eq 'groupDestIP') {
        $destAdrGroup = $rule->{'DST_IP'};
    }

    if ($custSrcNet || $custDestNet) {
        &FW::changeUsedCountIface($custSrcNet, $custDestNet, $action);
    }
    if ($custSrcAdr || $custDestIP) {
        &FW::changeUsedCountAdr($custSrcAdr, $custDestIP, $action);
    }
    if ($srcAdrGroup || $destAdrGroup) {
        &FW::changeUsedCountAddressGroup($srcAdrGroup, $destAdrGroup, $action);
    }
    if ($customService) {
        &FW::changeUsedCountService($customService, $action);
    }
    if ($customService_pfw) {
        &FW::changeUsedCountService($customService_pfw, $action);
    }
    if ($serviceGroup) {
        &FW::changeUsedCountServiceGroup($serviceGroup, $action);
    }
}

sub changeUsedCountIface
{
    my $p_custSrcIFace  = shift;
    my $p_custDestIFace = shift;
    my $p_action        = shift;

    my %custIfaces = ();
    &DATA::readCustIfaces(\%custIfaces);

    if ($p_action eq 'add') {
        if (defined $custIfaces{$p_custSrcIFace}) {
            $custIfaces{$p_custSrcIFace}{'USED_COUNT'}++;
        }
        if (defined $custIfaces{$p_custDestIFace}) {
            $custIfaces{$p_custDestIFace}{'USED_COUNT'}++;
        }
    }
    else {
        if (defined $custIfaces{$p_custSrcIFace}) {
            $custIfaces{$p_custSrcIFace}{'USED_COUNT'}--;
        }
        if (defined $custIfaces{$p_custDestIFace}) {
            $custIfaces{$p_custDestIFace}{'USED_COUNT'}--;
        }
    }

    if (defined $custIfaces{$p_custSrcIFace}) {
        $custIfaces{$p_custSrcIFace}{'USED_COUNT'} = 0 if ($custIfaces{$p_custSrcIFace}{'USED_COUNT'} < 0);
    }
    if (defined $custIfaces{$p_custDestIFace}) {
        $custIfaces{$p_custDestIFace}{'USED_COUNT'} = 0 if ($custIfaces{$p_custDestIFace}{'USED_COUNT'} < 0);
    }

    &DATA::saveCustIfaces(\%custIfaces);
}

sub changeUsedCountAdr
{
    my $p_custSrcAdr  = shift;
    my $p_custDestAdr = shift;
    my $p_action      = shift;

    my %custAddresses = ();
    &DATA::readCustAddresses(\%custAddresses);

    if ($p_action eq 'add') {
        if (defined $custAddresses{$p_custSrcAdr}) {
            $custAddresses{$p_custSrcAdr}{'USED_COUNT'}++;
        }
        if (defined $custAddresses{$p_custDestAdr}) {
            $custAddresses{$p_custDestAdr}{'USED_COUNT'}++;
        }
    }
    else {
        if (defined $custAddresses{$p_custSrcAdr}) {
            $custAddresses{$p_custSrcAdr}{'USED_COUNT'}--;
        }
        if (defined $custAddresses{$p_custDestAdr}) {
            $custAddresses{$p_custDestAdr}{'USED_COUNT'}--;
        }
    }
    if (defined $custAddresses{$p_custSrcAdr}) {
        $custAddresses{$p_custSrcAdr}{'USED_COUNT'} = 0 if ($custAddresses{$p_custSrcAdr}{'USED_COUNT'} < 0);
    }
    if (defined $custAddresses{$p_custDestAdr}) {
        $custAddresses{$p_custDestAdr}{'USED_COUNT'} = 0 if ($custAddresses{$p_custDestAdr}{'USED_COUNT'} < 0);
    }

    &DATA::saveCustAddresses(\%custAddresses);
}

sub changeUsedCountService
{
    my $p_custom = shift;
    my $p_action = shift;

    my %custServices = ();
    &DATA::readCustServices(\%custServices);

    if ($p_action eq 'add') {
        if (defined $custServices{$p_custom}) {
            $custServices{$p_custom}{'USED_COUNT'}++;
        }
    }
    else {
        if (defined $custServices{$p_custom}) {
            $custServices{$p_custom}{'USED_COUNT'}--;
        }
    }
    $custServices{$p_custom}{'USED_COUNT'} = 0 if ($custServices{$p_custom}{'USED_COUNT'} < 0);

    &DATA::saveCustServices(\%custServices);
}

sub changeUsedCountServiceGroup
{
    my $p_group  = shift;
    my $p_action = shift;
    my %groupConf;
    &DATA::readServiceGroupConf(\%groupConf);

    if (defined($groupConf{$p_group})) {
        if ($p_action eq 'add') {
            $groupConf{$p_group}{'USED_COUNT'}++;
        }
        else {
            $groupConf{$p_group}{'USED_COUNT'}--;
        }
        $groupConf{$p_group}{'USED_COUNT'} = 0 if ($groupConf{$p_group}{'USED_COUNT'} < 0);

        &DATA::saveServiceGroupConf(\%groupConf);
    }
}

sub changeUsedCountAddressGroup
{
    my $p_srcAdrGroup  = shift;
    my $p_destAdrGroup = shift;
    my $p_action       = shift;

    my %groupConf = ();
    &DATA::readAddressGroupConf(\%groupConf);

    if ($p_action eq 'add') {
        if (defined $groupConf{$p_srcAdrGroup}) {
            $groupConf{$p_srcAdrGroup}{'USED_COUNT'}++;
        }
        if (defined $groupConf{$p_destAdrGroup}) {
            $groupConf{$p_destAdrGroup}{'USED_COUNT'}++;
        }
    }
    else {
        if (defined $groupConf{$p_srcAdrGroup}) {
            $groupConf{$p_srcAdrGroup}{'USED_COUNT'}--;
        }
        if (defined $groupConf{$p_destAdrGroup}) {
            $groupConf{$p_destAdrGroup}{'USED_COUNT'}--;
        }
    }
    if (defined $groupConf{$p_srcAdrGroup}) {
        $groupConf{$p_srcAdrGroup}{'USED_COUNT'} = 0 if ($groupConf{$p_srcAdrGroup}{'USED_COUNT'} < 0);
    }
    if (defined $groupConf{$p_destAdrGroup}) {
        $groupConf{$p_destAdrGroup}{'USED_COUNT'} = 0 if ($groupConf{$p_destAdrGroup}{'USED_COUNT'} < 0);
    }

    &DATA::saveAddressGroupConf(\%groupConf);
}

sub hideAdvRule
{
    my $srcNetType = shift;
    my $dstNetType = shift;
    my $ruleType = shift;

    if($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on') {
        # Advanced Mode is enabled, don't hide anything
        return 0;
    }
    if($srcNetType ne 'defaultSrcNet'
        || ($dstNetType ne 'defaultDestNet' && $ruleType =~ /^(OUTGOING|PORTFW|PINHOLES)$/)) {
        # Rules with custom interfaces are only in adv. mode
        return 1;
    }
    if($ruleType =~ /^(EXTERNAL|PORTFW|PINHOLES)$/) {
        # Always create 'External IPcop Access', 'Port forwarding' and 'Internal Traffic' ('Pinholes' like Orange -> Green)
        return 0;
    }

    # If we are here the rule is an IPCop Access rule with Orange -> IPCop. Those rules are only created in adv. mode
    return 1;
}
# EOF
