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
# (c) 2018-2019, the Openfirewall Team
#

use strict;

# enable only the following on debugging purpose
use warnings;
no warnings 'once';

use Fcntl qw(:flock);
require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';
require '/usr/lib/ofw/protocols.pl';

# Debug level:
#	0 - create rules, no print
#	1 - create rules, print
#	2 - only print rules
my $debugLevel = 0;

#&General::log("puzzleFwRules: Renew rules");
# Debug

my @preparedRules = ();

# Init these settings, so we do not get a warning when settings are bad
$FW::fwSettings{'ADV_MODE_ENABLE'} = 'off';
$FW::fwSettings{'DEFAULT_LOG'}     = 'off';
$FW::fwSettings{'DEFAULT_LOGBC'}   = 'off';
$FW::fwSettings{'CON_STATE'}       = 'off';

&FW::readValidSettings();

my (%custIfaces, %custAddresses, %defaultNetworks, %groupAddresses, %custServices, %defaultServices);
my ($second, $minute, $hour, $day, $month, $year, $wday) = localtime(time);

# weekday starts on sunday with 0

my @allRuleTypes = ("INPUT", "OUTGOING", "EXTERNAL", "PINHOLES", "PORTFW");

my @runRuleTypes          = ();
my $doUpdateOfwRules    = 0;
my $doUpdateWirelessRules = 0;

# init timeframe settings
my %timeframeSettings = ();
foreach my $type (@allRuleTypes) {
    $timeframeSettings{$type . '_HAS_TIMEFRAME_RULES'} = 'no';
    $timeframeSettings{$type . '_NEXT_SWITCH_HOUR'}    = '99';
    $timeframeSettings{$type . '_NEXT_SWITCH_MINUTE'}  = '99';
}

&General::readhash($FW::timeframeLogfile, \%timeframeSettings) if (-e $FW::timeframeLogfile);


if ($#ARGV == -1) {
    # call without arguments (maybe testing on commandline), run all types
    @runRuleTypes = @allRuleTypes;
}

while (@ARGV) {
my $argument = shift;

if ($argument eq '-c') {
    # Check if the iptables rules need an update because of timeframe settings
    foreach my $type (@allRuleTypes) {
        print "Should we re-create the $type rules?\n" if ($debugLevel > 0);
        my $noUpdate = 0;

        # if there are no timeframe rules we don't need an update
        $noUpdate = 1 if ($timeframeSettings{$type . '_HAS_TIMEFRAME_RULES'} eq 'no');

        # if the switch hour is in future we don't need an update
        $noUpdate = 1 if ($timeframeSettings{$type . '_NEXT_SWITCH_HOUR'} > $hour);

        # if the switch hour this hour but the switch minute is in future we don't need an update
        $noUpdate = 1
            if ($timeframeSettings{$type . '_NEXT_SWITCH_HOUR'} == $hour
            && $timeframeSettings{$type . '_NEXT_SWITCH_MINUTE'} > $minute);

        # at midnight we always re-create the rules
        if ($hour == 0 && $minute >= 0 && $minute < 5 && $timeframeSettings{$type . '_HAS_TIMEFRAME_RULES'} eq 'yes') {
            $noUpdate = 0;
        }

        if ($noUpdate) {
            if ($debugLevel > 0) {
                print "The $type rules need _no_ update\n";

                # disable logging, it is filling the logs to much
                #&General::log("puzzleFwRules: $type rules need no update");
            }
        }
        else {
            push(@runRuleTypes, $type);
            if ($debugLevel > 0) {
                print "The $type rules need an update\n";
                &General::log("puzzleFwRules: the $type rules need update");
            }
        }
    }
}
elsif (($argument eq '-f') && ($#ARGV >= 0)) {

    # force update of one rule type
    my $type = shift;

    push(@runRuleTypes, grep(/^$type$/, @allRuleTypes));

    if ($debugLevel > 0) {
        print "Force update of '$type' rules\n";
        &General::log("puzzleFwRules: force update of '$type' rules");
    }
}
elsif ($argument eq '-a') {

    # force update of all (user & Openfirewall services) rules
    @runRuleTypes          = @allRuleTypes;
    $doUpdateOfwRules    = 1;
    $doUpdateWirelessRules = 1;

    if ($debugLevel > 0) {
        print "Force update of all (and I mean ALL) rules\n";
        &General::log("puzzleFwRules: force update of all rules");
    }
}
elsif ($argument eq '-u') {

    # force update of user rules
    @runRuleTypes = @allRuleTypes;

    if ($debugLevel > 0) {
        print "Force update of user rules\n";
        &General::log("puzzleFwRules: force update of user rules");
    }
}
elsif ($argument eq '-i') {

    $doUpdateOfwRules = 1;

    if ($debugLevel > 0) {
        print "Force update of services rules\n";
        &General::log("puzzleFwRules: force update of services rules");
    }
}
elsif ($argument eq '-w') {

    $doUpdateWirelessRules = 1;

    if ($debugLevel > 0) {
        print "Force update of Addressfilter rules\n";
        &General::log("puzzleFwRules: force update of Addressfilter rules");
    }
}
elsif ($argument eq '-d') {
    $debugLevel++;
}
else {

    # If we are here, a parameter was given to us that we do not know about.

    # TODO: error handling ?
    # rm -rf /
    # something else ?
}
} # while (@ARGV)


print "\n--> count: $#runRuleTypes \n\n" if ($debugLevel > 0);
if ($#runRuleTypes < 0 && $doUpdateOfwRules == 0 && $doUpdateWirelessRules == 0) {
    if ($debugLevel > 0) {
        print
"Exit from $0 because there is nothing to do. No Openfirewall rules and no timeframe rules to update\nHour: $hour\nMinute: $minute\n";
    }
    exit 0;
}

# reset switchtime for those types are really run now
foreach my $type (@runRuleTypes) {
    $timeframeSettings{$type . '_HAS_TIMEFRAME_RULES'} = 'no';
    $timeframeSettings{$type . '_NEXT_SWITCH_HOUR'}    = '99';
    $timeframeSettings{$type . '_NEXT_SWITCH_MINUTE'}  = '99';
}

# First clean up (for new rules if enabled or old rules if disabled now)
foreach my $type (@runRuleTypes) {

    #flush chain
    &prepareRuleDirect("-F FW_INPUT")   if ($type eq "INPUT");
    &prepareRuleDirect("-F FW_OUTGOING") if ($type eq "OUTGOING");

    # flush External Access rules
    &prepareRuleDirect("-F FW_XTACCESS") if ($type eq "EXTERNAL");
    &prepareRuleDirect("-F FW_PINHOLES") if ($type eq "PINHOLES");
    if($type eq "PORTFW") {
         &prepareRuleDirect("-t nat -F PORTFW");
         &prepareRuleDirect("-t nat -F PORTFWNAT");
         &prepareRuleDirect("-t mangle -F PORTFWMANGLE");
         &prepareRuleDirect("-F PORTFWACCESS");
    }
}

my %ruleConfig = ();
&DATA::readRuleConfig(\%ruleConfig);

# my %custIfaces;
&DATA::readCustIfaces(\%custIfaces);

# my %custAddresses;
&DATA::readCustAddresses(\%custAddresses);

# my %defaultNetworks = ();
&DATA::setup_default_networks(\%defaultNetworks);

# my %groupAddresses
&DATA::readAddressGroupConf(\%groupAddresses);

# my %custServices;
&DATA::readCustServices(\%custServices);

# my %defaultServices;
&DATA::readDefaultServices(\%defaultServices);
&DATA::readOfwServices(\%defaultServices);

my %groupServices;
&DATA::readServiceGroupConf(\%groupServices);

# Retrieve IPsec settings
my %ipsecSettings = ();
if (-e "/var/ofw/ipsec/settings") {
    &General::readhash("/var/ofw/ipsec/settings", \%ipsecSettings);
}
# Retrieve OpenVPN settings
my %ovpnSettings = ();
if (-e "/var/ofw/openvpn/settings") {
    &General::readhash("/var/ofw/openvpn/settings", \%ovpnSettings);
}
# Avoid some "Use of initialized value in string eq at line xxx" messages
$ipsecSettings{'ENABLED_RED_1'} = 'off' if (!exists($ipsecSettings{'ENABLED_RED_1'}));
$ipsecSettings{'ENABLED_BLUE_1'} = 'off' if (!exists($ipsecSettings{'ENABLED_BLUE_1'}));
$ovpnSettings{'ENABLED_RED_1'} = 'off' if (!exists($ovpnSettings{'ENABLED_RED_1'}));
$ovpnSettings{'ENABLED_BLUE_1'} = 'off' if (!exists($ovpnSettings{'ENABLED_BLUE_1'}));

foreach my $type (@runRuleTypes) {
    if($type eq "PORTFW") {
        # create POSTROUTING rules to be able to hit a portforward from inside local network

        foreach my $inIface (keys %defaultNetworks) {
            next if (!defined($defaultNetworks{$inIface}{'PFWMARK'}));

            my $rulebody;
            $rulebody = " -t nat -A PORTFWNAT -m mark --mark $defaultNetworks{$inIface}{'PFWMARK'}";
            $rulebody .= " -j SNAT --to-source $defaultNetworks{$defaultNetworks{$inIface}{'N2A'}}{'ADR'}";
            &prepareRule("$rulebody");
         }    # foreach my (keys %defaultNetworks)
    }

    foreach my $rule (@{$ruleConfig{$type}}) {
        # Enabled ?
        next if ($rule->{'ENABLED'} ne 'on');

        # Advanced Mode ?
        next if ($rule->{'RULEMODE'} eq 'adv' && &FW::hideAdvRule($rule->{'SRC_NET_TYPE'}, $rule->{'DST_NET_TYPE'}, $type));

         # are we in timeframe?
        if ($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on' && $rule->{'TIMEFRAME_ENABLED'} eq 'on') {
            $timeframeSettings{$type . '_HAS_TIMEFRAME_RULES'} = 'yes';

            if ($debugLevel > 0) {
                my $curDay = $day;
                print
"$rule->{'DAY_TYPE'} - $wday - activ: $rule->{$DATA::weekDays[$wday]} | $rule->{'START_DAY_MONTH'}. - Day: $curDay. - $rule->{'END_DAY_MONTH'}. | ";
                print
"$rule->{'START_HOUR'}:$rule->{'START_MINUTE'} - time: $hour:$minute - $rule->{'END_HOUR'}:$rule->{'END_MINUTE'} \n";
            }

            if ($rule->{'DAY_TYPE'} eq 'weekDays') {

                # check if the rule is enabled for the current day of the week
                next if ($rule->{$DATA::weekDays[$wday]} ne 'on');
            }
            else {
                my $curDay = $day;
                if ($rule->{'START_DAY_MONTH'} < $rule->{'END_DAY_MONTH'}) {

                    # e.g. start: 12, end: 25
                    next unless ($rule->{'START_DAY_MONTH'} <= $curDay && $curDay <= $rule->{'END_DAY_MONTH'});

                    #					print "day >< \n";
                }
                elsif ($rule->{'START_DAY_MONTH'} > $rule->{'END_DAY_MONTH'}) {

                    # e.g. start: 17, end: 12
                    next unless ($curDay <= $rule->{'END_DAY_MONTH'} || $rule->{'START_DAY_MONTH'} <= $curDay);

                    #					print "day <> \n";
                }
                else {    # $rule->{'START_DAY_MONTH'} == $rule->{'END_DAY_MONTH'}
                          # e.g. start: 20, end: 20
                    next unless ($curDay == $rule->{'START_DAY_MONTH'});

                    #					print "day == \n";
                }
            }
            print "^^pass day \n" if ($debugLevel > 0);

            my $goNext = 0;
            $goNext = 1
                unless (
                &inDayTime($rule->{'START_HOUR'}, $rule->{'END_HOUR'}, $rule->{'START_MINUTE'}, $rule->{'END_MINUTE'}));

            # update timeframe settings if necessary
            my $update       = 0;
            my $switchHour   = $timeframeSettings{$type . '_NEXT_SWITCH_HOUR'};
            my $switchMinute = $timeframeSettings{$type . '_NEXT_SWITCH_MINUTE'};

            # search nearest time in the future
            if ($hour < $rule->{'START_HOUR'}) {

                # current hour is before Start Hour

                # check if the Start Hour is before the previous calculated Switch Hour
                if ($rule->{'START_HOUR'} < $switchHour) {
                    $update       = 1;
                    $switchHour   = $rule->{'START_HOUR'};
                    $switchMinute = $rule->{'START_MINUTE'};
                }

                # when the previous calculated switch hour is the same, check switch minute
                elsif ($rule->{'START_HOUR'} == $switchHour
                    && $rule->{'START_MINUTE'} < $switchMinute)
                {
                    $update       = 1;
                    $switchHour   = $rule->{'START_HOUR'};
                    $switchMinute = $rule->{'START_MINUTE'};
                }
            }
            elsif ($hour == $rule->{'START_HOUR'}) {

                # current hour is the same as Start Hour

                if ($minute < $rule->{'START_MINUTE'}) {

                    # when switchHour is in future
                    if ($rule->{'START_HOUR'} < $switchHour)
                    {
                        $update       = 1;
                        $switchHour   = $rule->{'START_HOUR'};
                        $switchMinute = $rule->{'START_MINUTE'};
                    }

                    # start minute is in future but nearer then switch minute
                    if ($rule->{'START_MINUTE'} < $switchMinute)
                    {
                        $update       = 1;
                        $switchHour   = $rule->{'START_HOUR'};
                        $switchMinute = $rule->{'START_MINUTE'};
                    }
                }
            }

            if ($hour < $rule->{'END_HOUR'}) {

                # current hour is before End Hour

                # check if the End Hour is before the previous calculated Switch Hour
                if ($rule->{'END_HOUR'} < $switchHour) {
                    $update       = 1;
                    $switchHour   = $rule->{'END_HOUR'};
                    $switchMinute = $rule->{'END_MINUTE'};
                }

                # when the previous calculated switch hour is the same, check switch minute
                elsif ($rule->{'END_HOUR'} == $switchHour
                    && $rule->{'END_MINUTE'} < $switchMinute)
                {
                    $update       = 1;
                    $switchHour   = $rule->{'END_HOUR'};
                    $switchMinute = $rule->{'END_MINUTE'};
                }
            }
            elsif ($hour == $rule->{'END_HOUR'}) {

                # current hour is the same as End Hour

                # check if we have an event this hour
                if (  $minute < $rule->{'END_MINUTE'})
                {
                    # when switchHour is in future, and Start Minute
                    # (switchMinute) is less than End Minute...
                    # e.g. from 13:15 to 12:45, at 12:30
                    if($rule->{'END_HOUR'} < $switchHour)
                    {
                        $update       = 1;
                        $switchHour   = $rule->{'END_HOUR'};
                        $switchMinute = $rule->{'END_MINUTE'};
                    }

                    # end minute is in future but nearer than switch minute
                    if ($rule->{'END_MINUTE'} < $switchMinute)
                    {
                        $update       = 1;
                        $switchHour   = $rule->{'END_HOUR'};
                        $switchMinute = $rule->{'END_MINUTE'};
                    }
                }
            }

            if ($update) {
                $timeframeSettings{$type . '_NEXT_SWITCH_HOUR'}   = $switchHour;
                $timeframeSettings{$type . '_NEXT_SWITCH_MINUTE'} = $switchMinute;
            }
            if ($debugLevel > 0) {
                print $type. "_NEXT_SWITCH_HOUR  : $timeframeSettings{$type.'_NEXT_SWITCH_HOUR'}\n";
                print $type. "_NEXT_SWITCH_MINUTE: $timeframeSettings{$type.'_NEXT_SWITCH_MINUTE'}\n";
            }

            if ($goNext) {
                print " but don't pass time, rule is currently _NOT_ active\n" if ($debugLevel > 0);
                next;
            }
            print " and pass time, rule is currently active\n" if ($debugLevel > 0);
        }    # are we in timeframe? END

        my $inDev        = '';
        my $srcInterface = '';
        my @outDev       = ();
        my @srcAdres     = ();
        my @destAdres    = ();
        my $srcPort      = '';
        my @services     = ();

        my $extPfwAdr = '';
        my @extPfwServices     = ();

        my $logPrefix    = '';
        my $ruleAction   = '';
        my $limit        = '';
        my $limit_log    = '';
        my $limit_action = '';
        my $chain        = '';
        my $rulebody     = '';

        # incoming interface
        if ($rule->{'SRC_NET_TYPE'} eq 'defaultSrcNet') {
            if (defined($FW::interfaces{$rule->{'SRC_NET'}})
                && $FW::interfaces{$rule->{'SRC_NET'}}{'ACTIV'} eq 'yes')
            {
                $inDev = $FW::interfaces{$rule->{'SRC_NET'}}{'IFACE'};
            }
            else {

                # currently this interface is not available
                if ($rule->{'SRC_NET'} eq 'Any') {
                    $inDev = '';
                }
                else {
                    next;
                }
            }
            $srcInterface = $rule->{'SRC_NET'};
        }
        else {    # 'custSrcNet'
            if ($custIfaces{$rule->{'SRC_NET'}} eq '') {
                &General::log("ERROR in puzzleFwRules: Custom Interface $rule->{'SRC_NET'} does not exist");
                next;
            }
            $inDev = $custIfaces{$rule->{'SRC_NET'}}{'IFACE'};
        }

        if ($inDev ne '') {
            $inDev = "-i $inDev";
        }

        # we only need outgoing interface in a FORWARD rule
        if ($type eq 'OUTGOING' || $type eq 'PINHOLES' || $type eq 'PORTFW') {

            # outgoing interface
            if ($rule->{'DST_NET_TYPE'} eq 'defaultDestNet') {
                if (defined($FW::interfaces{$rule->{'DST_NET'}})
                    && $FW::interfaces{$rule->{'DST_NET'}}{'ACTIV'} eq 'yes')
                {
                    @outDev = ($FW::interfaces{$rule->{'DST_NET'}}{'IFACE'});
                }
                else {

                    # currently this interface is not available
                    if ($rule->{'DST_NET'} eq 'Any') {
                        @outDev = ('');
                    }
                    else {
                        next;
                    }
                }
            }
            else {    # 'custSrcNet'
                if ($custIfaces{$rule->{'DST_NET'}} eq '') {
                    &General::log("ERROR in puzzleFwRules: Custom Interface $rule->{'DST_NET'} does not exist");
                    next;
                }
                @outDev = ($custIfaces{$rule->{'DST_NET'}}{'IFACE'});
            }
        }
        else {

            # needed for INPUT rules as we loop over the outdevices
            @outDev = ('');
        }

        # source address
        # invert source address?
        my $invSrcAdr = "";
        if ($rule->{'INV_SRC_ADR'} eq 'on') {
            $invSrcAdr = "!";
        }

        if ($rule->{'SRC_ADR_TYPE'} eq 'defaultSrcAdr') {

            # already checked above: next if ($FW::interfaces{'SRC_NET'}{'ACTIV'} ne 'yes');
            @srcAdres = (&buildAddressParams($rule->{'SRC_ADR'}, "default", $invSrcAdr, "source"));
        }
        elsif ($rule->{'SRC_ADR_TYPE'} eq 'textSrcAdrip') {
            @srcAdres = ("$invSrcAdr -s $rule->{'SRC_ADR'}");
        }
        elsif ($rule->{'SRC_ADR_TYPE'} eq 'textSrcAdrmac') {
            @srcAdres = ("-m mac $invSrcAdr --mac-source $rule->{'SRC_ADR'}");
        }
        elsif ($rule->{'SRC_ADR_TYPE'} eq 'custSrcAdr') {
            unless (defined $custAddresses{$rule->{'SRC_ADR'}}{'ADDRESS'}) {
                &General::log("ERROR in puzzleFwRules: Custom Address $rule->{'SRC_ADR'} does not exist");
                next;
            }
            @srcAdres = (&buildAddressParams($rule->{'SRC_ADR'}, "custom", $invSrcAdr, "source"));
        }
        elsif ($rule->{'SRC_ADR_TYPE'} eq 'groupSrcAdr') {
            unless (defined $groupAddresses{$rule->{'SRC_ADR'}}{'ADDRESSES'}) {
                &General::log("ERROR in puzzleFwRules: Address Group $rule->{'SRC_ADR'} does not exist");
                next;
            }
            foreach my $adr (@{$groupAddresses{$rule->{'SRC_ADR'}}{'ADDRESSES'}}) {
                next if ($adr->{'ENABLED'} ne 'on');

                # Achim Weber TODO: maybe this check isn't necessary, not sure at the moment
                next
                    if (defined($FW::interfaces{'Red'})
                    && $FW::interfaces{'Red'}{'ACTIV'} ne 'yes'
                    && $adr->{'ADDRESS_TYP'} eq 'default'
                    && $adr->{'ADDRESS_NAME'} =~ /^Red/);

                @srcAdres = (
                    @srcAdres, &buildAddressParams($adr->{'ADDRESS_NAME'}, $adr->{'ADDRESS_TYP'}, $invSrcAdr, "source")
                );
            }
        }
        else {

            # at least one entry is needed for the later loop
            @srcAdres = (" ");
        }

        # source port, only in advanced mode available
        if (   $rule->{'SRC_PORT'} ne '-'
            && $FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on')
        {

            # invert source port?
            if ($rule->{'INV_SRC_PORT'} eq 'on') {
                $srcPort = "! --sport $rule->{'SRC_PORT'}";
            }
            else {
                $srcPort = "--sport $rule->{'SRC_PORT'}";
            }
        }

        # invert destination address?
        my $invDestAdr = "";
        if ($rule->{'INV_DST_IP'} eq 'on') {
            $invDestAdr = "!";
        }

        my $destAdrType = "destination";
        if($type eq 'PORTFW') {

            # TODO: May check if red interface is active/up

            $destAdrType = "extPfw";

            my @extAdr = (&buildAddressParams($rule->{'PORTFW_EXT_ADR'}, "default", "", "extPfw"));

            #  my $extPfwAdr = '';
            $extPfwAdr = 'N/A';
            if(defined($extAdr[0])) {
                # should always be available if we are here, but better check
                $extPfwAdr = $extAdr[0];
            }
            # when red is down we get 'N/A'
            next if($extPfwAdr =~ /N\/A/);

            # my @extPfwServices = ();
            if ($rule->{'PORTFW_SERVICE_TYPE'} eq 'custom') {
                @extPfwServices = &buildServiceParamsCustom($rule->{'PORTFW_SERVICE'}, $srcPort);
            }
            elsif ($rule->{'PORTFW_SERVICE_TYPE'} eq 'default') {
                @extPfwServices = &buildServiceParamsDefault($rule->{'PORTFW_SERVICE'}, $srcPort);
            }
        }

        # we only need destination addresses in a FORWARD rule
        # and in external access so we do not open alias IPs unexpected
        if ($type eq 'OUTGOING' || $type eq 'PINHOLES' || $type eq 'PORTFW' || $type eq 'EXTERNAL') {

            # destination address
            if ($rule->{'DST_IP_TYPE'} eq 'defaultDstIP') {
                @destAdres = (&buildAddressParams($rule->{'DST_IP'}, "default", $invDestAdr, $destAdrType));
            }
            elsif ($rule->{'DST_IP_TYPE'} eq 'ipDestTxt') {
                my $prefix = '';
                $prefix = '-d' if($destAdrType ne "extPfw");
                @destAdres = ("$invDestAdr $prefix $rule->{'DST_IP'}");
            }
            elsif ($rule->{'DST_IP_TYPE'} eq 'custDestIP') {
                unless (defined $custAddresses{$rule->{'DST_IP'}}{'ADDRESS'}) {
                    &General::log("ERROR in puzzleFwRules: Custom Address $rule->{'DST_IP'} does not exist");
                    next;
                }
                my $custAdr = $custAddresses{$rule->{'DST_IP'}};

                if ($custAdr->{'ADDRESS_TYPE'} ne 'ip') {
                    &General::log("ERROR in puzzleFwRules: Custom Address $rule->{'DST_IP'} - $Lang::tr{'mac adr not as dest'}");
                    next;
                }
                @destAdres = (&buildAddressParams($rule->{'DST_IP'}, "custom", $invDestAdr, $destAdrType));

            }
            elsif ($rule->{'DST_IP_TYPE'} eq 'groupDestIP') {
                unless (defined $groupAddresses{$rule->{'DST_IP'}}{'ADDRESSES'}) {
                    &General::log("ERROR in puzzleFwRules: Address Group $rule->{'DST_IP'} does not exist");
                    next;
                }
                foreach my $adr (@{$groupAddresses{$rule->{'DST_IP'}}{'ADDRESSES'}}) {
                    next if ($adr->{'ENABLED'} ne 'on');

                    # Achim Weber TODO: maybe this check isn't necessary, not sure at the moment
                    next
                        if (defined($FW::interfaces{'Red'})
                        && $FW::interfaces{'Red'}{'ACTIV'} ne 'yes'
                        && $adr->{'ADDRESS_TYP'} eq 'default'
                        && $adr->{'ADDRESS_NAME'} =~ /^Red/);

                    @destAdres = (
                        @destAdres,
                        &buildAddressParams($adr->{'ADDRESS_NAME'}, $adr->{'ADDRESS_TYP'}, $invDestAdr, $destAdrType)
                    );

                }
            }
            else {

                # at least one entry is needed for the later loop
                @destAdres = (" ");
            }
        }
        else {

            # at least one entry is needed for the later loop
            @destAdres = (" ");
        }

        # my @services = ();
        if ($rule->{'SERVICE_TYPE'} eq 'custom') {
            @services = &buildServiceParamsCustom($rule->{'SERVICE'}, $srcPort);
        }
        elsif ($rule->{'SERVICE_TYPE'} eq 'default') {
            @services = &buildServiceParamsDefault($rule->{'SERVICE'}, $srcPort);
        }
        elsif ($rule->{'SERVICE_TYPE'} eq 'serviceGroup') {
            my $group = $rule->{'SERVICE'};

            foreach my $service (@{$groupServices{$group}{'SERVICES'}}) {
                if ($service->{'ENABLED'} eq 'on') {
                    my @tmpServices = ();

                    if ($service->{'SERVICE_TYP'} eq 'default') {
                        @tmpServices = &buildServiceParamsDefault($service->{'SERVICE_NAME'}, $srcPort);
                    }
                    else {
                        @tmpServices = &buildServiceParamsCustom($service->{'SERVICE_NAME'}, $srcPort);
                    }
                    @services = (@services, @tmpServices);
                }
            }
        }
        else {

            # there is no service enabled, but we need at least one (empty) sting
            # in the array because of the later loop over the service array
            if ($srcPort ne '') {
                @services = ("-p tcp $srcPort", "-p udp $srcPort");
            }
            else {
                @services = (" ");
            }
        }

        # my $limit = '';
        if ($rule->{'LIMIT_TYPE'} eq 'average') {
            $limit = "-m limit --limit $rule->{'MATCH_LIMIT'}";
        }
        else {    # 'burst'
            $limit = "-m limit --limit-burst $rule->{'MATCH_LIMIT'}";
        }

        # my $logPrefix = '';
        # my $ruleAction = '';
        if ($rule->{'RULEACTION'} eq 'accept') {
            $ruleAction = 'ACCEPT';
        }
        elsif ($rule->{'RULEACTION'} eq 'drop') {
            $ruleAction = 'DROP';
        }
        elsif ($rule->{'RULEACTION'} eq 'reject') {
            $ruleAction = 'REJECT';
        }
        elsif ($rule->{'RULEACTION'} eq 'externalAccess') {
            $ruleAction = 'ACCEPT';
        }
        elsif ($rule->{'RULEACTION'} eq 'dmzPinholes') {
            $ruleAction = 'ACCEPT';
        }
        else {    # 'logOnly'
            $ruleAction = 'LOG';
        }

        $logPrefix  = "-j LOG --log-prefix \"\U$rule->{'SRC_NET'}\E $ruleAction \"";
        $ruleAction = "-j $ruleAction";

        # my $chain = '';
        if ($type eq 'INPUT') {
            $chain = "-A FW_INPUT";
        }
        elsif ($type eq 'EXTERNAL') {
            $chain = "-A FW_XTACCESS";
        }
        elsif ($type eq 'PINHOLES') {
            $chain = "-A FW_PINHOLES";
        }
        elsif ($type eq 'PORTFW') {
            $chain = "-A PORTFWACCESS";
        }
        else {    # 'OUTGOING'
            $chain = "-A FW_OUTGOING";
        }

        # my $limit_log = '';
        # my $limit_action = '';
        if ($rule->{'LIMIT_FOR'} eq 'log') {
            $limit_log = $limit;
        }
        elsif ($rule->{'LIMIT_FOR'} eq 'acceptOrDeny') {
            $limit_action = $limit;
        }
        elsif ($rule->{'LIMIT_FOR'} eq 'both') {
            $limit_log    = $limit;
            $limit_action = $limit;
        }

        if($type eq 'PORTFW') {

#######################################################
#~  Some rules created from "old" portforwarding /setportfw
#~      Config:
#~         Green:                192.168.2.190
#~         Blue:                   192.168.3.190
#~         Orange:             192.168.4.190

#~
#~         src IP:                 2.2.2.2
#~         Openfirewall ext IP:     192.168.11.190 (DEFAULT/Red Address)
#~         ext Port:             123 (tcp)
#~         internal IP:        1.1.1.1
#~         internal port:     456 (tcp)
#~
#~ /sbin/iptables -t nat -A PORTFW -p tcp -d 192.168.11.190 --dport 123 -j DNAT --to 1.1.1.1:456
#~ /sbin/iptables -t mangle -A PORTFWMANGLE -p tcp -s 192.168.2.190/255.255.255.0 -d 192.168.11.190 --dport 123 -j MARK --set-mark 1
#~ /sbin/iptables -t mangle -A PORTFWMANGLE -p tcp -s 192.168.3.190/255.255.255.0 -d 192.168.11.190 --dport 123 -j MARK --set-mark 21
#~ /sbin/iptables -t mangle -A PORTFWMANGLE -p tcp -s 192.168.4.190/255.255.255.0 -d 192.168.11.190 --dport 123 -j MARK --set-mark 31
#~ /sbin/iptables -A PORTFWACCESS -i eth1 -p tcp -s 2.2.2.2 -d 1.1.1.1 --dport 456 -j ACCEPT

#~         Openfirewall ext IP:     192.168.11.190 (DEFAULT/Red Address)
#~         ext Port:             123 (tcp)
#~         internal IP:        1.1.1.1
#~         internal port:     456 (tcp)
#~
#~ /sbin/iptables -t nat -A PORTFW -p tcp -d 192.168.11.190 --dport 123 -j DNAT --to 1.1.1.1:456
#~ /sbin/iptables -t mangle -A PORTFWMANGLE -p tcp -s 192.168.2.190/255.255.255.0 -d 192.168.11.190 --dport 123 -j MARK --set-mark 1
#~ /sbin/iptables -t mangle -A PORTFWMANGLE -p tcp -s 192.168.3.190/255.255.255.0 -d 192.168.11.190 --dport 123 -j MARK --set-mark 21
#~ /sbin/iptables -t mangle -A PORTFWMANGLE -p tcp -s 192.168.4.190/255.255.255.0 -d 192.168.11.190 --dport 123 -j MARK --set-mark 31
#~ /sbin/iptables -A PORTFWACCESS -i eth1 -p tcp -s 0.0.0.0/0 -d 1.1.1.1 --dport 456 -j ACCEPT


#~         src IP:                 2.2.2.2 + 3.3.3.3
#~         Openfirewall ext IP:     192.168.11.190 (DEFAULT/Red Address)
#~         ext Port:             123 (tcp)
#~         internal IP:        1.1.1.1
#~         internal port:     456 (tcp)
#~
#~ /sbin/iptables -t nat -A PORTFW -p tcp -d 192.168.11.190 --dport 123 -j DNAT --to 1.1.1.1:456
#~ /sbin/iptables -t mangle -A PORTFWMANGLE -p tcp -s 192.168.2.190/255.255.255.0 -d 192.168.11.190 --dport 123 -j MARK --set-mark 1
#~ /sbin/iptables -t mangle -A PORTFWMANGLE -p tcp -s 192.168.3.190/255.255.255.0 -d 192.168.11.190 --dport 123 -j MARK --set-mark 21
#~ /sbin/iptables -t mangle -A PORTFWMANGLE -p tcp -s 192.168.4.190/255.255.255.0 -d 192.168.11.190 --dport 123 -j MARK --set-mark 31
#~ /sbin/iptables -A PORTFWACCESS -i eth1 -p tcp -s 2.2.2.2 -d 1.1.1.1 --dport 456 -j ACCEPT
#~ /sbin/iptables -A PORTFWACCESS -i eth1 -p tcp -s 3.3.3.3 -d 1.1.1.1 --dport 456 -j ACCEPT


#~         Openfirewall ext IP:     192.168.11.190 (DEFAULT/Red Address)
#~         proto:                   GRE
#~         internal IP:        1.1.1.1
#~
#~ /sbin/iptables -t nat -A PORTFW -p gre -d 192.168.11.190 -j DNAT --to 1.1.1.1
#~ /sbin/iptables -A PORTFWACCESS -i eth1 -p gre -s 0.0.0.0/0 -d 1.1.1.1 -j ACCEPT

            foreach my $tmpOutDev (@outDev) {
                if ($tmpOutDev ne '') {
                    $tmpOutDev = "-o $tmpOutDev";
                }

#~                 print "tmpOutDev: '$tmpOutDev'\n";

                foreach my $tmpDestAdr (@destAdres) {

                    # remove netmask, iptables don't like the netmask in --to <IP>
                    # as the mask ist /32 there is no problem doing this
                    $tmpDestAdr =~ s/\/32//;
                    $tmpDestAdr =~ s/\/255.255.255.255//;

                    foreach my $service (@extPfwServices) {
                         foreach my $tmpSrcAdr (@srcAdres) {
                            # create DNAT rule string
                            $rulebody = " -t nat -A PORTFW $tmpSrcAdr -d $extPfwAdr $service -j DNAT --to $tmpDestAdr";
                            my $destService =  $services[0];
                            my $destPort = '';
                            if($service =~ /-p (tcp|udp)/ && $destService =~ /--dport\s+(\d+:\d+|\d+)/) {
                                $destPort = $1;
                                $destPort =~ s/:/-/;
                                $rulebody .= ":$destPort ";
                            }
                            &prepareRule("$rulebody");
                         }    # foreach my $tmpSrcAdr (@srcAdres)
                    }    # foreach $service (@extPfwServices)

                    foreach my $service (@extPfwServices) {
                        foreach my $inIface (keys %defaultNetworks) {
                            next if (!defined($defaultNetworks{$inIface}{'PFWMARK'}));

                            # create MANGLE MARK rule string
                            $rulebody = " -t mangle -A PORTFWMANGLE -s $defaultNetworks{$inIface}{'IPT'}";
                            $rulebody .= " -d $extPfwAdr $service -j MARK --set-mark $defaultNetworks{$inIface}{'PFWMARK'}";
                            &prepareRule("$rulebody");
                         }    # foreach my (keys %defaultNetworks)
                    }    # foreach $service (@extPfwServices)

                    foreach my $service (@services) {
                        foreach my $tmpSrcAdr (@srcAdres) {

                            # create rule string
                            $rulebody = "$chain $inDev $tmpOutDev $tmpSrcAdr -d $tmpDestAdr $service ";

                            #print "submit rule\n";
                            if ($rule->{'LOG_ENABLED'} eq 'on') {
                                &prepareRule("$rulebody $logPrefix $limit_log");
                            }
                            if ($rule->{'RULEACTION'} ne 'logOnly') {
                                &prepareRule("$rulebody $ruleAction $limit_action");
                            }
                        }    # foreach $tmpSrcAdr (@srcAdres)
                    }    # foreach $service (@services)

                }    # foreach $tmpDestAdr (@destAdres)
            }    # foreach my $tmpOutDev (@outDev)

        }
        else {
            # no special (== no portfw)

            foreach my $tmpOutDev (@outDev) {
                if ($tmpOutDev ne '') {
                    $tmpOutDev = "-o $tmpOutDev";
                }

                foreach my $tmpSrcAdr (@srcAdres) {
                    foreach my $tmpDestAdr (@destAdres) {
                        foreach my $service (@services) {


                            # create rule string
                            $rulebody = "$chain $inDev $tmpOutDev $tmpSrcAdr $tmpDestAdr $service ";

                            #print "submit rule\n";
                            if ($rule->{'LOG_ENABLED'} eq 'on') {
                                &prepareRule("$rulebody $logPrefix $limit_log");
                            }
                            if ($rule->{'RULEACTION'} ne 'logOnly') {
                                &prepareRule("$rulebody $ruleAction $limit_action");
                            }
                        }    # foreach $service (@services)
                    }    # foreach $tmpDestAdr (@destAdres)
                }    # foreach $tmpSrcAdr (@srcAdres)
            }    # foreach my $tmpOutDev (@outDev)

        }
    }    # foreach $line (@Rules)
}

####################################################
#
# create default rules
my $defaultRule   = '';
my %ifacePolicies = ();
&DATA::readReadPolicies(\%FW::interfaces, \%ifacePolicies);

if ($doUpdateOfwRules) {
    ## DEBUG
    print "Setup Openfirewall service rules\n" if ($debugLevel > 0);
    ## DEBUG END
    &prepareRuleDirect("-F FW_ADMIN");
    &prepareRuleDirect("-F FW_OFW");
    &prepareRuleDirect("-F FW_MARK_IPSEC");
    &prepareRuleDirect("-F FW_OFW_FORWARD");
    &prepareRuleDirect("-F FW_LOG");

    # Deny only those traffic which is open in vanila Openfirewall.
    # Other traffic blocked by Openfirewall rules. So it is possible by using related, established connections
    foreach my $inIface (keys %FW::interfaces) {
        ## DEBUG
        print " In: $inIface" if ($debugLevel > 0);
        ## DEBUG END

        unless (defined($ifacePolicies{$inIface})) {
            print ", Policy for interface '$inIface' not defined\n" if ($debugLevel > 0);
            next;
        }
        print ", Policy: $ifacePolicies{$inIface}{'POLICY'}\n" if ($debugLevel > 0);

        # only create rules for this interface if it is activ
        next if ($FW::interfaces{$inIface}{'ACTIV'} ne 'yes');

        # Special treatment for Blue / Addressfilter first
        if ($FW::interfaces{$inIface}{'COLOR'} eq 'BLUE_COLOR') {
            my @serviceXYZ;
            my $protoPort;

            # Allow IPsec if enabled, IPsec access does not need an Addressfilter entry so it much come first
            # but only if we have policy half-open/open
            if ($ipsecSettings{'ENABLED_BLUE_1'} eq 'on') {
                if ($ifacePolicies{$inIface}{'POLICY'} =~ /^half-open|open$/) {
                    @serviceXYZ = &buildServiceParamsDefault('Ofw IPsec', "");
                    foreach $protoPort (@serviceXYZ) {
                        &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} $protoPort -j ACCEPT");
                    }
                }
                # Mark outgoing ipsec-blue traffic with 3, outgoing blue traffic with 4
                &prepareRuleDirect("-A FW_MARK_IPSEC -o $FW::interfaces{$inIface}{'IFACE'} -m policy --dir out --pol ipsec --proto esp -j MARK --set-mark 3");
                &prepareRuleDirect("-A FW_MARK_IPSEC -o $FW::interfaces{$inIface}{'IFACE'} -m policy --dir out --pol none -j MARK --set-mark 4");
           }

            # Allow OpenVPN if enabled on blue, OpenVPN access does not need an Addressfilter entry so it much come first
            # but only if we have policy half-open/open
            if (($ovpnSettings{'ENABLED_BLUE_1'} eq 'on') && ($ifacePolicies{$inIface}{'POLICY'} =~ /^half-open|open$/)) {
                @serviceXYZ = &buildServiceParamsDefault('Ofw OpenVPN', "");
                foreach $protoPort (@serviceXYZ) {
                    &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} $protoPort -j ACCEPT");
                }
            }

            # Open DHCP, even for those not in Addressfilter
            @serviceXYZ = &buildServiceParamsDefault('Ofw dhcp', "");
            foreach $protoPort (@serviceXYZ) {
                &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} $protoPort -j ACCEPT");
            }
            # Add a firewall log filter for DHCP broadcast responses
            &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} -p udp --sport 67 --dport 68 -j DROP");

            if ($ifacePolicies{$inIface}{'ADDRESSFILTER'} eq 'on') {
                $doUpdateWirelessRules = 1;
                &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} -m conntrack --ctstate NEW -j ADRFILTERINPUT");
                &prepareRule("-A FW_OFW_FORWARD -i $FW::interfaces{$inIface}{'IFACE'} -m conntrack --ctstate NEW -j ADRFILTERFORWARD");
            }
        }

        if ($FW::interfaces{$inIface}{'COLOR'} ne "RED_COLOR") {
            # add 'Pinholes' for all policies and all 'our' interfaces except for RED.
            # Policy 'open' also needs Pinholes to be able to define a block or log rule.
            &prepareRule("-A FW_OFW_FORWARD -i $FW::interfaces{$inIface}{'IFACE'} -j FW_PINHOLES");
        }
        else {

            # always allow ping on red, with limited rate
            my @serviceXYZ = &buildServiceParamsDefault('Ping', "");
            foreach my $protoPort (@serviceXYZ) {
                &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} $protoPort -j ACCEPT -m limit --limit 1/second");
                # If we do not drop here, burst pings will be accepted through related established
                &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} $protoPort -j DROP");
            }

            # allow IPsec if enabled
            if ($ipsecSettings{'ENABLED_RED_1'} eq 'on') {
                my @serviceXYZ = &buildServiceParamsDefault('Ofw IPsec', "");
                foreach my $protoPort (@serviceXYZ) {
                    &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} $protoPort -j ACCEPT");
                }
                # Mark outgoing ipsec-red traffic with 1, outgoing red traffic with 2
                &prepareRuleDirect("-A FW_MARK_IPSEC -o $FW::interfaces{$inIface}{'IFACE'} -m policy --dir out --pol ipsec --proto esp -j MARK --set-mark 1");
                &prepareRuleDirect("-A FW_MARK_IPSEC -o $FW::interfaces{$inIface}{'IFACE'} -m policy --dir out --pol none -j MARK --set-mark 2");
            }

            # allow OpenVPN if enabled on red
            if ($ovpnSettings{'ENABLED_RED_1'} eq 'on') {
                my @serviceXYZ = &buildServiceParamsDefault('Ofw OpenVPN', "");
                foreach my $protoPort (@serviceXYZ) {
                    &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} $protoPort -j ACCEPT");
                }
            }
        }


        # open some default openfirewall services for policy 'half-open' and 'open'
        if ($ifacePolicies{$inIface}{'POLICY'} =~ /^half-open|open$/) {

            my @ofwServices = ();
            # Some Openfirewall services for Green
            if ($FW::interfaces{$inIface}{'COLOR'} =~ /^GREEN_COLOR$/) {
                @ofwServices = ('Ofw dhcp', 'Ofw dns', 'Ofw ntp', 'Ofw proxy', 'Ofw http', 'Ofw proxy-int-1', 'Ping');
                # Add a firewall log filter for DHCP broadcast responses
                &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} -p udp --sport 67 --dport 68 -j DROP");
            }
            # Some Openfirewall services for Blue (DHCP, IPsec, OpenVPN are already opened above)
            if ($FW::interfaces{$inIface}{'COLOR'} =~ /^BLUE_COLOR$/) {
                @ofwServices = ('Ofw dns', 'Ofw ntp', 'Ofw proxy', 'Ofw http', 'Ofw proxy-int-1', 'Ping');
            }
            # Some Openfirewall services for IPsec and OpenVPN (no DHCP needed for VPN)
            if ($FW::interfaces{$inIface}{'COLOR'} =~ /^IPSEC_COLOR|OVPN_COLOR$/) {
                @ofwServices = ('Ofw dns', 'Ofw ntp', 'Ofw proxy', 'Ofw http', 'Ofw proxy-int-1', 'Ping');
            }

            foreach my $service (@ofwServices) {
                my @serviceXYZ = &buildServiceParamsDefault($service, "");
                foreach my $protoPort (@serviceXYZ) {
                    &prepareRule("-A FW_OFW -i $FW::interfaces{$inIface}{'IFACE'} $protoPort -j ACCEPT");
                }
            }
        }   # if ($ifacePolicies{$inIface}{'POLICY'} =~ /^half-open|open$/)


        # allow internet/other network for policy 'open'
        if ($ifacePolicies{$inIface}{'POLICY'} eq 'open') {

            # get outgoing interfaces
            my @outDevs = &getOutIfacesByColor($FW::interfaces{$inIface}{'COLOR'}, $inIface);

            # forward
            foreach my $outIface (@outDevs) {
                &prepareRule("-A FW_OFW_FORWARD -i $FW::interfaces{$inIface}{'IFACE'} -o $outIface -j ACCEPT");
            }    # forward END

        }    #  if ($ifacePolicies{$inIface}{'POLICY'} eq 'open') {

        # default Logging (if enabled) + DROP/REJECT rules per interface
        $defaultRule = "-A FW_LOG -i $FW::interfaces{$inIface}{'IFACE'}";
        my $defaultAction = 'DROP';
        $defaultAction = 'REJECT' if ($ifacePolicies{$inIface}{'DEFAULT_ACTION'} eq 'reject');
        if ($ifacePolicies{$inIface}{'DEFAULT_LOG'} eq 'on') {
            if ($ifacePolicies{$inIface}{'DEFAULT_LOGBC'} eq 'on') {
                &prepareRule("$defaultRule -j LOG --log-prefix \"\U$inIface\E $defaultAction \" ");
            }
            else {
                # do not log broadcasts
                &prepareRule("$defaultRule -m pkttype ! --pkt-type broadcast -j LOG --log-prefix \"\U$inIface\E $defaultAction \" ");
            }
        }
        &prepareRule("$defaultRule -j $defaultAction");

    }    # foreach (source) interface END

    # create admin rules
    foreach my $iface (sort keys %FW::interfaces) {
        next if ($FW::interfaces{$iface}{'COLOR'} eq 'RED_COLOR');

        my $key = 'ADMIN_' . $FW::interfaces{$iface}{'ID'};
        if (defined($FW::fwSettings{$key}) && $FW::fwSettings{$key} eq 'on') {
            $defaultRule = "-I FW_ADMIN -i $FW::interfaces{$iface}{'IFACE'} ";
            if (defined($FW::fwSettings{'USE_ADMIN_MAC'}) && $FW::fwSettings{'USE_ADMIN_MAC'} eq 'on') {
                $defaultRule .= "-m mac --mac-source $FW::fwSettings{'ADMIN_MAC'} ";
            }

            # Openfirewall https
            my @ofwHTTPS = &buildServiceParamsDefault('Ofw https', "");
            foreach my $httpsProtoPort (@ofwHTTPS) {
                &prepareRule("$defaultRule $httpsProtoPort -j ACCEPT");
            }

            # Openfirewall ssh
            my @ofwSSH = &buildServiceParamsDefault('Ofw ssh', "");
            foreach my $sshProtoPort (@ofwSSH) {
                &prepareRule("$defaultRule $sshProtoPort -j ACCEPT");
            }

        }
    }

    # add Pinholes for Custom Interfaces
    if ($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on') {
        foreach my $iface (keys %custIfaces) {
            ## DEBUG
            print " Custom: $iface\n" if ($debugLevel > 0);
            ## DEBUG END

            &prepareRule("-A FW_OFW_FORWARD -i $custIfaces{$iface}{'IFACE'} -j FW_PINHOLES");

            my $defaultRule = "-A FW_LOG -i $custIfaces{$iface}{'IFACE'} -j";
            my $defaultAction = 'DROP';
            $defaultAction = 'REJECT' if ($ifacePolicies{$iface}{'DEFAULT_ACTION'} eq 'reject');
            if ($ifacePolicies{$iface}{'DEFAULT_LOG'} eq 'on') {
                &prepareRule("$defaultRule LOG --log-prefix \"\U$iface\E $defaultAction \" ");
            }
            &prepareRule("$defaultRule $defaultAction");
        }
    }

    # default Logging (if enabled) + DROP/REJECT rules for everything to catch everything
    $defaultRule = "-A FW_LOG -j";
    my $defaultAction = 'DROP';
    if ($FW::fwSettings{'DEFAULT_LOG'} eq 'on') {
        &prepareRule("$defaultRule LOG --log-prefix \"$defaultAction \" ");
    }
    &prepareRule("$defaultRule $defaultAction");
}

if ($doUpdateWirelessRules) {
    ## DEBUG
    print "Setup Addressfilter rules\n" if ($debugLevel > 0);
    ## DEBUG END
    &prepareRule("-F ADRFILTERINPUT");
    &prepareRule("-F ADRFILTERFORWARD");

    my %blueAdresses = ();
    &DATA::readBlueAddresses(\%blueAdresses);

    foreach my $inIface (keys %FW::interfaces) {

        next if ($FW::interfaces{$inIface}{'COLOR'} ne "BLUE_COLOR");

        next unless (defined($ifacePolicies{$inIface}));

        # only create rules for this interface if it is activ
        next if ($FW::interfaces{$inIface}{'ACTIV'} ne 'yes');

        # only fill this chain if Addressfilter is active
        next unless ($ifacePolicies{$inIface}{'ADDRESSFILTER'} eq 'on');

        # Addressfilter input and forward
        foreach my $key (keys %blueAdresses) {
            next if ($blueAdresses{$key}{'SOURCE_ADR_IPT'} eq '');

            my $rule = "-A ADRFILTERINPUT $blueAdresses{$key}{'SOURCE_ADR_IPT'} ";
            $rule .= " -i $FW::interfaces{$inIface}{'IFACE'} -j RETURN";
            &prepareRule($rule);

            $rule = "-A ADRFILTERFORWARD $blueAdresses{$key}{'SOURCE_ADR_IPT'} ";
            $rule .= " -i $FW::interfaces{$inIface}{'IFACE'} -j RETURN";
            &prepareRule($rule);
        }

        # Drop/Reject anything that did not match Addressfilter
        &prepareRule("-A ADRFILTERINPUT -i $FW::interfaces{$inIface}{'IFACE'} -j FW_LOG");
        &prepareRule("-A ADRFILTERFORWARD -i $FW::interfaces{$inIface}{'IFACE'} -j FW_LOG");
    }
}

# now run all iptables rules we did prepare before
&submitAllRules();

# write timeframe settings
&General::writehash($FW::timeframeLogfile, \%timeframeSettings);

exit 0;

sub prepareRuleDirect
{
    my $rule = shift;
    ## DEBUG
    #print "$rule\n" if ($debugLevel > 0);
    ## DEBUG END

    push(@preparedRules, "/sbin/iptables $rule");
}

sub prepareRule
{
    my $rule = shift;
    ## DEBUG
    #print "$rule\n" if ($debugLevel > 0);
    ## DEBUG END

    # When using NETKEY, we have ipsec-red and ipsec-blue interfaces, replace that with proper policy matching
    # outgoing packets are marked to differentiate between 'normal' and IPsec
    if (defined($FW::interfaces{"IPsec-Red"}) && ($FW::interfaces{"IPsec-Red"}{'ACTIV'} eq 'yes')) {
        $rule =~ s|-o $FW::interfaces{'Red'}{'IFACE'}|-o $FW::interfaces{'Red'}{'IFACE'} -m mark --mark 2|;
        $rule =~ s|-i $FW::interfaces{'Red'}{'IFACE'}|-i $FW::interfaces{'Red'}{'IFACE'} -m policy --dir in --pol none|;
        if (index($rule, 'ipsec-') != -1) {
            $rule =~ s|-o ipsec-red|-o $FW::interfaces{'Red'}{'IFACE'} -m mark --mark 1|;
            $rule =~ s|-i ipsec-red|-i $FW::interfaces{'Red'}{'IFACE'} -m policy --dir in --pol ipsec --proto esp|;
        }
    }
    if (defined($FW::interfaces->{"IPsec-Blue"}) && ($FW::interfaces{"IPsec-Blue"}{'ACTIV'} eq 'yes')) {
        $rule =~ s|-o $FW::interfaces{'Blue'}{'IFACE'}|-o $FW::interfaces{'Blue'}{'IFACE'} -m mark --mark 4|;
        $rule =~ s|-i $FW::interfaces{'Blue'}{'IFACE'}|-i $FW::interfaces{'Blue'}{'IFACE'} -m policy --dir in --pol none|;
        if (index($rule, 'ipsec-') != -1) {
            $rule =~ s|-o ipsec-blue|-o $FW::interfaces{'Blue'}{'IFACE'} -m mark --mark 3|;
            $rule =~ s|-i ipsec-blue|-i $FW::interfaces{'Blue'}{'IFACE'} -m policy --dir in --pol ipsec --proto esp|;
        }
    }

    push(@preparedRules, "/sbin/iptables $rule");
}

sub submitAllRules
{
    my $lockfile;
    unless (open($lockfile, '>', '/var/lock/puzzleFwRules')) {
        &General::log("ERROR in puzzleFwRules: open lockfile failed");
        die("ERROR in puzzleFwRules: open lockfile failed");
    }
    unless (flock($lockfile, LOCK_EX)) {
        &General::log("ERROR in puzzleFwRules: lock failed");
        die("ERROR in puzzleFwRules: lock failed");
    }
    foreach my $rule (@preparedRules) {
        ## DEBUG
        print "$rule\n" if ($debugLevel > 0);
        ## DEBUG END
        if ($debugLevel < 2) {
            # Write to log in case iptables complains.
            # Should not happen but if it does we want to know about it.
            my $rc = system($rule);

            &General::log("ERROR in puzzleFwRules: $rc $rule") if ($rc);
        }
    }
    unless (flock($lockfile, LOCK_UN)) {
        &General::log("ERROR in puzzleFwRules: unlock failed");
        die("ERROR in puzzleFwRules: unlock failed");
    }
}

# &inDayTime($rule->{'START_HOUR'}, $rule->{'END_HOUR'}, $rule->{'START_MINUTE'}, $rule->{'END_MINUTE'})
sub inDayTime
{
    my $startHour   = shift;
    my $endHour     = shift;
    my $startMinute = shift;
    my $endMinute   = shift;

    if ($startHour < $endHour) {

        # e.g. start: 8:45, end: 17:05
        return 0 unless ($startHour <= $hour && $hour <= $endHour);

        #		print "hour >< \n";
        # check if we are in start hour:
        if ($hour == $startHour) {

            # ok we are in start hour
            # check if current minute is before start minute
            return 0 if ($minute < $startMinute);

            #			print "minute < \n";
        }
        elsif ($hour == $endHour) {    # check if we are in end hour

            # ok we are in end hour
            # check if current minute is end minute or later
            return 0 if ($endMinute <= $minute);

            #			print "minute > \n";
        }
    }
    elsif ($startHour > $endHour) {

        # e.g. start: 22:00, end: 9:55
        # check if current hour is after endhour and before start
        return 0 if ($endHour < $hour && $hour < $startHour);

        #		print "hour >= \n";
        # check if we are in start hour:
        if ($hour == $startHour) {

            # ok we are in start hour
            # check if current minute is before start minute
            return 0 if ($minute < $startMinute);

            #			print "minute < \n";
        }
        elsif ($hour == $endHour) {    # check if we are in end hour

            # ok we are in end hour
            # check if current minute is end minute or later
            return 0 if ($endMinute <= $minute);

            #			print "minute > \n";
        }
    }
    else {
        # $startHour == $endHour

        if ($startMinute < $endMinute) {

            # e.g. start: 22:05, end: 22:30 - active: 0 hours, 25 minutes

            # check if current hour is the time within the rule is active
            return 0 unless ($hour == $startHour);
            #			print "hour == \n";

            # check if current minute is before start or current minute is equal to end minute or later
            return 0 if ($minute < $startMinute || $endMinute <= $minute);
            #			print "minute >< \n";
        }
        elsif ($startMinute > $endMinute) {

            # e.g. start: 22:45, end: 22:20 - active: 23 hours, 35 minutes
            # when we are not in starthour(==endhour), we are always in timeframe
            if ($hour == $startHour) {

                # check if current minute is  after or equal end minute and before start
                return 0 if ($endMinute <= $minute && $minute < $startMinute );

                #				print "minute <> \n";
            }
        }

        # here is no else.
        # starttime == endtime -> this rule is enabled for whole day
    }
    return 1;
}

sub buildServiceParamsCustom
{
    my $p_serviceName = shift;
    my $p_srcPort     = shift;
    my $service_1     = '';
    my $service_2     = '';
    my $protoInv      = '';

    # if the protocol is tcp/upd we invert the ports not the protocol direct
    $protoInv = '!' if ($custServices{$p_serviceName}{'PROTOCOL_INVERT'} eq 'on');

    unless (defined $custServices{$p_serviceName}{'PROTOCOL'}) {
        &General::log("ERROR in puzzleFwRules: Custom Service $p_serviceName does not exist");
    }
    elsif ($custServices{$p_serviceName}{'PROTOCOL'} eq 'tcpudp') {
        $service_1 = "-p tcp $p_srcPort $custServices{$p_serviceName}{'PORT_IPT'}";
        $service_2 = "-p udp $p_srcPort $custServices{$p_serviceName}{'PORT_IPT'}";
    }
    elsif ($custServices{$p_serviceName}{'PROTOCOL'} eq 'tcp') {
        $service_1 = "-p tcp $p_srcPort $custServices{$p_serviceName}{'PORT_IPT'}";
    }
    elsif ($custServices{$p_serviceName}{'PROTOCOL'} eq 'udp') {
        $service_1 = "-p udp $p_srcPort $custServices{$p_serviceName}{'PORT_IPT'}";
    }
    elsif ($custServices{$p_serviceName}{'PROTOCOL'} eq 'icmp') {
        if ($custServices{$p_serviceName}{'ICMP_TYPE'} ne 'ALL') {
            $service_1 = "-p icmp $protoInv --icmp-type $custServices{$p_serviceName}{'ICMP_TYPE'}";
        }
        else {
            $service_1 = "$protoInv -p icmp";
        }
    }
    elsif ($custServices{$p_serviceName}{'PROTOCOL'} ne 'all') {
        $service_1 = "$protoInv -p $Protocols::protocols{$custServices{$p_serviceName}{'PROTOCOL'}}";
    }
    my @protoArr = ();
    push(@protoArr, $service_1) if ($service_1 ne '');
    push(@protoArr, $service_2) if ($service_2 ne '');

    return @protoArr;
}

sub buildServiceParamsDefault
{
    my $p_serviceName = shift;
    my $p_srcPort     = shift;
    my $service_1     = '';
    my $service_2     = '';
    my $service_3     = '';
    my $service_4     = '';

    if ($p_serviceName eq 'Ofw IPsec') {
        # TODO: do we need GRE ?
        $service_1 = "-p esp";
        $service_2 = "-p ah";
        $service_3 = "-p udp --sport 500 --dport 500";
        $service_4 = "-p udp --dport 4500";
    }
    elsif ($defaultServices{$p_serviceName}{'PROTOCOL'} eq 'tcpudp') {
        $service_1 = "-p tcp $p_srcPort $defaultServices{$p_serviceName}{'PORT_IPT'}";
        $service_2 = "-p udp $p_srcPort $defaultServices{$p_serviceName}{'PORT_IPT'}";
    }
    elsif ($defaultServices{$p_serviceName}{'PROTOCOL'} eq 'tcp') {
        $service_1 = "-p tcp $p_srcPort $defaultServices{$p_serviceName}{'PORT_IPT'}";
    }
    elsif ($defaultServices{$p_serviceName}{'PROTOCOL'} eq 'udp') {
        $service_1 = "-p udp $p_srcPort $defaultServices{$p_serviceName}{'PORT_IPT'}";
    }
    elsif ($defaultServices{$p_serviceName}{'PROTOCOL'} eq 'icmp') {
        $service_1 = "-p icmp $defaultServices{$p_serviceName}{'PORT_IPT'}";
    }
    else {
        $service_1 = "-p $Protocols::protocols{$defaultServices{$p_serviceName}{'PROTOCOL'}}";
    }
    my @serviceArr;
    push(@serviceArr, $service_1);
    push(@serviceArr, $service_2) if ($service_2 ne '');
    push(@serviceArr, $service_3) if ($service_3 ne '');
    push(@serviceArr, $service_4) if ($service_4 ne '');

    return @serviceArr;
}

######################################################
# creates a source/destination address
# returns: the address in iptables format
# on error: returns an empty array
######################################################
sub buildAddressParams
{
    my $p_addressName  = shift;
    my $p_addressType  = shift;
    my $p_addressInv   = shift;
    my $p_sourceOrDest = shift;

    my $prefixIP  = "-s";
    my $prefixMAC = '-m mac --mac-source';
    if($p_sourceOrDest eq 'extPfw') {
         $prefixIP = "";
    }
    elsif ($p_sourceOrDest ne 'source') {
        $prefixIP = "-d";

        # A MAC address can not be a destination address.
        # In case there is a MAC as destination entered we return an empty array
    }


    if ($p_addressType eq 'custom') {
        unless (defined $custAddresses{$p_addressName}{'ADDRESS'}) {
            &General::log("ERROR in puzzleFwRules: Custom Address $p_addressName does not exist");
            return ();
        }

        my $custAdr = $custAddresses{$p_addressName};
        if ($custAdr->{'ADDRESS_TYPE'} eq 'ip') {
            return "$p_addressInv $prefixIP $custAdr->{'ADDRESS'}/$custAdr->{'NETMASK'}";
        }
        else {
            if ($p_sourceOrDest eq 'source') {
                return "$p_addressInv $prefixMAC $custAdr->{'ADDRESS'}";
            }
            else {

                # Damn it is a MAC address as destination :-(
                return ();
            }
        }
    }
    elsif ($p_addressType eq 'default') {
        # Check for defined and non-empty
        return () unless (defined($defaultNetworks{$p_addressName}{'IPT'}));
        return () unless (length($defaultNetworks{$p_addressName}{'IPT'}));

        return "$p_addressInv $prefixIP $defaultNetworks{$p_addressName}{'IPT'}";
    }

    # we should never come to here
    return ();
}

######################################################
# creates a group of all outgoing interfaces which are
# lower or equal to the given interface color.
#
# returns: the array of interfaces
# on error: returns an empty array
######################################################
sub getOutIfacesByColor
{
    my $searchColor    = shift;
    my $inIfaceDefault = shift;

    my @ifaceArr = ();

    foreach my $outIface (keys %FW::interfaces) {

        # no need to create a rule for in/out the same interface
        # NOTE: this checks names and not the devices.
        #		For custom source interfaces the parameter is empty.
        next if ($inIfaceDefault eq $outIface);

        # only create rules for this interface if it is activ
        next if ($FW::interfaces{$outIface}{'ACTIV'} ne 'yes');

        if ($searchColor =~ /^GREEN_COLOR|IPSEC_COLOR|OVPN_COLOR$/) {

            # search for one of Green or VPN -> every outgoing interface has lower or equal color level
            push(@ifaceArr, $FW::interfaces{$outIface}{'IFACE'});
        }
        elsif ($searchColor =~ /^BLUE_COLOR$/
            && $FW::interfaces{$outIface}{'COLOR'} =~ /^BLUE_COLOR|ORANGE_COLOR|RED_COLOR$/)
        {

            # search is Blue -> every Blue, orange and red outgoing interface has lower or equal color level
            push(@ifaceArr, $FW::interfaces{$outIface}{'IFACE'});
        }
        elsif ($searchColor =~ /^ORANGE_COLOR$/
            && $FW::interfaces{$outIface}{'COLOR'} =~ /^ORANGE_COLOR|RED_COLOR$/)
        {

            # search is orange -> every orange and red outgoing interface has lower or equal color level
            push(@ifaceArr, $FW::interfaces{$outIface}{'IFACE'});
        }
        elsif ($searchColor =~ /^RED_COLOR$/
            && $FW::interfaces{$outIface}{'COLOR'} =~ /^RED_COLOR$/)
        {

            # search is red -> every red outgoing interface has lower or equal color level
            push(@ifaceArr, $FW::interfaces{$outIface}{'IFACE'});
        }
    }

    return @ifaceArr;
}

