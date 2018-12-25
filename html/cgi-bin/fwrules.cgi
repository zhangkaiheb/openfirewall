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
# $Id: fwrules.cgi 7066 2013-06-09 12:50:18Z dotzball $
#
#
# Darren Critchley February 2003 - I added the multiple external access rules for each port forward
# A couple of things to remember when reading the code
#   There are two kinds of records in the config file, those with a number in the first field, and then 0,
#       these are port forward rules, these records will have a 0 or 0.0.0.0 in position 9 (ORIG_ADR)
#       If there is a 0, it means that there are external access rules, otherwise the port is open to ALL.
#   The second type of record is a number followed by a number which indicates that it is an external access
#   rule. The first number indicates which Portfw rule it belongs to, and the second is just a unique key.
#
# Darren Critchley - March 5, 2003 - if you come along after me and work on this page, please comment your
#       work. Put your name, and date and then your comment - it helps the person that comes along after you
#       to figure out why and how things have changed, and it is considered good coding practice
# Thanks . . .
#
# Achim Weber November - December 2003
#       I modified this file to work with BlockOutTraffic addon.
#       This is the rule-creator-page
#
# Achim Weber January 2004
#       When BOT is disabled your are able to edit rules now,
#       settings are checked for validation everytime now,
#       if settings invalid, you can't edit rules and get message+Edit-button,
#
# Achim Weber Autumn 2004
#       There are many changes for BlockOutTraffic 2.2.
#
# Achim Weber April 2005
#       Remove rule wizard again
#
# Achim Weber Summer 2005
#       Implement data layer
#
# 6 May 2006 Achim Weber:
#       Re-worked code to use it in Openfirewall 1.5, renamed all variables, keys, etc.
#       from "BOT" to "FW".

# Add entry in menu
# MENUENTRY firewall 070 "firewall rules" "firewall rules"
#
# Make sure translation exists $Lang::tr{'firewall rules'}

use strict;

# enable only the following on debugging purpose
use warnings;
no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';

my (%cgiparams, %selected, %checked, %radio);

my @weekDays = (
    $Lang::tr{'sunday'},   $Lang::tr{'monday'}, $Lang::tr{'tuesday'}, $Lang::tr{'wednesday'},
    $Lang::tr{'thursday'}, $Lang::tr{'friday'}, $Lang::tr{'saturday'}
);

my %defaultNetworks = ();
my $errormessage;
my $error = '';
my $warnOpenFwMessage;

# enable(==1)/disable(==0) HTML Form debugging
my $debugFormparams = 0;

&initAllParams();

my %ruleConfig = ();
&DATA::readRuleConfig(\%ruleConfig);

&Header::showhttpheaders();

my $invalidSettings = 1;
$invalidSettings = &FW::readValidSettings();
if ($invalidSettings) {
    $errormessage = $Lang::tr{'settingsfile bad'};
    undef %cgiparams;
    &resetCgiParams();
}

if ($cgiparams{'BOX_ACTION'} eq $Lang::tr{'cancel'}) {
    undef %cgiparams;
    &resetCgiParams();
}

if (   $cgiparams{'BOX_ACTION'} eq $Lang::tr{'next'}
    || $cgiparams{'BOX_ACTION'} eq $Lang::tr{'save'})
{

    # check dependency between the input / output interfaces
    &checkBetweenParams();

    unless ($errormessage) {
        &validateSrcParams();
        &validateDestParams();
        &validateAdditionalParams();
        &validateTimeParams();
    }

    if ($errormessage) {
        $error = 'error';

        if ($cgiparams{'BOX_NAME'} eq 'EnterParams') {
            $cgiparams{'BOX_ACTION'} = $Lang::tr{'back'};
        }
        else {
            $cgiparams{'BOX_ACTION'} = $Lang::tr{'next'};
        }
    }
}

if ($cgiparams{'BOX_ACTION'} eq $Lang::tr{'save'}) {
    my $newRule = &buildRuleObject();

    my $ruletype = 'OUTGOING';
    if ($cgiparams{'RULETYPE'} eq 'INPUT') {
        $ruletype = 'INPUT';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'EXTERNAL') {
        $ruletype = 'EXTERNAL';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PINHOLES') {
        $ruletype = 'PINHOLES';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PORTFW') {
        $ruletype = 'PORTFW';
    }
    elsif ($cgiparams{'RULETYPE'} ne 'OUTGOING') {
        die 'false Ruletype';
    }

    my $position = 0;
    foreach my $rule (@{$ruleConfig{$ruletype}}) {

        # we dont have to check the edited rule
        next if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}
            && $cgiparams{'OLD_POSITION'} == $position);
        $position++;

        my $sameRule = 1;

        foreach my $key (@DATA::ruleKeys_unique) {
            if ($rule->{$key} ne $newRule->{$key}) {
                $sameRule = 0;
                last;
            }
        }

        if ($sameRule) {

            # same rule, check timeframe
            if (   $rule->{'TIMEFRAME_ENABLED'} eq 'on'
                && $newRule->{'TIMEFRAME_ENABLED'} eq 'on')
            {

                #@DATA::timeKeys_all

                my $sameTime = 1;
                foreach my $key (@DATA::timeKeys_all) {
                    if ($rule->{$key} ne $newRule->{$key}) {
                        $sameTime = 0;
                        last;
                    }
                }
                next unless ($sameTime);
            }

            $errormessage = $Lang::tr{'rule exists'};

            if ($cgiparams{'BOX_NAME'} eq 'EnterParams') {
                $cgiparams{'BOX_ACTION'} = $Lang::tr{'back'};
            }
            else {
                $cgiparams{'BOX_ACTION'} = $Lang::tr{'next'};
            }
            last;
        }
    }

    unless ($errormessage) {

        if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {

            &FW::changeUsedCountInRule(@{$ruleConfig{$cgiparams{'OLD_RULETYPE'}}}[ $cgiparams{'OLD_POSITION'} ],
                'remove');
            splice(@{$ruleConfig{$cgiparams{'OLD_RULETYPE'}}}, $cgiparams{'OLD_POSITION'}, 1);
        }

        &FW::changeUsedCountInRule($newRule, 'add');
        if ($cgiparams{'RULE_POSITION'} > -1) {
            splice(@{$ruleConfig{$ruletype}}, $cgiparams{'RULE_POSITION'}, 0, $newRule);
        }
        else {
            push(@{$ruleConfig{$ruletype}}, $newRule);
        }

        &DATA::saveRuleConfig(\%ruleConfig);

        undef %cgiparams;
        &resetCgiParams();
        if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
            &General::log($Lang::tr{'firewall rule updated'});
        }
        else {
            &General::log($Lang::tr{'firewall rule added'});
        }
        `/usr/local/bin/setfwrules -f $ruletype < /dev/null > /dev/null 2>&1 &`;
    }    # end unless($errormessage)
}

# Darren Critchley - Allows rules to be enabled and disabled
if (   $cgiparams{'ACTION'} eq $Lang::tr{'toggle enable disable'}
    || $cgiparams{'ACTION'} eq "$Lang::tr{'toggle enable disable'}log")
{
    my $ruletype = 'OUTGOING';
    if ($cgiparams{'RULETYPE'} eq 'INPUT') {
        $ruletype = 'INPUT';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'EXTERNAL') {
        $ruletype = 'EXTERNAL';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PINHOLES') {
        $ruletype = 'PINHOLES';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PORTFW') {
        $ruletype = 'PORTFW';
    }
    elsif ($cgiparams{'RULETYPE'} ne 'OUTGOING') {
        die 'false Ruletype';
    }

    #~  print "type: $ruletype - RULETYPE: $cgiparams{'RULETYPE'} - Pos: $cgiparams{'RULE_POSITION'}";
    if ($cgiparams{'ACTION'} eq $Lang::tr{'toggle enable disable'}) {
        ${$ruleConfig{$ruletype}}[ $cgiparams{'RULE_POSITION'} ]->{'ENABLED'} = $cgiparams{'ENABLED'};
    }
    elsif ($cgiparams{'ACTION'} eq "$Lang::tr{'toggle enable disable'}log") {
        ${$ruleConfig{$ruletype}}[ $cgiparams{'RULE_POSITION'} ]->{'LOG_ENABLED'} = $cgiparams{'LOG_ENABLED'};
    }

    &DATA::saveRuleConfig(\%ruleConfig);

    &General::log($Lang::tr{'firewall rule updated'});
    `/usr/local/bin/setfwrules -f $ruletype < /dev/null > /dev/null 2>&1 &`;
    undef %cgiparams;
    &resetCgiParams();
}

if (($cgiparams{'ACTION'} eq $Lang::tr{'edit'} || $cgiparams{'ACTION'} eq $Lang::tr{'copy rule'})
    && $cgiparams{'BOX_ACTION'} eq '')
{
    my $ruletype = 'OUTGOING';
    if ($cgiparams{'RULETYPE'} eq 'INPUT') {
        $ruletype = 'INPUT';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'EXTERNAL') {
        $ruletype = 'EXTERNAL';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PINHOLES') {
        $ruletype = 'PINHOLES';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PORTFW') {
        $ruletype = 'PORTFW';
    }
    elsif ($cgiparams{'RULETYPE'} ne 'OUTGOING') {
        die 'false Ruletype';
    }

    $cgiparams{'OLD_POSITION'} = $cgiparams{'RULE_POSITION'};
    $cgiparams{'OLD_RULETYPE'} = $cgiparams{'RULETYPE'};

    my $ruleFound = 0;

    if (defined @{$ruleConfig{$ruletype}}[ $cgiparams{'RULE_POSITION'} ]) {
        my $rule = @{$ruleConfig{$ruletype}}[ $cgiparams{'RULE_POSITION'} ];
        &initCgiParamsFromConf($rule);
        $ruleFound = 1;

        # use a new position for the new rule
        $cgiparams{'RULE_POSITION'} = -1 if ($cgiparams{'ACTION'} eq "$Lang::tr{'copy rule'}");
    }
    if ($ruleFound) {
        $cgiparams{'BOX_ACTION'} = "$Lang::tr{'back'}";
    }
}    # end if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'})

# Darren Critchley - broke out Remove routine as the logic is getting too complex to be combined with the Edit
if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    my $ruletype = 'OUTGOING';
    if ($cgiparams{'RULETYPE'} eq 'INPUT') {
        $ruletype = 'INPUT';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'EXTERNAL') {
        $ruletype = 'EXTERNAL';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PINHOLES') {
        $ruletype = 'PINHOLES';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PORTFW') {
        $ruletype = 'PORTFW';
    }
    elsif ($cgiparams{'RULETYPE'} ne 'OUTGOING') {
        die 'false Ruletype';
    }

    if (defined @{$ruleConfig{$ruletype}}[ $cgiparams{'RULE_POSITION'} ]) {
        my $rule = @{$ruleConfig{$ruletype}}[ $cgiparams{'RULE_POSITION'} ];

        &FW::changeUsedCountInRule($rule, 'remove');

        splice(@{$ruleConfig{$ruletype}}, $cgiparams{'RULE_POSITION'}, 1);

        &DATA::saveRuleConfig(\%ruleConfig);

        &General::log($Lang::tr{'firewall rule removed'});

        undef %cgiparams;
        &resetCgiParams();
        `/usr/local/bin/setfwrules -f $ruletype < /dev/null > /dev/null 2>&1 &`;
    }
}

# routine to move a rule up/down in sequence
if (   $cgiparams{'ACTION'} eq $Lang::tr{'up'}
    || $cgiparams{'ACTION'} eq $Lang::tr{'down'})
{
    my $ruletype = 'OUTGOING';
    if ($cgiparams{'RULETYPE'} eq 'INPUT') {
        $ruletype = 'INPUT';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'EXTERNAL') {
        $ruletype = 'EXTERNAL';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PINHOLES') {
        $ruletype = 'PINHOLES';
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PORTFW') {
        $ruletype = 'PORTFW';
    }
    elsif ($cgiparams{'RULETYPE'} ne 'OUTGOING') {
        die 'false Ruletype';
    }

    if (defined @{$ruleConfig{$ruletype}}[ $cgiparams{'RULE_POSITION'} ]) {
        my $rule = @{$ruleConfig{$ruletype}}[ $cgiparams{'RULE_POSITION'} ];

        splice(@{$ruleConfig{$ruletype}}, $cgiparams{'RULE_POSITION'}, 1);

        # init with "down"
        my $newPosition = $cgiparams{'RULE_POSITION'} + 1;
        if ($cgiparams{'ACTION'} eq $Lang::tr{'up'}) {
            $newPosition = $cgiparams{'RULE_POSITION'} - 1;
        }

        splice(@{$ruleConfig{$ruletype}}, $newPosition, 0, $rule);

        &DATA::saveRuleConfig(\%ruleConfig);

        &General::log($Lang::tr{'firewall rule updated'});
        `/usr/local/bin/setfwrules -f $ruletype < /dev/null > /dev/null 2>&1 &`;
    }
    undef %cgiparams;
    &resetCgiParams();
}

&Header::openpage($Lang::tr{'firewall configuration'}, 1, '');
&Header::openbigbox('100%', 'left');

###############
# DEBUG DEBUG
if ($debugFormparams == 1) {
    &Header::openbox('100%', 'left', 'DEBUG');
    my $debugCount = 0;
    foreach my $line (sort keys %cgiparams) {
        print "$line = $cgiparams{$line}<br />\n";
        $debugCount++;
    }
    print "&nbsp;Count: $debugCount\n";
    &Header::closebox();
}

# DEBUG DEBUG
###############

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "$errormessage\n";
    &Header::closebox();

    $error = 'error';
}

if (!$invalidSettings) {
    if (   $cgiparams{'ACTION'} eq ''
        || $cgiparams{'ACTION'}     eq "$Lang::tr{'rules'}"
        || $cgiparams{'BOX_ACTION'} eq "$Lang::tr{'cancel'}"
        || $cgiparams{'BOX_ACTION'} eq "$Lang::tr{'save'}")
    {
        if ($warnOpenFwMessage) {
            &Header::openbox('100%', 'left', $Lang::tr{'warning messages'}, 'warning');
            print "<b>$Lang::tr{'note'}:</b><br />$warnOpenFwMessage\n";
            &Header::closebox();
        }
        &printSelectNewRuleBox();
        &printCurrentRulesBox('all');
    }
    else {
        if ($cgiparams{'BOX_ACTION'} eq "$Lang::tr{'next'}") {
            &printOverviewBox();
        }
        else {
            &printEnterParamsBox();
        }
    }
}
else {
    &printInvalidSettingsBox();
}

&Header::closebigbox();
&Header::closepage();

sub printCurrentRulesBox
{
    my $printMode = shift;
    &Header::openbox('100%', 'left', "$Lang::tr{'current rules'}:");

    if ($printMode eq 'all' || $cgiparams{'RULETYPE'} eq 'OUTGOING') {
        &printCurrentRules('OUTGOING', $printMode);

#### DEBUG:
        #       foreach $line (@forwardRules) {
        #           print "$line<br />\n";
        #       }
#### end DEBUG

        print "<br />";
    }

    if ($printMode eq 'all' || $cgiparams{'RULETYPE'} eq 'INPUT') {
        &printCurrentRules('INPUT', $printMode);
#### DEBUG:
        #       foreach $line (@inputRules) {
        #           print "$line<br />\n";
        #       }
#### end DEBUG
        print "<br />";
    }

    if ($printMode eq 'all' || $cgiparams{'RULETYPE'} eq 'PINHOLES') {
        if (&FW::haveInternalNet()) {
            &printCurrentRules('PINHOLES', $printMode);
            print "<br />";
        }
    }

    if ($printMode eq 'all' || $cgiparams{'RULETYPE'} eq 'PORTFW') {
        &printCurrentRules('PORTFW', $printMode);
        print "<br />";
    }

    if ($printMode eq 'all' || $cgiparams{'RULETYPE'} eq 'EXTERNAL') {
        &printCurrentRules('EXTERNAL', $printMode);
        print "<br />";
    }

    print <<END;
<table>
<tr>
    <td class='boldbase'>&nbsp; $Lang::tr{'legend'}:</td>
    <td align='right'>&nbsp;<img src='/images/input.gif' alt='=&gt;' /></td>
    <td class='base' align='left'>$Lang::tr{'standard rule'}</td>
    <td align='right'>&nbsp;<img src='/images/inputdeny.gif' alt='=X&gt;' /></td>
    <td class='base' align='left'>$Lang::tr{'deny rule'}</td>
    <td align='right'>&nbsp;<img src='/images/inputlog.gif' alt='=log&gt;' /></td>
    <td class='base' align='left'>$Lang::tr{'logging rule'}</td>
    <td align='right'>&nbsp;<img src='/images/inputadv.gif' alt='=ADV&gt;' /></td>
    <td class='base' align='left'>$Lang::tr{'advanced rule'}</td>
    <td colspan='2'></td>
</tr>
<tr>
    <td class='boldbase'></td>
    <td align='right'>&nbsp;<img src='/images/on.gif' alt='$Lang::tr{'click to disable'}' /></td>
    <td class='base' align='left'>$Lang::tr{'click to disable'}</td>
    <td align='right'>&nbsp;<img src='/images/off.gif' alt='$Lang::tr{'click to enable'}' /></td>
    <td class='base' align='left'>$Lang::tr{'click to enable'}</td>
    <td align='right'>&nbsp;<img src='/images/logging.gif' alt='$Lang::tr{'logging'} $Lang::tr{'click to disable'}' /></td>
    <td class='base' align='left'>$Lang::tr{'logging'} $Lang::tr{'click to disable'}</td>
    <td align='right'>&nbsp;<img src='/images/loggingoff.gif' alt='$Lang::tr{'logging'} $Lang::tr{'click to enable'}' /></td>
    <td class='base' align='left'>$Lang::tr{'logging'} $Lang::tr{'click to enable'}</td>
    <td colspan='2'></td>
</tr>
<tr>
    <td class='boldbase'></td>
    <td align='right'>&nbsp;<img src='/images/edit.gif' alt='$Lang::tr{'edit'}' /></td>
    <td class='base' align='left'>$Lang::tr{'edit'}</td>
    <td align='right'>&nbsp;<img src='/images/copy.gif' alt='$Lang::tr{'copy rule'}' /></td>
    <td class='base' align='left'>$Lang::tr{'copy rule'}</td>
    <td align='right'>&nbsp;<img src='/images/delete.gif' alt='$Lang::tr{'remove'}' /></td>
    <td class='base' align='left'>$Lang::tr{'remove'}</td>
    <td align='right'>&nbsp;<img src='/images/up.gif' alt='$Lang::tr{'up'}' /></td>
    <td class='base' align='left'>$Lang::tr{'up'}</td>
    <td align='right'>&nbsp;<img src='/images/down.gif' alt='$Lang::tr{'down'}' /></td>
    <td class='base' align='left'>$Lang::tr{'down'}</td>
</tr>
</table>
END

    &Header::closebox();
}

sub printCurrentRules
{
    my $type      = shift;
    my $printMode = shift;

    my $cellspacing = 2;
    my $cellpadding = 1;
    print <<END;
<table width='100%' border='0' cellspacing='$cellspacing' cellpadding='$cellpadding'>
<tr>
    <td colspan='6' class='boldbase' align='left'>
END

    my $dst_text = $Lang::tr{'destination'};
    my $widthAdr = '23';
    my $widthRemark = '26';
    my $colHeaderDestIface = $Lang::tr{'net dst br iface'};

    if ($type eq 'OUTGOING') {
        print "<b>$Lang::tr{'outgoing traffic'}:</b>";
    }
    elsif ($type eq 'INPUT') {
        $colHeaderDestIface = "<div class='ofw_box'>$colHeaderDestIface</div>";
        print "<b>$Lang::tr{'openfirewall access'}:</b>";
    }
    elsif ($type eq 'EXTERNAL') {
        $colHeaderDestIface = "<div class='ofw_box'>$colHeaderDestIface</div>";
        print "<b>$Lang::tr{'external openfirewall access'}:</b>";
    }
    elsif ($type eq 'PINHOLES') {
        print "<b>$Lang::tr{'internal traffic'}:</b>";
    }
    elsif ($type eq 'PORTFW') {
        $dst_text = $Lang::tr{'pfw internal destination'};
        print "<b>$Lang::tr{'ssport forwarding'}:</b>";
    }


    print <<END;
    </td>
</tr>
<tr>
    <td width='2%' class='boldbase' align='center'>#</td>
    <td width='10%' class='boldbase' align='center'>$Lang::tr{'net br iface'}</td>
    <td width='$widthAdr%' class='boldbase' align='center'>$Lang::tr{'source'}</td>
    <td width='3%' class='boldbase' align='center'>&nbsp;</td>
    <td width='10%' class='boldbase' align='center'>$colHeaderDestIface</td>
    <td width='$widthAdr%' class='boldbase' align='center'>$dst_text</td>
    <td width='$widthRemark%' class='boldbase' align='center'>$Lang::tr{'remark'}</td>
END

    my $actionTitle = "$Lang::tr{'action'}";
    $actionTitle = '' if ($printMode ne 'all');

    my $actionColCount = 7;
    my $actionWidth = $actionColCount * 20 + ($actionColCount - 1) * $cellspacing + ($actionColCount - 1) * 2 * $cellpadding;
    print <<END;
    <td width='6%' class='boldbase' colspan='$actionColCount' align='center' >
        <img src='/images/null.gif' alt='' width="$actionWidth" height="1"/><br/>
        $actionTitle
    </td>
</tr>
END

    my $id = 0;
    my $idlast = $#{$ruleConfig{$type}};
    foreach my $rule (@{$ruleConfig{$type}}) {

        # Advanced Mode ?
        next if ($rule->{'RULEMODE'} eq 'adv' && &FW::hideAdvRule($rule->{'SRC_NET_TYPE'}, $rule->{'DST_NET_TYPE'}, $type));

        my $gif        = '';
        my $forwardgif = 'input';
        my $forwardalt = '=&gt;';

        my $toggle    = '';
        my $toggleLog = '';
        my $loggif    = '';
        my $srcNet    = '';
        my $destNet   = '';

        my $srcNetColor       = '';
        my $srcNetInvertColor = 'RED';
        if (   $FW::fwSettings{'SHOW_COLORS'} eq 'on'
            && $rule->{'SRC_NET_TYPE'} eq 'defaultSrcNet'
            && defined($FW::interfaces{$rule->{'SRC_NET'}}))
        {
            if ($FW::interfaces{$rule->{'SRC_NET'}}{'COLOR'} eq 'GREEN_COLOR') {
                $srcNetColor = 'ofw_iface_bg_green';
            }
            elsif ($FW::interfaces{$rule->{'SRC_NET'}}{'COLOR'} eq 'BLUE_COLOR') {
                $srcNetColor = 'ofw_iface_bg_blue';
            }
            elsif ($FW::interfaces{$rule->{'SRC_NET'}}{'COLOR'} eq 'ORANGE_COLOR') {
                $srcNetColor = 'ofw_iface_bg_orange';
            }
            elsif ($FW::interfaces{$rule->{'SRC_NET'}}{'COLOR'} eq 'RED_COLOR') {
                $srcNetColor       = 'ofw_iface_bg_red';
                $srcNetInvertColor = 'BLACK';
            }
            elsif ($FW::interfaces{$rule->{'SRC_NET'}}{'COLOR'} eq 'IPSEC_COLOR') {
                $srcNetColor = 'ofw_iface_bg_ipsec';
            }
            elsif ($FW::interfaces{$rule->{'SRC_NET'}}{'COLOR'} eq 'OVPN_COLOR') {
                $srcNetColor = 'ofw_iface_bg_ovpn';
            }

        }

        # Always display interface name (there are more than one interface per color possible)
        $srcNet = &General::translateinterface($rule->{'SRC_NET'});

        my $destNetColor       = '';
        my $destNetInvertColor = 'RED';

        if ($type eq 'OUTGOING' || $type eq 'PINHOLES' || $type eq 'PORTFW') {
            if (   $FW::fwSettings{'SHOW_COLORS'} eq 'on'
                && $rule->{'DST_NET_TYPE'} eq 'defaultDestNet'
                && defined($FW::interfaces{$rule->{'DST_NET'}}))
            {
                if ($FW::interfaces{$rule->{'DST_NET'}}{'COLOR'} eq 'GREEN_COLOR') {
                    $destNetColor = 'ofw_iface_bg_green';
                }
                elsif ($FW::interfaces{$rule->{'DST_NET'}}{'COLOR'} eq 'BLUE_COLOR') {
                    $destNetColor = 'ofw_iface_bg_blue';
                }
                elsif ($FW::interfaces{$rule->{'DST_NET'}}{'COLOR'} eq 'ORANGE_COLOR') {
                    $destNetColor = 'ofw_iface_bg_orange';
                }
                elsif ($FW::interfaces{$rule->{'DST_NET'}}{'COLOR'} eq 'RED_COLOR') {
                    $destNetColor       = 'ofw_iface_bg_red';
                    $destNetInvertColor = 'BLACK';
                }
                elsif ($FW::interfaces{$rule->{'DST_NET'}}{'COLOR'} eq 'IPSEC_COLOR') {
                    $destNetColor = 'ofw_iface_bg_ipsec';
                }
                elsif ($FW::interfaces{$rule->{'DST_NET'}}{'COLOR'} eq 'OVPN_COLOR') {
                    $destNetColor = 'ofw_iface_bg_ovpn';
                }
            }

            # Always display interface name (there are more than one interface per color possible)
            $destNet = &General::translateinterface($rule->{'DST_NET'});
        }
        elsif (($type eq 'INPUT') || ($type eq 'EXTERNAL')) {
            $destNetColor = 'ofw_iface_bg_fw';
            $destNet = 'OFW';
        }

        # Darren Critchley highlight the row we are editing
        if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} && $cgiparams{'RULE_POSITION'} eq $id) {
            print "<tr class='selectcolour'>";
            $srcNetColor = '';
        }
        else {
            print "<tr class='table".int(($id % 2) + 1)."colour'>";
        }

        $loggif = "logging";
        if ($rule->{'LOG_ENABLED'} eq 'on') {
            $toggleLog = 'off';
        }
        else {
            $loggif .= 'off';
            $toggleLog = 'on';
        }

        my $imageType =
"input type='image' name='$Lang::tr{'toggle enable disable'}' title='$Lang::tr{'logging'} $Lang::tr{'toggle enable disable'}' ";
        $imageType = "img" if ($printMode ne 'all');

        if ($rule->{'RULEMODE'} eq 'adv') {
            $forwardgif = 'inputadv';
            $forwardalt = '=ADV&gt;';
        }
        else {    # $rule->{'RULEMODE'} eq 'std'
            $forwardgif = 'input';
            $forwardalt = '=&gt;';
        }
        if ($rule->{'RULEACTION'} eq 'logOnly') {
            $forwardgif .= 'log';
            $forwardalt = '=log&gt;';
            $imageType  = "img";
        }
        elsif ($rule->{'RULEACTION'} eq 'drop' || $rule->{'RULEACTION'} eq 'reject') {
            $forwardgif .= 'deny';
            $forwardalt = '=X&gt;';
        }

        if ($rule->{'ENABLED'} eq 'on') {
            $gif    = 'on.gif';
            $toggle = 'off';
        }
        else {
            $gif    = 'off.gif';
            $toggle = 'on';
        }

        my $srcaddr = $rule->{'SRC_ADR'};
        if ($rule->{'INV_SRC_ADR'} eq 'on') {
            $srcaddr =
                  "<strong><font color='RED'>! (</font></strong>"
                . $rule->{'SRC_ADR'}
                . "<strong><font color='RED'>)</font></strong>";
        }
        if ($rule->{'SRC_PORT'} ne '-') {
            if ($rule->{'INV_SRC_PORT'} eq 'on') {
                $srcaddr .= "&nbsp;:&nbsp;<strong><font color='RED'>! (</font></strong>";
                $srcaddr .= "$rule->{'SRC_PORT'}";
                $srcaddr .= "<strong><font color='RED'>)</font></strong>";
            }
            else {
                $srcaddr .= "&nbsp;:&nbsp;$rule->{'SRC_PORT'}";
            }
        }

        my $displayID = 1 + $id;
        print <<END;
    <td class='boldbase'>$displayID</td>
    <td align='center' class='$srcNetColor'>$srcNet</td>
    <td align='center'>$srcaddr</td>
    <td align='center'><img src='/images/$forwardgif.gif' alt='$forwardalt' /></td>
    <td align='center' class='$destNetColor'>$destNet</td>
END

        my $dstaddr = $rule->{'DST_IP'};
        if ($type eq 'OUTGOING' || $type eq 'PINHOLES' || $type eq 'PORTFW') {
            if ($rule->{'INV_DST_IP'} eq 'on') {
                $dstaddr =
                      "<strong><font color='RED'>! (</font></strong>"
                    . $rule->{'DST_IP'}
                    . "<strong><font color='RED'>)</font></strong>";
            }
        }
        else {
            $dstaddr = "OFW";
        }

        if ($rule->{'SERVICE_TYPE'} ne '-') {
            $dstaddr .= "&nbsp;:&nbsp;$rule->{'SERVICE'}";
        }

        print "<td align='center'>$dstaddr</td>";

        unless (defined $rule->{'REMARK'}) { $rule->{'REMARK'} = ''; }
        if ($printMode ne 'all') {
            print <<END;
    <td colspan='8' align='left'>$rule->{'REMARK'}</td>
</tr>
END
        }
        else {
            print <<END;
    <td align='left'>$rule->{'REMARK'}</td>
    <td align='center'>
        <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif' alt='$Lang::tr{'toggle enable disable'}' title='$Lang::tr{'toggle enable disable'}' />
            <input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
            <input type='hidden' name='RULE_POSITION' value='$id' />
            <input type='hidden' name='ENABLED' value='$toggle' />
            <input type='hidden' name='RULETYPE' value='$type' />
        </form>
    </td>
    <td align='center'>
        <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
            <$imageType src='/images/$loggif.gif' alt='$Lang::tr{'logging'} $Lang::tr{'toggle enable disable'}' />
            <input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}log' />
            <input type='hidden' name='RULE_POSITION' value='$id' />
            <input type='hidden' name='LOG_ENABLED' value='$toggleLog' />
            <input type='hidden' name='RULETYPE' value='$type' />
        </form>
    </td>
    <td align='center'>
        <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
            <input type='image' name='$Lang::tr{'edit'}' value='$id' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}'  />
            <input type='hidden' name='RULE_POSITION' value='$id' />
            <input type='hidden' name='RULETYPE' value='$type' />
        </form>
    </td>
    <td align='center'>
        <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='hidden' name='ACTION' value='$Lang::tr{'copy rule'}' />
            <input type='image' name='$Lang::tr{'copy rule'}' value='$id' src='/images/copy.gif' alt='$Lang::tr{'copy rule'}' title='$Lang::tr{'copy rule'}'  />
            <input type='hidden' name='RULE_POSITION' value='$id' />
            <input type='hidden' name='RULETYPE' value='$type' />
        </form>
    </td>
    <td align='center'>
        <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
            <input type='image' name='$Lang::tr{'remove'}' value='$id' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
            <input type='hidden' name='RULE_POSITION' value='$id' />
            <input type='hidden' name='RULETYPE' value='$type' />
        </form>
    </td>
END
            if ($id > 0) {
                print <<END;
    <td align='center'>
        <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='hidden' name='ACTION' value='$Lang::tr{'up'}' />
            <input type='image' name='$Lang::tr{'up'}' value='$id' src='/images/up.gif' alt='$Lang::tr{'up'}' title='$Lang::tr{'up'}' />
            <input type='hidden' name='RULE_POSITION' value='$id' />
            <input type='hidden' name='RULETYPE' value='$type' />
        </form>
    </td>
END
            }
            else {
                print <<END;
    <td align='center'>
        <img src='/images/null.gif' width='20' height='1' border='0' alt='spacer' />
    </td>
END
            }
            if ($idlast != $id) {
                print <<END;
    <td align='center'>
        <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='hidden' name='ACTION' value='$Lang::tr{'down'}' />
            <input type='image' name='$Lang::tr{'down'}' value='$id' src='/images/down.gif' alt='$Lang::tr{'down'}' title='$Lang::tr{'down'}' />
            <input type='hidden' name='RULE_POSITION' value='$id' />
            <input type='hidden' name='RULETYPE' value='$type' />
        </form>
    </td>
END
            }
            else {
                print <<END;
    <td align='center'>
        <img src='/images/null.gif' width='20' height='1' border='0' alt='spacer' />
    </td>
END
            }
            print "</tr>";
        }

        if($type eq 'PORTFW') {

            # Only display openfirewall external destination line if address is not the red address or the service is different
            if($rule->{'PORTFW_EXT_ADR'} ne 'Red Address'
                || $rule->{'PORTFW_SERVICE'} ne $rule->{'SERVICE'}
                || $rule->{'PORTFW_SERVICE_TYPE'} ne $rule->{'SERVICE_TYPE'})
            {
                my $extAddr = $rule->{'PORTFW_EXT_ADR'};
                $extAddr .= "&nbsp;:&nbsp;$rule->{'PORTFW_SERVICE'}";

                 # Darren Critchley highlight the row we are editing
                if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} && $cgiparams{'RULE_POSITION'} eq $id) {
                    print "<tr class='selectcolour'>";
                }
                else {
                    print "<tr class='table".int(($id % 2) + 1)."colour'>";
                }
               print <<END;
    <td colspan='2' class='boldbase' />
    <td colspan='13' class='boldbase' align='left'>
        $Lang::tr{'pfw openfirewall destination'}:&nbsp;
        $extAddr
    </td>
</tr>
END
            }
        }

        # display only if the option is really used
        if (
            (
                   ($rule->{'LIMIT_FOR'} eq 'log' && $rule->{'LOG_ENABLED'} eq 'on')
                || $rule->{'LIMIT_FOR'}       eq 'acceptOrDeny'
                || $rule->{'LIMIT_FOR'}       eq 'both'
                || $rule->{'MATCH_STRING_ON'} eq 'on'
            )    # string match
            && $FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on'
            )
        {

            # Darren Critchley highlight the row we are editing
            if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} && $cgiparams{'RULE_POSITION'} eq $id) {
                print "<tr class='selectcolour'>";
                $srcNetColor = '';
            }
            else {
                print "<tr class='table".int(($id % 2) + 1)."colour'>";
            }
            my $options = "$Lang::tr{'adv options'}&nbsp;:&nbsp;&nbsp;";
            if ($rule->{'MATCH_STRING_ON'} eq 'on') {
                if ($rule->{'INV_MATCH_STRING'} eq 'on') {
                    $options .=
"--string <strong><font color='RED'>! (</font></strong> $rule->{'MATCH_STRING'} <strong><font color='RED'>)</font></strong> ;&nbsp;&nbsp;";
                }
                else {
                    $options .= "--string $rule->{'MATCH_STRING'} ;&nbsp;&nbsp;";
                }
            }
            if ($rule->{'LIMIT_FOR'} eq 'log') {
                $options .= "$Lang::tr{'match log'}&nbsp;:&nbsp;";
            }
            elsif ($rule->{'LIMIT_FOR'} eq 'acceptOrDeny') {
                $options .= "$Lang::tr{'match accept deny'}&nbsp;:&nbsp;";
            }
            elsif ($rule->{'LIMIT_FOR'} eq 'both') {
                $options .= "$Lang::tr{'match both'}&nbsp;:&nbsp;";
            }

            if ($rule->{'LIMIT_TYPE'} eq 'average') {
                $options .= "--limit $rule->{'MATCH_LIMIT'} ;&nbsp;&nbsp;";
            }
            elsif ($rule->{'LIMIT_TYPE'} eq 'burst') {
                $options .= "--limit-burst $rule->{'MATCH_LIMIT'} ;";
            }
            print <<END;
    <td colspan='2' class='boldbase'></td>
    <td colspan='13' class='boldbase' align='left'>$options</td>
</tr>
END
        }

        if ($rule->{'TIMEFRAME_ENABLED'} eq 'on' && $FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on') {
            my $startDay = $rule->{'START_DAY_MONTH'};
            my $endDay   = $rule->{'END_DAY_MONTH'};

            my $dayText = "$startDay&nbsp;";
            $dayText .= "$Lang::tr{'days to'}&nbsp;";
            $dayText .= "$endDay&nbsp;$Lang::tr{'of month'}&nbsp;&nbsp;";

            if ($rule->{'DAY_TYPE'} eq 'weekDays') {
                $dayText = "";
                my $currDay = 0;
                for (; $currDay <= 6; $currDay++) {
                    my $dayKey = $DATA::weekDays[$currDay];
                    next unless ($rule->{$dayKey} eq 'on');
                    $dayText .= "$weekDays[$currDay]&nbsp;&nbsp;";
                }
            }
            $dayText .= "-";

            my $startHour   = $rule->{'START_HOUR'} < 10   ? "0" . $rule->{'START_HOUR'}   : $rule->{'START_HOUR'};
            my $startMinute = $rule->{'START_MINUTE'} < 10 ? "0" . $rule->{'START_MINUTE'} : $rule->{'START_MINUTE'};
            my $endHour     = $rule->{'END_HOUR'} < 10     ? "0" . $rule->{'END_HOUR'}     : $rule->{'END_HOUR'};
            my $endMinute   = $rule->{'END_MINUTE'} < 10   ? "0" . $rule->{'END_MINUTE'}   : $rule->{'END_MINUTE'};

            # Darren Critchley highlight the row we are editing
            if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} && $cgiparams{'RULE_POSITION'} eq $id) {
                print "<tr class='selectcolour'>";
            }
            else {
                print "<tr class='table".int(($id % 2) + 1)."colour'>";
            }
            print <<END;
    <td colspan='2' class='boldbase' />
    <td colspan='13' class='boldbase' align='left'>
        $Lang::tr{'rule active'}:&nbsp;
        $dayText
        &nbsp; $startHour:$startMinute
        &nbsp;
        $Lang::tr{'days to'}
        &nbsp;
        $endHour:$endMinute
    </td>
</tr>
END
        }

        # Change bgcolor when a new rule is added
        $id++;

    }    # end while (<RULES>)
    print "</table>";
}

# Validate Field Entries
sub validateSrcParams
{
    if ($cgiparams{'SRC_NET_TYPE'} eq 'defaultSrcNet') {
        my $foundIface = 0;
        if ($cgiparams{'DEFAULT_SRC_NET'} eq "Any") {
            $foundIface = 1;
        }
        else {
            foreach my $ifaceName (sort keys %FW::interfaces) {
                if ($cgiparams{'DEFAULT_SRC_NET'} eq $ifaceName) {
                    $foundIface = 1;
                    last;
                }
            }
        }

        if ($foundIface == 0) {
            $errormessage .= "$Lang::tr{'invalid iface'}<br />";
        }
    }
    elsif ($cgiparams{'SRC_NET_TYPE'} eq 'custSrcNet') {
        if ($cgiparams{'CUST_SRC_NET'} eq '' || $cgiparams{'CUST_SRC_NET'} eq 'BLANK') {
            $errormessage .= "$Lang::tr{'invalid iface'}<br />";
        }
    }
    else {
        $errormessage .= "$Lang::tr{'none iface type'}<br />";
    }

    if ($cgiparams{'SRC_ADR_TYPE'} eq 'textSrcAdr') {

        # change '-' in mac to ':'
        $cgiparams{'SRC_ADRESS_TXT'} =~ s/-/:/g;

        if ($cgiparams{'SRC_ADRESSFORMAT'} =~ /^ip$/) {
            if (!&General::validipormask($cgiparams{'SRC_ADRESS_TXT'})) {
                $errormessage .= "$Lang::tr{'ip bad'}<br />";
            }
        }
        elsif ($cgiparams{'SRC_ADRESSFORMAT'} =~ /^mac$/) {
            if (!&General::validmac($cgiparams{'SRC_ADRESS_TXT'})) {
                $errormessage .= "$Lang::tr{'mac bad'}<br />";
            }
        }
        else {
            $errormessage .= "$Lang::tr{'invalid addressformat'}<br />";
        }
    }
    elsif ($cgiparams{'SRC_ADR_TYPE'} eq 'defaultSrcAdr') {
        if ($cgiparams{'DEFAULT_SRC_ADR'} eq '') {
            $errormessage .= "$Lang::tr{'invalid net'}<br />";
        }
    }
    elsif ($cgiparams{'SRC_ADR_TYPE'} eq 'custSrcAdr') {
        if ($cgiparams{'CUST_SRC_ADR'} eq '' || $cgiparams{'CUST_SRC_ADR'} eq 'BLANK') {
            $errormessage .= "$Lang::tr{'invalid address'}<br />";
        }
    }
    elsif ($cgiparams{'SRC_ADR_TYPE'} eq 'groupSrcAdr') {
        if ($cgiparams{'GROUP_SRC_ADR'} eq '') {
            $errormessage .= "$Lang::tr{'invalid address group'}<br />";
        }
    }
    else {
        $errormessage .= "$Lang::tr{'none address type'}<br />";
    }

    if ($cgiparams{'INV_SRC_ADR'} ne 'on') {
        $cgiparams{'INV_SRC_ADR'} = 'off';
    }

    if ($cgiparams{'SRC_PORT_ON'} eq 'on') {
        $cgiparams{'SRC_PORT'} =~ tr/-/:/;

        my $validError = &General::validportrange($cgiparams{'SRC_PORT'}, 'src');
        if ($validError) {
            $errormessage .= "$validError<br />";
        }

        if ($cgiparams{'INV_SRC_PORT'} ne 'on') {
            $cgiparams{'INV_SRC_PORT'} = 'off';
        }
    }
    else {
        $cgiparams{'SRC_PORT'}     = '-';
        $cgiparams{'INV_SRC_PORT'} = 'off';
    }
    return;
}

sub validateDestParams
{
    unless ($cgiparams{'RULETYPE'} =~ /^(INPUT|OUTGOING|EXTERNAL|PINHOLES|PORTFW)$/) {
        $errormessage .= "$Lang::tr{'invalid dest'}<br />";
    }

    if($cgiparams{'RULETYPE'} eq 'PORTFW') {

        ######################
        ## Openfirewall external destination
        ######################
        if ($cgiparams{'PORTFW_EXT_ADR'} eq '') {
            $errormessage .= "$Lang::tr{'invalid openfirewall red address'}<br />";
        }

        if ($cgiparams{'PORTFW_SERVICE_TYPE'} eq 'custom') {

            # validproto
            if ($cgiparams{'PORTFW_CUST_SERVICE'} eq '' || $cgiparams{'PORTFW_CUST_SERVICE'} eq 'BLANK') {
                $errormessage .= "$Lang::tr{'invalid service'}<br />";
            }
        }
        elsif ($cgiparams{'PORTFW_SERVICE_TYPE'} eq 'default') {

            # validproto
            if ($cgiparams{'PORTFW_DEFAULT_SERVICE'} eq '' || $cgiparams{'PORTFW_DEFAULT_SERVICE'} eq 'BLANK') {
                $errormessage .= "$Lang::tr{'invalid service'}<br />";
            }
        }
        else {
            $errormessage .= "$Lang::tr{'none service type'}<br />";
        }

        # Check for reserved ports
        if($errormessage eq '') {
            # only needed for Openfirewall 'Red Adress', not necessary for an alias
            if($cgiparams{'PORTFW_EXT_ADR'} eq 'Red Address') {
                my %extService = ();
                &DATA::getServiceParams($cgiparams{'PORTFW_SERVICE_TYPE'}, $cgiparams{'PORTFW_CUST_SERVICE'}, $cgiparams{'PORTFW_DEFAULT_SERVICE'}, \%extService);

                if (&DATA::isReservedPort($extService{'PROTOCOL'}, $extService{'PORT'})) {
                    if($extService{'IS_RANGE'} ) {
                        $errormessage .= "$Lang::tr{'reserved external portrange'}<br />";
                    }
                    else {
                        $errormessage .= "$Lang::tr{'reserved external port'}<br />";
                    }
                }
            }
        }
    }

    if ($cgiparams{'RULETYPE'} eq 'OUTGOING' || $cgiparams{'RULETYPE'} eq 'PINHOLES' || $cgiparams{'RULETYPE'} eq 'PORTFW') {
        if ($cgiparams{'DST_NET_TYPE'} eq 'defaultDestNet') {
            my $foundIface = 0;

            # Any is not allowed in Pinholes and in Portforwarding
            if ($cgiparams{'DEFAULT_DST_NET'} eq "Any" && $cgiparams{'RULETYPE'} eq 'OUTGOING') {
                $foundIface = 1;
            }
            else {
                foreach my $ifaceName (sort keys %FW::interfaces) {
                    if ($cgiparams{'DEFAULT_DST_NET'} eq $ifaceName) {
                        $foundIface = 1;
                        last;
                    }
                }
            }

            if ($foundIface == 0) {
                $errormessage .= "$Lang::tr{'invalid iface'}<br />";
            }
        }
        elsif ($cgiparams{'DST_NET_TYPE'} eq 'custDestNet') {
            if ($cgiparams{'CUST_DST_NET'} eq '' || $cgiparams{'CUST_DST_NET'} eq 'BLANK') {
                $errormessage .= "$Lang::tr{'invalid iface'}<br />";
            }
        }
        else {
            $errormessage .= "$Lang::tr{'none iface type'}<br />";
        }

        if ($cgiparams{'DST_IP_TYPE'} eq 'defaultDstIP' && $cgiparams{'RULETYPE'} ne 'PORTFW') {
            if ($cgiparams{'DEFAULT_DST_IP'} eq '') {
                $errormessage .= "$Lang::tr{'invalid net'}<br />";
            }
        }
        elsif ($cgiparams{'DST_IP_TYPE'} eq 'custDestIP') {
            my %customAdr = ();
            &DATA::readCustAddresses(\%customAdr);

            if (   $cgiparams{'CUST_DST_ADR'} eq ''
                || $cgiparams{'CUST_DST_ADR'} eq 'BLANK'
                || !defined($customAdr{$cgiparams{'CUST_DST_ADR'}}))
            {
                $errormessage .= "$Lang::tr{'invalid address'}<br />";
            }

            if ($customAdr{$cgiparams{'CUST_DST_ADR'}}{'ADDRESS_TYPE'} eq 'mac') {
                $errormessage .= "$Lang::tr{'mac adr not as dest'}<br />";
            }
            elsif($cgiparams{'RULETYPE'} eq 'PORTFW') {
                my $mask = $customAdr{$cgiparams{'CUST_DST_ADR'}}{'NETMASK'};
                if($mask ne '32' && $mask ne '255.255.255.255') {
                    $errormessage .= "$Lang::tr{'only host ip adr allowed in portfw'}<br />";
                }
            }
        }
        elsif ($cgiparams{'DST_IP_TYPE'} eq 'ipDestTxt') {
            if($cgiparams{'RULETYPE'} eq 'PORTFW') {
                if (!&General::validip($cgiparams{'DEST_IP_TXT'})) {
                    $errormessage .= "$Lang::tr{'ip bad'}<br />";
                }
            }
            else {
                if (!&General::validipormask($cgiparams{'DEST_IP_TXT'})) {
                    $errormessage .= "$Lang::tr{'ip bad'}<br />";
                }
            }
        }
        elsif ($cgiparams{'DST_IP_TYPE'} eq 'groupDestIP' && $cgiparams{'RULETYPE'} ne 'PORTFW') {
            if ($cgiparams{'GROUP_DST_ADR'} eq '') {
                $errormessage .= "$Lang::tr{'invalid address group'}<br />";
            }
        }
        else {
            $errormessage .= "$Lang::tr{'none address type'}<br />";
        }

        if ($cgiparams{'INV_DST_IP'} ne 'on' || $cgiparams{'RULETYPE'} eq 'PORTFW') {
            $cgiparams{'INV_DST_IP'} = 'off';
        }
    }

    if (!defined($cgiparams{'SERVICE_ON'}) || $cgiparams{'SERVICE_ON'} ne 'on') {
        $cgiparams{'SERVICE_ON'} = 'off';
    }

    if ($cgiparams{'SERVICE_ON'} eq 'on') {

        if ($cgiparams{'SERVICE_TYPE'} eq 'serviceGroup' && $cgiparams{'RULETYPE'} ne 'PORTFW') {

            # validproto
            if ($cgiparams{'SERVICE_GROUP'} eq '') {
                $errormessage .= "$Lang::tr{'invalid service'}<br />";
            }
        }
        elsif ($cgiparams{'SERVICE_TYPE'} eq 'custom') {

            # validproto
            if ($cgiparams{'CUST_SERVICE'} eq '' || $cgiparams{'CUST_SERVICE'} eq 'BLANK') {
                $errormessage .= "$Lang::tr{'invalid service'}<br />";
            }
        }
        elsif ($cgiparams{'SERVICE_TYPE'} eq 'default') {

            # validproto
            if ($cgiparams{'DEFAULT_SERVICE'} eq '' || $cgiparams{'DEFAULT_SERVICE'} eq 'BLANK') {
                $errormessage .= "$Lang::tr{'invalid service'}<br />";
            }
        }
        else {
            $errormessage .= "$Lang::tr{'none service type'}<br />";
        }
    }

    # check if source and destination interface are the same,
    # only necessary for forward rules
    if ($cgiparams{'RULETYPE'} eq 'OUTGOING' || $cgiparams{'RULETYPE'} eq 'PINHOLES') {
        if (   $cgiparams{'DST_NET_TYPE'} eq 'defaultDestNet'
            && $cgiparams{'SRC_NET_TYPE'} eq 'defaultSrcNet')

        {
            if (   $cgiparams{'DEFAULT_SRC_NET'} eq $cgiparams{'DEFAULT_DST_NET'}
                && $cgiparams{'DEFAULT_SRC_NET'} ne 'Any')
            {
                $errormessage .= "$Lang::tr{'source iface and dest iface can not be same'}<br />";
            }
        }
        elsif ($cgiparams{'DST_NET_TYPE'} eq 'custDestNet'
            && $cgiparams{'SRC_NET_TYPE'} eq 'custSrcNet')
        {
            if (   $cgiparams{'CUST_SRC_NET'} eq $cgiparams{'CUST_DST_NET'})
            {
                $errormessage .= "$Lang::tr{'source iface and dest iface can not be same'}<br />";
            }
        }
    }

    # check if source and destination network/address are the same
    if (   $cgiparams{'DST_IP_TYPE'} eq 'defaultDstIP'
        && $cgiparams{'SRC_ADR_TYPE'} eq 'defaultSrcAdr')
    {
        if (   $cgiparams{'DEFAULT_SRC_ADR'} eq $cgiparams{'DEFAULT_DST_IP'}
            && $cgiparams{'INV_SRC_ADR'} eq $cgiparams{'INV_DST_IP'}
            && $cgiparams{'DEFAULT_SRC_ADR'} ne 'Any')
        {
            $errormessage .= "$Lang::tr{'source adr and dest adr can not be same'}<br />";
        }
    }
    elsif ($cgiparams{'DST_IP_TYPE'} eq 'custDestIP'
        && $cgiparams{'SRC_ADR_TYPE'} eq 'custSrcAdr')
    {
        if (   $cgiparams{'CUST_SRC_ADR'} eq $cgiparams{'CUST_DST_ADR'}
            && $cgiparams{'INV_SRC_ADR'} eq $cgiparams{'INV_DST_IP'})
        {
            $errormessage .= "$Lang::tr{'source adr and dest adr can not be same'}<br />";
        }
    }
    elsif ($cgiparams{'DST_IP_TYPE'} eq 'groupDestIP'
        && $cgiparams{'SRC_ADR_TYPE'} eq 'groupSrcAdr')
    {
        if (   $cgiparams{'GROUP_SRC_ADR'} eq $cgiparams{'GROUP_DST_ADR'}
            && $cgiparams{'INV_SRC_ADR'} eq $cgiparams{'INV_DST_IP'})
        {
            $errormessage .= "$Lang::tr{'source adr and dest adr can not be same'}<br />";
        }
    }

    return;
}

sub checkBetweenParams
{

    if($cgiparams{'RULETYPE'} eq 'PORTFW') {

        my %dest = ();
        &DATA::getServiceParams($cgiparams{'SERVICE_TYPE'}, $cgiparams{'CUST_SERVICE'}, $cgiparams{'DEFAULT_SERVICE'}, \%dest);

        my %ext = ();
        &DATA::getServiceParams($cgiparams{'PORTFW_SERVICE_TYPE'}, $cgiparams{'PORTFW_CUST_SERVICE'}, $cgiparams{'PORTFW_DEFAULT_SERVICE'}, \%ext);

        if($cgiparams{'PORTFW_SERVICE_TYPE'} eq 'custom') {
            if($ext{'PORT_INVERT'} eq 'on') {
                $errormessage .= "$Lang::tr{'invert port not allowed in portfw'}<br />";
            }
            if($ext{'PROTOCOL_INVERT'} eq 'on') {
                $errormessage .= "$Lang::tr{'invert proto not allowed in portfw'}<br />";
            }
        }

        if($cgiparams{'SERVICE_TYPE'} eq 'custom') {
            if($dest{'PORT_INVERT'} eq 'on') {
                $errormessage .= "$Lang::tr{'invert port not allowed in portfw'}<br />";
            }
            if($dest{'PROTOCOL_INVERT'} eq 'on') {
                $errormessage .= "$Lang::tr{'invert proto not allowed in portfw'}<br />";
            }
        }

        if( ($dest{'IS_RANGE'} || $ext{'IS_RANGE'}) && ($dest{'PORT'} ne $ext{'PORT'})) {
            $errormessage .= "$Lang::tr{'using portrange in portfw'}<br />";
        }
        if($dest{'PROTOCOL'} ne $ext{'PROTOCOL'}) {
            $errormessage .= "$Lang::tr{'same proto in portfw'}<br />";
        }
    }



    # Check if this is an advanced rule
    if ($cgiparams{'RULEACTION'} eq 'accept') {

        if ($cgiparams{'RULETYPE'} eq 'EXTERNAL') {

            # External Openfirewall access
            $warnOpenFwMessage .= "$Lang::tr{'rule opens your Firewall'}<br />";
        }
        elsif ($cgiparams{'RULETYPE'} eq 'PORTFW') {

            # Port forwording
            $warnOpenFwMessage .= "$Lang::tr{'rule opens your Firewall'}<br />";
        }
        elsif ($cgiparams{'RULETYPE'} eq 'INPUT') {

            # Openfirewall access
            if ($FW::fwSettings{'ADV_MODE_ENABLE'} ne 'on') {

                # only allow Openfirewall access from Green, Blue or VPN
                if (($cgiparams{'SRC_NET_TYPE'} eq 'defaultSrcNet') && ($FW::interfaces{$cgiparams{'DEFAULT_SRC_NET'}}{'COLOR'} eq 'ORANGE_COLOR')) {
                    $errormessage .= "$Lang::tr{'openfirewall access only from green blue and vpn'}<br />";
                }
            }
            else {
                if ($cgiparams{'SRC_NET_TYPE'} eq 'defaultSrcNet') {

                    # only allow Openfirewall access from Green, Blue or VPN
                    if ($FW::interfaces{$cgiparams{'DEFAULT_SRC_NET'}}{'COLOR'} eq 'ORANGE_COLOR') {
                        $errormessage .= "$Lang::tr{'openfirewall access only from green blue and vpn'}<br />";
                    }
                }
                else {    # we don't know if the custom source interface opens the Firewall
                    $warnOpenFwMessage .= "$Lang::tr{'rule can open your Firewall'}<br />";
                }
            }
        }
        elsif ($cgiparams{'RULETYPE'} eq 'OUTGOING' || $cgiparams{'RULETYPE'} eq 'PINHOLES') {

            # Internal traffic or outgoing traffic
            if ($cgiparams{'SRC_NET_TYPE'} eq 'defaultSrcNet') {
                if ($cgiparams{'DST_NET_TYPE'} eq 'defaultDestNet') {

                    if (   $cgiparams{'DEFAULT_SRC_NET'} eq 'Any'
                        || $FW::interfaces{$cgiparams{'DEFAULT_SRC_NET'}}{'COLOR'} eq 'RED_COLOR')
                    {
                        $warnOpenFwMessage .= "$Lang::tr{'rule opens your Firewall'}<br />";
                    }
                    elsif ($FW::interfaces{$cgiparams{'DEFAULT_SRC_NET'}}{'COLOR'} eq 'ORANGE_COLOR') {

                        # Orange is only allowed to access red
                        if ($FW::interfaces{$cgiparams{'DEFAULT_DST_NET'}}{'COLOR'} ne 'RED_COLOR')
                        {
                            $warnOpenFwMessage .= "$Lang::tr{'rule opens your Firewall'}<br />";
                        }
                    }
                    elsif ($FW::interfaces{$cgiparams{'DEFAULT_SRC_NET'}}{'COLOR'} eq 'BLUE_COLOR') {

                        # Blue is not allowed to access green/VPN
                        if ($FW::interfaces{$cgiparams{'DEFAULT_DST_NET'}}{'COLOR'} eq 'GREEN_COLOR'
                                || $FW::interfaces{$cgiparams{'DEFAULT_DST_NET'}}{'COLOR'} eq 'IPSEC_COLOR'
                                || $FW::interfaces{$cgiparams{'DEFAULT_DST_NET'}}{'COLOR'} eq 'OVPN_COLOR')
                        {
                            # destIface is: GREEN or VPN
                            $warnOpenFwMessage .= "$Lang::tr{'rule opens your Firewall'}<br />";
                        }
                    }
                }
                else {    # we don't know if the custom destination interface opens the Firewall

                    # Achim TODO: May check if the custom interface is external, if it is external it is like 'RED'
                    # -> no problem to open this

                    $warnOpenFwMessage .= "$Lang::tr{'rule can open your Firewall'}<br />";
                }
            }
            else {    # we don't know if the custom source interface opens the Firewall

                # Achim TODO: May check if the custom interface is internal and outgoing interface is RED/external
                # in this case it is no problem to open this

                $warnOpenFwMessage .= "$Lang::tr{'rule can open your Firewall'}<br />";
            }
        }
    }

    if ($warnOpenFwMessage) {
        $cgiparams{'RULEMODE'} = "adv";
    }
    else {
        $cgiparams{'RULEMODE'} = "std";
    }
}

sub validateAdditionalParams
{
    if (!defined($cgiparams{'ENABLED'}) || $cgiparams{'ENABLED'} ne 'on') {
        $cgiparams{'ENABLED'} = 'off';
    }

    if ($cgiparams{'LOG_ENABLED'} ne 'on') {
        $cgiparams{'LOG_ENABLED'} = 'off';
    }

    if ($cgiparams{'TIMEFRAME_ENABLED'} ne 'on') {
        $cgiparams{'TIMEFRAME_ENABLED'} = 'off';
    }

    # Darren Critchley - Remove commas from remarks
    $cgiparams{'REMARK'} = &stripcommas($cgiparams{'REMARK'});

    if ($cgiparams{'RULE_POSITION'} eq '') {
        $errormessage .= "$Lang::tr{'select rule position'}<br/>";
    }

    if ($cgiparams{'MATCH_STRING_ON'} eq 'on') {
        $cgiparams{'MATCH_STRING'} = &stripcommas($cgiparams{'MATCH_STRING'});

        if ($cgiparams{'INV_MATCH_STRING'} ne 'on') {
            $cgiparams{'INV_MATCH_STRING'} = 'off';
        }
    }
    else {
        $cgiparams{'MATCH_STRING_ON'} = 'off';
        $cgiparams{'MATCH_STRING'}    = "";
    }

    if ($cgiparams{'LIMIT_FOR'} =~ /^(none|log|acceptOrDeny|both)$/) {

        if ($cgiparams{'LIMIT_TYPE'} eq 'average') {
            if (
                !(
                       $cgiparams{'MATCH_LIMIT_AVG'} =~ /^\d+\/(sec|minute|hour|day)$/
                    || $cgiparams{'MATCH_LIMIT_AVG'} =~ /^\d+$/
                )
                )
            {
                $errormessage .=
"$Lang::tr{'invalid limit params'}:<br />max average match rate: default 10/minute [Packets per second unless followed by /sec /minute /hour /day suffixes]";
            }
        }
        elsif ($cgiparams{'LIMIT_TYPE'} eq 'burst') {
            unless ($cgiparams{'MATCH_LIMIT_BURST'} =~ /^\d+$/) {
                $errormessage .= "$Lang::tr{'invalid limit params'}:<br />number to match in a burst, default 5";
            }
        }
        else {
            $errormessage .= "$Lang::tr{'none limit type'}<br />";
        }
    }
    else {
        $errormessage .= "$Lang::tr{'none limit for'}<br />";
    }
    return;
}

sub validateTimeParams
{
    if ($cgiparams{'DAY_TYPE'} eq 'dayOfMonth') {
        unless ($cgiparams{'START_DAY_MONTH'} =~ /^\d+$/
            && $cgiparams{'START_DAY_MONTH'} >= 1
            && $cgiparams{'START_DAY_MONTH'} <= 31)
        {
            $errormessage .= "$Lang::tr{'invalid start day'}<br />";
        }
        unless ($cgiparams{'END_DAY_MONTH'} =~ /^\d+$/
            && $cgiparams{'END_DAY_MONTH'} >= 1
            && $cgiparams{'END_DAY_MONTH'} <= 31)
        {
            $errormessage .= "$Lang::tr{'invalid end day'}<br />";
        }
    }
    elsif ($cgiparams{'DAY_TYPE'} eq 'weekDays') {
        my $oneDayEnabled = 0;
        if ($cgiparams{'MON'} ne 'on') {
            $cgiparams{'MON'} = 'off';
            $oneDayEnabled++;
        }
        if ($cgiparams{'TUE'} ne 'on') {
            $cgiparams{'TUE'} = 'off';
            $oneDayEnabled++;
        }
        if ($cgiparams{'WED'} ne 'on') {
            $cgiparams{'WED'} = 'off';
            $oneDayEnabled++;
        }
        if ($cgiparams{'THU'} ne 'on') {
            $cgiparams{'THU'} = 'off';
            $oneDayEnabled++;
        }
        if ($cgiparams{'FRI'} ne 'on') {
            $cgiparams{'FRI'} = 'off';
            $oneDayEnabled++;
        }
        if ($cgiparams{'SAT'} ne 'on') {
            $cgiparams{'SAT'} = 'off';
            $oneDayEnabled++;
        }
        if ($cgiparams{'SUN'} ne 'on') {
            $cgiparams{'SUN'} = 'off';
            $oneDayEnabled++;
        }
        unless ($oneDayEnabled < 7) {
            $errormessage .= "$Lang::tr{'at least one day enabled'}<br />";
        }
    }
    else {
        $errormessage .= "$Lang::tr{'none day type'}<br />";
    }

    unless ($cgiparams{'START_HOUR'} =~ /^\d+$/
        && $cgiparams{'START_HOUR'} >= 0
        && $cgiparams{'START_HOUR'} <= 23)
    {
        $errormessage .= "$Lang::tr{'invalid start hour'}<br />";
    }

    unless ($cgiparams{'END_HOUR'} =~ /^\d+$/
        && $cgiparams{'END_HOUR'} >= 0
        && $cgiparams{'END_HOUR'} <= 23)
    {
        $errormessage .= "$Lang::tr{'invalid end hour'}<br />";
    }

    unless ($cgiparams{'START_MINUTE'} =~ /^\d+$/
        && $cgiparams{'START_MINUTE'} >= 0
        && $cgiparams{'START_MINUTE'} <= 59)
    {
        $errormessage .= "$Lang::tr{'invalid start minute'}<br />";
    }

    unless ($cgiparams{'END_MINUTE'} =~ /^\d+$/
        && $cgiparams{'END_MINUTE'} >= 0
        && $cgiparams{'END_MINUTE'} <= 59)
    {
        $errormessage .= "$Lang::tr{'invalid end minute'}<br />";
    }
    return;
}

# Darren Critchey - Replaces commas with spaces - stops users from messing up the config files
sub stripcommas
{
    my $outstring = $_[0];
    $outstring =~ tr/,/ /;
    $outstring =~ tr/\'/ /;    # noticed that ' messes the config file up so lets get rid of them too
    $outstring =~ tr/\"/ /;    # noticed that " messes config file up so lets get rid of them too
    return $outstring;
}

sub initAllParams
{
    &resetCgiParams();

    &General::getcgihash(\%cgiparams);

    &DATA::setup_default_networks(\%defaultNetworks);

    return;
}

sub resetCgiParams
{
    $cgiparams{'KEY1'}              = -1;
    $cgiparams{'RULE_POSITION'}     = -1;
    $cgiparams{'OLD_POSITION'}      = -1;
    $cgiparams{'RULEACTION'}        = '';
    $cgiparams{'RULEMODE'}          = 'std';
    $cgiparams{'ACTION'}            = '';
    $cgiparams{'SRC_NET_TYPE'}      = 'defaultSrcNet';
    $cgiparams{'DEFAULT_SRC_NET'}   = 'Green';
    $cgiparams{'CUST_SRC_NET'}      = '';
    $cgiparams{'SRC_ADR_TYPE'}      = 'defaultSrcAdr';
    $cgiparams{'DEFAULT_SRC_ADR'}   = 'Green Network';
    $cgiparams{'CUST_SRC_ADR'}      = '';
    $cgiparams{'GROUP_SRC_ADR'}     = '';
    $cgiparams{'SRC_ADRESSFORMAT'}  = 'ip';
    $cgiparams{'SRC_ADRESS_TXT'}    = '';
    $cgiparams{'INV_SRC_ADR'}       = 'off';
    $cgiparams{'SRC_PORT_ON'}       = 'off';
    $cgiparams{'SRC_PORT'}          = '';
    $cgiparams{'INV_SRC_PORT'}      = 'off';

    $cgiparams{'PORTFW_EXT_ADR'} = 'Red Address';
    $cgiparams{'PORTFW_SERVICE_TYPE'} = 'default';
    $cgiparams{'PORTFW_CUST_SERVICE'} = '--';
    $cgiparams{'PORTFW_DEFAULT_SERVICE'} = '--';

    $cgiparams{'RULETYPE'}          = 'OUTGOING';
    $cgiparams{'OLD_RULETYPE'}      = 'OUTGOING';
    $cgiparams{'DST_NET_TYPE'}      = 'defaultDestNet';
    $cgiparams{'DEFAULT_DST_NET'}   = 'Red';
    $cgiparams{'CUST_DST_NET'}      = '';
    $cgiparams{'DST_IP_TYPE'}       = 'defaultDstIP';
    $cgiparams{'DEFAULT_DST_IP'}    = 'Any';
    $cgiparams{'CUST_DST_ADR'}      = '';
    $cgiparams{'GROUP_DST_ADR'}     = '';
    $cgiparams{'DEST_IP_TXT'}       = '';
    $cgiparams{'GROUP_DST_ADR'}     = '';
    $cgiparams{'INV_DST_IP'}        = 'off';
    # Don't init SERVICE_ON so we can use it as checkbox with 'on' as default
    #$cgiparams{'SERVICE_ON'}        = 'on';
    $cgiparams{'SERVICE_TYPE'}      = 'default';
    $cgiparams{'SERVICE_GROUP'}     = '';
    # Don't init ENABLED so we can use it as checkbox with 'on' as default
    #$cgiparams{'ENABLED'}           = 'on';
    $cgiparams{'CUST_SERVICE'}      = '';
    $cgiparams{'DEFAULT_SERVICE'}   = '';
    $cgiparams{'LOG_ENABLED'}       = 'off';
    $cgiparams{'TIMEFRAME_ENABLED'} = 'off';
    $cgiparams{'REMARK'}            = '';
    $cgiparams{'MATCH_STRING_ON'}   = 'off';
    $cgiparams{'MATCH_STRING'}      = '';
    $cgiparams{'INV_MATCH_STRING'}  = 'off';
    $cgiparams{'LIMIT_FOR'}         = 'log';
    $cgiparams{'LIMIT_TYPE'}        = 'average';
    $cgiparams{'MATCH_LIMIT_AVG'}   = '10/minute';
    $cgiparams{'MATCH_LIMIT_BURST'} = '5';
    $cgiparams{'BOX_ACTION'}        = '';
    $cgiparams{'BOX_NAME'}          = '';
    $cgiparams{'ADV_CONFIG'}        = 'services';
    $cgiparams{'DAY_TYPE'}          = 'dayOfMonth';
    $cgiparams{'START_DAY_MONTH'}   = '1';
    $cgiparams{'END_DAY_MONTH'}     = '31';

    $cgiparams{'MON'} = 'off';
    $cgiparams{'TUE'} = 'off';
    $cgiparams{'WED'} = 'off';
    $cgiparams{'THU'} = 'off';
    $cgiparams{'FRI'} = 'off';
    $cgiparams{'SAT'} = 'off';
    $cgiparams{'SUN'} = 'off';

    $cgiparams{'START_HOUR'}   = '0';
    $cgiparams{'START_MINUTE'} = '0';
    $cgiparams{'END_HOUR'}     = '0';
    $cgiparams{'END_MINUTE'}   = '0';

    return;
}

sub printSelectNewRuleBox
{
    &Header::openbox('100%', 'left', "$Lang::tr{'add a new rule'}:", $error);

    print <<END;
<table width='100%'>
<tr>
    <td align='left'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
            <input type='submit' name='ACTION' value='$Lang::tr{'outgoing traffic'}' />
            <input type='hidden' name='RULETYPE' value='OUTGOING'  />
END
        &printHiddenFormParams('addNewRule');

    print <<END;
        </form>
    </td>
    <td align='left'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
           <input type='submit' name='ACTION' value='$Lang::tr{'openfirewall access'}' />
           <input type='hidden' name='RULETYPE' value='INPUT'  />
END
    &printHiddenFormParams('addNewRule');

    if (&FW::haveInternalNet()) {
        print <<END;
        </form>
    </td>
    <td align='left'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
            <input type='submit' name='ACTION' value='$Lang::tr{'internal traffic'}' />
            <input type='hidden' name='RULETYPE' value='PINHOLES'  />
END
        &printHiddenFormParams('addNewRule');
    }

        print <<END;
        </form>
    </td>
    <td align='left'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
           <input type='submit' name='ACTION' value='$Lang::tr{'ssport forwarding'}' />
           <input type='hidden' name='RULETYPE' value='PORTFW'  />
END
    &printHiddenFormParams('addNewRule');


    print <<END;
        </form>
    </td>
    <td align='left'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
            <input type='submit' name='ACTION' value='$Lang::tr{'external openfirewall access'}' />
            <input type='hidden' name='RULETYPE' value='EXTERNAL'  />
END
    &printHiddenFormParams('addNewRule');

    print <<END;
        </form>
    </td>
    <td align='left' width='90%'></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/firewall-fwrules.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END

    &Header::closebox();
}

sub printInvalidSettingsBox
{
    &Header::openbox('100%', 'left', '', $error);
    print <<END;
<table width='100%'>
<tr>
    <td align='left'>$Lang::tr{'settingsfile bad. please edit'}</td>
</tr>
<tr>
    <td align='center'>
        <form method='post' action='$FW::settingsCGI'>
            <input type='submit' name='ACTION' value='$Lang::tr{'edit'}' />
            <input type='hidden' name='EDIT_FORM' value='settings' />
        </form>
    </td>
</tr>
</table>
END
    &Header::closebox();
}

sub openEnterBox
{
    my $title = '';
    if ($cgiparams{'RULETYPE'} eq 'INPUT') {
        $title = $Lang::tr{'openfirewall access'};
    }
    elsif ($cgiparams{'RULETYPE'} eq 'OUTGOING') {
        $title = $Lang::tr{'outgoing traffic'};
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PINHOLES') {
        $title = $Lang::tr{'internal traffic'};
    }
    elsif ($cgiparams{'RULETYPE'} eq 'EXTERNAL') {
        $title = $Lang::tr{'external openfirewall access'};
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PORTFW') {
        $title = $Lang::tr{'ssport forwarding'};
    }

    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        &Header::openbox('100%', 'left', "$Lang::tr{'edit a rule'}: $title", $error);
    }
    else {
        &Header::openbox('100%', 'left', "$Lang::tr{'add a new rule'}: $title", $error);
    }
}

sub printEnterParamsBox
{
    &openEnterBox();


    # not existing here means they're undefined and the default value should be used
    $cgiparams{'SERVICE_ON'} = 'on' unless exists $cgiparams{'SERVICE_ON'};
    $cgiparams{'ENABLED'} = 'on'  unless exists $cgiparams{'ENABLED'};

############################################################################################
    # Source
############################################################################################

    $radio{'SRC_NET_TYPE'}{'defaultSrcNet'}            = '';
    $radio{'SRC_NET_TYPE'}{'custSrcNet'}               = '';
    $radio{'SRC_NET_TYPE'}{$cgiparams{'SRC_NET_TYPE'}} = "checked='checked'";

    $radio{'SRC_ADR_TYPE'}{'textSrcAdr'}               = '';
    $radio{'SRC_ADR_TYPE'}{'defaultSrcAdr'}            = '';
    $radio{'SRC_ADR_TYPE'}{'custSrcAdr'}               = '';
    $radio{'SRC_ADR_TYPE'}{'groupSrcAdr'}              = '';
    $radio{'SRC_ADR_TYPE'}{$cgiparams{'SRC_ADR_TYPE'}} = "checked='checked'";

    $selected{'SRC_ADRESSFORMAT'}{'ip'}                           = '';
    $selected{'SRC_ADRESSFORMAT'}{'mac'}                          = '';
    $selected{'SRC_ADRESSFORMAT'}{$cgiparams{'SRC_ADRESSFORMAT'}} = "selected='selected'";

    $checked{'INV_SRC_ADR'}{'off'}                     = '';
    $checked{'INV_SRC_ADR'}{'on'}                      = '';
    $checked{'INV_SRC_ADR'}{$cgiparams{'INV_SRC_ADR'}} = "checked='checked'";

    $checked{'SRC_PORT_ON'}{'off'}                     = '';
    $checked{'SRC_PORT_ON'}{'on'}                      = '';
    $checked{'SRC_PORT_ON'}{$cgiparams{'SRC_PORT_ON'}} = "checked='checked'";

    $checked{'INV_SRC_PORT'}{'off'}                      = '';
    $checked{'INV_SRC_PORT'}{'on'}                       = '';
    $checked{'INV_SRC_PORT'}{$cgiparams{'INV_SRC_PORT'}} = "checked='checked'";

    if ($cgiparams{'SRC_PORT_ON'} ne 'on') {
        $cgiparams{'SRC_PORT'} = '';
    }

    print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td class='boldbase'>$Lang::tr{'source'}</td>
</tr>
</table>
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td  width='4%' class='base'></td>
END

    if($cgiparams{'RULETYPE'} eq 'PORTFW')
    {
        # we filter source by Openfirewall external IP (red IP, Aliases etc.) -> don't restrict by interface
        print <<END;
    <td  width='1%' class='base'>
        <input type='hidden' name='SRC_NET_TYPE' value='defaultSrcNet'  />
    </td>
    <td colspan='2' class='base'>
        <input type='hidden' name='DEFAULT_SRC_NET' value='Any'  />
        <input type='hidden' name='CUST_SRC_NET' value='$cgiparams{'CUST_SRC_NET'}' />
    </td>
</tr>

END

    }
    else
    {
        # All but PORTFW rules
        my %customIfaces_src = ();
        my %customifacesCount_src = &DATA::readCustIfaces(\%customIfaces_src);
        my @customInterfaces_src = sort keys(%customIfaces_src);

        my $showCustomInterfacesInternal_src = 0;
        my $showCustomInterfacesExternal_src = 0;

        if($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on') {
            if($customifacesCount_src{'NUM_INTERNAL'} > 0
                && $cgiparams{'RULETYPE'} ne 'EXTERNAL') {
                $showCustomInterfacesInternal_src = 1;
            }
            if($customifacesCount_src{'NUM_EXTERNAL'} > 0
                && $cgiparams{'RULETYPE'} eq 'EXTERNAL') {
                $showCustomInterfacesExternal_src = 1;
            }
        }

        if($showCustomInterfacesInternal_src || $showCustomInterfacesExternal_src) {
            print <<END;
    <td  width='1%' class='base'>
        <input type='radio' name='SRC_NET_TYPE' value='defaultSrcNet' $radio{'SRC_NET_TYPE'}{'defaultSrcNet'} />
    </td>
    <td colspan='2' class='base'>
END
        }
        else
        {
                        print <<END;
    <td colspan='3' class='base'>
        <input type='hidden' name='SRC_NET_TYPE' value='defaultSrcNet' />
END
        }

print <<END;
        $Lang::tr{'default interfaces'}:&nbsp;
        <select name='DEFAULT_SRC_NET'>
END

        # External Access for external interface(s) only
        # Input, Pinholes and Outgoing rules for internal interfaces only
        # Portforwards are special, and handled separately
        foreach my $iface (sort keys %FW::interfaces) {

            # Check for external OK
            next if (($cgiparams{'RULETYPE'} eq 'EXTERNAL') && ($FW::interfaces{$iface}{'COLOR'} ne 'RED_COLOR'));
            # Check for internal OK
            next if (($cgiparams{'RULETYPE'} ne 'EXTERNAL') && ($FW::interfaces{$iface}{'COLOR'} eq 'RED_COLOR'));

            print "<option value='$iface'";
            print " selected='selected'" if ($cgiparams{'DEFAULT_SRC_NET'} eq $iface);
            print ">".&General::translateinterface($iface)."</option>";
        }

        print <<END;
        </select>
    </td>
</tr>
END

        if ($showCustomInterfacesInternal_src || $showCustomInterfacesExternal_src)
        {    # show this option only if there are Custom Interfaces available
            print <<END;
<tr>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='SRC_NET_TYPE' value='custSrcNet' $radio{'SRC_NET_TYPE'}{'custSrcNet'} />
    </td>
    <td colspan='2' class='base'>
        $Lang::tr{'custom interfaces'}:&nbsp;
        <select name='CUST_SRC_NET'>
END

            foreach my $iface (@customInterfaces_src) {
                if( ($showCustomInterfacesInternal_src && $customIfaces_src{$iface}{'EXTERNAL'} ne 'on')
                    || ($showCustomInterfacesExternal_src && $customIfaces_src{$iface}{'EXTERNAL'} eq 'on') ) {
                    print "<option value='$iface'";
                    print " selected='selected'" if ($cgiparams{'CUST_SRC_NET'} eq $iface);
                    print ">".&General::translateinterface($iface)."</option>";
                }
            }
            print <<END;
        </select>
    </td>
</tr>
END
        }
        else {
            print
    "<tr><td colspan='4'><input type='hidden' name='CUST_SRC_NET' value='$cgiparams{'CUST_SRC_NET'}' /></td></tr>\n";
        }

        print <<END;
<tr>
    <td></td>
    <td colspan='3' bgcolor='#000000'><img src='/images/null.gif' width='1' height='1' border='0' alt='--------' /></td>
</tr>
END

    }

    if ($cgiparams{'RULETYPE'} eq 'EXTERNAL' || $cgiparams{'RULETYPE'} eq 'PORTFW') {
        print <<END;
<tr>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='SRC_ADR_TYPE' value='defaultSrcAdr' $radio{'SRC_ADR_TYPE'}{'defaultSrcAdr'} />
    </td>
    <td colspan='2' class='base'>
        $Lang::tr{'address'}:&nbsp;
        Any&nbsp;
        <input type='hidden' name='DEFAULT_SRC_ADR' value='Any' />
    </td>
</tr>
END
    }
    else
    {
        print <<END;
<tr>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='SRC_ADR_TYPE' value='defaultSrcAdr' $radio{'SRC_ADR_TYPE'}{'defaultSrcAdr'} />
    </td>
    <td colspan='2' class='base'>
        $Lang::tr{'default networks'}:&nbsp;
        <select name='DEFAULT_SRC_ADR'>
END
        foreach my $network (sort keys %defaultNetworks) {
            next if ($defaultNetworks{$network}{'LOCATION'} eq "IPCOP");
            print "<option value='$network'";
            print " selected='selected'" if ($cgiparams{'DEFAULT_SRC_ADR'} eq $network);
            print ">$network</option>";
        }

        print <<END;
        </select>
    </td>
</tr>
END
    }

    print <<END;
<tr>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='SRC_ADR_TYPE' value='textSrcAdr' $radio{'SRC_ADR_TYPE'}{'textSrcAdr'} />
    </td>
    <td class='base' width='25%'>
        $Lang::tr{'addressformat'}:&nbsp;
        <select name='SRC_ADRESSFORMAT'>
            <option value='ip' $selected{'SRC_ADRESSFORMAT'}{'ip'}>IP</option>
            <option value='mac' $selected{'SRC_ADRESSFORMAT'}{'mac'}>MAC</option>
        </select>
    </td>
    <td class='base' width='70%' align='left' >
        $Lang::tr{'source address'}:&nbsp;
        <input type='text' name='SRC_ADRESS_TXT' value='$cgiparams{'SRC_ADRESS_TXT'}' size='20' maxlength='18' />&nbsp;
    </td>
</tr>
END


    my %customAdr = ();
    &DATA::readCustAddresses(\%customAdr);
    my @customAddresses = sort keys(%customAdr);

    if ($#customAddresses >= 0) {    # show this option only if there are Custom Networks available
        print <<END;
<tr>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='SRC_ADR_TYPE' value='custSrcAdr' $radio{'SRC_ADR_TYPE'}{'custSrcAdr'} />
    </td>
    <td colspan='2' class='base'>
        $Lang::tr{'custom addresses'}:&nbsp;
        <select name='CUST_SRC_ADR'>
END
        print "<option value='BLANK' selected='selected'>N/A</option>" if ($#customAddresses < 0);
        foreach my $adr (@customAddresses) {
            print "<option value='$adr'";
            print " selected='selected'" if ($cgiparams{'CUST_SRC_ADR'} eq $adr);
            print ">$adr</option>";

        }
        print <<END;
        </select>
    </td>
</tr>
END
    }
    else {
        print
"<tr><td colspan='4'><input type='hidden' name='CUST_SRC_ADR' value='$cgiparams{'CUST_SRC_ADR'}' /></td></tr>\n";
    }

###########

    my %addressGroupConf = ();
    &DATA::readAddressGroupConf(\%addressGroupConf);
    my @adrGroups = sort keys(%addressGroupConf);

    if ($#adrGroups >= 0) {    # show this option only if there are address groups available
        print <<END;
<tr>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='SRC_ADR_TYPE' value='groupSrcAdr' $radio{'SRC_ADR_TYPE'}{'groupSrcAdr'} />
    </td>
    <td colspan='2' class='base'>
        $Lang::tr{'address groups'}:&nbsp;
        <select name='GROUP_SRC_ADR'>
END
        print "<option value='BLANK' selected='selected'>N/A</option>" if ($#adrGroups < 0);
        foreach my $adrGroup (@adrGroups) {
            print "<option value='$adrGroup'";
            print " selected='selected'" if ($cgiparams{'GROUP_SRC_ADR'} eq $adrGroup);
            print ">$adrGroup</option>";

        }
        print <<END;
        </select>
    </td>
</tr>
END
    }
    else {
        print
"<tr><td colspan='4'><input type='hidden' name='GROUP_SRC_ADR' value='$cgiparams{'GROUP_SRC_ADR'}' /></td></tr>\n";
    }
#######
    if ($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on' && $cgiparams{'RULETYPE'} ne 'PORTFW') {

        print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td colspan='2' class='base'>
        &nbsp; <input type='checkbox' name='INV_SRC_ADR' $checked{'INV_SRC_ADR'}{'on'} />
        $Lang::tr{'fw invert'}&nbsp;
    </td>
</tr>
END
    }
    else {
        print "<tr><td colspan='4'><input type='hidden' name='INV_SRC_ADR' value='off' /></td></tr>\n";
    }

    if ($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on'|| $cgiparams{'RULETYPE'} eq 'PORTFW') {
        print <<END;
<tr>
    <td></td>
    <td colspan='3' bgcolor='#000000'><img src='/images/null.gif' width='1' height='1' border='0' alt='--------' /></td>
</tr>
<tr>
    <td class='base'></td>
    <td class='base'>
        <input type='checkbox' name='SRC_PORT_ON' $checked{'SRC_PORT_ON'}{'on'} />
    </td>
    <td colspan='2' class='base'>
        $Lang::tr{'use src port'}:
    </td>
</tr>
<tr>
    <td class='base'></td>
    <td class='base'>
    </td>
    <td colspan='2' class='base' >
        $Lang::tr{'source port'}:&nbsp;
        <input type='text' name='SRC_PORT' value='$cgiparams{'SRC_PORT'}' size='14' maxlength='12' />
    </td>
</tr>
END
        if($cgiparams{'RULETYPE'} ne 'PORTFW') {
            print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td colspan='2' class='base'>
        &nbsp; <input type='checkbox' name='INV_SRC_PORT' $checked{'INV_SRC_PORT'}{'on'} />
        $Lang::tr{'fw invert'}&nbsp;
    </td>
</tr>
END
        }
        else
        {
            print "<tr><td colspan='4'>\n";
            print "<input type='hidden' name='INV_SRC_PORT' value='off' /></td></tr>\n";
        }
    }
    else {
        print "<tr><td colspan='4'><input type='hidden' name='SRC_PORT_ON' value='off' />\n";
        print "<input type='hidden' name='SRC_PORT' value='' />\n";
        print "<input type='hidden' name='INV_SRC_PORT' value='off' /></td></tr>\n";
    }
    print <<END;
<tr>
    <td colspan='4' bgcolor='#000000'><img src='/images/null.gif' width='1' height='2' border='0' alt='--------' /></td>
</tr>
</table>
END


###########################################################################################
    # Openfirewall external destination for Port Forwarding
############################################################################################
    if ($cgiparams{'RULETYPE'} eq 'PORTFW') {

    $radio{'PORTFW_SERVICE_TYPE'}{'custom'}                   = '';
    $radio{'PORTFW_SERVICE_TYPE'}{'default'}                  = '';
    $radio{'PORTFW_SERVICE_TYPE'}{$cgiparams{'PORTFW_SERVICE_TYPE'}} = "checked='checked'";

        print <<END;
<table width='100%'>
<tr>
    <td class='boldbase'>$Lang::tr{'pfw openfirewall destination'}</td>
</tr>
</table>

<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td  width='4%' class='base'></td>
    <td  width='1%' class='base'></td>
    <td colspan='2' class='base'>
        $Lang::tr{'alias ip'}:&nbsp;
        <select name='PORTFW_EXT_ADR'>
END
        foreach my $ofwAdr (sort keys %defaultNetworks) {
            next unless ($defaultNetworks{$ofwAdr}{'LOCATION'} eq "IPCOP" && $defaultNetworks{$ofwAdr}{'COLOR'} eq "RED_COLOR");

            my $aliasIp = "";
            $aliasIp = " ($defaultNetworks{$ofwAdr}{'ADR'})" if($ofwAdr ne 'Red Address');
            print "<option value='$ofwAdr'";
            print " selected='selected'" if ($cgiparams{'PORTFW_EXT_ADR'} eq $ofwAdr);
            print ">".$ofwAdr.$aliasIp."</option>";
        }

        print <<END;
        </select>
    </td>
</tr>
END


  my %customSrv_pfw = ();
    &DATA::readCustServices(\%customSrv_pfw);
    my @customServices_pfw = keys(%customSrv_pfw);

    if ($#customServices_pfw >= 0) {
        print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='PORTFW_SERVICE_TYPE' value='custom' $radio{'PORTFW_SERVICE_TYPE'}{'custom'} />
        $Lang::tr{'custom services'}:&nbsp;
        <select name='PORTFW_CUST_SERVICE'>
END
        print "<option value='BLANK' selected='selected'>N/A</option>" if ($#customServices_pfw < 0);
        foreach my $service (sort @customServices_pfw) {
            print "<option value='$service'";
            print " selected='selected'" if ($cgiparams{'PORTFW_CUST_SERVICE'} eq $service);
            print ">$service</option>";

        }
        print <<END;
        </select>
    </td>
</tr>
END
    }
    else {
        print
"<tr><td colspan='3'><input type='hidden' name='PORTFW_CUST_SERVICE' value='$cgiparams{'PORTFW_CUST_SERVICE'}' /></td></tr>\n";
    }
    print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
END

if($#customServices_pfw >= 0) {
    print"<input type='radio' name='PORTFW_SERVICE_TYPE' value='default' $radio{'PORTFW_SERVICE_TYPE'}{'default'} />\n";
}
else
{
    print"<input type='hidden' name='PORTFW_SERVICE_TYPE' value='default' />\n";
}

print <<END;
        $Lang::tr{'default services'}:&nbsp;
        <select name='PORTFW_DEFAULT_SERVICE'>
END

    my %defaultServices_pfw = ();
    &DATA::readDefaultServices(\%defaultServices_pfw);

    print "<option value='BLANK'";
    print "selected='selected'" if ($cgiparams{'PORTFW_DEFAULT_SERVICE'} eq '');
    print ">-- $Lang::tr{'default services'} --</option>";
    foreach my $defService (sort keys %defaultServices_pfw) {
        print "<option value='$defService'";
        print " selected='selected'" if ($cgiparams{'PORTFW_DEFAULT_SERVICE'} eq $defService);
        print ">$defService ($defaultServices_pfw{$defService}{'PORT_NR'})</option>";

    }
    print <<END;
        </select>
    </td>
</tr>
<tr>
    <td colspan='4' bgcolor='#000000'><img src='/images/null.gif' width='1' height='2' border='0' alt='--------' /></td>
</tr>
</table>
END
    }
    else {
        print <<END;
<table width='100%' cellpadding='0' cellspacing='0' border='0'>
<tr>
    <td >
        <input type='hidden' name='PORTFW_EXT_ADR' value='--' />
        <input type='hidden' name='PORTFW_SERVICE_TYPE' value='--' />
        <input type='hidden' name='PORTFW_CUST_SERVICE' value='--' />
        <input type='hidden' name='PORTFW_DEFAULT_SERVICE' value='--' />
    </td>
</tr>
</table>
END
    }


###########################################################################################
    # Destination
############################################################################################

    my $ruletype_text = $Lang::tr{'openfirewall access'};
    my $destination_text = $Lang::tr{'destination'};
    if ($cgiparams{'RULETYPE'} eq 'OUTGOING') {
        $ruletype_text = $Lang::tr{'outgoing traffic'};
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PINHOLES') {
        $ruletype_text = $Lang::tr{'internal traffic'};
        # Change default destination interface to green
        $cgiparams{'DEFAULT_DST_NET'} = 'Green' if ($cgiparams{'DEFAULT_DST_NET'} eq 'Red');
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PORTFW') {
        $destination_text = $Lang::tr{'pfw internal destination'};
        $ruletype_text = $Lang::tr{'internal network'};
        # Change default destination interface to orange if it exists
        $cgiparams{'DEFAULT_DST_NET'} = 'Orange' if (&FW::haveOrangeNet() && ($cgiparams{'DEFAULT_DST_NET'} eq 'Red'));
    }
    elsif ($cgiparams{'RULETYPE'} eq 'EXTERNAL') {
        $ruletype_text = $Lang::tr{'external openfirewall access'};
    }

    $radio{'RULETYPE'}{'INPUT'}                = '';
    $radio{'RULETYPE'}{'OUTGOING'}              = '';
    $radio{'RULETYPE'}{'EXTERNAL'}             = '';
    $radio{'RULETYPE'}{'PINHOLES'}             = '';
    $radio{'RULETYPE'}{$cgiparams{'RULETYPE'}} = "checked='checked'";

    $radio{'DST_NET_TYPE'}{'defaultDestNet'}           = '';
    $radio{'DST_NET_TYPE'}{'custDestNet'}              = '';
    $radio{'DST_NET_TYPE'}{$cgiparams{'DST_NET_TYPE'}} = "checked='checked'";

    $radio{'DST_IP_TYPE'}{'defaultDstIP'}            = '';
    $radio{'DST_IP_TYPE'}{'custDestIP'}              = '';
    $radio{'DST_IP_TYPE'}{'groupDestIP'}             = '';
    $radio{'DST_IP_TYPE'}{'ipDestTxt'}               = '';
    if($cgiparams{'RULETYPE'} eq 'PORTFW'
        && $cgiparams{'DST_IP_TYPE'} ne 'custDestIP'
        && $cgiparams{'DST_IP_TYPE'} ne 'ipDestTxt') {
        $cgiparams{'DST_IP_TYPE'} = 'custDestIP';
    }
    $radio{'DST_IP_TYPE'}{$cgiparams{'DST_IP_TYPE'}} = "checked='checked'";

    $checked{'INV_DST_IP'}{'off'}                    = '';
    $checked{'INV_DST_IP'}{'on'}                     = '';
    $checked{'INV_DST_IP'}{$cgiparams{'INV_DST_IP'}} = "checked='checked'";

    $checked{'SERVICE_ON'}{'off'}                    = '';
    $checked{'SERVICE_ON'}{'on'}                     = '';
    $checked{'SERVICE_ON'}{$cgiparams{'SERVICE_ON'}} = "checked='checked'";

    $radio{'SERVICE_TYPE'}{'custom'}                   = '';
    $radio{'SERVICE_TYPE'}{'default'}                  = '';
    $radio{'SERVICE_TYPE'}{'serviceGroup'}             = '';
    $radio{'SERVICE_TYPE'}{$cgiparams{'SERVICE_TYPE'}} = "checked='checked'";

    print <<END;
<table width='100%'>
<tr>
    <td class='boldbase' >$destination_text
    </td>
</tr>
</table>

<table width='100%' cellpadding='0' cellspacing='5' border='0'>
END

        print <<END;
<tr>
    <td width='4%' class='base' />
    <td width='1%' class='base' />
    <td width='95%' class='base' />
</tr>
<tr>
    <td class='base'></td>
    <td colspan='2' class='base'>
        $ruletype_text
        <input type='hidden' name='RULETYPE' value='$cgiparams{'RULETYPE'}' />
    </td>
</tr>
END

    if ($cgiparams{'RULETYPE'} ne 'EXTERNAL' && $cgiparams{'RULETYPE'} ne 'INPUT')
    {

        my %customIfaces_dst = ();
        my %customifacesCount_dst = &DATA::readCustIfaces(\%customIfaces_dst);
        my @customInterfaces_dst = sort keys(%customIfaces_dst);
        my $showCustomInterfacesInternal_dst = 0;
        my $showCustomInterfacesExternal_dst = 0;

        if($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on') {
            if($customifacesCount_dst{'NUM_INTERNAL'} > 0
                && ($cgiparams{'RULETYPE'} eq 'PINHOLES' || $cgiparams{'RULETYPE'} eq 'PORTFW' )) {
                $showCustomInterfacesInternal_dst = 1;
            }
            if($customifacesCount_dst{'NUM_EXTERNAL'} > 0
                && $cgiparams{'RULETYPE'} eq 'OUTGOING') {
                $showCustomInterfacesExternal_dst = 1;
            }
        }

        print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
END

        if($showCustomInterfacesInternal_dst || $showCustomInterfacesExternal_dst) {
            print "<input type='radio' name='DST_NET_TYPE' value='defaultDestNet' $radio{'DST_NET_TYPE'}{'defaultDestNet'} />\n";
        }
        else {
            print "<input type='hidden' name='DST_NET_TYPE' value='defaultDestNet' $radio{'DST_NET_TYPE'}{'defaultDestNet'} />\n";
        }

        print <<END;
        $Lang::tr{'default interfaces'}:&nbsp;
        <select name='DEFAULT_DST_NET'>
END
            foreach my $iface (sort keys %FW::interfaces) {

                if($cgiparams{'RULETYPE'} eq 'OUTGOING')
                {
                    # Outgoing, only red
                    next if ($FW::interfaces{$iface}{'COLOR'} ne 'RED_COLOR');
                }

                if($cgiparams{'RULETYPE'} eq 'PINHOLES' ||  $cgiparams{'RULETYPE'} eq 'PORTFW')
                {
                    # Internal traffic or port forwarding, only internal interfaces
                    next if ($FW::interfaces{$iface}{'COLOR'} eq 'RED_COLOR');
                }

                print "<option value='$iface'";
                print " selected='selected'" if ($cgiparams{'DEFAULT_DST_NET'} eq $iface);
                print ">".&General::translateinterface($iface)."</option>";
            }

            print <<END;
        </select>
    </td>
</tr>
END
#~ print<<END;
#~ <tr>
#~     <td colspan='3'>
#~         <input type='hidden' name='CUST_DST_NET' value='$cgiparams{'CUST_DST_NET'}' />
#~     </td>
#~ </tr>
#~ END

#~         }
#~         elsif ($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on') {

#~             # Advanced mode is on and we don't have a Pinhole rule
#~         else {

#~             # Default interfaces
#~             print <<END;
#~ <tr>
#~     <td class='base'></td>
#~     <td class='base'></td>
#~     <td class='base'>
#~         <input type='radio' name='DST_NET_TYPE' value='defaultDestNet' $radio{'DST_NET_TYPE'}{'defaultDestNet'} />
#~         $Lang::tr{'default interfaces'}:&nbsp;
#~         <select name='DEFAULT_DST_NET'>
#~ END
#~             foreach my $iface (sort keys %FW::interfaces) {
#~                 print "<option value='$iface'";
#~                 print " selected='selected'" if ($cgiparams{'DEFAULT_DST_NET'} eq $iface);
#~                 print ">".&General::translateinterface($iface)."</option>";
#~             }

#~             print <<END;
#~         </select>
#~     </td>
#~ </tr>
#~ END


            # Custom interfaces
            if ($showCustomInterfacesInternal_dst || $showCustomInterfacesExternal_dst) {

                # show this option only if there are Custom Networks available
                print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='DST_NET_TYPE' value='custDestNet' $radio{'DST_NET_TYPE'}{'custDestNet'} />
        $Lang::tr{'custom interfaces'}:&nbsp;
        <select name='CUST_DST_NET'>
END
                print "<option value='BLANK' selected='selected'>N/A</option>" if ($#customInterfaces_dst < 0);
                foreach my $iface (@customInterfaces_dst) {
                    if( ($showCustomInterfacesInternal_dst && $customIfaces_dst{$iface}{'EXTERNAL'} ne 'on')
                        || ($showCustomInterfacesExternal_dst && $customIfaces_dst{$iface}{'EXTERNAL'} eq 'on') ) {
                        print "<option value='$iface'";
                        print " selected='selected'" if ($cgiparams{'CUST_DST_NET'} eq $iface);
                        print ">".&General::translateinterface($iface)."</option>";
                    }
                }
                print <<END;
        </select>
    </td>
</tr>
END
            }
            else {
                print
"<tr><td colspan='3'><input type='hidden' name='CUST_DST_NET' value='$cgiparams{'CUST_DST_NET'}' /></td></tr>\n";
            }

#~         }
#~         else {
#~             print "<input type='hidden' name='DEFAULT_DST_NET' value='$cgiparams{'DEFAULT_DST_NET'}' />\n";
#~             print "<input type='hidden' name='CUST_DST_NET' value='$cgiparams{'CUST_DST_NET'}' />\n";
#~         }

        print <<END;
<tr>
    <td colspan='3' class='base'>&nbsp;</td>
</tr>
END

        my $showDestDefaultAdr = 0;

        if($cgiparams{'RULETYPE'} eq 'PORTFW') {
            print "<tr><td colspan='3'><input type='hidden' name='DEFAULT_DST_IP' value='-' /></td></tr>\n";
        }
        else {
            $showDestDefaultAdr = 1;
            print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='DST_IP_TYPE' value='defaultDstIP' $radio{'DST_IP_TYPE'}{'defaultDstIP'} />
        $Lang::tr{'default networks'}:&nbsp;
        <select name='DEFAULT_DST_IP'>
END
            foreach my $network (sort keys %defaultNetworks) {
                next if ($defaultNetworks{$network}{'LOCATION'} eq "IPCOP");
                print "<option value='$network'";
                print " selected='selected'" if ($cgiparams{'DEFAULT_DST_IP'} eq $network);
                print ">$network</option>";
            }

            print <<END;
        </select>
    </td>
</tr>
END
        }

        my $showDestCustAdr = 0;
        if ($#customAddresses >= 0) {
            $showDestCustAdr = 1;

            # show this option only if there are Custom Networks available
            print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='DST_IP_TYPE' value='custDestIP' $radio{'DST_IP_TYPE'}{'custDestIP'} />
        $Lang::tr{'custom addresses'}:&nbsp;
        <select name='CUST_DST_ADR'>
END
            print "<option value='BLANK' selected='selected'>N/A</option>" if ($#customAddresses < 0);
            foreach my $adr (sort @customAddresses) {
                print "<option value='$adr'";
                print " selected='selected'" if ($cgiparams{'CUST_DST_ADR'} eq $adr);
                print ">$adr</option>";

            }
            print <<END;
        </select>
    </td>
</tr>
END
        }
        else {
            if($cgiparams{'RULETYPE'} eq 'PORTFW') {
                # Fall back to text input
                $radio{'DST_IP_TYPE'}{'ipDestTxt'} = "checked='checked'";
            }
            print
"<tr><td colspan='3'><input type='hidden' name='CUST_DST_ADR' value='$cgiparams{'CUST_DST_ADR'}' /></td></tr>\n";
        }

##########################################
        my $showDestAdrGrp = 0;
        if ($#adrGroups >= 0 &&  $cgiparams{'RULETYPE'} ne 'PORTFW') {    # show this option only if there are address groups available
            $showDestAdrGrp = 1;
            print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='DST_IP_TYPE' value='groupDestIP' $radio{'DST_IP_TYPE'}{'groupDestIP'} />
        $Lang::tr{'address groups'}:&nbsp;
        <select name='GROUP_DST_ADR'>
END
            print "<option value='BLANK' selected='selected'>N/A</option>" if ($#adrGroups < 0);
            foreach my $adrGroup (@adrGroups) {
                print "<option value='$adrGroup'";
                print " selected='selected'" if ($cgiparams{'GROUP_DST_ADR'} eq $adrGroup);
                print ">$adrGroup</option>";

            }
            print <<END;
        </select>
    </td>
</tr>
END
        }
        else {
            print
"<tr><td colspan='3'><input type='hidden' name='GROUP_DST_ADR' value='$cgiparams{'GROUP_DST_ADR'}' /></td></tr>\n";
        }

        my $dstIpTxtLabel = $Lang::tr{'destination ip or net'};
        if( $cgiparams{'RULETYPE'} eq 'PORTFW') {
            $dstIpTxtLabel =  $Lang::tr{'destination ip'};
        }
        print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
END

if($showDestDefaultAdr || $showDestCustAdr || $showDestAdrGrp) {
    print"<input type='radio' name='DST_IP_TYPE' value='ipDestTxt' $radio{'DST_IP_TYPE'}{'ipDestTxt'} />\n";
}
else
{
    print"<input type='hidden' name='DST_IP_TYPE' value='ipDestTxt' />\n";
}

print <<END;

        $dstIpTxtLabel:&nbsp;
        <input type='text' name='DEST_IP_TXT' value='$cgiparams{'DEST_IP_TXT'}' size='21' maxlength='19' />
    </td>
</tr>
END
        if ($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on' &&  $cgiparams{'RULETYPE'} ne 'PORTFW') {

            print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
        &nbsp; <input type='checkbox' name='INV_DST_IP' $checked{'INV_DST_IP'}{'on'} />
        $Lang::tr{'fw invert'}&nbsp;
    </td>
</tr>
END
        }
        else
        {
            print "<tr><td colspan='3'><input type='hidden' name='INV_DST_IP' value='off' /></td></tr>\n";

        }
        print <<END;
<tr>
    <td></td>
    <td colspan='2' bgcolor='#000000'><img src='/images/null.gif' width='1' height='1' border='0' alt='--------' /></td>
</tr>
END
    }
    else {

        # this is an [External] Openfirewall Access  rule
        print <<END;
<tr>
    <td colspan='3'>
        <input type='hidden' name='DST_NET_TYPE' value='$cgiparams{'DST_NET_TYPE'}' />
        <input type='hidden' name='DEFAULT_DST_NET' value='$cgiparams{'DEFAULT_DST_NET'}' />
        <input type='hidden' name='CUST_DST_NET' value='$cgiparams{'CUST_DST_NET'}' />

        <input type='hidden' name='DST_IP_TYPE' value='$cgiparams{'DST_IP_TYPE'}' />
        <input type='hidden' name='DEST_IP_TXT' value='$cgiparams{'DEST_IP_TXT'}' />
        <input type='hidden' name='GROUP_DST_ADR' value='$cgiparams{'GROUP_DST_ADR'}' />
        <input type='hidden' name='CUST_DST_ADR' value='$cgiparams{'CUST_DST_ADR'}' />
        <input type='hidden' name='INV_DST_IP' value='$cgiparams{'INV_DST_IP'}' />
    </td>
</tr>
END
    }

    print <<END;
<tr>
    <td class='base'></td>
END

    if($cgiparams{'RULETYPE'} ne 'EXTERNAL' && $cgiparams{'RULETYPE'} ne 'PORTFW') {
        print <<END;
    <td class='base'>
        <input type='checkbox' name='SERVICE_ON' $checked{'SERVICE_ON'}{'on'} />
    </td>
    <td class='base'>
        $Lang::tr{'use Service'}&nbsp;
END
    }
    else
    {
        print <<END;
    <td class='base' colspan='2'>
    <input type='hidden' name='SERVICE_ON' value='on' />
END
        print"\n";
    }
    print <<END;
    </td>
</tr>
END

    my %groupConf;
    &DATA::readServiceGroupConf(\%groupConf);

    my @existingGroups      = sort(keys(%groupConf));
    my $existingGroupsCount = @existingGroups;
    my $showServiceGroups = 0;
    if ($existingGroupsCount > 0 && $cgiparams{'RULETYPE'} ne 'PORTFW') {
        $showServiceGroups = 1;
        print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='SERVICE_TYPE' value='serviceGroup' $radio{'SERVICE_TYPE'}{'serviceGroup'} />
        $Lang::tr{'service groups'}:&nbsp;
        <select name='SERVICE_GROUP'>
END
        foreach my $group (@existingGroups) {
            print "<option value='$group' ";
            print " selected='selected'" if ($cgiparams{'SERVICE_GROUP'} eq $group);
            print ">$group</option>";
        }
        print <<END;
        </select>
    </td>
</tr>
END
    }
    else {
        print
"<tr><td colspan='3'><input type='hidden' name='SERVICE_GROUP' value='$cgiparams{'SERVICE_GROUP'}' /></td></tr>\n";
    }

    my %customSrv = ();
    &DATA::readCustServices(\%customSrv);
    my @customServices = keys(%customSrv);

    my $showCustomServices = 0;
    if ($#customServices >= 0) {
        $showCustomServices = 1;
        print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
        <input type='radio' name='SERVICE_TYPE' value='custom' $radio{'SERVICE_TYPE'}{'custom'} />
        $Lang::tr{'custom services'}:&nbsp;
        <select name='CUST_SERVICE'>
END
        print "<option value='BLANK' selected='selected'>N/A</option>" if ($#customServices < 0);
        foreach my $service (sort @customServices) {
            print "<option value='$service'";
            print " selected='selected'" if ($cgiparams{'CUST_SERVICE'} eq $service);
            print ">$service</option>";

        }
        print <<END;
        </select>
    </td>
</tr>
END
    }
    else {
        print
"<tr><td colspan='3'><input type='hidden' name='CUST_SERVICE' value='$cgiparams{'CUST_SERVICE'}' /></td></tr>\n";
    }
    print <<END;
<tr>
    <td class='base'></td>
    <td class='base'></td>
    <td class='base'>
END

if($showCustomServices || $showServiceGroups) {
    print"<input type='radio' name='SERVICE_TYPE' value='default' $radio{'SERVICE_TYPE'}{'default'} />\n";
}
else
{
    print"<input type='hidden' name='SERVICE_TYPE' value='default' />\n";
}

print <<END;
        $Lang::tr{'default services'}:&nbsp;
        <select name='DEFAULT_SERVICE'>
END

    my %defaultServices = ();
    &DATA::readDefaultServices(\%defaultServices);

    print "<option value='BLANK'";
    print "selected='selected'" if ($cgiparams{'DEFAULT_SERVICE'} eq '');
    print ">-- $Lang::tr{'default services'} --</option>";

    if($cgiparams{'RULETYPE'} eq 'EXTERNAL' || $cgiparams{'RULETYPE'} eq 'INPUT'){
        my %ofwServices = ();
        &DATA::readOfwServices(\%ofwServices);
        foreach my $defService (sort keys %ofwServices) {
            print "<option value='$defService'";
            print " selected='selected'" if ($cgiparams{'DEFAULT_SERVICE'} eq $defService);
            print ">$defService ($ofwServices{$defService}{'PORT_NR'})</option>";

        }
        print "<option value='BLANK'> --- </option>";
    }

    foreach my $defService (sort keys %defaultServices) {
        print "<option value='$defService'";
        print " selected='selected'" if ($cgiparams{'DEFAULT_SERVICE'} eq $defService);
        print ">$defService ($defaultServices{$defService}{'PORT_NR'})</option>";

    }
    print <<END;
        </select>
    </td>
</tr>
<tr>
    <td colspan='4' bgcolor='#000000'><img src='/images/null.gif' width='1' height='2' border='0' alt='--------' /></td>
</tr>
</table>
END

############################################################################################
    # Additional
############################################################################################

    $checked{'ENABLED'}{'off'}                 = '';
    $checked{'ENABLED'}{'on'}                  = '';
    $checked{'ENABLED'}{$cgiparams{'ENABLED'}} = "checked='checked'";

    $checked{'LOG_ENABLED'}{'off'}                     = '';
    $checked{'LOG_ENABLED'}{'on'}                      = '';
    $checked{'LOG_ENABLED'}{$cgiparams{'LOG_ENABLED'}} = "checked='checked'";

    $selected{'RULEACTION'}{'accept'}                 = '';
    $selected{'RULEACTION'}{'drop'}                   = '';
    $selected{'RULEACTION'}{'reject'}                 = '';
    $selected{'RULEACTION'}{'logOnly'}                = '';
    $selected{'RULEACTION'}{$cgiparams{'RULEACTION'}} = "selected='selected'";

    $checked{'MATCH_STRING_ON'}{'off'}                         = '';
    $checked{'MATCH_STRING_ON'}{'on'}                          = '';
    $checked{'MATCH_STRING_ON'}{$cgiparams{'MATCH_STRING_ON'}} = "checked='checked'";

    $checked{'INV_MATCH_STRING'}{'off'}                          = '';
    $checked{'INV_MATCH_STRING'}{'on'}                           = '';
    $checked{'INV_MATCH_STRING'}{$cgiparams{'INV_MATCH_STRING'}} = "checked='checked'";

    $selected{'LIMIT_FOR'}{'none'}                  = '';
    $selected{'LIMIT_FOR'}{'log'}                   = '';
    $selected{'LIMIT_FOR'}{'acceptOrDeny'}          = '';
    $selected{'LIMIT_FOR'}{'both'}                  = '';
    $selected{'LIMIT_FOR'}{$cgiparams{'LIMIT_FOR'}} = "selected='selected'";

    $radio{'LIMIT_TYPE'}{'average'}                = '';
    $radio{'LIMIT_TYPE'}{'burst'}                  = '';
    $radio{'LIMIT_TYPE'}{$cgiparams{'LIMIT_TYPE'}} = "checked='checked'";

    print <<END;
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td class='boldbase' >$Lang::tr{'additional'}</td>
</tr>
</table>

<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td width='4%' class='base' ></td>
    <td class='base' >
        <input type='checkbox' name='ENABLED' $checked{'ENABLED'}{'on'} />&nbsp;
        <font class='boldbase'>$Lang::tr{'rule enabled'}</font>
    </td>
</tr>
<tr>
    <td width='4%' class='base' ></td>
    <td class='base' >
        <input type='checkbox' name='LOG_ENABLED' $checked{'LOG_ENABLED'}{'on'} />&nbsp;
        <font class='boldbase'>$Lang::tr{'log rule'}</font>
    </td>
</tr>
END

    if ($cgiparams{'RULETYPE'} eq 'PORTFW') {
        print "<tr><td colspan='2'><input type='hidden' name='RULEACTION' value='accept' /></td></tr>\n";
    }
    else {
        print <<END;
<tr>
    <td width='4%' class='base' ></td>
    <td class='base'>
        $Lang::tr{'rule action'}:&nbsp;
        <select name='RULEACTION'>
            <option value='accept' $selected{'RULEACTION'}{'accept'}>$Lang::tr{'fw accept'}</option>
            <option value='drop' $selected{'RULEACTION'}{'drop'}>$Lang::tr{'fw drop'}</option>
            <option value='reject' $selected{'RULEACTION'}{'reject'}>$Lang::tr{'fw reject'}</option>
            <option value='logOnly' $selected{'RULEACTION'}{'logOnly'}>$Lang::tr{'fw log only'}</option>
        </select>&nbsp;
    </td>
</tr>
END
    }
    print <<END;
<tr>
    <td width='4%' class='base' ></td>
    <td class='base'>
        <font class='boldbase'>$Lang::tr{'remark'}:</font>
        <img src='/blob.gif' alt='*' />&nbsp;
        <input type='text' name='REMARK' value='$cgiparams{'REMARK'}' size='55' maxlength='50' />
    </td>
</tr>

<tr>
    <td width='4%' class='base' ></td>
    <td class='base'>
        <img src='/blob.gif' alt='*' align='top' />&nbsp;
        <font class='base'>$Lang::tr{'this field may be blank'}</font>
    </td>
</tr>
</table>
END
    if ($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on') {
        print <<END;
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
        <td width='4%' class='base' ></td>
        <td bgcolor='#000000'><img src='/images/null.gif' width='1' height='2' border='0' alt='--------' /></td>
    </tr>
    <tr>
        <td width='4%' class='base' ></td>
        <td class='boldbase' >$Lang::tr{'adv options'}</td>
    </tr>
    <tr>
        <td width='4%' class='base' ></td>
        <td class='base' >
<!-- # Not sure if this is used often. As in current version the config is stored
     # in plain text files, the string don't have comma inside.
     # For now i comment this out, maybe include it in later version with DB stored
     # config.
        <input type='checkbox' name='MATCH_STRING_ON' $checked{'MATCH_STRING_ON'}{'on'} />&nbsp;
        Match <b>string</b>
        <input type='text' name='MATCH_STRING' value='$cgiparams{'MATCH_STRING'}' size='55' maxlength='50' />
    </td>
</tr>
<tr>
    <td width='4%' class='base' ></td>
    <td class='base'>
        &nbsp; <input type='checkbox' name='INV_MATCH_STRING' $checked{'INV_MATCH_STRING'}{'on'} />
        $Lang::tr{'fw invert'}&nbsp;
    </td>
</tr>
<tr>
    <td width='4%' class='base' ></td>
    <td class='base' >
-->
        <input type='hidden' name='MATCH_STRING_ON' value='off' />&nbsp;
        <input type='hidden' name='MATCH_STRING' value='' />
        <input type='hidden' name='INV_MATCH_STRING' value='off' />
        Match <b>limit</b>:
        <select name='LIMIT_FOR'>
            <option value='none' $selected{'LIMIT_FOR'}{'none'} >$Lang::tr{'match none'}</option>
            <option value='log' $selected{'LIMIT_FOR'}{'log'} >$Lang::tr{'match log'}</option>
            <option value='acceptOrDeny' $selected{'LIMIT_FOR'}{'acceptOrDeny'} >$Lang::tr{'match accept deny'}</option>
            <option value='both' $selected{'LIMIT_FOR'}{'both'} >$Lang::tr{'match both'}</option>
        </select>
    </td>
</tr>
<tr>
    <td width='4%' class='base' ></td>
    <td class='base' >
        <input type='radio' name='LIMIT_TYPE' value='average' $radio{'LIMIT_TYPE'}{'average'} />
        &nbsp;--limit avg &nbsp;
        <input type='text' name='MATCH_LIMIT_AVG' value='$cgiparams{'MATCH_LIMIT_AVG'}' size='55' maxlength='50' />
    </td>
</tr>
<tr>
    <td width='4%' class='base' ></td>
    <td class='base' >
        <input type='radio' name='LIMIT_TYPE' value='burst' $radio{'LIMIT_TYPE'}{'burst'} />
        &nbsp;--limit-burst number &nbsp;
        <input type='text' name='MATCH_LIMIT_BURST' value='$cgiparams{'MATCH_LIMIT_BURST'}' size='55' maxlength='50' />
    </td>
</tr>
</table>
END
    }
    else {
        print <<END;
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td colspan='2'>
        <input type='hidden' name='MATCH_STRING_ON' value='off' />
        <input type='hidden' name='MATCH_STRING' value='' />
        <input type='hidden' name='INV_MATCH_STRING' value='off' />
        <input type='hidden' name='LIMIT_FOR' value='$cgiparams{'LIMIT_FOR'}' />
        <input type='hidden' name='LIMIT_TYPE' value='average' />
        <input type='hidden' name='MATCH_LIMIT_AVG' value='$cgiparams{'MATCH_LIMIT_AVG'}' />
        <input type='hidden' name='MATCH_LIMIT_BURST' value='$cgiparams{'MATCH_LIMIT_BURST'}' />
    </td>
</tr>
</table>
END
    }

############################################################################################
    # Time
############################################################################################

    if ($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on') {

        $checked{'TIMEFRAME_ENABLED'}{'off'}                           = '';
        $checked{'TIMEFRAME_ENABLED'}{'on'}                            = '';
        $checked{'TIMEFRAME_ENABLED'}{$cgiparams{'TIMEFRAME_ENABLED'}} = "checked='checked'";

        $radio{'DAY_TYPE'}{'dayOfMonth'}           = '';
        $radio{'DAY_TYPE'}{'weekDays'}             = '';
        $radio{'DAY_TYPE'}{$cgiparams{'DAY_TYPE'}} = "checked='checked'";

        print <<END;
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
        <td bgcolor='#000000' colspan='2'><img src='/images/null.gif' width='1' height='2' border='0' alt='--------' /></td>
</tr>
<tr>
    <td class='boldbase' >$Lang::tr{'add timeframe'}</td>
</tr>
</table>

<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td width='4%' class='base' ></td>
    <td colspan='3' class='base' >
        <input type='checkbox' name='TIMEFRAME_ENABLED' $checked{'TIMEFRAME_ENABLED'}{'on'} />&nbsp;
        <font class='boldbase'>$Lang::tr{'add timeframe'}</font>
    </td>
</tr>
<tr>
    <td width='4%' class='base' ></td>
    <td colspan='3' class='base' >$Lang::tr{'days'}:</td>
</tr>
<tr>
    <td width='4%' class='base' ></td>
    <td width='1%' class='base'></td>
    <td width='1%' class='base' >
        <input type='radio' value='dayOfMonth' name='DAY_TYPE' $radio{'DAY_TYPE'}{'dayOfMonth'} />&nbsp;
    </td>
    <td class='base' >
        <select name='START_DAY_MONTH'>
END
        my $currDay = 1;
        for (; $currDay <= 31; $currDay++) {
            print "<option value='$currDay'";
            print " selected='selected'" if ($cgiparams{'START_DAY_MONTH'} eq $currDay);
            print ">$currDay</option>";
        }
        print <<END;
        </select>
        &nbsp;
        $Lang::tr{'days to'}
        &nbsp;
        <select name='END_DAY_MONTH'>
END
        $currDay = 1;
        for (; $currDay <= 31; $currDay++) {
            print "<option value='$currDay'";
            print " selected='selected'" if ($cgiparams{'END_DAY_MONTH'} eq $currDay);
            print ">$currDay</option>";
        }
        print <<END;
        </select>
    </td>
</tr>
<tr>
    <td class='base' ></td>
    <td class='base' ></td>
    <td width='1%' class='base' >
        <input type='radio' value='weekDays' name='DAY_TYPE' $radio{'DAY_TYPE'}{'weekDays'} />&nbsp;
    </td>
    <td class='base' >$Lang::tr{'days of the week'}:</td>
</tr>
END
        $currDay = 0;
        for (; $currDay <= 6; $currDay++) {
            my $dayKey = $DATA::weekDays[$currDay];

            $checked{$dayKey}{'on'}                = '';
            $checked{$dayKey}{'off'}               = '';
            $checked{$dayKey}{$cgiparams{$dayKey}} = "checked='checked'";

            print <<END;
<tr>
    <td class='base' ></td>
    <td class='base' ></td>
    <td class='base' ></td>
    <td class='base' >
        <input type='checkbox' name='$dayKey' $checked{$dayKey}{'on'} />
        &nbsp;$weekDays[$currDay]
    </td>
</tr>
END
        }

        print <<END;
<tr>
    <td class='base' ></td>
    <td colspan='3' bgcolor='#000000'><img src='/images/null.gif' width='1' height='1' border='0' alt='--------' /></td>
</tr>
<tr>
    <td class='base' ></td>
    <td colspan='3' class='base' >$Lang::tr{'daytime'}:</td>
</tr>
<tr>
    <td class='base' ></td>
    <td class='base' ></td>
    <td class='base' ></td>
    <td class='base' >
        <select name='START_HOUR'>
END

        my $currHour = 0;
        for (; $currHour <= 23; $currHour++) {
            my $hourDisplay = $currHour < 10 ? "0$currHour" : $currHour;
            print "<option value='$currHour'";
            print " selected='selected'" if ($cgiparams{'START_HOUR'} eq $currHour);
            print ">$hourDisplay</option>";
        }
        print <<END;
        </select>:
        <select name='START_MINUTE'>
END

        my $currMinute = 0;
        for (; $currMinute <= 55; $currMinute += 5) {
            my $minuteDisplay = $currMinute < 10 ? "0$currMinute" : $currMinute;
            print "<option value='$currMinute'";
            print " selected='selected'" if ($cgiparams{'START_MINUTE'} eq $currMinute);
            print ">$minuteDisplay</option>";
        }
        print <<END;
        </select>
        &nbsp;
        $Lang::tr{'days to'}
        &nbsp;
        <select name='END_HOUR'>
END

        $currHour = 0;
        for (; $currHour <= 23; $currHour++) {
            my $hourDisplay = $currHour < 10 ? "0$currHour" : $currHour;
            print "<option value='$currHour'";
            print " selected='selected'" if ($cgiparams{'END_HOUR'} eq $currHour);
            print ">$hourDisplay</option>";
        }
        print <<END;
        </select>:
        <select name='END_MINUTE'>
END

        $currMinute = 0;
        for (; $currMinute <= 55; $currMinute += 5) {
            my $minuteDisplay = $currMinute < 10 ? "0$currMinute" : $currMinute;
            print "<option value='$currMinute'";
            print " selected='selected'" if ($cgiparams{'END_MINUTE'} eq $currMinute);
            print ">$minuteDisplay</option>";
        }
        print <<END;
        </select>
    </td>
</tr>
<tr>
    <td colspan='4'><img src='/images/null.gif' width='1' height='2' border='0' alt='--------' /></td>
</tr>
</table>
END
    }
    else {
        print <<END;
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td colspan='2'>
        <input type='hidden' name='TIMEFRAME_ENABLED' value='off' />
        <input type='hidden' name='START_DAY_MONTH' value='1' />
        <input type='hidden' name='END_DAY_MONTH' value='1' />
        <input type='hidden' name='DAY_TYPE' value='$cgiparams{'DAY_TYPE'}' />
END

        my $currDay = 0;
        for (; $currDay <= 6; $currDay++) {
            my $dayKey = $DATA::weekDays[$currDay];
            print "<input type='hidden' name='$dayKey' value='off' />\n";
        }
         print <<END;
        <input type='hidden' name='START_HOUR' value='0' />
        <input type='hidden' name='START_MINUTE' value='0' />
        <input type='hidden' name='END_HOUR' value='0' />
        <input type='hidden' name='END_MINUTE' value='0' />
    </td>
</tr>
</table>
END
    }

    &printHiddenFormParams('EnterParams');
    &printEnterButtons('EnterParams');
    print <<END;
</form>
END
    &Header::closebox();

}

sub buildRuleObject
{
    my %newRule = ();
    $newRule{'ENABLED'} = $cgiparams{'ENABLED'};    # [1] we start with 1, [0] is key

    #   $newRule{'HASHKEY'} = $cgiparams{'RULETYPE'};                   # [2]
    $newRule{'RULEMODE'}     = $cgiparams{'RULEMODE'};        # [3]
    $newRule{'SRC_NET_TYPE'} = $cgiparams{'SRC_NET_TYPE'};    # [4]

    if ($cgiparams{'SRC_NET_TYPE'} eq 'defaultSrcNet') {
        $newRule{'SRC_NET'} = $cgiparams{'DEFAULT_SRC_NET'};    # [5]
    }
    else {                                                      #'custSrcNet'
        $newRule{'SRC_NET'} = $cgiparams{'CUST_SRC_NET'};       # [5]
    }

    $newRule{'SRC_ADR_TYPE'} = $cgiparams{'SRC_ADR_TYPE'};      # [6a]

    if ($cgiparams{'SRC_ADR_TYPE'} eq 'textSrcAdr') {
        $newRule{'SRC_ADR_TYPE'} .= $cgiparams{'SRC_ADRESSFORMAT'};    # [6b]
        $newRule{'SRC_ADR'} = $cgiparams{'SRC_ADRESS_TXT'};            # [7]
    }
    elsif ($cgiparams{'SRC_ADR_TYPE'} eq 'defaultSrcAdr') {
        $newRule{'SRC_ADR'} = $cgiparams{'DEFAULT_SRC_ADR'};           # [7]
    }
    elsif ($cgiparams{'SRC_ADR_TYPE'} eq 'custSrcAdr') {
        $newRule{'SRC_ADR'} = $cgiparams{'CUST_SRC_ADR'};              # [7]
    }
    else {                                                             #'groupSrcAdr'
        $newRule{'SRC_ADR'} = $cgiparams{'GROUP_SRC_ADR'};             # [7]
    }

    $newRule{'INV_SRC_ADR'} = $cgiparams{'INV_SRC_ADR'};               # [8]

    if ($cgiparams{'SRC_PORT_ON'} eq 'on') {
        $newRule{'SRC_PORT'} = $cgiparams{'SRC_PORT'};                 # [9]
    }
    else {
        $newRule{'SRC_PORT'} = "-";                                    # [9]
    }

    $newRule{'INV_SRC_PORT'} = $cgiparams{'INV_SRC_PORT'};             # [10]

    $newRule{'PORTFW_EXT_ADR'} = $cgiparams{'PORTFW_EXT_ADR'};      # [11]
    $newRule{'PORTFW_SERVICE_TYPE'} = $cgiparams{'PORTFW_SERVICE_TYPE'}; # [12]

    if($cgiparams{'PORTFW_SERVICE_TYPE'} eq 'custom') {
        $newRule{'PORTFW_SERVICE'} = $cgiparams{'PORTFW_CUST_SERVICE'}; # [13]
    }
    else {
        # 'default'
        $newRule{'PORTFW_SERVICE'} = $cgiparams{'PORTFW_DEFAULT_SERVICE'}; # [13]
    }


    $newRule{'DST_NET_TYPE'} = $cgiparams{'DST_NET_TYPE'};             # [14]

    if ($cgiparams{'DST_NET_TYPE'} eq 'defaultDestNet') {
        $newRule{'DST_NET'} = $cgiparams{'DEFAULT_DST_NET'};           # [15]
    }
    else {                                                             #'custDestNet'
        $newRule{'DST_NET'} = $cgiparams{'CUST_DST_NET'};              # [15]
    }

    $newRule{'DST_IP_TYPE'} = $cgiparams{'DST_IP_TYPE'};               # [16]

    if ($cgiparams{'DST_IP_TYPE'} eq 'defaultDstIP') {
        $newRule{'DST_IP'} = $cgiparams{'DEFAULT_DST_IP'};             # [17]
    }
    elsif ($cgiparams{'DST_IP_TYPE'} eq 'custDestIP') {
        $newRule{'DST_IP'} = $cgiparams{'CUST_DST_ADR'};               # [17]
    }
    elsif ($cgiparams{'DST_IP_TYPE'} eq 'groupDestIP') {
        $newRule{'DST_IP'} = $cgiparams{'GROUP_DST_ADR'};              # [17]
    }
    else {                                                             # 'ipDestTxt'
        $newRule{'DST_IP'} = $cgiparams{'DEST_IP_TXT'};                # [17]
    }

    $newRule{'INV_DST_IP'} = $cgiparams{'INV_DST_IP'};                 # [18]

    if ($cgiparams{'SERVICE_ON'} eq 'on') {
        $newRule{'SERVICE_TYPE'} = $cgiparams{'SERVICE_TYPE'};         # [19]
        if ($cgiparams{'SERVICE_TYPE'} eq 'custom') {
            $newRule{'SERVICE'} = $cgiparams{'CUST_SERVICE'};          # [20]
        }
        elsif ($cgiparams{'SERVICE_TYPE'} eq 'serviceGroup') {
            $newRule{'SERVICE'} = $cgiparams{'SERVICE_GROUP'};         # [20]
        }
        else {                                                         # 'default'
            $newRule{'SERVICE'} = $cgiparams{'DEFAULT_SERVICE'};       # [20]
        }
    }
    else {
        $newRule{'SERVICE_TYPE'} = "-";                                # [19]
        $newRule{'SERVICE'}      = "-";                                # [20]
    }

    $newRule{'LOG_ENABLED'} = $cgiparams{'LOG_ENABLED'};               # [21]
    $newRule{'LIMIT_FOR'}   = $cgiparams{'LIMIT_FOR'};                 # [22]

    if ($cgiparams{'LIMIT_FOR'} eq 'none') {
        $newRule{'LIMIT_TYPE'}  = "-";                                 # [23]
        $newRule{'MATCH_LIMIT'} = "-";                                 # [24]
    }
    else {
        $newRule{'LIMIT_TYPE'} = $cgiparams{'LIMIT_TYPE'};             # [23]
        if ($cgiparams{'LIMIT_TYPE'} eq 'average') {
            $newRule{'MATCH_LIMIT'} = $cgiparams{'MATCH_LIMIT_AVG'};    # [24]
        }
        else {                                                          # 'burst'
            $newRule{'MATCH_LIMIT'} = $cgiparams{'MATCH_LIMIT_BURST'};    # [24]
        }
    }

    $newRule{'MATCH_STRING_ON'} = $cgiparams{'MATCH_STRING_ON'};          # [25]

    if ($cgiparams{'MATCH_STRING_ON'} eq 'on') {
        $newRule{'MATCH_STRING'}     = $cgiparams{'MATCH_STRING'};        # [26]
        $newRule{'INV_MATCH_STRING'} = $cgiparams{'INV_MATCH_STRING'};    # [27]
    }
    else {
        $newRule{'MATCH_STRING'}     = "-";                               # [26]
        $newRule{'INV_MATCH_STRING'} = "-";                               # [27]
    }
    $newRule{'RULEACTION'}        = $cgiparams{'RULEACTION'};             # [28]
    $newRule{'TIMEFRAME_ENABLED'} = $cgiparams{'TIMEFRAME_ENABLED'};      # [29]
    $newRule{'REMARK'}            = $cgiparams{'REMARK'};                 # [30]

    # Time parameter
    $newRule{'DAY_TYPE'}        = $cgiparams{'DAY_TYPE'};
    $newRule{'START_DAY_MONTH'} = $cgiparams{'START_DAY_MONTH'};
    $newRule{'END_DAY_MONTH'}   = $cgiparams{'END_DAY_MONTH'};

    $newRule{'MON'} = $cgiparams{'MON'};
    $newRule{'TUE'} = $cgiparams{'TUE'};
    $newRule{'WED'} = $cgiparams{'WED'};
    $newRule{'THU'} = $cgiparams{'THU'};
    $newRule{'FRI'} = $cgiparams{'FRI'};
    $newRule{'SAT'} = $cgiparams{'SAT'};
    $newRule{'SUN'} = $cgiparams{'SUN'};

    $newRule{'START_HOUR'}   = $cgiparams{'START_HOUR'};
    $newRule{'START_MINUTE'} = $cgiparams{'START_MINUTE'};
    $newRule{'END_HOUR'}     = $cgiparams{'END_HOUR'};
    $newRule{'END_MINUTE'}   = $cgiparams{'END_MINUTE'};

    return \%newRule;
}

sub initCgiParamsFromConf
{
    my $rule = shift;

    # $rule->{'HASHKEY'}

    $cgiparams{'ENABLED'} = $rule->{'ENABLED'};    # [1] we start with 1, [0] is key

    #~  $cgiparams{'RULETYPE'} = $rule->{'HASHKEY'}[2];                 # [2]
    $cgiparams{'RULEMODE'}     = $rule->{'RULEMODE'};        # [3]
    $cgiparams{'SRC_NET_TYPE'} = $rule->{'SRC_NET_TYPE'};    # [4]

    if ($cgiparams{'SRC_NET_TYPE'} eq 'defaultSrcNet') {
        $cgiparams{'DEFAULT_SRC_NET'} = $rule->{'SRC_NET'};    # [5]
    }
    else {                                                     #'custSrcNet'
        $cgiparams{'CUST_SRC_NET'} = $rule->{'SRC_NET'};       # [5]
    }

    $cgiparams{'SRC_ADR_TYPE'} = $rule->{'SRC_ADR_TYPE'};      # [6a]

    if ($cgiparams{'SRC_ADR_TYPE'} eq 'textSrcAdrip') {
        $cgiparams{'SRC_ADR_TYPE'}     = 'textSrcAdr';
        $cgiparams{'SRC_ADRESSFORMAT'} = "ip";                  # [6b]
        $cgiparams{'SRC_ADRESS_TXT'}   = $rule->{'SRC_ADR'};    # [7]
    }
    elsif ($cgiparams{'SRC_ADR_TYPE'} eq 'textSrcAdrmac') {
        $cgiparams{'SRC_ADR_TYPE'}     = 'textSrcAdr';
        $cgiparams{'SRC_ADRESSFORMAT'} = "mac";                 # [6b]
        $cgiparams{'SRC_ADRESS_TXT'}   = $rule->{'SRC_ADR'};    # [7]
    }
    elsif ($cgiparams{'SRC_ADR_TYPE'} eq 'defaultSrcAdr') {
        $cgiparams{'DEFAULT_SRC_ADR'} = $rule->{'SRC_ADR'};     # [7]
    }
    elsif ($cgiparams{'SRC_ADR_TYPE'} eq 'custSrcAdr') {
        $cgiparams{'CUST_SRC_ADR'} = $rule->{'SRC_ADR'};        # [7]
    }
    else {                                                      #'groupSrcAdr'
        $cgiparams{'GROUP_SRC_ADR'} = $rule->{'SRC_ADR'};       # [7]
    }

    $cgiparams{'INV_SRC_ADR'} = $rule->{'INV_SRC_ADR'};         # [8]

    if ($rule->{'SRC_PORT'} ne '-') {
        $cgiparams{'SRC_PORT_ON'} = 'on';
        $cgiparams{'SRC_PORT'}    = $rule->{'SRC_PORT'};        # [9]
    }
    else {
        $cgiparams{'SRC_PORT_ON'} = 'off';
        $cgiparams{'SRC_PORT'}    = '';                         # [9]
    }

    $cgiparams{'INV_SRC_PORT'} = $rule->{'INV_SRC_PORT'};       # [10]

    $cgiparams{'PORTFW_EXT_ADR'} = $rule->{'PORTFW_EXT_ADR'};      # [11]
    $cgiparams{'PORTFW_SERVICE_TYPE'} = $rule->{'PORTFW_SERVICE_TYPE'}; # [12]

    if($rule->{'PORTFW_SERVICE_TYPE'} eq 'custom') {
        $cgiparams{'PORTFW_CUST_SERVICE'} = $rule->{'PORTFW_SERVICE'}; # [13]
    }
    else {
        # 'default'
        $cgiparams{'PORTFW_DEFAULT_SERVICE'} = $rule->{'PORTFW_SERVICE'}; # [13]
    }

    $cgiparams{'DST_NET_TYPE'} = $rule->{'DST_NET_TYPE'};       # [14]

    if ($cgiparams{'DST_NET_TYPE'} eq 'defaultDestNet') {
        $cgiparams{'DEFAULT_DST_NET'} = $rule->{'DST_NET'};     # [15]
    }
    else {                                                      #'custDestNet'
        $cgiparams{'CUST_DST_NET'} = $rule->{'DST_NET'};        # [15]
    }

    $cgiparams{'DST_IP_TYPE'} = $rule->{'DST_IP_TYPE'};         # [16]

    if ($cgiparams{'DST_IP_TYPE'} eq 'defaultDstIP') {
        $cgiparams{'DEFAULT_DST_IP'} = $rule->{'DST_IP'};       # [17]
    }
    elsif ($cgiparams{'DST_IP_TYPE'} eq 'custDestIP') {
        $cgiparams{'CUST_DST_ADR'} = $rule->{'DST_IP'};         # [17]
    }
    elsif ($cgiparams{'DST_IP_TYPE'} eq 'groupDestIP') {
        $cgiparams{'GROUP_DST_ADR'} = $rule->{'DST_IP'};        # [17]
    }
    else {                                                      # 'ipDestTxt'
        $cgiparams{'DEST_IP_TXT'} = $rule->{'DST_IP'};          # [17]
    }

    $cgiparams{'INV_DST_IP'} = $rule->{'INV_DST_IP'};           # [18]

    if ($rule->{'SERVICE_TYPE'} ne '-') {
        $cgiparams{'SERVICE_ON'}   = 'on';
        $cgiparams{'SERVICE_TYPE'} = $rule->{'SERVICE_TYPE'};    # [19]
        if ($cgiparams{'SERVICE_TYPE'} eq 'custom') {
            $cgiparams{'CUST_SERVICE'} = $rule->{'SERVICE'};     # [20]
        }
        elsif ($cgiparams{'SERVICE_TYPE'} eq 'serviceGroup') {
            $cgiparams{'SERVICE_GROUP'} = $rule->{'SERVICE'};    # [20]
        }
        else {                                                   # 'default'
            $cgiparams{'DEFAULT_SERVICE'} = $rule->{'SERVICE'};    # [20]
        }
    }
    else {
        $cgiparams{'SERVICE_ON'} = 'off';
    }

    $cgiparams{'LOG_ENABLED'} = $rule->{'LOG_ENABLED'};            # [21]
    $cgiparams{'LIMIT_FOR'}   = $rule->{'LIMIT_FOR'};              # [22]

    if ($cgiparams{'LIMIT_FOR'} ne 'none') {
        $cgiparams{'LIMIT_TYPE'} = $rule->{'LIMIT_TYPE'};          # [23]
        if ($cgiparams{'LIMIT_TYPE'} eq 'average') {
            $cgiparams{'MATCH_LIMIT_AVG'} = $rule->{'MATCH_LIMIT'};    # [24]
        }
        else {                                                         # 'burst'
            $cgiparams{'MATCH_LIMIT_BURST'} = $rule->{'MATCH_LIMIT'};    # [24]
        }
    }

    $cgiparams{'MATCH_STRING_ON'} = $rule->{'MATCH_STRING_ON'};          # [25]

    if ($cgiparams{'MATCH_STRING_ON'} eq 'on') {
        $cgiparams{'MATCH_STRING'}     = $rule->{'MATCH_STRING'};        # [26]
        $cgiparams{'INV_MATCH_STRING'} = $rule->{'INV_MATCH_STRING'};    # [27]
    }
    $cgiparams{'RULEACTION'} = $rule->{'RULEACTION'};                    # [28]

    $cgiparams{'TIMEFRAME_ENABLED'} = $rule->{'TIMEFRAME_ENABLED'};      # [29]
    if (defined $rule->{'REMARK'}) {
        $cgiparams{'REMARK'} = $rule->{'REMARK'}; # [30]
    }

    if ($cgiparams{'TIMEFRAME_ENABLED'} eq 'on') {

        # Time parameter
        $cgiparams{'DAY_TYPE'}        = $rule->{'DAY_TYPE'};
        $cgiparams{'START_DAY_MONTH'} = $rule->{'START_DAY_MONTH'};
        $cgiparams{'END_DAY_MONTH'}   = $rule->{'END_DAY_MONTH'};

        $cgiparams{'MON'} = $rule->{'MON'};
        $cgiparams{'TUE'} = $rule->{'TUE'};
        $cgiparams{'WED'} = $rule->{'WED'};
        $cgiparams{'THU'} = $rule->{'THU'};
        $cgiparams{'FRI'} = $rule->{'FRI'};
        $cgiparams{'SAT'} = $rule->{'SAT'};
        $cgiparams{'SUN'} = $rule->{'SUN'};

        $cgiparams{'START_HOUR'}   = $rule->{'START_HOUR'};
        $cgiparams{'START_MINUTE'} = $rule->{'START_MINUTE'};
        $cgiparams{'END_HOUR'}     = $rule->{'END_HOUR'};
        $cgiparams{'END_MINUTE'}   = $rule->{'END_MINUTE'};
    }

    return;
}

sub printHiddenFormParams
{
    my $currBox = shift;

    if ($currBox ne "Overview") {
        print <<END;
            <input type='hidden' name='RULE_POSITION' value='$cgiparams{'RULE_POSITION'}' />
END
    }

    if ($currBox ne "addNewRule" ) {
        print "<input type='hidden' name='ACTION' value='$cgiparams{'ACTION'}' />";
    }

    if ($currBox ne "addNewRule" && $currBox ne "EnterParams") {
        print "<input type='hidden' name='RULETYPE' value='$cgiparams{'RULETYPE'}' />";
    }

    if ($currBox ne "EnterParams") {

        if(defined($cgiparams{'SERVICE_ON'})) {
            print "<input type='hidden' name='SERVICE_ON' value='$cgiparams{'SERVICE_ON'}' />\n";
        }
        if(defined($cgiparams{'ENABLED'})) {
            print "<input type='hidden' name='ENABLED' value='$cgiparams{'ENABLED'}' />\n";
        }

        print <<END;
        <input type='hidden' name='SRC_NET_TYPE' value='$cgiparams{'SRC_NET_TYPE'}' />
        <input type='hidden' name='DEFAULT_SRC_NET' value='$cgiparams{'DEFAULT_SRC_NET'}' />
        <input type='hidden' name='CUST_SRC_NET' value='$cgiparams{'CUST_SRC_NET'}' />
        <input type='hidden' name='SRC_ADR_TYPE' value='$cgiparams{'SRC_ADR_TYPE'}' />
        <input type='hidden' name='DEFAULT_SRC_ADR' value='$cgiparams{'DEFAULT_SRC_ADR'}' />
        <input type='hidden' name='CUST_SRC_ADR' value='$cgiparams{'CUST_SRC_ADR'}' />
        <input type='hidden' name='GROUP_SRC_ADR' value='$cgiparams{'GROUP_SRC_ADR'}' />
        <input type='hidden' name='SRC_ADRESSFORMAT' value='$cgiparams{'SRC_ADRESSFORMAT'}' />
        <input type='hidden' name='SRC_ADRESS_TXT' value='$cgiparams{'SRC_ADRESS_TXT'}' />
        <input type='hidden' name='INV_SRC_ADR' value='$cgiparams{'INV_SRC_ADR'}' />
        <input type='hidden' name='SRC_PORT_ON' value='$cgiparams{'SRC_PORT_ON'}' />
        <input type='hidden' name='SRC_PORT' value='$cgiparams{'SRC_PORT'}' />
        <input type='hidden' name='INV_SRC_PORT' value='$cgiparams{'INV_SRC_PORT'}' />

        <input type='hidden' name='PORTFW_EXT_ADR' value='$cgiparams{'PORTFW_EXT_ADR'}' />
        <input type='hidden' name='PORTFW_SERVICE_TYPE' value='$cgiparams{'PORTFW_SERVICE_TYPE'}' />
        <input type='hidden' name='PORTFW_CUST_SERVICE' value='$cgiparams{'PORTFW_CUST_SERVICE'}' />
        <input type='hidden' name='PORTFW_DEFAULT_SERVICE' value='$cgiparams{'PORTFW_DEFAULT_SERVICE'}' />

        <input type='hidden' name='DST_NET_TYPE' value='$cgiparams{'DST_NET_TYPE'}' />
        <input type='hidden' name='DEFAULT_DST_NET' value='$cgiparams{'DEFAULT_DST_NET'}' />
        <input type='hidden' name='CUST_DST_NET' value='$cgiparams{'CUST_DST_NET'}' />
        <input type='hidden' name='DEST_IP_TXT' value='$cgiparams{'DEST_IP_TXT'}' />
        <input type='hidden' name='INV_DST_IP' value='$cgiparams{'INV_DST_IP'}' />
        <input type='hidden' name='DST_IP_TYPE' value='$cgiparams{'DST_IP_TYPE'}' />
        <input type='hidden' name='DEFAULT_DST_IP' value='$cgiparams{'DEFAULT_DST_IP'}' />
        <input type='hidden' name='CUST_DST_ADR' value='$cgiparams{'CUST_DST_ADR'}' />
        <input type='hidden' name='GROUP_DST_ADR' value='$cgiparams{'GROUP_DST_ADR'}' />
        <input type='hidden' name='SERVICE_TYPE' value='$cgiparams{'SERVICE_TYPE'}' />
        <input type='hidden' name='CUST_SERVICE' value='$cgiparams{'CUST_SERVICE'}' />
        <input type='hidden' name='DEFAULT_SERVICE' value='$cgiparams{'DEFAULT_SERVICE'}' />
        <input type='hidden' name='SERVICE_GROUP' value='$cgiparams{'SERVICE_GROUP'}' />

        <input type='hidden' name='LOG_ENABLED' value='$cgiparams{'LOG_ENABLED'}' />
        <input type='hidden' name='TIMEFRAME_ENABLED' value='$cgiparams{'TIMEFRAME_ENABLED'}' />
        <input type='hidden' name='REMARK' value='$cgiparams{'REMARK'}' />
        <input type='hidden' name='MATCH_STRING_ON' value='$cgiparams{'MATCH_STRING_ON'}' />
        <input type='hidden' name='MATCH_STRING' value='$cgiparams{'MATCH_STRING'}' />
        <input type='hidden' name='INV_MATCH_STRING' value='$cgiparams{'INV_MATCH_STRING'}' />
        <input type='hidden' name='LIMIT_FOR' value='$cgiparams{'LIMIT_FOR'}' />
        <input type='hidden' name='LIMIT_TYPE' value='$cgiparams{'LIMIT_TYPE'}' />
        <input type='hidden' name='MATCH_LIMIT_AVG' value='$cgiparams{'MATCH_LIMIT_AVG'}' />
        <input type='hidden' name='MATCH_LIMIT_BURST' value='$cgiparams{'MATCH_LIMIT_BURST'}' />

        <input type='hidden' name='DAY_TYPE' value='$cgiparams{'DAY_TYPE'}' />
        <input type='hidden' name='START_DAY_MONTH' value='$cgiparams{'START_DAY_MONTH'}' />
        <input type='hidden' name='END_DAY_MONTH' value='$cgiparams{'END_DAY_MONTH'}' />

        <input type='hidden' name='MON' value='$cgiparams{'MON'}' />
        <input type='hidden' name='TUE' value='$cgiparams{'TUE'}' />
        <input type='hidden' name='WED' value='$cgiparams{'WED'}' />
        <input type='hidden' name='THU' value='$cgiparams{'THU'}' />
        <input type='hidden' name='FRI' value='$cgiparams{'FRI'}' />
        <input type='hidden' name='SAT' value='$cgiparams{'SAT'}' />
        <input type='hidden' name='SUN' value='$cgiparams{'SUN'}' />

        <input type='hidden' name='START_HOUR' value='$cgiparams{'START_HOUR'}' />
        <input type='hidden' name='START_MINUTE' value='$cgiparams{'START_MINUTE'}' />
        <input type='hidden' name='END_HOUR' value='$cgiparams{'END_HOUR'}' />
        <input type='hidden' name='END_MINUTE' value='$cgiparams{'END_MINUTE'}' />
END
    }

    print <<END;
        <input type='hidden' name='OLD_POSITION' value='$cgiparams{'OLD_POSITION'}' />
        <input type='hidden' name='OLD_RULETYPE' value='$cgiparams{'OLD_RULETYPE'}' />
        <input type='hidden' name='BOX_NAME' value='$currBox' />
        <input type='hidden' name='KEY1' value='$cgiparams{'KEY1'}' />
        <input type='hidden' name='RULEMODE' value='$cgiparams{'RULEMODE'}' />
END
}

sub printOverviewBox
{
    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        &Header::openbox('100%', 'left', "$Lang::tr{'edit a rule'}: $Lang::tr{'overview'}");
    }
    else {
        &Header::openbox('100%', 'left', "$Lang::tr{'add a new rule'}: $Lang::tr{'overview'}");
    }


    # not existing here means they're undefined and not selected on enter params box
    $cgiparams{'SERVICE_ON'} = 'off' unless exists $cgiparams{'SERVICE_ON'};
    $cgiparams{'ENABLED'} = 'off'  unless exists $cgiparams{'ENABLED'};

    my $src_adr_inv      = "";
    my $src_adr_inv_tail = "";
    if ($cgiparams{'INV_SRC_ADR'} eq 'on') {
        $src_adr_inv      = " <strong><font color='RED'>! (</font></strong>";
        $src_adr_inv_tail = "<strong><font color='RED'>)</font></strong>";
    }
    my $ruleTypeTxt = $Lang::tr{'outgoing traffic'};
    my  $destination_text = $Lang::tr{'destination'};
    if ($cgiparams{'RULETYPE'} eq 'INPUT') {
        $ruleTypeTxt = $Lang::tr{'openfirewall access'};
    }
    elsif ($cgiparams{'RULETYPE'} eq 'EXTERNAL') {
        $ruleTypeTxt = $Lang::tr{'external openfirewall access'};
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PORTFW') {
        $destination_text = $Lang::tr{'pfw internal destination'};
        $ruleTypeTxt = $Lang::tr{'internal network'};
    }
    elsif ($cgiparams{'RULETYPE'} eq 'PINHOLES') {
        $ruleTypeTxt = $Lang::tr{'internal traffic'};
    }

    my $src_net = "\u$cgiparams{'DEFAULT_SRC_NET'}";
    if ($cgiparams{'SRC_NET_TYPE'} eq 'custSrcNet') {
        $src_net = $cgiparams{'CUST_SRC_NET'};
    }

    my $src_address = $cgiparams{'SRC_ADRESS_TXT'};
    if ($cgiparams{'SRC_ADR_TYPE'} eq 'defaultSrcAdr') {
        $src_address = $cgiparams{'DEFAULT_SRC_ADR'};
    }
    elsif ($cgiparams{'SRC_ADR_TYPE'} eq 'custSrcAdr') {
        $src_address = $cgiparams{'CUST_SRC_ADR'};
    }
    elsif ($cgiparams{'SRC_ADR_TYPE'} eq 'groupSrcAdr') {
        $src_address = $cgiparams{'GROUP_SRC_ADR'};
    }

    print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>

<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td colspan='2' class='base'>
        <font class='boldbase'>$Lang::tr{'source'}:</font>
    </td>
    <td class='boldbase' >&nbsp;</td>
</tr>
<tr>
    <td width='2%' class='base' ></td>
    <td width='10%' class='base' >
        <font class='boldbase'>$Lang::tr{'fw iface'}:</font>&nbsp;
    </td>
    <td width='88%' class='boldbase' >$src_net</td>
</tr>
<tr>
    <td class='base' ></td>
    <td class='base' >
        <font class='boldbase'>$Lang::tr{'address'}:</font>&nbsp;
    </td>
    <td class='base' >$src_adr_inv<b>$src_address</b>$src_adr_inv_tail</td>
</tr>
END
    if ($cgiparams{'SRC_PORT_ON'} eq 'on') {
        my $src_port_inv      = "";
        my $src_port_inv_tail = "";
        if ($cgiparams{'INV_SRC_PORT'} eq 'on') {
            $src_port_inv      = " <strong><font color='RED'>! (</font></strong>";
            $src_port_inv_tail = "<strong><font color='RED'>)</font></strong>";
        }
        print <<END;
<tr>
    <td class='base' ></td>
    <td class='base' >
        <font class='boldbase'>$Lang::tr{'port'}:</font>&nbsp;
    </td>
    <td class='base' >$src_port_inv<b>$cgiparams{'SRC_PORT'}</b>$src_port_inv_tail</td>
</tr>
END
    }

    if($cgiparams{'RULETYPE'} eq 'PORTFW') {

        my $ext_service = $cgiparams{'PORTFW_CUST_SERVICE'};
        if ($cgiparams{'PORTFW_SERVICE_TYPE'} eq 'default') {
            $ext_service = $cgiparams{'PORTFW_DEFAULT_SERVICE'};
        }

        print <<END;
<tr>
    <td colspan='3' class='base'>&nbsp;</td>
</tr>
<tr>
    <td colspan='3' class='base'>
        <font class='boldbase'>$Lang::tr{'pfw openfirewall destination'}:</font>
    </td>
</tr>
<tr>
    <td class='base' ></td>
    <td class='base' >
        <font class='boldbase'>$Lang::tr{'alias ip'}:</font>&nbsp;
    </td>
    <td class='boldbase' >$cgiparams{'PORTFW_EXT_ADR'}</td>
</tr>
<tr>
    <td class='base' ></td>
    <td class='base' >
        <font class='boldbase'>$Lang::tr{'service'}:</font>&nbsp;
    </td>
    <td class='boldbase'>$ext_service</td>
</tr>
END

    }

    print <<END;
<tr>
    <td colspan='3' class='base'>&nbsp;</td>
</tr>
<tr>
    <td colspan='2' class='boldbase'>$destination_text:&nbsp;</td>
    <td class='boldbase'>$ruleTypeTxt</td>
</tr>
END
    if ($cgiparams{'RULETYPE'} eq 'OUTGOING' || $cgiparams{'RULETYPE'} eq 'PINHOLES' || $cgiparams{'RULETYPE'} eq 'PORTFW') {
        my $dst_ip_inv      = "";
        my $dst_ip_inv_tail = "";
        if ($cgiparams{'INV_DST_IP'} eq 'on') {
            $dst_ip_inv      = " <strong><font color='RED'>! (</font></strong>";
            $dst_ip_inv_tail = "<strong><font color='RED'>)</font></strong>";
        }

        my $dst_net = "\u$cgiparams{'DEFAULT_DST_NET'}";
        if ($cgiparams{'DST_NET_TYPE'} eq 'custDestNet') {
            $dst_net = $cgiparams{'CUST_DST_NET'};
        }
        my $dst_ip = $cgiparams{'DEST_IP_TXT'};
        if ($cgiparams{'DST_IP_TYPE'} eq 'defaultDstIP') {
            $dst_ip = $cgiparams{'DEFAULT_DST_IP'};
        }
        elsif ($cgiparams{'DST_IP_TYPE'} eq 'custDestIP') {
            $dst_ip = $cgiparams{'CUST_DST_ADR'};
        }
        elsif ($cgiparams{'DST_IP_TYPE'} eq 'groupDestIP') {
            $dst_ip = $cgiparams{'GROUP_DST_ADR'};
        }

        print <<END;
<tr>
    <td class='base' ></td>
    <td class='base' >
        <font class='boldbase'>$Lang::tr{'fw iface'}:</font>&nbsp;
    </td>
    <td class='boldbase' >$dst_net</td>
</tr>
<tr>
    <td class='base' ></td>
    <td class='base' >
        <font class='boldbase'>$Lang::tr{'ip address'}:</font>&nbsp;
    </td>
    <td class='base' >$dst_ip_inv<b>$dst_ip</b>$dst_ip_inv_tail</td>
</tr>
END
    }

    if ($cgiparams{'SERVICE_ON'} eq 'on') {
        my $dst_service = $cgiparams{'CUST_SERVICE'};
        if ($cgiparams{'SERVICE_TYPE'} eq 'default') {
            $dst_service = $cgiparams{'DEFAULT_SERVICE'};
        }
        elsif ($cgiparams{'SERVICE_TYPE'} eq 'serviceGroup') {
            $dst_service = $cgiparams{'SERVICE_GROUP'};
        }

        print <<END;
<tr>
    <td class='base' ></td>
    <td class='base' >
        <font class='boldbase'>$Lang::tr{'service'}:</font>&nbsp;
    </td>
    <td class='boldbase'>$dst_service</td>
</tr>
END
    }

    my $ruleAction = '';
    if ($cgiparams{'RULEACTION'} eq 'accept') {
        $ruleAction = $Lang::tr{'fw accept'};
    }
    elsif ($cgiparams{'RULEACTION'} eq 'drop') {
        $ruleAction = $Lang::tr{'fw drop'};
    }
    elsif ($cgiparams{'RULEACTION'} eq 'reject') {
        $ruleAction = $Lang::tr{'fw reject'};
    }
    elsif ($cgiparams{'RULEACTION'} eq 'logOnly') {
        $ruleAction = $Lang::tr{'fw log only'};
    }

    print <<END;
<tr>
    <td colspan='3' class='base'>&nbsp;</td>
</tr>
<tr>
    <td colspan='2' class='base'>
        <font class='boldbase'>$Lang::tr{'rule action'}:</font>
    </td>
    <td class='boldbase'>$ruleAction</td>
</tr>
<tr>
    <td colspan='2' class='base'>
        <font class='boldbase'>$Lang::tr{'rule enabled'}:</font>
    </td>
    <td class='base' >
        <img  src="/images/$cgiparams{'ENABLED'}.gif" alt='$cgiparams{'ENABLED'}' border='0' />
    </td>
</tr>
<tr>
    <td colspan='2' class='base'>
        <font class='boldbase'>$Lang::tr{'log rule'}:</font>
    </td>
    <td class='base' >
        <img  src="/images/$cgiparams{'LOG_ENABLED'}.gif" alt='$cgiparams{'LOG_ENABLED'}' border='0' />
    </td>
</tr>
<tr>
    <td colspan='2' class='base'>
        <font class='boldbase'>$Lang::tr{'remark'}:&nbsp;</font>
    </td>
    <td class='boldbase'>$cgiparams{'REMARK'}</td>
</tr>
<tr>
    <td colspan='2' class='base'>
        <font class='boldbase'>$Lang::tr{'rule position'}:</font>
    </td>
    <td class='base'>
        <select name='RULE_POSITION'>
END

    my $ruleCount = 0;
    if (defined($ruleConfig{'INPUT'}) && $cgiparams{'RULETYPE'} eq 'INPUT') {
        $ruleCount = @{$ruleConfig{'INPUT'}};
    }
    elsif (defined($ruleConfig{'OUTGOING'}) && $cgiparams{'RULETYPE'} eq 'OUTGOING') {
        $ruleCount = @{$ruleConfig{'OUTGOING'}};
    }
    elsif (defined($ruleConfig{'EXTERNAL'}) && $cgiparams{'RULETYPE'} eq 'EXTERNAL') {
        $ruleCount = @{$ruleConfig{'EXTERNAL'}};
    }
    elsif (defined($ruleConfig{'PINHOLES'}) && $cgiparams{'RULETYPE'} eq 'PINHOLES') {
        $ruleCount = @{$ruleConfig{'PINHOLES'}};
    }
    elsif (defined($ruleConfig{'PORTFW'}) && $cgiparams{'RULETYPE'} eq 'PORTFW') {
        $ruleCount = @{$ruleConfig{'PORTFW'}};
    }

    $cgiparams{'RULE_POSITION'} = $ruleCount if ($cgiparams{'RULE_POSITION'} < 0);

    # if we want to add a new rule we have to increment the total count
    $ruleCount++ if ($cgiparams{'ACTION'} ne $Lang::tr{'edit'});

    for (my $countIndex = 0; $countIndex < $ruleCount; $countIndex++) {
        print "<option value='$countIndex'";
        print " selected='selected'" if ($cgiparams{'RULE_POSITION'} eq $countIndex);
        my $displayID = $countIndex + 1;
        print ">$displayID</option>";
    }

    print <<END;
        </select>
    </td>
</tr>
<tr>
    <td colspan='3' class='base'>&nbsp;</td>
</tr>
END

    if ($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on' && $cgiparams{'TIMEFRAME_ENABLED'} eq 'on') {
        my $startDay = $cgiparams{'START_DAY_MONTH'};
        my $endDay   = $cgiparams{'END_DAY_MONTH'};

        my $dayText = "$startDay&nbsp;$Lang::tr{'days to'}&nbsp;$endDay&nbsp;$Lang::tr{'of month'}";

        if ($cgiparams{'DAY_TYPE'} eq 'weekDays') {
            $dayText = "";
            my $currDay = 0;
            for (; $currDay <= 6; $currDay++) {
                my $dayKey = $DATA::weekDays[$currDay];
                next unless ($cgiparams{$dayKey} eq 'on');
                $dayText .= "$weekDays[$currDay]&nbsp;&nbsp;";
            }

        }

        my $startHour = $cgiparams{'START_HOUR'} < 10 ? "0" . $cgiparams{'START_HOUR'} : $cgiparams{'START_HOUR'};
        my $startMinute =
            $cgiparams{'START_MINUTE'} < 10 ? "0" . $cgiparams{'START_MINUTE'} : $cgiparams{'START_MINUTE'};
        my $endHour   = $cgiparams{'END_HOUR'} < 10   ? "0" . $cgiparams{'END_HOUR'}   : $cgiparams{'END_HOUR'};
        my $endMinute = $cgiparams{'END_MINUTE'} < 10 ? "0" . $cgiparams{'END_MINUTE'} : $cgiparams{'END_MINUTE'};

        print <<END;
<tr>
    <td colspan='2' class='base'>
        <font class='boldbase'>$Lang::tr{'rule active'}:</font>
    </td>
    <td class='base' ></td>
</tr>
<tr>
    <td class='base'></td>
    <td class='boldbase'>$Lang::tr{'days'}:</td>
    <td class='boldbase'>$dayText</td>
</tr>
<tr>
    <td class='base'></td>
    <td class='base'>
        <font class='boldbase'>$Lang::tr{'daytime'}:</font>
    </td>
    <td class='boldbase'>
        $startHour:$startMinute
        &nbsp;
        $Lang::tr{'days to'}
        &nbsp;
        $endHour:$endMinute
    </td>
</tr>
<tr>
    <td colspan='3' class='base'>&nbsp;</td>
</tr>
END
    }
    if ($FW::fwSettings{'ADV_MODE_ENABLE'} eq 'on') {
        if ($cgiparams{'MATCH_STRING_ON'} eq 'on') {

            my $invMatchString     = "";
            my $invMatchStringTail = "";
            if ($cgiparams{'INV_MATCH_STRING'} eq 'on') {
                $invMatchString     = " <strong><font color='RED'>! (</font></strong>";
                $invMatchStringTail = "<strong><font color='RED'>)</font></strong>";
            }
            print <<END;
<tr>
    <td colspan='2' class='base'>
        <font class='boldbase'>Match string:</font>
    </td>
    <td class='base' >
        $invMatchString<b>$cgiparams{'MATCH_STRING'}</b>$invMatchStringTail
    </td>
</tr>
END
        }
        if ($cgiparams{'LIMIT_FOR'} ne 'none') {
            my $limitFor = "";
            if ($cgiparams{'LIMIT_FOR'} eq 'log') {
                $limitFor = $Lang::tr{'match log'};
            }
            elsif ($cgiparams{'LIMIT_FOR'} eq 'acceptOrDeny') {
                $limitFor = $Lang::tr{'match accept deny'};
            }
            elsif ($cgiparams{'LIMIT_FOR'} eq 'both') {
                $limitFor = $Lang::tr{'match both'};
            }

            my $limitOption = "--limit";
            my $limitValue  = $cgiparams{'MATCH_LIMIT_AVG'};
            if ($cgiparams{'LIMIT_TYPE'} eq 'burst') {
                $limitOption = "--limit-burst ";
                $limitValue  = $cgiparams{'MATCH_LIMIT_BURST'};
            }

            print <<END;
<tr>
    <td colspan='2' class='base'>
        <font class='boldbase'>Match limit:</font>
    </td>
    <td class='boldbase'>$limitFor</td>
</tr>
<tr>
    <td class='base'></td>
    <td class='base'>
        <font class='boldbase'>$limitOption</font>
    </td>
    <td class='boldbase'>$limitValue</td>
</tr>
END
        }
    }
    if ($warnOpenFwMessage) {
        print <<END;
<tr>
    <td colspan='3' class='base'>
        <font color='RED'>
            <b>$Lang::tr{'note'}:</b><br />
            $warnOpenFwMessage
        </font>
    </td>
</tr>
END
    }

    print <<END;
</table>
END
    &printHiddenFormParams('Overview');
    &printEnterButtons('Overview');
    print <<END;
<input type='hidden' name='RULEACTION' value='$cgiparams{'RULEACTION'}' />
</form>
END

    &Header::closebox();
    &printCurrentRulesBox('single');
}

sub printEnterButtons
{
    my $boxName      = shift;
    my $backDisabled = '';
    my $nextDisabled = '';
    if ($boxName eq 'EnterParams') {
        $backDisabled = "disabled='disabled'";
    }
    elsif ($boxName eq 'Overview') {
        $nextDisabled = "disabled='disabled'";
    }
    print <<END;
<table width='100%'>
<tr>
    <td width='10%'>&nbsp;</td>
    <td class='base' width='60%'>
        <input type='submit' name='BOX_ACTION' value='$Lang::tr{'back'}' $backDisabled />&nbsp;
        <input type='submit' name='BOX_ACTION' value='$Lang::tr{'next'}' $nextDisabled/>&nbsp;
        <input type='submit' name='BOX_ACTION' value='$Lang::tr{'save'}' />&nbsp;
        <input type='reset' name='BOX_ACTION' value='$Lang::tr{'reset'}' />&nbsp;
        <input type='submit' name='BOX_ACTION' value='$Lang::tr{'cancel'}' />
    </td>
    <td width='10%'>&nbsp;</td>
</tr>
</table>
END
}
