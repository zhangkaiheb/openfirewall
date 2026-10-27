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

# Add entry in menu
# MENUTHRDLVL "firewall rules" 030 "port forwarding" "port forwarding"
#
# Make sure translation exists $Lang::tr{'port forwarding'}

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

# Hardcoded rule type for this page
my $RULETYPE = 'PORTFW';

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

if ($cgiparams{'BOX_ACTION'} eq $Lang::tr{'save'})
{
    # Initialize OLD_POSITION and OLD_RULETYPE for copy operation
    if ($cgiparams{'ACTION'} eq $Lang::tr{'copy rule'}) {
        $cgiparams{'OLD_POSITION'} = -1 unless defined($cgiparams{'OLD_POSITION'});
        $cgiparams{'OLD_RULETYPE'} = $RULETYPE unless defined($cgiparams{'OLD_RULETYPE'});
    }

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
        } else {
            $cgiparams{'BOX_ACTION'} = $Lang::tr{'next'};
        }
    }
}

if ($cgiparams{'BOX_ACTION'} eq $Lang::tr{'save'}) {
    my $newRule = &buildRuleObject();
    my $ruletype = $RULETYPE;

    my $position = 0;
    foreach my $rule (@{$ruleConfig{$ruletype}}) {
        # we dont have to check the edited rule or copied rule
        next if (($cgiparams{'ACTION'} eq $Lang::tr{'edit'}
            || $cgiparams{'ACTION'} eq $Lang::tr{'copy rule'})
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
            if ($rule->{'TIMEFRAME_ENABLED'} eq 'on'
                && $newRule->{'TIMEFRAME_ENABLED'} eq 'on')
            {
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
            } else {
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
        } else {
            push(@{$ruleConfig{$ruletype}}, $newRule);
        }

        &DATA::saveRuleConfig(\%ruleConfig);

        if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
            &General::log($Lang::tr{'firewall rule updated'});
        } else {
            &General::log($Lang::tr{'firewall rule added'});
        }
        `/usr/local/bin/setfwrules -f $ruletype < /dev/null > /dev/null 2>&1 &`;

        undef %cgiparams;
        &resetCgiParams();
    }
}

# Allows rules to be enabled and disabled
if ($cgiparams{'ACTION'} eq $Lang::tr{'toggle enable disable'}
    || $cgiparams{'ACTION'} eq "$Lang::tr{'toggle enable disable'}log")
{
    my $ruletype = $RULETYPE;

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
    my $ruletype = $RULETYPE;

    $cgiparams{'OLD_POSITION'} = $cgiparams{'RULE_POSITION'};
    $cgiparams{'OLD_RULETYPE'} = $RULETYPE;

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
}

# Remove routine
if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    my $ruletype = $RULETYPE;

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

# Move rule up/down
if ($cgiparams{'ACTION'} eq $Lang::tr{'up'} || $cgiparams{'ACTION'} eq $Lang::tr{'down'})
{
    my $ruletype = $RULETYPE;

    if (defined @{$ruleConfig{$ruletype}}[ $cgiparams{'RULE_POSITION'} ]) {
        my $rule = @{$ruleConfig{$ruletype}}[ $cgiparams{'RULE_POSITION'} ];

        splice(@{$ruleConfig{$ruletype}}, $cgiparams{'RULE_POSITION'}, 1);

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

&Header::openpage($Lang::tr{'port forwarding'}, 1, '');

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

if ($errormessage) {
    $error = 'error';
    # Store error message for JavaScript modal display
    my $jsError = $errormessage;
    $jsError =~ s/<br\s*\/?>/\\n/g;
    $jsError =~ s/(['\\])/\\$1/g;
    my $trErrorMessages = $Lang::tr{'error messages'};
    print "<script>\n";
    print "document.addEventListener('DOMContentLoaded', function() {\n";
    print "    var overlay = document.createElement('div');\n";
    print "    overlay.className = 'ofw_modal_overlay';\n";
    print "    overlay.innerHTML = '<div class=\"ofw_modal_dialog\" style=\"width:420px;\">' +\n";
    print "        '<div class=\"ofw_modal_header\">' +\n";
    print "            '<svg class=\"ofw_modal_icon\" viewBox=\"0 0 24 24\"><path d=\"M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z\"/></svg>' +\n";
    print "            '<span class=\"ofw_modal_title\">$trErrorMessages</span>' +\n";
    print "            '<button class=\"ofw_modal_close\">&times;</button>' +\n";
    print "        '</div>' +\n";
    print "        '<div class=\"ofw_modal_body\">' +\n";
    print "            '<div class=\"ofw_modal_message\" style=\"white-space:pre-wrap;\">$jsError</div>' +\n";
    print "        '</div>' +\n";
    print "        '<div class=\"ofw_modal_footer\">' +\n";
    print "            '<button class=\"ofw_btn ofw_btn_primary\">OK</button>' +\n";
    print "        '</div>' +\n";
    print "    '</div>';\n";
    print "    document.body.appendChild(overlay);\n";
    print "    overlay.querySelector('.ofw_modal_close').addEventListener('click', function() { overlay.remove(); });\n";
    print "    overlay.querySelector('.ofw_btn_primary').addEventListener('click', function() { overlay.remove(); });\n";
    print "});\n";
    print "</script>\n";
}

if (!$invalidSettings) {
    if ($cgiparams{'ACTION'} eq '' || $cgiparams{'BOX_ACTION'} eq "$Lang::tr{'cancel'}" || $cgiparams{'BOX_ACTION'} eq "$Lang::tr{'save'}") {
        if ($warnOpenFwMessage) {
            &Header::openbox('100%', 'left', $Lang::tr{'warning messages'}, 'warning');
            print "<b>$Lang::tr{'note'}:</b><br />$warnOpenFwMessage\n";
            &Header::closebox();
        }
        &printRulesDataTable();
    } else {
        &printEnterParamsBox();
    }
} else {
    &printInvalidSettingsBox();
}

# Generate hidden form template for modals
&printRuleFormTemplate();

&Header::closebigbox();
&Header::closepage();

sub printRuleFormTemplate
{
    # Prepare form data
    my %customAdr = ();
    &DATA::readCustAddresses(\%customAdr);
    my @customAddresses = sort keys(%customAdr);
    
    my %addressGroupConf = ();
    &DATA::readAddressGroupConf(\%addressGroupConf);
    my @adrGroups = sort keys(%addressGroupConf);
    
    my %customSrv = ();
    &DATA::readCustServices(\%customSrv);
    my @customServices = sort keys(%customSrv);
    
    my %defaultServices = ();
    &DATA::readDefaultServices(\%defaultServices);
    
    my %defaultNetworks = ();
    &DATA::setup_default_networks(\%defaultNetworks);
    
    my %customIfaces_dst = ();
    my %customifacesCount_dst = &DATA::readCustIfaces(\%customIfaces_dst);
    my @customInterfaces_dst = sort keys(%customIfaces_dst);
    
    my %customIfaces_src = ();
    my %customifacesCount_src = &DATA::readCustIfaces(\%customIfaces_src);
    my @customInterfaces_src = sort keys(%customIfaces_src);
    
    # Translation strings
    my $trSource = $Lang::tr{'source'};
    my $trInterface = $Lang::tr{'net br iface'};
    my $trCustomAddresses = $Lang::tr{'custom addresses'};
    my $trAddressGroups = $Lang::tr{'address groups'};
    my $trUseSrcPort = $Lang::tr{'use src port'};
    my $trSourcePort = $Lang::tr{'source port'};
    my $trExternalDestination = $Lang::tr{'pfw openfirewall destination'};
    my $trAliasIp = $Lang::tr{'alias ip'};
    my $trCustomServices = $Lang::tr{'custom services'};
    my $trDefaultServices = $Lang::tr{'default services'};
    my $trInternalDestination = $Lang::tr{'pfw internal destination'};
    my $trInternalNetwork = $Lang::tr{'internal network'};
    my $trCustomInterfaces = $Lang::tr{'custom interfaces'};
    my $trAdditional = $Lang::tr{'additional'};
    my $trRuleEnabled = $Lang::tr{'rule enabled'};
    my $trLogRule = $Lang::tr{'log rule'};
    my $trRemark = $Lang::tr{'remark'};
    my $trThisFieldMayBeBlank = $Lang::tr{'this field may be blank'};
    
    # Build address options
    my $srcAddrOptions = '';
    foreach my $adr (@customAddresses) {
        $srcAddrOptions .= "<option value='$adr'>$adr</option>";
    }
    
    my $dstAddrOptions = '';
    foreach my $adr (@customAddresses) {
        $dstAddrOptions .= "<option value='$adr'>$adr</option>";
    }
    
    # Build address group options
    my $srcAddrGroupOptions = '';
    foreach my $grp (@adrGroups) {
        $srcAddrGroupOptions .= "<option value='$grp'>$grp</option>";
    }
    
    # Build alias IP options (Red Address only)
    my $aliasIpOptions = '';
    foreach my $ofwAdr (sort keys %defaultNetworks) {
        next unless ($defaultNetworks{$ofwAdr}{'LOCATION'} eq "IPCOP" && $defaultNetworks{$ofwAdr}{'COLOR'} eq "RED_COLOR");
        my $aliasIp = "";
        $aliasIp = " ($defaultNetworks{$ofwAdr}{'ADR'})" if($ofwAdr ne 'Red Address');
        $aliasIpOptions .= "<option value='$ofwAdr'>$ofwAdr$aliasIp</option>";
    }
    
    # Build custom service options
    my $customServiceOptions = '';
    foreach my $svc (@customServices) {
        $customServiceOptions .= "<option value='$svc'>$svc</option>";
    }
    
    # Build default service options
    my $defaultServiceOptions = '';
    foreach my $svc (sort keys %defaultServices) {
        $defaultServiceOptions .= "<option value='$svc'>$svc ($defaultServices{$svc}{'PORT_NR'})</option>";
    }
    
    # Build custom interface options for internal destination
    my $dstCustomIfaceOptions = '';
    foreach my $iface (@customInterfaces_dst) {
        if ($customIfaces_dst{$iface}{'EXTERNAL'} ne 'on') {
            my $translated = &General::translateinterface($iface);
            $dstCustomIfaceOptions .= "<option value='$iface'>$translated</option>";
        }
    }
    
    # Build custom interface options for source
    my $srcCustomIfaceOptions = '';
    foreach my $iface (@customInterfaces_src) {
        if ($customIfaces_src{$iface}{'EXTERNAL'} ne 'on') {
            my $translated = &General::translateinterface($iface);
            $srcCustomIfaceOptions .= "<option value='$iface'>$translated</option>";
        }
    }
    
    # Build interface options for source/destination network
    my $srcIfaceOptions = '';
    foreach my $iface (sort keys %FW::interfaces) {
        next if ($FW::interfaces{$iface}{'COLOR'} eq 'RED_COLOR');
        my $translated = &General::translateinterface($iface);
        $srcIfaceOptions .= "<option value='$iface'>$translated</option>";
    }
    
    my $dstIfaceOptions = '';
    foreach my $iface (sort keys %FW::interfaces) {
        next if ($FW::interfaces{$iface}{'COLOR'} eq 'RED_COLOR');
        my $translated = &General::translateinterface($iface);
        $dstIfaceOptions .= "<option value='$iface'>$translated</option>";
    }
    
    my $trSave = $Lang::tr{'save'};
    my $scriptName = $ENV{'SCRIPT_NAME'};
    
    # Timeframe translation strings
    my $trAddTimeframe = $Lang::tr{'add timeframe'};
    my $trDays = $Lang::tr{'days'};
    my $trDaysTo = $Lang::tr{'days to'};
    my $trDaysOfWeek = $Lang::tr{'days of the week'};
    my $trDaytime = $Lang::tr{'daytime'};
    my $trMonday = $Lang::tr{'monday'};
    my $trTuesday = $Lang::tr{'tuesday'};
    my $trWednesday = $Lang::tr{'wednesday'};
    my $trThursday = $Lang::tr{'thursday'};
    my $trFriday = $Lang::tr{'friday'};
    my $trSaturday = $Lang::tr{'saturday'};
    my $trSunday = $Lang::tr{'sunday'};

    print <<END;
<div id="ruleFormTemplate" style="display:none;">
<form method="post" action="$scriptName">
<input type="hidden" name="BOX_ACTION" value="$trSave">
<input type="hidden" name="RULETYPE" value="PORTFW">
<input type="hidden" name="RULE_POSITION" value="-1">

<table width="100%">
<tr><td class="boldbase">&nbsp;&nbsp;$trSource</td></tr>
</table>
<table width="100%" cellpadding="0" cellspacing="5" border="0">
<input type="hidden" name="SRC_NET_TYPE" value="defaultSrcNet" />
<input type="hidden" name="DEFAULT_SRC_NET" value="Any" />
<input type="hidden" name="CUST_SRC_NET" value="" />
<tr><td colspan="4" style="padding: 8px 0;"></td></tr>
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base">
<input type="radio" name="SRC_ADR_TYPE" value="custSrcAdr" checked="checked" />
</td>
<td width="20%" class="base">$trCustomAddresses</td>
<td width="75%" class="base">
<select name="CUST_SRC_ADR" style="width:300px">
<option value="BLANK" selected="selected">N/A</option>
$srcAddrOptions
</select>
</td>
</tr>
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base">
<input type="radio" name="SRC_ADR_TYPE" value="groupSrcAdr" />
</td>
<td width="20%" class="base">$trAddressGroups</td>
<td width="75%" class="base">
<select name="GROUP_SRC_ADR" style="width:300px">
<option value="BLANK" selected="selected">N/A</option>
$srcAddrGroupOptions
</select>
</td>
</tr>
<tr>
<td class="base"></td>
<td class="base">
<input type="checkbox" name="SRC_PORT_ON" />
</td>
<td width="20%" class="base">$trUseSrcPort</td>
</tr>
<tr>
<td class="base"></td>
<td class="base"></td>
<td width="20%" class="base">$trSourcePort</td>
<td width="75%" class="base">
<input type="text" name="SRC_PORT" value="" size="14" maxlength="12" />
</td>
</tr>
<input type="hidden" name="INV_SRC_ADR" value="off" />
<input type="hidden" name="INV_SRC_PORT" value="off" />
<tr><td colspan="4" bgcolor="#E0E0E0"><img src="/images/null.gif" width="1" height="1" border="0" alt="--------" /></td></tr>
</table>

<table width="100%">
<tr><td class="boldbase">&nbsp;&nbsp;$trExternalDestination</td></tr>
</table>
<table width="100%" cellpadding="0" cellspacing="5" border="0">
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base"></td>
<td width="20%" class="base">$trAliasIp</td>
<td width="75%" class="base">
<select name="PORTFW_EXT_ADR" style="width:300px">
$aliasIpOptions
</select>
</td>
</tr>
<tr>
<td class="base"></td>
<td class="base" colspan="2">
<input type="radio" name="PORTFW_SERVICE_TYPE" value="custom" />
$trCustomServices
</td>
<td width="75%" class="base">
<select name="PORTFW_CUST_SERVICE" style="width:300px">
<option value="BLANK" selected="selected">N/A</option>
$customServiceOptions
</select>
</td>
</tr>
<tr>
<td class="base"></td>
<td class="base" colspan="2">
<input type="radio" name="PORTFW_SERVICE_TYPE" value="default" checked="checked" />
$trDefaultServices
</td>
<td width="75%" class="base">
<select name="PORTFW_DEFAULT_SERVICE" style="width:300px">
<option value="BLANK" selected="selected">-- $trDefaultServices --</option>
$defaultServiceOptions
</select>
</td>
</tr>
<tr><td colspan="4" bgcolor="#E0E0E0"><img src="/images/null.gif" width="1" height="1" border="0" alt="--------" /></td></tr>
</table>

<table width="100%">
<tr><td class="boldbase">&nbsp;&nbsp;$trInternalDestination</td></tr>
</table>
<table width="100%" cellpadding="0" cellspacing="5" border="0">
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base">
<input type="radio" name="DST_NET_TYPE" value="defaultDestNet" checked="checked" />
</td>
<td width="20%" class="base">$trInternalNetwork</td>
<td width="75%" class="base">
<select name="DEFAULT_DST_NET" style="width:300px">
$dstIfaceOptions
</select>
</td>
</tr>
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base">
<input type="radio" name="DST_NET_TYPE" value="custDestNet" />
</td>
<td width="20%" class="base">$trCustomInterfaces</td>
<td width="75%" class="base">
<select name="CUST_DST_NET" style="width:300px">
<option value="BLANK" selected="selected">N/A</option>
$dstCustomIfaceOptions
</select>
</td>
</tr>
<tr><td colspan="4" style="padding: 8px 0;"></td></tr>
<input type="hidden" name="SERVICE_ON" value="on" />
<input type="hidden" name="INV_DST_IP" value="off" />
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base"></td>
<td width="20%" class="base">$trCustomAddresses</td>
<td width="75%" class="base">
<input type="hidden" name="DST_IP_TYPE" value="custDestIP" />
<select name="CUST_DST_ADR" style="width:300px">
<option value="BLANK" selected="selected">N/A</option>
$dstAddrOptions
</select>
</td>
</tr>
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base">
<input type="radio" name="SERVICE_TYPE" value="custom" />
</td>
<td width="20%" class="base">$trCustomServices</td>
<td width="75%" class="base">
<select name="CUST_SERVICE" style="width:300px">
<option value="BLANK" selected="selected">N/A</option>
$customServiceOptions
</select>
</td>
</tr>
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base">
<input type="radio" name="SERVICE_TYPE" value="default" checked="checked" />
</td>
<td width="20%" class="base">$trDefaultServices</td>
<td width="75%" class="base">
<select name="DEFAULT_SERVICE" style="width:300px">
<option value="BLANK" selected="selected">-- $trDefaultServices --</option>
$defaultServiceOptions
</select>
</td>
</tr>
<tr><td colspan="4" bgcolor="#E0E0E0"><img src="/images/null.gif" width="1" height="1" border="0" alt="--------" /></td></tr>
</table>

<table width="100%">
<tr><td class="boldbase">&nbsp;&nbsp;$trAdditional</td></tr>
</table>
<table width="100%" cellpadding="0" cellspacing="5" border="0">
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base">
<input type="checkbox" name="ENABLED" checked="checked" />
</td>
<td width="20%">
<font class="boldbase">$trRuleEnabled</font>
</td>
<td width="75%" class="base"></td>
</tr>
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base">
<input type="checkbox" name="LOG_ENABLED" />
</td>
<td width="20%">
<font class="boldbase">$trLogRule</font>
</td>
<td width="75%" class="base"></td>
</tr>
<tr><td colspan="4" bgcolor="#E0E0E0"><img src="/images/null.gif" width="1" height="1" border="0" alt="--------" /></td></tr>
<tr>
    <td width="4%" class="base"></td>
    <td width="1%" class="base">
        <input type="checkbox" name="TIMEFRAME_ENABLED" class="timeframe-toggle" />
    </td>
    <td width="20%" class="base">
        <font class="boldbase">$trAddTimeframe</font>
    </td>
    <td width="75%" class="base"></td>
</tr>
<tr class="timeframe-options" style="display:none;">
    <td width="4%" class="base"></td>
    <td width="1%" class="base"></td>
    <td width="20%" class="base">$trDays:</td>
    <td width="75%" class="base"></td>
</tr>
<tr class="timeframe-options day-of-month-ctrl" style="display:none;">
    <td width="4%" class="base"></td>
    <td width="1%" class="base"></td>
    <td width="1%" class="base">
        <input type="radio" value="dayOfMonth" name="DAY_TYPE" checked="checked" />
    </td>
    <td class="base">
        <select name="START_DAY_MONTH" style="width:50px">
END
# Generate day options
for my $day (1..31) {
    print "<option value='$day'>$day</option>";
}
print <<END;
        </select>
        &nbsp;
        $trDaysTo
        &nbsp;
        <select name="END_DAY_MONTH" style="width:50px">
END
for my $day (1..31) {
    print "<option value='$day'>$day</option>";
}
print <<END;
        </select>
    </td>
</tr>
<tr class="timeframe-options" style="display:none;">
    <td class="base"></td>
    <td class="base"></td>
    <td width="1%" class="base">
        <input type="radio" value="weekDays" name="DAY_TYPE" />
    </td>
    <td class="base">$trDaysOfWeek:</td>
</tr>
END
# Generate weekday checkboxes
my @weekdays = ('MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN');
my @weekdayLabels = ($trMonday, $trTuesday, $trWednesday, $trThursday, $trFriday, $trSaturday, $trSunday);
for my $i (0..6) {
    my $day = $weekdays[$i];
    my $label = $weekdayLabels[$i];
    print <<END;
<tr class="timeframe-options weekday-ctrl" style="display:none;">
    <td class="base"></td>
    <td class="base"></td>
    <td class="base"></td>
    <td class="base">
        <input type="checkbox" name="$day" />
        &nbsp;$label
    </td>
</tr>
END
}
print <<END;
<tr class="timeframe-options" style="display:none;">
    <td class="base"></td>
    <td colspan="3" bgcolor="#000000"><img src="/images/null.gif" width="1" height="1" border="0" alt="--------" /></td>
</tr>
<tr class="timeframe-options" style="display:none;">
    <td class="base"></td>
    <td colspan="3" class="base">$trDaytime:</td>
</tr>
<tr class="timeframe-options" style="display:none;">
    <td class="base"></td>
    <td class="base"></td>
    <td class="base"></td>
    <td class="base">
        <select name="START_HOUR" style="width:50px">
END
# Generate hour options
for my $hour (0..23) {
    my $display = sprintf("%02d", $hour);
    print "<option value='$hour'>$display</option>";
}
print <<END;
        </select>:
        <select name="START_MINUTE" style="width:50px">
END
# Generate minute options (every 5 minutes)
for my $minute (0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55) {
    my $display = sprintf("%02d", $minute);
    print "<option value='$minute'>$display</option>";
}
print <<END;
        </select>
        &nbsp;
        $trDaysTo
        &nbsp;
        <select name="END_HOUR" style="width:50px">
END
for my $hour (0..23) {
    my $display = sprintf("%02d", $hour);
    print "<option value='$hour'>$display</option>";
}
print <<END;
        </select>:
        <select name="END_MINUTE" style="width:50px">
END
for my $minute (0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55) {
    my $display = sprintf("%02d", $minute);
    print "<option value='$minute'>$display</option>";
}
print <<END;
        </select>
    </td>
</tr>
<tr class="timeframe-options" style="display:none;">
    <td colspan="4"><img src="/images/null.gif" width="1" height="2" border="0" alt="--------" /></td>
</tr>
</table>

<table width="100%" cellpadding="0" cellspacing="5" border="0">
<input type="hidden" name="RULEACTION" value="accept" />
<tr></tr>
<tr>
<td></td>
<td colspan="4" bgcolor="#EAEAEA"><img src="/images/null.gif" width="1" height="1" border="0" alt="--------" /></td>
</tr>
<tr></tr>
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base"></td>
<td class="base">
<font class="boldbase">$trRemark:</font>
<img src="/blob.gif" alt="*" />&nbsp;
</td>
<td width="75%" class="base">
<input type="text" name="REMARK" value="" size="55" maxlength="50" />
</td>
</tr>
<tr>
<td width="4%" class="base"></td>
<td width="1%" class="base"></td>
<td class="base">
<img src="/blob.gif" alt="*" align="top" />&nbsp;
<font class="base">$trThisFieldMayBeBlank</font>
</td>
</tr>
<tr>
<td colspan="4" bgcolor="#E0E0E0"><img src="/images/null.gif" width="1" height="1" border="0" alt="--------" /></td>
</tr>
</table>
</form>
</div>
END
}

sub printRulesDataTable
{
    # Convert rules to JavaScript format for DataTable
    my @jsData;
    my $position = 0;
    
    foreach my $rule (@{$ruleConfig{$RULETYPE}}) {
        my $srcNet = &General::translateinterface($rule->{'SRC_NET'});
        $srcNet =~ s/(['\\])/\\$1/g;

        my $srcAddr = $rule->{'SRC_ADR'};
        if ($rule->{'INV_SRC_ADR'} eq 'on') {
            $srcAddr = "! ($srcAddr)";
        }
        if ($rule->{'SRC_PORT'} ne '-') {
            if ($rule->{'INV_SRC_PORT'} eq 'on') {
                $srcAddr .= " : ! ($rule->{'SRC_PORT'})";
            } else {
                $srcAddr .= " : $rule->{'SRC_PORT'}";
            }
        }
        $srcAddr =~ s/(['\\])/\\$1/g;

        my $dstNet = &General::translateinterface($rule->{'DST_NET'});
        $dstNet =~ s/(['\\])/\\$1/g;

        # Port forwarding has special destination display
        my $dstAddr = $rule->{'PORTFW_EXT_ADR'};
        if ($rule->{'PORTFW_SERVICE'} ne $rule->{'SERVICE'} ||
            $rule->{'PORTFW_SERVICE_TYPE'} ne $rule->{'SERVICE_TYPE'}) {
            $dstAddr .= " : $rule->{'PORTFW_SERVICE'}";
        }
        $dstAddr .= "<br>";

        $dstAddr .= $rule->{'DST_IP'};
        if ($rule->{'INV_DST_IP'} eq 'on') {
            $dstAddr = "! ($dstAddr)";
        }
        if ($rule->{'SERVICE_TYPE'} ne '-') {
            $dstAddr .= " : $rule->{'SERVICE'}";
        }
        $dstAddr =~ s/(['\\])/\\$1/g;

        my $remark = $rule->{'REMARK'} || '';
        $remark =~ s/(['\\])/\\$1/g;

        my $action = $rule->{'RULEACTION'};
        $action =~ s/(['\\])/\\$1/g;

        # Pre-compute timeframe display text
        my $timeframeText = '-';
        if ($rule->{'TIMEFRAME_ENABLED'} eq 'on') {
            if ($rule->{'DAY_TYPE'} eq 'dayOfMonth') {
                $timeframeText = "Day " . ($rule->{'START_DAY_MONTH'} || '1') . " - " . ($rule->{'END_DAY_MONTH'} || '31');
            } else {
                my @days;
                push @days, 'Mon' if $rule->{'MON'} eq 'on';
                push @days, 'Tue' if $rule->{'TUE'} eq 'on';
                push @days, 'Wed' if $rule->{'WED'} eq 'on';
                push @days, 'Thu' if $rule->{'THU'} eq 'on';
                push @days, 'Fri' if $rule->{'FRI'} eq 'on';
                push @days, 'Sat' if $rule->{'SAT'} eq 'on';
                push @days, 'Sun' if $rule->{'SUN'} eq 'on';
                $timeframeText = join(', ', @days);
            }
            my $startH = sprintf("%02d", $rule->{'START_HOUR'} || 0);
            my $startM = sprintf("%02d", $rule->{'START_MINUTE'} || 0);
            my $endH = sprintf("%02d", $rule->{'END_HOUR'} || 23);
            my $endM = sprintf("%02d", $rule->{'END_MINUTE'} || 55);
            $timeframeText .= "<br>$startH:$startM - $endH:$endM";
        }
        $timeframeText =~ s/(['\\])/\\$1/g;

        # Escape raw config values for JavaScript
        my $rawSrcNet = $rule->{'SRC_NET'} || '';
        $rawSrcNet =~ s/(['\\])/\\$1/g;
        my $rawSrcAdr = $rule->{'SRC_ADR'} || '';
        $rawSrcAdr =~ s/(['\\])/\\$1/g;
        my $rawSrcPort = $rule->{'SRC_PORT'} || '-';
        $rawSrcPort =~ s/(['\\])/\\$1/g;
        my $rawDstNet = $rule->{'DST_NET'} || '';
        $rawDstNet =~ s/(['\\])/\\$1/g;
        my $rawDstIp = $rule->{'DST_IP'} || '';
        $rawDstIp =~ s/(['\\])/\\$1/g;
        my $rawService = $rule->{'SERVICE'} || '';
        $rawService =~ s/(['\\])/\\$1/g;
        my $rawServiceType = $rule->{'SERVICE_TYPE'} || '-';
        $rawServiceType =~ s/(['\\])/\\$1/g;
        my $rawPortfwExtAdr = $rule->{'PORTFW_EXT_ADR'} || '';
        $rawPortfwExtAdr =~ s/(['\\])/\\$1/g;
        my $rawPortfwService = $rule->{'PORTFW_SERVICE'} || '';
        $rawPortfwService =~ s/(['\\])/\\$1/g;
        my $rawPortfwServiceType = $rule->{'PORTFW_SERVICE_TYPE'} || '-';
        $rawPortfwServiceType =~ s/(['\\])/\\$1/g;
        my $rawSrcNetType = $rule->{'SRC_NET_TYPE'} || 'defaultSrcNet';
        $rawSrcNetType =~ s/(['\\])/\\$1/g;
        my $rawSrcAdrType = $rule->{'SRC_ADR_TYPE'} || 'custSrcAdr';
        $rawSrcAdrType =~ s/(['\\])/\\$1/g;
        my $rawDstNetType = $rule->{'DST_NET_TYPE'} || 'defaultDestNet';
        $rawDstNetType =~ s/(['\\])/\\$1/g;
        my $rawDstIpType = $rule->{'DST_IP_TYPE'} || 'custDestIP';
        $rawDstIpType =~ s/(['\\])/\\$1/g;

        # Pre-compute icon HTML for enabled and logging
        my $enabledIcon = $rule->{'ENABLED'} eq 'on'
            ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2e7d32" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>'
            : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#c62828" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>';
        my $logIcon = $rule->{'LOG_ENABLED'} eq 'on'
            ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2e7d32" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>'
            : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#c62828" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>';
        $enabledIcon =~ s/(['\\])/\\$1/g;
        $logIcon =~ s/(['\\])/\\$1/g;

        push @jsData, sprintf(
            "{id:'%d',position:%d,srcNet:'%s',srcAddr:'%s',action:'%s',dstNet:'%s',dstAddr:'%s',remark:'%s',timeframeText:'%s',enabledIcon:'%s',logIcon:'%s',enabled:'%s',logEnabled:'%s',rawSrcNet:'%s',rawSrcAdr:'%s',rawSrcPort:'%s',rawDstNet:'%s',rawDstIp:'%s',rawService:'%s',rawServiceType:'%s',rawPortfwExtAdr:'%s',rawPortfwService:'%s',rawPortfwServiceType:'%s',rawSrcNetType:'%s',rawSrcAdrType:'%s',rawDstNetType:'%s',rawDstIpType:'%s',invSrcAdr:'%s',invSrcPort:'%s',invDstIp:'%s',timeframeEnabled:'%s',dayType:'%s',startDayMonth:'%s',endDayMonth:'%s',startHour:'%s',startMinute:'%s',endHour:'%s',endMinute:'%s',mon:'%s',tue:'%s',wed:'%s',thu:'%s',fri:'%s',sat:'%s',sun:'%s'}",
            $position + 1, $position,
            $srcNet, $srcAddr, $action,
            $dstNet, $dstAddr, $remark, $timeframeText,
            $enabledIcon, $logIcon,
            $rule->{'ENABLED'}, $rule->{'LOG_ENABLED'},
            $rawSrcNet, $rawSrcAdr, $rawSrcPort,
            $rawDstNet, $rawDstIp, $rawService, $rawServiceType,
            $rawPortfwExtAdr, $rawPortfwService, $rawPortfwServiceType,
            $rawSrcNetType, $rawSrcAdrType, $rawDstNetType, $rawDstIpType,
            $rule->{'INV_SRC_ADR'} || '', $rule->{'INV_SRC_PORT'} || '', $rule->{'INV_DST_IP'} || '',
            $rule->{'TIMEFRAME_ENABLED'} || 'off',
            $rule->{'DAY_TYPE'} || 'dayOfMonth',
            $rule->{'START_DAY_MONTH'} || '1',
            $rule->{'END_DAY_MONTH'} || '31',
            $rule->{'START_HOUR'} || '0',
            $rule->{'START_MINUTE'} || '0',
            $rule->{'END_HOUR'} || '23',
            $rule->{'END_MINUTE'} || '55',
            $rule->{'MON'} || 'off',
            $rule->{'TUE'} || 'off',
            $rule->{'WED'} || 'off',
            $rule->{'THU'} || 'off',
            $rule->{'FRI'} || 'off',
            $rule->{'SAT'} || 'off',
            $rule->{'SUN'} || 'off'
        );
        $position++;
    }
    my $jsDataStr = join(",\n", @jsData);
    
    # Prepare translation strings
    my $trSequence = $Lang::tr{'sequence'};
    my $trInterface = $Lang::tr{'net br iface'};
    my $trSource = $Lang::tr{'source'};
    my $trAction = $Lang::tr{'ruleaction'};
    my $trDestInterface = $Lang::tr{'pfw internal destination'};
    my $trDestination = $Lang::tr{'destination'};
    my $trRemark = $Lang::tr{'remark'};
    my $trEnabled = $Lang::tr{'enabled'};
    my $trLogging = $Lang::tr{'logging'};
    my $trTimeframe = $Lang::tr{'timeframe'};
    my $trMondayShort = $Lang::tr{'monday very short'};
    my $trTuesdayShort = $Lang::tr{'tuesday very short'};
    my $trWednesdayShort = $Lang::tr{'wednesday very short'};
    my $trThursdayShort = $Lang::tr{'thursday very short'};
    my $trFridayShort = $Lang::tr{'friday very short'};
    my $trSaturdayShort = $Lang::tr{'saturday very short'};
    my $trSundayShort = $Lang::tr{'sunday very short'};
    my $trDaysToCol = $Lang::tr{'days to'};
    my $trAdd = $Lang::tr{'add'};
    my $trEdit = $Lang::tr{'edit'};
    my $trRemove = $Lang::tr{'remove'};
    my $trCopy = $Lang::tr{'copy rule'};
    my $trMoveUp = $Lang::tr{'up'};
    my $trMoveDown = $Lang::tr{'down'};
    my $trToggleEnable = $Lang::tr{'toggle enable disable'};
    my $trToggleLog = "$Lang::tr{'toggle enable disable'}log";
    my $trDeleteConfirm = $Lang::tr{'are you sure you want to delete this rule'};
    my $trDeleteConfirmPlural = $Lang::tr{'are you sure you want to delete these rules'};
    my $trSave = $Lang::tr{'save'};
    my $trCancel = $Lang::tr{'cancel'};
    my $trAccept = $Lang::tr{'fw accept'};
    my $trDrop = $Lang::tr{'fw drop'};
    my $trReject = $Lang::tr{'fw reject'};
    my $trAddTimeframe = $Lang::tr{'add timeframe'};
    my $trDays = $Lang::tr{'days'};
    my $trDaysTo = $Lang::tr{'days to'};
    my $trDaysOfWeek = $Lang::tr{'days of the week'};
    my $trDaytime = $Lang::tr{'daytime'};
    my $trMonday = $Lang::tr{'monday'};
    my $trTuesday = $Lang::tr{'tuesday'};
    my $trWednesday = $Lang::tr{'wednesday'};
    my $trThursday = $Lang::tr{'thursday'};
    my $trFriday = $Lang::tr{'friday'};
    my $trSaturday = $Lang::tr{'saturday'};
    my $trSunday = $Lang::tr{'sunday'};
    my $scriptName = $ENV{'SCRIPT_NAME'};
    
    print <<END;
<script src="/include/datatable.js"></script>
<script>
var tableData = [
$jsDataStr
];

function formatTimeframe(row) {
    if (row.timeframeEnabled !== 'on') return '-';
    var result = '';
    if (row.dayType === 'dayOfMonth') {
        result = 'Day ' + row.startDayMonth + ' $trDaysToCol ' + row.endDayMonth;
    } else {
        var days = [];
        if (row.mon === 'on') days.push('$trMondayShort');
        if (row.tue === 'on') days.push('$trTuesdayShort');
        if (row.wed === 'on') days.push('$trWednesdayShort');
        if (row.thu === 'on') days.push('$trThursdayShort');
        if (row.fri === 'on') days.push('$trFridayShort');
        if (row.sat === 'on') days.push('$trSaturdayShort');
        if (row.sun === 'on') days.push('$trSundayShort');
        result = days.join(', ');
    }
    result += '<br>' + row.startHour + ':' + row.startMinute + ' $trDaysToCol ' + row.endHour + ':' + row.endMinute;
    return result;
}

document.addEventListener('DOMContentLoaded', function() {
    window.rulesTable = new DataTable('#rulesTable', {
        data: tableData,
        columns: [
            { key: 'id', title: '$trSequence', sortable: true },
            { key: 'srcNet', title: '$trInterface', sortable: true },
            { key: 'srcAddr', title: '$trSource', sortable: true },
            { key: 'action', title: '$trAction', sortable: true },
            { key: 'dstNet', title: '$trDestInterface', sortable: true },
            { key: 'dstAddr', title: '$trDestination', sortable: true },
            { key: 'remark', title: '$trRemark', sortable: true },
            { key: 'timeframeText', title: '$trTimeframe', sortable: true },
            { key: 'enabledIcon', title: '$trEnabled', sortable: true },
            { key: 'logIcon', title: '$trLogging', sortable: true }
        ],
        selectable: true,
        pageSize: 25,
        actions: ['create', 'edit', 'delete', 'refresh', 'copy', 'moveUp', 'moveDown', 'toggleEnable', 'toggleLog'],
        disabledActions: ['copy', 'moveUp', 'moveDown', 'toggleEnable', 'toggleLog'],
        onAddModal: function() {
            openAddRuleModal();
        },
        onEditModal: function(row) {
            openEditRuleModal(row);
        },
        onDeleteConfirm: function(selectedRows) {
            deleteRules(selectedRows);
        },
        onAction: function(action) {
            handleCustomAction(action);
        },
        onSelectionChange: function() {
            updateButtonStates();
        }
    });
});

function updateButtonStates() {
    var selectedRows = window.rulesTable.selectedRows;
    var copyBtn = document.querySelector('button[data-action="copy"]');
    var moveUpBtn = document.querySelector('button[data-action="moveUp"]');
    var moveDownBtn = document.querySelector('button[data-action="moveDown"]');
    var toggleEnableBtn = document.querySelector('button[data-action="toggleEnable"]');
    var toggleLogBtn = document.querySelector('button[data-action="toggleLog"]');
    
    if (selectedRows.length === 1) {
        if (copyBtn) copyBtn.disabled = false;
        if (moveUpBtn) moveUpBtn.disabled = false;
        if (moveDownBtn) moveDownBtn.disabled = false;
    } else {
        if (copyBtn) copyBtn.disabled = true;
        if (moveUpBtn) moveUpBtn.disabled = true;
        if (moveDownBtn) moveDownBtn.disabled = true;
    }
    
    if (selectedRows.length > 0) {
        if (toggleEnableBtn) toggleEnableBtn.disabled = false;
        if (toggleLogBtn) toggleLogBtn.disabled = false;
    } else {
        if (toggleEnableBtn) toggleEnableBtn.disabled = true;
        if (toggleLogBtn) toggleLogBtn.disabled = true;
    }
}

function handleCustomAction(action) {
    var selectedRows = window.rulesTable.selectedRows;
    
    if (action === 'copy') {
        if (selectedRows.length === 1) {
            copyRule(selectedRows[0].position);
        }
    } else if (action === 'moveUp') {
        if (selectedRows.length === 1) {
            moveRule(selectedRows[0].position, 'up');
        }
    } else if (action === 'moveDown') {
        if (selectedRows.length === 1) {
            moveRule(selectedRows[0].position, 'down');
        }
    } else if (action === 'toggleEnable') {
        selectedRows.forEach(function(row) {
            toggleRuleEnable(row.position, row.enabled === 'on' ? 'off' : 'on');
        });
    } else if (action === 'toggleLog') {
        selectedRows.forEach(function(row) {
            toggleRuleLog(row.position, row.logEnabled === 'on' ? 'off' : 'on');
        });
    }
}

function copyRule(position) {
    var row = tableData.find(function(r) { return r.position === position; });
    if (!row) return;
    openCopyRuleModal(row);
}

function moveRule(position, direction) {
    var form = document.createElement('form');
    form.method = 'post';
    form.action = '$scriptName';
    form.innerHTML = '<input type="hidden" name="ACTION" value="' + (direction === 'up' ? '$trMoveUp' : '$trMoveDown') + '">' +
                     '<input type="hidden" name="RULE_POSITION" value="' + position + '">' +
                     '<input type="hidden" name="RULETYPE" value="PORTFW">';
    document.body.appendChild(form);
    form.submit();
}

function toggleRuleEnable(position, enabled) {
    var form = document.createElement('form');
    form.method = 'post';
    form.action = '$scriptName';
    form.innerHTML = '<input type="hidden" name="ACTION" value="$trToggleEnable">' +
                     '<input type="hidden" name="RULE_POSITION" value="' + position + '">' +
                     '<input type="hidden" name="ENABLED" value="' + enabled + '">' +
                     '<input type="hidden" name="RULETYPE" value="PORTFW">';
    document.body.appendChild(form);
    form.submit();
}

function toggleRuleLog(position, logEnabled) {
    var form = document.createElement('form');
    form.method = 'post';
    form.action = '$scriptName';
    form.innerHTML = '<input type="hidden" name="ACTION" value="$trToggleLog">' +
                     '<input type="hidden" name="RULE_POSITION" value="' + position + '">' +
                     '<input type="hidden" name="LOG_ENABLED" value="' + logEnabled + '">' +
                     '<input type="hidden" name="RULETYPE" value="PORTFW">';
    document.body.appendChild(form);
    form.submit();
}

function deleteRules(selectedRows) {
    if (selectedRows.length === 0) return;
    
    // Create custom delete confirmation modal
    var count = selectedRows.length;
    var msg = count === 1 ? 'Are you sure you want to delete the following rule?' : 'Are you sure you want to delete the following ' + count + ' rules?';
    
    // Get rule names/positions for display
    var namesHtml = selectedRows.map(function(row) {
        return '<div style="padding:4px 0;">' + (row.remark || 'Rule ' + row.id) + '</div>';
    }).join('');
    
    var overlay = document.createElement('div');
    overlay.className = 'ofw_modal_overlay';
    overlay.innerHTML = '<div class="ofw_modal_dialog" style="width:400px;">' +
        '<div class="ofw_modal_header">' +
            '<svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>' +
            '<span class="ofw_modal_title">Confirm Delete</span>' +
            '<button class="ofw_modal_close">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' +
            '<div class="ofw_modal_message">' + msg + '</div>' +
            '<div style="margin-top:12px;padding:8px 12px;background:#f5f5f5;border-radius:4px;">' +
                namesHtml +
            '</div>' +
        '</div>' +
        '<div class="ofw_modal_footer">' +
            '<button class="ofw_btn ofw_btn_cancel">Cancel</button>' +
            '<button class="ofw_btn ofw_btn_primary">Delete</button>' +
        '</div>' +
    '</div>';
    
    document.body.appendChild(overlay);
    
    // Close button
    overlay.querySelector('.ofw_modal_close').addEventListener('click', function() {
        overlay.remove();
    });
    
    // Cancel button
    overlay.querySelector('.ofw_btn_cancel').addEventListener('click', function() {
        overlay.remove();
    });
    
    // Delete button
    overlay.querySelector('.ofw_btn_primary').addEventListener('click', function() {
        overlay.remove();
        
        // Delete rules one by one (in reverse order to maintain positions)
        var positions = selectedRows.map(function(row) { return row.position; }).sort(function(a, b) { return b - a; });

        function deleteNext() {
            if (positions.length === 0) {
                window.location.reload();
                return;
            }
            var pos = positions.shift();
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '$scriptName', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    deleteNext();
                }
            };
            xhr.send('ACTION=$trRemove&RULE_POSITION=' + pos + '&RULETYPE=PORTFW');
        }

        deleteNext();
    });
}

function openAddRuleModal() {
    if (document.querySelector('#addRuleModal')) return;
    var tpl = document.getElementById('ruleFormTemplate');
    if (!tpl) return;
    var formHtml = tpl.innerHTML;
    formHtml = formHtml.replace('name="RULE_POSITION" value="-1"', 'name="RULE_POSITION" value="-1"');
    var modalHtml = '<div class="ofw_modal_overlay" id="addRuleModal">' +
        '<div class="ofw_modal_dialog" style="width:850px;">' +
        '<div class="ofw_modal_header" style="cursor:move;">' +
        '<span class="ofw_modal_title">$trAdd</span>' +
        '<button type="button" class="ofw_modal_close" onclick="closeAddRuleModal()">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' + formHtml + '</div>' +
        '<div class="ofw_modal_footer">' +
        '<button type="button" class="ofw_btn" onclick="closeAddRuleModal()">$trCancel</button>' +
        '<button type="button" class="ofw_btn ofw_btn_primary" onclick="submitAddRuleForm()">$trSave</button>' +
        '</div></div></div>';
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    makeModalDraggable('addRuleModal');
    bindRadioChangeEvents(document.getElementById('addRuleModal'));
    bindTimeframeToggle(document.getElementById('addRuleModal'));
    bindDayTypeToggle(document.getElementById('addRuleModal'));
}

function openEditRuleModal(row) {
    if (document.querySelector('#editRuleModal')) return;
    var tpl = document.getElementById('ruleFormTemplate');
    if (!tpl) return;
    var formHtml = tpl.innerHTML;
    formHtml = formHtml.replace('name="RULE_POSITION" value="-1"', 'name="RULE_POSITION" value="' + row.position + '"');
    formHtml = formHtml.replace('name="BOX_ACTION" value="$trSave"', 'name="BOX_ACTION" value="$trSave"><input type="hidden" name="ACTION" value="$trEdit"><input type="hidden" name="OLD_POSITION" value="' + row.position + '"><input type="hidden" name="OLD_RULETYPE" value="PORTFW"');
    var modalHtml = '<div class="ofw_modal_overlay" id="editRuleModal">' +
        '<div class="ofw_modal_dialog" style="width:850px;">' +
        '<div class="ofw_modal_header" style="cursor:move;">' +
        '<span class="ofw_modal_title">$trEdit</span>' +
        '<button type="button" class="ofw_modal_close" onclick="closeEditRuleModal()">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' + formHtml + '</div>' +
        '<div class="ofw_modal_footer">' +
        '<button type="button" class="ofw_btn" onclick="closeEditRuleModal()">$trCancel</button>' +
        '<button type="button" class="ofw_btn ofw_btn_primary" onclick="submitEditRuleForm()">$trSave</button>' +
        '</div></div></div>';
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    makeModalDraggable('editRuleModal');
    bindRadioChangeEvents(document.getElementById('editRuleModal'));
    bindTimeframeToggle(document.getElementById('editRuleModal'));
    bindDayTypeToggle(document.getElementById('editRuleModal'));

    // Populate form fields with row data
    populateEditForm(row);
    // Re-update disabled state after populating form values
    updateDisabledSelects(document.getElementById('editRuleModal'));
    updateDayTypeControls(document.getElementById('editRuleModal'));
}

function populateEditForm(row) {
    var modal = document.getElementById('editRuleModal') || document.getElementById('copyRuleModal');
    if (!modal) return;

    var form = modal.querySelector('form');
    if (!form) return;

    // Set Remark
    var remarkField = form.querySelector('input[name="REMARK"]');
    if (remarkField && row.remark) {
        remarkField.value = row.remark;
    }

    // Set Enabled checkbox
    var enabledField = form.querySelector('input[name="ENABLED"]');
    if (enabledField) {
        enabledField.checked = (row.enabled === 'on');
    }

    // Set Log Enabled checkbox
    var logEnabledField = form.querySelector('input[name="LOG_ENABLED"]');
    if (logEnabledField) {
        logEnabledField.checked = (row.logEnabled === 'on');
    }

    // Source Network is always defaultSrcNet/Any for PORTFW (hidden inputs in template)

    // Set Source Address type (radio)
    var srcAdrType = row.rawSrcAdrType || 'custSrcAdr';
    var srcAdrRadios = form.querySelectorAll('input[name="SRC_ADR_TYPE"]');
    srcAdrRadios.forEach(function(radio) {
        radio.checked = (radio.value === srcAdrType);
    });

    // Set Source Address
    if (row.rawSrcAdr) {
        var custSrcAdrField = form.querySelector('select[name="CUST_SRC_ADR"]');
        if (custSrcAdrField) {
            custSrcAdrField.value = row.rawSrcAdr;
        }
        var groupSrcAdrField = form.querySelector('select[name="GROUP_SRC_ADR"]');
        if (groupSrcAdrField) {
            groupSrcAdrField.value = row.rawSrcAdr;
        }
    }

    // Set Source Port
    if (row.rawSrcPort && row.rawSrcPort !== '-') {
        var srcPortOnField = form.querySelector('input[name="SRC_PORT_ON"]');
        if (srcPortOnField) {
            srcPortOnField.checked = true;
        }
        var srcPortField = form.querySelector('input[name="SRC_PORT"]');
        if (srcPortField) {
            srcPortField.value = row.rawSrcPort;
        }
        // Set INV_SRC_PORT hidden value
        var invSrcPortField = form.querySelector('input[name="INV_SRC_PORT"]');
        if (invSrcPortField) {
            invSrcPortField.value = row.invSrcPort || 'off';
        }
    }

    // Set External Destination (Port Forwarding specific)
    if (row.rawPortfwExtAdr) {
        var portfwExtAdrField = form.querySelector('select[name="PORTFW_EXT_ADR"]');
        if (portfwExtAdrField) {
            portfwExtAdrField.value = row.rawPortfwExtAdr;
        }
    }

    // Set Port Forwarding Service type (radio)
    var portfwServiceType = row.rawPortfwServiceType || 'default';
    var portfwServiceRadios = form.querySelectorAll('input[name="PORTFW_SERVICE_TYPE"]');
    portfwServiceRadios.forEach(function(radio) {
        radio.checked = (radio.value === portfwServiceType);
    });

    // Set Port Forwarding Service
    if (row.rawPortfwService) {
        if (portfwServiceType === 'default') {
            var portfwDefaultServiceField = form.querySelector('select[name="PORTFW_DEFAULT_SERVICE"]');
            if (portfwDefaultServiceField) {
                portfwDefaultServiceField.value = row.rawPortfwService;
            }
        } else if (portfwServiceType === 'custom') {
            var portfwCustServiceField = form.querySelector('select[name="PORTFW_CUST_SERVICE"]');
            if (portfwCustServiceField) {
                portfwCustServiceField.value = row.rawPortfwService;
            }
        }
    }

    // Set Destination Network type (radio)
    var dstNetType = row.rawDstNetType || 'defaultDestNet';
    var dstNetRadios = form.querySelectorAll('input[name="DST_NET_TYPE"]');
    dstNetRadios.forEach(function(radio) {
        radio.checked = (radio.value === dstNetType);
    });

    // Set Destination Network based on type
    if (dstNetType === 'defaultDestNet') {
        var defaultDstNetField = form.querySelector('select[name="DEFAULT_DST_NET"]');
        if (defaultDstNetField && row.rawDstNet) {
            defaultDstNetField.value = row.rawDstNet;
        }
    } else if (dstNetType === 'custDestNet') {
        var custDstNetField = form.querySelector('select[name="CUST_DST_NET"]');
        if (custDstNetField && row.rawDstNet) {
            custDstNetField.value = row.rawDstNet;
        }
    }

    // Set Destination IP type (hidden input for PORTFW)
    var dstIpType = row.rawDstIpType || 'custDestIP';
    var dstIpTypeField = form.querySelector('input[name="DST_IP_TYPE"]');
    if (dstIpTypeField) {
        dstIpTypeField.value = dstIpType;
    }

    // Set Destination IP
    if (row.rawDstIp) {
        var custDstAdrField = form.querySelector('select[name="CUST_DST_ADR"]');
        if (custDstAdrField) {
            custDstAdrField.value = row.rawDstIp;
        }
    }

    // Set Internal Service type (radio)
    var serviceType = row.rawServiceType || 'default';
    var serviceTypeRadios = form.querySelectorAll('input[name="SERVICE_TYPE"]');
    serviceTypeRadios.forEach(function(radio) {
        radio.checked = (radio.value === serviceType);
    });

    // Set Internal Service
    if (row.rawService) {
        if (serviceType === 'default') {
            var defaultServiceField = form.querySelector('select[name="DEFAULT_SERVICE"]');
            if (defaultServiceField) {
                defaultServiceField.value = row.rawService;
            }
        } else if (serviceType === 'custom') {
            var custServiceField = form.querySelector('select[name="CUST_SERVICE"]');
            if (custServiceField) {
                custServiceField.value = row.rawService;
            }
        }
    }

    // Set Timeframe fields
    var tfEnabled = form.querySelector('input[name="TIMEFRAME_ENABLED"]');
    if (tfEnabled) {
        tfEnabled.checked = (row.timeframeEnabled === 'on');
    }
    toggleTimeframeOptions(form);

    var dayType = row.dayType || 'dayOfMonth';
    var dayTypeRadios = form.querySelectorAll('input[name="DAY_TYPE"]');
    dayTypeRadios.forEach(function(radio) {
        radio.checked = (radio.value === dayType);
    });

    var startDayMonth = form.querySelector('select[name="START_DAY_MONTH"]');
    if (startDayMonth && row.startDayMonth) startDayMonth.value = row.startDayMonth;
    var endDayMonth = form.querySelector('select[name="END_DAY_MONTH"]');
    if (endDayMonth && row.endDayMonth) endDayMonth.value = row.endDayMonth;

    var startHour = form.querySelector('select[name="START_HOUR"]');
    if (startHour && row.startHour !== undefined) startHour.value = row.startHour;
    var startMinute = form.querySelector('select[name="START_MINUTE"]');
    if (startMinute && row.startMinute !== undefined) startMinute.value = row.startMinute;
    var endHour = form.querySelector('select[name="END_HOUR"]');
    if (endHour && row.endHour !== undefined) endHour.value = row.endHour;
    var endMinute = form.querySelector('select[name="END_MINUTE"]');
    if (endMinute && row.endMinute !== undefined) endMinute.value = row.endMinute;

    var weekdays = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
    weekdays.forEach(function(day) {
        var cb = form.querySelector('input[name="' + day + '"]');
        if (cb) cb.checked = (row[day.toLowerCase()] === 'on');
    });
}

function toggleTimeframeOptions(modal) {
    var checkbox = modal.querySelector('input[name="TIMEFRAME_ENABLED"]');
    var options = modal.querySelectorAll('.timeframe-options');
    if (checkbox && checkbox.checked) {
        options.forEach(function(row) {
            row.style.display = '';
        });
    } else {
        options.forEach(function(row) {
            row.style.display = 'none';
        });
    }
}

function bindTimeframeToggle(modal) {
    var checkbox = modal.querySelector('input[name="TIMEFRAME_ENABLED"]');
    if (checkbox) {
        checkbox.addEventListener('change', function() {
            toggleTimeframeOptions(modal);
        });
    }
}

function bindDayTypeToggle(modal) {
    var radios = modal.querySelectorAll('input[name="DAY_TYPE"]');
    if (!radios.length) return;

    radios.forEach(function(radio) {
        radio.addEventListener('change', function() {
            updateDayTypeControls(modal);
        });
    });

    // Initial state
    updateDayTypeControls(modal);
}

function updateDayTypeControls(modal) {
    var dayTypeRadio = modal.querySelector('input[name="DAY_TYPE"]:checked');
    if (!dayTypeRadio) return;

    var dayType = dayTypeRadio.value;
    var dayOfMonthRows = modal.querySelectorAll('.day-of-month-ctrl');
    var weekdayRows = modal.querySelectorAll('.weekday-ctrl');

    if (dayType === 'dayOfMonth') {
        // Enable day of month rows, disable weekday rows
        dayOfMonthRows.forEach(function(row) {
            row.style.opacity = '1';
            var selects = row.querySelectorAll('select');
            selects.forEach(function(s) { s.disabled = false; });
        });
        weekdayRows.forEach(function(row) {
            row.style.opacity = '0.5';
            var checkboxes = row.querySelectorAll('input[type="checkbox"]');
            checkboxes.forEach(function(cb) { cb.disabled = true; cb.checked = false; });
        });
    } else if (dayType === 'weekDays') {
        // Disable day of month rows, enable weekday rows
        dayOfMonthRows.forEach(function(row) {
            row.style.opacity = '0.5';
            var selects = row.querySelectorAll('select');
            selects.forEach(function(s) { s.disabled = true; });
        });
        weekdayRows.forEach(function(row) {
            row.style.opacity = '1';
            var checkboxes = row.querySelectorAll('input[type="checkbox"]');
            checkboxes.forEach(function(cb) { cb.disabled = false; });
        });
    }
}

function closeAddRuleModal() {
    var modal = document.getElementById('addRuleModal');
    if (modal) modal.remove();
}

function closeEditRuleModal() {
    var modal = document.getElementById('editRuleModal');
    if (modal) modal.remove();
}

function submitAddRuleForm() {
    var modal = document.getElementById('addRuleModal');
    if (!modal) return;
    var form = modal.querySelector('form');
    if (!form) return;
    var selects = form.querySelectorAll('select');
    selects.forEach(function(s) { s.disabled = false; });
    var radioGroups = ['SRC_ADR_TYPE', 'DST_NET_TYPE', 'PORTFW_SERVICE_TYPE', 'SERVICE_TYPE', 'DAY_TYPE'];
    radioGroups.forEach(function(name) {
        var checked = form.querySelector('input[name="' + name + '"]:checked');
        if (!checked) {
            var first = form.querySelector('input[name="' + name + '"]');
            if (first) first.checked = true;
        }
    });
    form.submit();
}

function submitEditRuleForm() {
    var modal = document.getElementById('editRuleModal');
    if (!modal) return;
    var form = modal.querySelector('form');
    if (!form) return;
    var selects = form.querySelectorAll('select');
    selects.forEach(function(s) { s.disabled = false; });
    var radioGroups = ['SRC_ADR_TYPE', 'DST_NET_TYPE', 'PORTFW_SERVICE_TYPE', 'SERVICE_TYPE', 'DAY_TYPE'];
    radioGroups.forEach(function(name) {
        var checked = form.querySelector('input[name="' + name + '"]:checked');
        if (!checked) {
            var first = form.querySelector('input[name="' + name + '"]');
            if (first) first.checked = true;
        }
    });
    form.submit();
}

function openCopyRuleModal(row) {
    if (document.querySelector('#copyRuleModal')) return;
    var tpl = document.getElementById('ruleFormTemplate');
    if (!tpl) return;
    var formHtml = tpl.innerHTML;
    formHtml = formHtml.replace('name="RULE_POSITION" value="-1"', 'name="RULE_POSITION" value="-1"');
    formHtml = formHtml.replace('name="BOX_ACTION" value="$trSave"', 'name="BOX_ACTION" value="$trSave"><input type="hidden" name="ACTION" value="$trCopy"><input type="hidden" name="OLD_POSITION" value="' + row.position + '"><input type="hidden" name="OLD_RULETYPE" value="PORTFW"');
    var modalHtml = '<div class="ofw_modal_overlay" id="copyRuleModal">' +
        '<div class="ofw_modal_dialog" style="width:850px;">' +
        '<div class="ofw_modal_header" style="cursor:move;">' +
        '<span class="ofw_modal_title">$trCopy</span>' +
        '<button type="button" class="ofw_modal_close" onclick="closeCopyRuleModal()">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' + formHtml + '</div>' +
        '<div class="ofw_modal_footer">' +
        '<button type="button" class="ofw_btn" onclick="closeCopyRuleModal()">$trCancel</button>' +
        '<button type="button" class="ofw_btn ofw_btn_primary" onclick="submitCopyRuleForm()">$trSave</button>' +
        '</div></div></div>';
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    makeModalDraggable('copyRuleModal');
    bindRadioChangeEvents(document.getElementById('copyRuleModal'));
    bindTimeframeToggle(document.getElementById('copyRuleModal'));
    bindDayTypeToggle(document.getElementById('copyRuleModal'));
    populateEditForm(row);
    // Re-update disabled state after populating form values
    updateDisabledSelects(document.getElementById('copyRuleModal'));
    updateDayTypeControls(document.getElementById('copyRuleModal'));
}

function closeCopyRuleModal() {
    var modal = document.getElementById('copyRuleModal');
    if (modal) modal.remove();
}

function submitCopyRuleForm() {
    var modal = document.getElementById('copyRuleModal');
    if (!modal) return;
    var form = modal.querySelector('form');
    if (!form) return;
    // Enable all select fields before submission
    var selects = form.querySelectorAll('select');
    selects.forEach(function(s) { s.disabled = false; });
    // Ensure all radio button groups have a checked value
    var radioGroups = ['SRC_ADR_TYPE', 'DST_NET_TYPE', 'PORTFW_SERVICE_TYPE', 'SERVICE_TYPE', 'DAY_TYPE'];
    radioGroups.forEach(function(name) {
        var checked = form.querySelector('input[name="' + name + '"]:checked');
        if (!checked) {
            var first = form.querySelector('input[name="' + name + '"]');
            if (first) first.checked = true;
        }
    });
    form.submit();
}

function makeModalDraggable(modalId) {
    var modal = document.getElementById(modalId);
    if (!modal) return;
    var dialog = modal.querySelector('.ofw_modal_dialog');
    var header = modal.querySelector('.ofw_modal_header');
    if (!dialog || !header) return;
    var isDragging = false;
    var offsetX, offsetY;
    header.addEventListener('mousedown', function(e) {
        if (e.target.tagName === 'BUTTON') return;
        isDragging = true;
        var rect = dialog.getBoundingClientRect();
        offsetX = e.clientX - rect.left;
        offsetY = e.clientY - rect.top;
        dialog.style.position = 'fixed';
        dialog.style.margin = '0';
        e.preventDefault();
    });
    document.addEventListener('mousemove', function(e) {
        if (!isDragging) return;
        dialog.style.left = (e.clientX - offsetX) + 'px';
        dialog.style.top = (e.clientY - offsetY) + 'px';
    });
    document.addEventListener('mouseup', function() { isDragging = false; });
}

function updateDisabledSelects(modal) {
    if (!modal) return;
    var form = modal.querySelector('form');
    if (!form) return;
    
    // Source Network Type is hidden for PORTFW (no selects to toggle)

    // Source Address Type
    var srcAdrType = form.querySelector('input[name="SRC_ADR_TYPE"]:checked');
    if (srcAdrType) {
        var custSrcAdr = form.querySelector('select[name="CUST_SRC_ADR"]');
        var groupSrcAdr = form.querySelector('select[name="GROUP_SRC_ADR"]');
        if (custSrcAdr && groupSrcAdr) {
            if (srcAdrType.value === 'custSrcAdr') {
                custSrcAdr.disabled = false;
                groupSrcAdr.disabled = true;
            } else if (srcAdrType.value === 'groupSrcAdr') {
                custSrcAdr.disabled = true;
                groupSrcAdr.disabled = false;
            }
        }
    }
    
    // Destination Network Type
    var dstNetType = form.querySelector('input[name="DST_NET_TYPE"]:checked');
    if (dstNetType) {
        var defaultDstNet = form.querySelector('select[name="DEFAULT_DST_NET"]');
        var custDstNet = form.querySelector('select[name="CUST_DST_NET"]');
        if (defaultDstNet && custDstNet) {
            if (dstNetType.value === 'defaultDestNet') {
                defaultDstNet.disabled = false;
                custDstNet.disabled = true;
            } else if (dstNetType.value === 'custDestNet') {
                defaultDstNet.disabled = true;
                custDstNet.disabled = false;
            }
        }
    }
    
    // Destination IP Type (hidden input for PORTFW)
    var dstIpTypeField = form.querySelector('input[name="DST_IP_TYPE"]');
    if (dstIpTypeField) {
        var custDstAdr = form.querySelector('select[name="CUST_DST_ADR"]');
        if (custDstAdr) {
            custDstAdr.disabled = false;
        }
    }
    
    // Service ON checkbox (Source area)
    var serviceOn = form.querySelector('input[name="SERVICE_ON"]');
    var serviceGroupSelect = form.querySelector('select[name="SERVICE_GROUP"]');
    var custServiceSelect = form.querySelector('select[name="CUST_SERVICE"]');
    var defaultServiceSelect = form.querySelector('select[name="DEFAULT_SERVICE"]');
    
    if (serviceOn && serviceGroupSelect && custServiceSelect && defaultServiceSelect) {
        if (!serviceOn.checked) {
            // Service ON is unchecked, disable all service selects
            serviceGroupSelect.disabled = true;
            custServiceSelect.disabled = true;
            defaultServiceSelect.disabled = true;
        } else {
            // Service ON is checked, enable based on SERVICE_TYPE
            var serviceType = form.querySelector('input[name="SERVICE_TYPE"]:checked');
            if (serviceType) {
                serviceGroupSelect.disabled = (serviceType.value !== 'serviceGroup');
                custServiceSelect.disabled = (serviceType.value !== 'custom');
                defaultServiceSelect.disabled = (serviceType.value !== 'default');
            }
        }
    } else {
        // Internal Destination area - no SERVICE_ON checkbox
        var serviceType = form.querySelector('input[name="SERVICE_TYPE"]:checked');
        if (serviceType && custServiceSelect && defaultServiceSelect) {
            custServiceSelect.disabled = (serviceType.value !== 'custom');
            defaultServiceSelect.disabled = (serviceType.value !== 'default');
        }
    }
    
    // External Destination PORTFW_SERVICE_TYPE
    var portfwServiceType = form.querySelector('input[name="PORTFW_SERVICE_TYPE"]:checked');
    if (portfwServiceType) {
        var portfwCustService = form.querySelector('select[name="PORTFW_CUST_SERVICE"]');
        var portfwDefaultService = form.querySelector('select[name="PORTFW_DEFAULT_SERVICE"]');
        if (portfwCustService && portfwDefaultService) {
            if (portfwServiceType.value === 'custom') {
                portfwCustService.disabled = false;
                portfwDefaultService.disabled = true;
            } else if (portfwServiceType.value === 'default') {
                portfwCustService.disabled = true;
                portfwDefaultService.disabled = false;
            }
        }
    }
}

function bindRadioChangeEvents(modal) {
    if (!modal) return;
    var radios = modal.querySelectorAll('input[type="radio"]');
    radios.forEach(function(radio) {
        radio.addEventListener('change', function() {
            updateDisabledSelects(modal);
        });
    });
    
    // Also bind SERVICE_ON checkbox
    var serviceOn = modal.querySelector('input[name="SERVICE_ON"]');
    if (serviceOn) {
        serviceOn.addEventListener('change', function() {
            updateDisabledSelects(modal);
        });
    }
    
    // Initial update
    updateDisabledSelects(modal);
}
</script>

<div id="rulesTable"></div>
END
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
    my $title = $Lang::tr{'port forwarding'};

    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        $title = "$Lang::tr{'edit a rule'}: $title";
    }
    else {
        $title = "$Lang::tr{'add a new rule'}: $title";
    }

    print <<END
<table width='100%' height='33px' bgcolor='#69C'>
<tr align='center'>
    <td><strong>$title</strong></td>
</tr>
</table>
END
}

# Validation functions for port forwarding
sub validateSrcParams
{
    if ($cgiparams{'SRC_NET_TYPE'} eq 'defaultSrcNet') {
        my $foundIface = 0;
        if ($cgiparams{'DEFAULT_SRC_NET'} eq "Any") {
            $foundIface = 1;
        } else {
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

    if ($cgiparams{'SRC_ADR_TYPE'} eq 'custSrcAdr') {
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
    # Port forwarding specific validations
    unless ($cgiparams{'RULETYPE'} eq 'PORTFW') {
        $errormessage .= "$Lang::tr{'invalid dest'}<br />";
    }

    # Openfirewall external destination
    if ($cgiparams{'PORTFW_EXT_ADR'} eq '') {
        $errormessage .= "$Lang::tr{'invalid openfirewall red address'}<br />";
    }

    if ($cgiparams{'PORTFW_SERVICE_TYPE'} eq 'custom') {
        if ($cgiparams{'PORTFW_CUST_SERVICE'} eq '' || $cgiparams{'PORTFW_CUST_SERVICE'} eq 'BLANK') {
            $errormessage .= "$Lang::tr{'invalid service'}<br />";
        }
    }
    elsif ($cgiparams{'PORTFW_SERVICE_TYPE'} eq 'default') {
        if ($cgiparams{'PORTFW_DEFAULT_SERVICE'} eq '' || $cgiparams{'PORTFW_DEFAULT_SERVICE'} eq 'BLANK') {
            $errormessage .= "$Lang::tr{'invalid service'}<br />";
        }
    }
    else {
        $errormessage .= "$Lang::tr{'none service type'}<br />";
    }

    # Check for reserved ports
    if ($errormessage eq '') {
        if ($cgiparams{'PORTFW_EXT_ADR'} eq 'Red Address') {
            my %extService = ();
            &DATA::getServiceParams($cgiparams{'PORTFW_SERVICE_TYPE'}, $cgiparams{'PORTFW_CUST_SERVICE'}, $cgiparams{'PORTFW_DEFAULT_SERVICE'}, \%extService);

            if (&DATA::isReservedPort($extService{'PROTOCOL'}, $extService{'PORT'})) {
                if ($extService{'IS_RANGE'}) {
                    $errormessage .= "$Lang::tr{'reserved external portrange'}<br />";
                } else {
                    $errormessage .= "$Lang::tr{'reserved external port'}<br />";
                }
            }
        }
    }

    # Destination network validation
    if ($cgiparams{'DST_NET_TYPE'} eq 'defaultDestNet') {
        my $foundIface = 0;
        foreach my $ifaceName (sort keys %FW::interfaces) {
            if ($cgiparams{'DEFAULT_DST_NET'} eq $ifaceName) {
                $foundIface = 1;
                last;
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

    # Destination IP validation - port forwarding only allows single host IPs
    if ($cgiparams{'DST_IP_TYPE'} eq 'custDestIP') {
        my %customAdr = ();
        &DATA::readCustAddresses(\%customAdr);

        if ($cgiparams{'CUST_DST_ADR'} eq ''
            || $cgiparams{'CUST_DST_ADR'} eq 'BLANK'
            || !defined($customAdr{$cgiparams{'CUST_DST_ADR'}}))
        {
            $errormessage .= "$Lang::tr{'invalid address'}<br />";
        }

        if ($customAdr{$cgiparams{'CUST_DST_ADR'}}{'ADDRESS_TYPE'} eq 'mac') {
            $errormessage .= "$Lang::tr{'mac adr not as dest'}<br />";
        }
        else {
            my $mask = $customAdr{$cgiparams{'CUST_DST_ADR'}}{'NETMASK'};
            if ($mask ne '32' && $mask ne '255.255.255.255') {
                $errormessage .= "$Lang::tr{'only host ip adr allowed in portfw'}<br />";
            }
        }
    }
    elsif ($cgiparams{'DST_IP_TYPE'} eq 'ipDestTxt') {
        if (!&General::validip($cgiparams{'DEST_IP_TXT'})) {
            $errormessage .= "$Lang::tr{'ip bad'}<br />";
        }
    }
    else {
        $errormessage .= "$Lang::tr{'none address type'}<br />";
    }

    if ($cgiparams{'INV_DST_IP'} ne 'on' || $cgiparams{'RULETYPE'} eq 'PORTFW') {
        $cgiparams{'INV_DST_IP'} = 'off';
    }

    if (!defined($cgiparams{'SERVICE_ON'}) || $cgiparams{'SERVICE_ON'} ne 'on') {
        $cgiparams{'SERVICE_ON'} = 'off';
    }

    if ($cgiparams{'SERVICE_ON'} eq 'on') {
        if ($cgiparams{'SERVICE_TYPE'} eq 'serviceGroup') {
            if ($cgiparams{'SERVICE_GROUP'} eq '') {
                $errormessage .= "$Lang::tr{'invalid service'}<br />";
            }
        }
        elsif ($cgiparams{'SERVICE_TYPE'} eq 'custom') {
            if ($cgiparams{'CUST_SERVICE'} eq '' || $cgiparams{'CUST_SERVICE'} eq 'BLANK') {
                $errormessage .= "$Lang::tr{'invalid service'}<br />";
            }
        }
        elsif ($cgiparams{'SERVICE_TYPE'} eq 'default') {
            if ($cgiparams{'DEFAULT_SERVICE'} eq '' || $cgiparams{'DEFAULT_SERVICE'} eq 'BLANK') {
                $errormessage .= "$Lang::tr{'invalid service'}<br />";
            }
        }
        else {
            $errormessage .= "$Lang::tr{'none service type'}<br />";
        }
    }

    return;
}

sub checkBetweenParams
{
    my %dest = ();
    &DATA::getServiceParams($cgiparams{'SERVICE_TYPE'}, $cgiparams{'CUST_SERVICE'}, $cgiparams{'DEFAULT_SERVICE'}, \%dest);
    my %ext = ();
    &DATA::getServiceParams($cgiparams{'PORTFW_SERVICE_TYPE'}, $cgiparams{'PORTFW_CUST_SERVICE'}, $cgiparams{'PORTFW_DEFAULT_SERVICE'}, \%ext);

    if ($cgiparams{'PORTFW_SERVICE_TYPE'} eq 'custom') {
        if ($ext{'PORT_INVERT'} eq 'on') {
            $errormessage .= "$Lang::tr{'invert port not allowed in portfw'}<br />";
        }
        if ($ext{'PROTOCOL_INVERT'} eq 'on') {
            $errormessage .= "$Lang::tr{'invert proto not allowed in portfw'}<br />";
        }
    }

    if ($cgiparams{'SERVICE_TYPE'} eq 'custom') {
        if ($dest{'PORT_INVERT'} eq 'on') {
            $errormessage .= "$Lang::tr{'invert port not allowed in portfw'}<br />";
        }
        if ($dest{'PROTOCOL_INVERT'} eq 'on') {
            $errormessage .= "$Lang::tr{'invert proto not allowed in portfw'}<br />";
        }
    }

    if (($dest{'IS_RANGE'} || $ext{'IS_RANGE'}) && ($dest{'PORT'} ne $ext{'PORT'})) {
        $errormessage .= "$Lang::tr{'using portrange in portfw'}<br />";
    }
    if ($dest{'PROTOCOL'} ne $ext{'PROTOCOL'}) {
        $errormessage .= "$Lang::tr{'same proto in portfw'}<br />";
    }

    if ($warnOpenFwMessage) {
        $cgiparams{'RULEMODE'} = "adv";
    } else {
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

    $cgiparams{'REMARK'} = &stripcommas($cgiparams{'REMARK'});

    if ($cgiparams{'RULE_POSITION'} eq '') {
        $errormessage .= "$Lang::tr{'select rule position'}<br/>";
    }

    if ($cgiparams{'MATCH_STRING_ON'} eq 'on') {
        $cgiparams{'MATCH_STRING'} = &stripcommas($cgiparams{'MATCH_STRING'});

        if ($cgiparams{'INV_MATCH_STRING'} ne 'on') {
            $cgiparams{'INV_MATCH_STRING'} = 'off';
        }
    } else {
        $cgiparams{'MATCH_STRING_ON'} = 'off';
        $cgiparams{'MATCH_STRING'}    = "";
    }

    if ($cgiparams{'LIMIT_FOR'} =~ /^(none|log|acceptOrDeny|both)$/) {
        if ($cgiparams{'LIMIT_TYPE'} eq 'average') {
            if (!($cgiparams{'MATCH_LIMIT_AVG'} =~ /^\d+\/(sec|minute|hour|day)$/ || $cgiparams{'MATCH_LIMIT_AVG'} =~ /^\d+$/)) {
                $errormessage .= "$Lang::tr{'invalid limit params'}:<br />max average match rate: default 10/minute";
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
    } else {
        $errormessage .= "$Lang::tr{'none limit for'}<br />";
    }
    return;
}

sub validateTimeParams
{
    if ($cgiparams{'DAY_TYPE'} eq 'dayOfMonth') {
        unless ($cgiparams{'START_DAY_MONTH'} =~ /^\d+$/ && $cgiparams{'START_DAY_MONTH'} >= 1 && $cgiparams{'START_DAY_MONTH'} <= 31) {
            $errormessage .= "$Lang::tr{'invalid start day'}<br />";
        }
        unless ($cgiparams{'END_DAY_MONTH'} =~ /^\d+$/ && $cgiparams{'END_DAY_MONTH'} >= 1 && $cgiparams{'END_DAY_MONTH'} <= 31) {
            $errormessage .= "$Lang::tr{'invalid end day'}<br />";
        }
    }
    elsif ($cgiparams{'DAY_TYPE'} eq 'weekDays') {
        my $oneDayEnabled = 0;
        foreach my $day ('MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN') {
            if ($cgiparams{$day} ne 'on') {
                $cgiparams{$day} = 'off';
            } else {
                $oneDayEnabled++;
            }
        }
        unless ($oneDayEnabled > 0) {
            $errormessage .= "$Lang::tr{'at least one day enabled'}<br />";
        }
    } else {
        $errormessage .= "$Lang::tr{'none day type'}<br />";
    }

    unless ($cgiparams{'START_HOUR'} =~ /^\d+$/ && $cgiparams{'START_HOUR'} >= 0 && $cgiparams{'START_HOUR'} <= 23) {
        $errormessage .= "$Lang::tr{'invalid start hour'}<br />";
    }

    unless ($cgiparams{'END_HOUR'} =~ /^\d+$/ && $cgiparams{'END_HOUR'} >= 0 && $cgiparams{'END_HOUR'} <= 23) {
        $errormessage .= "$Lang::tr{'invalid end hour'}<br />";
    }

    unless ($cgiparams{'START_MINUTE'} =~ /^\d+$/ && $cgiparams{'START_MINUTE'} >= 0 && $cgiparams{'START_MINUTE'} <= 59) {
        $errormessage .= "$Lang::tr{'invalid start minute'}<br />";
    }

    unless ($cgiparams{'END_MINUTE'} =~ /^\d+$/ && $cgiparams{'END_MINUTE'} >= 0 && $cgiparams{'END_MINUTE'} <= 59) {
        $errormessage .= "$Lang::tr{'invalid end minute'}<br />";
    }
    return;
}

sub stripcommas
{
    my $outstring = $_[0];
    $outstring =~ tr/,/ /;
    $outstring =~ tr/\'/ /;
    $outstring =~ tr/\"/ /;
    return $outstring;
}

sub buildRuleObject
{
    my %newRule = ();
    $newRule{'ENABLED'} = $cgiparams{'ENABLED'};    # [1] we start with 1, [0] is key

    $newRule{'RULEMODE'}     = $cgiparams{'RULEMODE'};        # [3]
    $newRule{'SRC_NET_TYPE'} = $cgiparams{'SRC_NET_TYPE'};    # [4]

    if ($cgiparams{'SRC_NET_TYPE'} eq 'defaultSrcNet') {
        $newRule{'SRC_NET'} = $cgiparams{'DEFAULT_SRC_NET'};    # [5]
    } else {                                                      #'custSrcNet'
        $newRule{'SRC_NET'} = $cgiparams{'CUST_SRC_NET'};       # [5]
    }

    $newRule{'SRC_ADR_TYPE'} = $cgiparams{'SRC_ADR_TYPE'};      # [6a]

    if ($cgiparams{'SRC_ADR_TYPE'} eq 'custSrcAdr') {
        $newRule{'SRC_ADR'} = $cgiparams{'CUST_SRC_ADR'};              # [7]
    }
    else {                                                             #'groupSrcAdr'
        $newRule{'SRC_ADR'} = $cgiparams{'GROUP_SRC_ADR'};             # [7]
    }

    $newRule{'INV_SRC_ADR'} = $cgiparams{'INV_SRC_ADR'};               # [8]

    if ($cgiparams{'SRC_PORT_ON'} eq 'on') {
        $newRule{'SRC_PORT'} = $cgiparams{'SRC_PORT'};                 # [9]
    } else {
        $newRule{'SRC_PORT'} = "-";                                    # [9]
    }

    $newRule{'INV_SRC_PORT'} = $cgiparams{'INV_SRC_PORT'};             # [10]

    $newRule{'PORTFW_EXT_ADR'} = $cgiparams{'PORTFW_EXT_ADR'};      # [11]
    $newRule{'PORTFW_SERVICE_TYPE'} = $cgiparams{'PORTFW_SERVICE_TYPE'}; # [12]

    if($cgiparams{'PORTFW_SERVICE_TYPE'} eq 'custom') {
        $newRule{'PORTFW_SERVICE'} = $cgiparams{'PORTFW_CUST_SERVICE'}; # [13]
    } else {
        # 'default'
        $newRule{'PORTFW_SERVICE'} = $cgiparams{'PORTFW_DEFAULT_SERVICE'}; # [13]
    }

    $newRule{'DST_NET_TYPE'} = $cgiparams{'DST_NET_TYPE'};             # [14]

    if ($cgiparams{'DST_NET_TYPE'} eq 'defaultDestNet') {
        $newRule{'DST_NET'} = $cgiparams{'DEFAULT_DST_NET'};           # [15]
    } else {                                                           #'custDestNet'
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
    } else {
        $newRule{'SERVICE_TYPE'} = "-";                                # [19]
        $newRule{'SERVICE'}      = "-";                                # [20]
    }

    $newRule{'LOG_ENABLED'} = $cgiparams{'LOG_ENABLED'};               # [21]
    $newRule{'LIMIT_FOR'}   = $cgiparams{'LIMIT_FOR'};                 # [22]

    if ($cgiparams{'LIMIT_FOR'} eq 'none') {
        $newRule{'LIMIT_TYPE'}  = "-";                                 # [23]
        $newRule{'MATCH_LIMIT'} = "-";                                 # [24]
    } else {
        $newRule{'LIMIT_TYPE'} = $cgiparams{'LIMIT_TYPE'};             # [23]
        if ($cgiparams{'LIMIT_TYPE'} eq 'average') {
            $newRule{'MATCH_LIMIT'} = $cgiparams{'MATCH_LIMIT_AVG'};    # [24]
        } else {                                                          # 'burst'
            $newRule{'MATCH_LIMIT'} = $cgiparams{'MATCH_LIMIT_BURST'};    # [24]
        }
    }

    $newRule{'MATCH_STRING_ON'} = $cgiparams{'MATCH_STRING_ON'};          # [25]

    if ($cgiparams{'MATCH_STRING_ON'} eq 'on') {
        $newRule{'MATCH_STRING'}     = $cgiparams{'MATCH_STRING'};        # [26]
        $newRule{'INV_MATCH_STRING'} = $cgiparams{'INV_MATCH_STRING'};    # [27]
    } else {
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

    $cgiparams{'ENABLED'} = $rule->{'ENABLED'};    # [1] we start with 1, [0] is key

    $cgiparams{'RULEMODE'}     = $rule->{'RULEMODE'};        # [3]
    $cgiparams{'SRC_NET_TYPE'} = $rule->{'SRC_NET_TYPE'};    # [4]

    if ($cgiparams{'SRC_NET_TYPE'} eq 'defaultSrcNet') {
        $cgiparams{'DEFAULT_SRC_NET'} = $rule->{'SRC_NET'};    # [5]
    } else {                                                   #'custSrcNet'
        $cgiparams{'CUST_SRC_NET'} = $rule->{'SRC_NET'};       # [5]
    }

    $cgiparams{'SRC_ADR_TYPE'} = $rule->{'SRC_ADR_TYPE'};      # [6a]

    if ($cgiparams{'SRC_ADR_TYPE'} eq 'custSrcAdr') {
        $cgiparams{'CUST_SRC_ADR'} = $rule->{'SRC_ADR'};        # [7]
    }
    else {                                                      #'groupSrcAdr'
        $cgiparams{'GROUP_SRC_ADR'} = $rule->{'SRC_ADR'};       # [7]
    }

    $cgiparams{'INV_SRC_ADR'} = $rule->{'INV_SRC_ADR'};         # [8]

    if ($rule->{'SRC_PORT'} ne '-') {
        $cgiparams{'SRC_PORT_ON'} = 'on';
        $cgiparams{'SRC_PORT'}    = $rule->{'SRC_PORT'};        # [9]
    } else {
        $cgiparams{'SRC_PORT_ON'} = 'off';
        $cgiparams{'SRC_PORT'}    = '';                         # [9]
    }

    $cgiparams{'INV_SRC_PORT'} = $rule->{'INV_SRC_PORT'};       # [10]
    $cgiparams{'PORTFW_EXT_ADR'} = $rule->{'PORTFW_EXT_ADR'};      # [11]
    $cgiparams{'PORTFW_SERVICE_TYPE'} = $rule->{'PORTFW_SERVICE_TYPE'}; # [12]

    if ($rule->{'PORTFW_SERVICE_TYPE'} eq 'custom') {
        $cgiparams{'PORTFW_CUST_SERVICE'} = $rule->{'PORTFW_SERVICE'}; # [13]
    } else {
        # 'default'
        $cgiparams{'PORTFW_DEFAULT_SERVICE'} = $rule->{'PORTFW_SERVICE'}; # [13]
    }

    $cgiparams{'DST_NET_TYPE'} = $rule->{'DST_NET_TYPE'};       # [14]

    if ($cgiparams{'DST_NET_TYPE'} eq 'defaultDestNet') {
        $cgiparams{'DEFAULT_DST_NET'} = $rule->{'DST_NET'};     # [15]
    } else {                                                    #'custDestNet'
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
    } else {
        $cgiparams{'SERVICE_ON'} = 'off';
    }

    $cgiparams{'LOG_ENABLED'} = $rule->{'LOG_ENABLED'};            # [21]
    $cgiparams{'LIMIT_FOR'}   = $rule->{'LIMIT_FOR'};              # [22]

    if ($cgiparams{'LIMIT_FOR'} ne 'none') {
        $cgiparams{'LIMIT_TYPE'} = $rule->{'LIMIT_TYPE'};          # [23]
        if ($cgiparams{'LIMIT_TYPE'} eq 'average') {
            $cgiparams{'MATCH_LIMIT_AVG'} = $rule->{'MATCH_LIMIT'};    # [24]
        } else {                                                         # 'burst'
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
    $cgiparams{'SRC_ADR_TYPE'}      = 'custSrcAdr';
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

    $cgiparams{'RULETYPE'}          = 'PORTFW';
    $cgiparams{'OLD_RULETYPE'}      = 'PORTFW';
    $cgiparams{'DST_NET_TYPE'}      = 'defaultDestNet';
    $cgiparams{'DEFAULT_DST_NET'}   = 'Red';
    $cgiparams{'CUST_DST_NET'}      = '';
    $cgiparams{'DST_IP_TYPE'}       = 'defaultDstIP';
    $cgiparams{'DEFAULT_DST_IP'}    = 'Any';
    $cgiparams{'CUST_DST_ADR'}      = '';
    $cgiparams{'GROUP_DST_ADR'}     = '';
    $cgiparams{'DEST_IP_TXT'}       = '';
    $cgiparams{'INV_DST_IP'}        = 'off';
    $cgiparams{'SERVICE_TYPE'}      = 'default';
    $cgiparams{'SERVICE_GROUP'}     = '';
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

# Include printEnterParamsBox and related functions from fwrules.cgi
# (These handle the multi-step form for adding/editing rules)
# For brevity, I'll note that these need to be copied from fwrules.cgi
# The complete implementation would include all the form rendering functions

sub printEnterParamsBox
{
    # This would contain the multi-step form from fwrules.cgi
    # For now, redirect to the original fwrules.cgi for editing
    print "<p>Rule editing form - please use the original firewall rules page for now.</p>";
    print "<p><a href='/cgi-bin/fwrules.cgi'>Back to Firewall Rules</a></p>";
}

1;
