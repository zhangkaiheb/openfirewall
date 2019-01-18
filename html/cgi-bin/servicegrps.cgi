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
# (c) 2014-2018, the Openfirewall Team
#

# Add entry in menu
# MENUENTRY firewall 040 "service groups" "service groups"

use strict;

# enable only the following on debugging purpose
use warnings;
no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';

&Header::showhttpheaders();

my %cgiparams    = ();
my $errormessage = '';
my $error        = '';
$cgiparams{'ACTION'}     = '';
$cgiparams{'USED_COUNT'} = 0;
&General::getcgihash(\%cgiparams);

# vars for setting up sort order
my $sort_col  = '1';
my $sort_type = 'a';
my $sort_dir  = 'asc';
my $junk;

if ($ENV{'QUERY_STRING'} ne '') {
    my ($item1, $item2, $item3) = split(/\&/, $ENV{'QUERY_STRING'});
    if ($item1 ne '') {
        ($junk, $sort_col) = split(/\=/, $item1);
    }
    if ($item2 ne '') {
        ($junk, $sort_type) = split(/\=/, $item2);
    }
    if ($item3 ne '') {
        ($junk, $sort_dir) = split(/\=/, $item3);
    }
}

my %serviceGroupConf;
my %custServices = ();

&DATA::readServiceGroupConf(\%serviceGroupConf);
&DATA::readCustServices(\%custServices);

my (%radio, %selected, %checked);

my @customServices = sort(keys %custServices);

$cgiparams{'GROUP_TYP'}            = 'existing';
$cgiparams{'GROUP_NEW'}            = '';
$cgiparams{'GROUP_EXISTING'}       = '';
$cgiparams{'REMARK'}               = '';
$cgiparams{'SERVICE_TYP'}          = 'default';
$cgiparams{'SERVICE_NAME_CUSTOM'}  = '';
$cgiparams{'SERVICE_NAME_DEFAULT'} = '';
$cgiparams{'ENABLED'}              = '';

&General::getcgihash(\%cgiparams);

$cgiparams{'GROUP_NEW'} = &Header::cleanConfNames($cgiparams{'GROUP_NEW'});

if ($cgiparams{'ACTION'} eq $Lang::tr{'add'}) {
    &validateServiceGroupingParams(\%serviceGroupConf);
    unless ($errormessage) {
        my %newEntry = ();
        if ($cgiparams{'GROUP_TYP'} eq 'existing') {
            $newEntry{'GROUP_NAME'} = $cgiparams{'GROUP_EXISTING'};
            $newEntry{'ENABLED'}    = $cgiparams{'ENABLED'};
        }
        else {
            $newEntry{'GROUP_NAME'}                                  = $cgiparams{'GROUP_NEW'};
            $serviceGroupConf{$newEntry{'GROUP_NAME'}}{'USED_COUNT'} = 0;
            $serviceGroupConf{$newEntry{'GROUP_NAME'}}{'REMARK'}     = $cgiparams{'REMARK'};
            $serviceGroupConf{$newEntry{'GROUP_NAME'}}{'SERVICES'}   = ();

            # we have to be sure that at least one service is enabled,
            # this is the first service -> enable it
            $newEntry{'ENABLED'} = 'on';
        }

        $newEntry{'SERVICE_TYP'} = $cgiparams{'SERVICE_TYP'};
        if ($cgiparams{'SERVICE_TYP'} eq 'default') {
            $newEntry{'SERVICE_NAME'} = $cgiparams{'SERVICE_NAME_DEFAULT'};
        }
        else {
            $newEntry{'SERVICE_NAME'} = $cgiparams{'SERVICE_NAME_CUSTOM'};
            &FW::changeUsedCountService($newEntry{'SERVICE_NAME'}, "add");
        }

        push(@{$serviceGroupConf{$newEntry{'GROUP_NAME'}}{'SERVICES'}}, \%newEntry);
        &DATA::saveServiceGroupConf(\%serviceGroupConf);
        &General::log("$Lang::tr{'service added to group'}: $newEntry{'SERVICE_NAME'} -> $newEntry{'GROUP_NAME'}");

        # submit the changes to iptables rules
        if (   $serviceGroupConf{$newEntry{'GROUP_NAME'}}{'USED_COUNT'} > 0
            && $cgiparams{'GROUP_TYP'} eq 'existing')
        {
            `/usr/local/bin/setfwrules --user < /dev/null > /dev/null 2>&1 &`;
        }
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
    }
}

# this variable saves the entered remark on update error
my $tmpRemark;

if ($cgiparams{'ACTION'} eq $Lang::tr{'update'}) {
    &validateServiceGroupingParams(\%serviceGroupConf);

    unless ($errormessage) {
        my $group    = $cgiparams{'GROUP_NEW'};
        my $groupOld = $cgiparams{'OLD_GROUP'};
        $serviceGroupConf{$groupOld}{'REMARK'} = $cgiparams{'REMARK'};

        # if the name (==Key) has changed, we have to copy/move the old data to new key
        if ($group ne $groupOld) {
            $serviceGroupConf{$group}{'REMARK'}     = $serviceGroupConf{$groupOld}{'REMARK'};
            $serviceGroupConf{$group}{'USED_COUNT'} = $serviceGroupConf{$groupOld}{'USED_COUNT'};
            $serviceGroupConf{$group}{'SERVICES'}   = ();

            foreach my $service (@{$serviceGroupConf{$groupOld}{'SERVICES'}}) {
                push(@{$serviceGroupConf{$group}{'SERVICES'}}, $service);
            }
            delete($serviceGroupConf{$groupOld});
        }
        &DATA::saveServiceGroupConf(\%serviceGroupConf);

        &General::log("$Lang::tr{'service group updated'}: $group");
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
    }
    else {
        $cgiparams{'GROUP'}  = $cgiparams{'OLD_GROUP'};
        $cgiparams{'ACTION'} = $Lang::tr{'edit'};
        $tmpRemark           = $cgiparams{'REMARK'};
    }
}

my $disabled        = "";
my $disabledNameTxt = "";
my $hiddenGroupName = "";
if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
    my $group = $cgiparams{'GROUP'};
    $cgiparams{'GROUP_NEW'} = $group;
    $cgiparams{'REMARK'}    = $serviceGroupConf{$group}{'REMARK'};
    $cgiparams{'REMARK'}    = $tmpRemark if (defined $tmpRemark);
    $cgiparams{'GROUP_TYP'} = 'new';
    $disabled               = "disabled='disabled'";
    if ($serviceGroupConf{$group}{'USED_COUNT'} > 0) {
        $disabledNameTxt = "disabled='disabled'";
        $hiddenGroupName = "<input type='hidden' name='GROUP_NEW' value='$cgiparams{'GROUP_NEW'}' />";
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    my $group = $cgiparams{'GROUP'};

    if ($cgiparams{'TYP'} eq 'group') {
        foreach my $service (@{$serviceGroupConf{$group}{'SERVICES'}}) {
            if ($service->{'SERVICE_TYP'} ne 'default') {
                &FW::changeUsedCountService($service->{'SERVICE_NAME'}, "remove");
            }
        }
        delete($serviceGroupConf{$group});
        &DATA::saveServiceGroupConf(\%serviceGroupConf);
        &General::log("$Lang::tr{'service group deleted'}: $group");

        # A group can only be removed when it is not used
        # -> no need to run setfwrules
    }
    else {
        my $service = $serviceGroupConf{$group}{'SERVICES'}[ $cgiparams{'SERVICE_ID'} ];
        if ($service->{'SERVICE_TYP'} ne 'default') {
            &FW::changeUsedCountService($service->{'SERVICE_NAME'}, "remove");
        }

        &General::log("$Lang::tr{'service from group deleted'}: $service->{'SERVICE_NAME'} -> $group");
        splice(@{$serviceGroupConf{$group}{'SERVICES'}}, $cgiparams{'SERVICE_ID'}, 1);

        # we have to be sure, that at least one service is enabled
        my $serviceCount = @{$serviceGroupConf{$group}{'SERVICES'}};
        if ($serviceCount < 2) {
            $serviceGroupConf{$group}{'SERVICES'}[0]->{'ENABLED'} = 'on';
            &General::log(
"$Lang::tr{'service in group enabled'}: $serviceGroupConf{$group}{'SERVICES'}[0]->{'SERVICE_NAME'} -> on"
            );
        }
        &DATA::saveServiceGroupConf(\%serviceGroupConf);
        `/usr/local/bin/setfwrules --user < /dev/null > /dev/null 2>&1 &`;
    }
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'toggle enable disable'}) {
    my $group            = $cgiparams{'GROUP'};
    my $isEnabledService = 0;

    if ($cgiparams{'ENABLED'} ne 'on') {

        # we have to be sure, that at least one service is enabled
        my $id = 0;
        foreach my $entry (@{$serviceGroupConf{$group}{'SERVICES'}}) {
            if ($entry->{'ENABLED'} eq 'on' && $id != $cgiparams{'SERVICE_ID'}) {
                $isEnabledService = 1;
                last;
            }
            $id++;
        }
    }
    else {

        # user want to enable a service, no need to check for another service beeing enabled
        $isEnabledService = 1;
    }

    if ($isEnabledService) {
        $serviceGroupConf{$group}{'SERVICES'}[ $cgiparams{'SERVICE_ID'} ]->{'ENABLED'} = $cgiparams{'ENABLED'};
        &DATA::saveServiceGroupConf(\%serviceGroupConf);
        &General::log(
"$Lang::tr{'service in group enabled'}: $serviceGroupConf{$group}{'SERVICES'}[$cgiparams{'SERVICE_ID'}]->{'SERVICE_NAME'} -> $cgiparams{'ENABLED'}"
        );
        `/usr/local/bin/setfwrules --user < /dev/null > /dev/null 2>&1 &`;
    }
    else {
        $errormessage .= "$Lang::tr{'at least one service enabled'} <br />";
    }
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'reset'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

&Header::openpage($Lang::tr{'service grouping settings'}, 1, '');
&Header::openbigbox('100%', 'left');

if (   $cgiparams{'ACTION'} eq ''
    || $cgiparams{'ACTION'} eq $Lang::tr{'show adv config'})
{
    $cgiparams{'GROUP_TYP'}            = 'existing';
    $cgiparams{'GROUP_NEW'}            = '';
    $cgiparams{'GROUP_EXISTING'}       = '';
    $cgiparams{'REMARK'}               = '';
    $cgiparams{'SERVICE_TYP'}          = 'default';
    $cgiparams{'SERVICE_NAME_CUSTOM'}  = '';
    $cgiparams{'SERVICE_NAME_DEFAULT'} = '';
    $cgiparams{'ENABLED'}              = 'on';
    $cgiparams{'DEFAULT_SERVICE'}      = '';
}

# DEBUG DEBUG
#&Header::openbox('100%', 'left', 'DEBUG');
#foreach my $line (keys %cgiparams) {
#   print "$line = $cgiparams{$line}<br />\n";
#}
#print "$ENV{'QUERY_STRING'}\n";
#&Header::closebox();

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

&Header::openbox('100%', 'left', "$Lang::tr{'add service grouping'}:", $error);

$radio{'GROUP_TYP'}{'new'}                   = '';
$radio{'GROUP_TYP'}{'existing'}              = '';
$radio{'GROUP_TYP'}{$cgiparams{'GROUP_TYP'}} = "checked='checked'";

$radio{'SERVICE_TYP'}{'default'}                 = '';
$radio{'SERVICE_TYP'}{'custom'}                  = '';
$radio{'SERVICE_TYP'}{$cgiparams{'SERVICE_TYP'}} = "checked='checked'";

$cgiparams{'ENABLED'} = 'off' if ($cgiparams{'ENABLED'} ne 'on');
$checked{'ENABLED'}{'off'}                 = '';
$checked{'ENABLED'}{'on'}                  = '';
$checked{'ENABLED'}{$cgiparams{'ENABLED'}} = "checked='checked'";

my @existingGroups      = sort(keys(%serviceGroupConf));
my $existingGroupsCount = @existingGroups;

print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td width='25%'>
END

if($existingGroupsCount > 0) {
    print"<input type='radio' name='GROUP_TYP' value='new' $radio{'GROUP_TYP'}{'new'} />\n";
}
else
{
    print"<input type='hidden' name='GROUP_TYP' value='new' />\n";
}

print <<END;
        $Lang::tr{'service group name'}:
    </td>
    <td width='25%'>
        <input type='text' name='GROUP_NEW' value='$cgiparams{'GROUP_NEW'}' size='20' maxlength='18' $disabledNameTxt  onkeyup='this.form.GROUP_TYP[0].checked=true'/>
        $hiddenGroupName
    </td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr>
END

if ($existingGroupsCount > 0) {
    print <<END;
<tr>
    <td>
        <input type='radio' name='GROUP_TYP' value='existing' $radio{'GROUP_TYP'}{'existing'} $disabled/>
        $Lang::tr{'service group name'}:
    </td>
    <td colspan='3'>
        <select name='GROUP_EXISTING' $disabled onclick='this.form.GROUP_TYP[1].checked=true'>
END

    foreach my $group (@existingGroups) {
        print "<option value='$group' ";
        print " selected='selected'" if ($cgiparams{'GROUP_EXISTING'} eq $group);
        print ">$group</option>";
    }
    print <<END;
        </select>
    </td>
</tr>
END
}
print <<END;
<tr>
    <td>$Lang::tr{'remark'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='3'><input type='text' name='REMARK' value='$cgiparams{'REMARK'}' maxlength='50' /></td>
</tr><tr>
    <td colspan='4' bgcolor='#000000'><img src='/images/null.gif' width='1' height='1' border='0' alt='--------' /></td>
</tr>
<tr>
    <td>
END

if($#customServices >= 0) {
    print"<input type='radio' name='SERVICE_TYP' value='default' $radio{'SERVICE_TYP'}{'default'} $disabled/>\n";
}
else
{
    print"<input type='hidden' name='SERVICE_TYP' value='default' />\n";
}

print <<END;
        $Lang::tr{'default services'}:
    </td>
    <td colspan='3'>
        <select name='SERVICE_NAME_DEFAULT' $disabled  onclick='this.form.SERVICE_TYP[0].checked=true'>
END

my %defaultServices = ();
&DATA::readDefaultServices(\%defaultServices);
my %ofwServices = ();
&DATA::readOfwServices(\%ofwServices);

print "<option value='BLANK'";
print "selected='selected'" unless (defined $cgiparams{'DEFAULT_SERVICE'});
print ">-- $Lang::tr{'default services'} --</option>";
foreach my $defService (sort keys %ofwServices) {
    print "<option value='$defService'";
    print " selected='selected'" if ($cgiparams{'SERVICE_NAME_DEFAULT'} eq $defService);
    print ">$defService ($ofwServices{$defService}{'PORT_NR'})</option>";

}
print "<option value='BLANK'> --- </option>";
foreach my $defService (sort keys %defaultServices) {
    print "<option value='$defService'";
    print " selected='selected'" if ($cgiparams{'SERVICE_NAME_DEFAULT'} eq $defService);
    print ">$defService ($defaultServices{$defService}{'PORT_NR'})</option>";

}
print <<END;
        </select>
    </td>
</tr>
END

if ($#customServices >= 0) {
    print <<END;
<tr>
    <td>
        <input type='radio' name='SERVICE_TYP' value='custom' $radio{'SERVICE_TYP'}{'custom'} $disabled />
        $Lang::tr{'custom services'}:
    </td>
    <td colspan='3'>
        <select name='SERVICE_NAME_CUSTOM' $disabled onclick='this.form.SERVICE_TYP[1].checked=true'>
END
    print "<option value='BLANK' selected='selected'>N/A</option>" if ($#customServices < 0);
    foreach my $service (@customServices) {
        print "<option value='$service'";
        print " selected='selected'" if ($cgiparams{'SERVICE_NAME_CUSTOM'} eq $service);
        print ">$service</option>";
    }
    print <<END;
        </select>
    </td>
</tr>
END
}
print <<END;
<tr>
    <td>$Lang::tr{'enabled'}:</td>
    <td colspan='3'><input type='checkbox' name='ENABLED' $checked{'ENABLED'}{'on'} $disabled /></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment2buttons'>
        <img src='/blob.gif' alt='*' align='top' />&nbsp;
        <font class='base'>$Lang::tr{'this field may be blank'}</font>
    </td>
END

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
    print "<td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'update'}' />\n";
    print "<input type='hidden' name='OLD_GROUP' value='$cgiparams{'GROUP'}' /></td>\n";
    print "<td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'reset'}' /></td>\n";
}
else {
    print "<td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' /></td>\n";
    print "<td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'reset'}' /></td>\n";
}
print <<END;
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/firewall-servicegroups.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
END

&Header::closebox();

&Header::openbox('100%', 'left', "$Lang::tr{'service groups'}:");

foreach my $group (sort keys %serviceGroupConf) {
    my $remark = "";
    if (defined($serviceGroupConf{$group}{'REMARK'}) && $serviceGroupConf{$group}{'REMARK'} ne "") {
        $remark = " - " . $serviceGroupConf{$group}{'REMARK'};
    }
    my $color = "";
    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} && $cgiparams{'GROUP'} eq $group) {
        $color = "class='selectcolour'";
    }

    print <<END;
<div align='center'>
<table width='100%' align='center'>
<tr align="left" $color>
    <td colspan='2'>
        <strong>
            $group $remark - $Lang::tr{'used'}&nbsp;$serviceGroupConf{$group}{'USED_COUNT'}x :
        </strong>
    </td>
    <td align='center'>
    <form method='post' name='frm$group' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='TYP' value='group' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
        <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif'  alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
        <input type='hidden' name='GROUP' value='$group' />
    </form>
    </td>
END

    if ($serviceGroupConf{$group}{'USED_COUNT'} > 0) {
        print "<td align='center'><img src='/images/null.gif' width='20' height='20' border='0' alt='' /></td>";
    }
    else {
        print <<END;
    <td align='center'>
    <form method='post' name='frm$group' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='TYP' value='group' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
        <input type='hidden' name='GROUP' value='$group' />
    </form>
    </td>
END
    }
    print "</tr>\n";

    my $id = 0;
    my ($gif, $toggle, $typ);
    my $serviceCount = @{$serviceGroupConf{$group}{'SERVICES'}};
    foreach my $entry (@{$serviceGroupConf{$group}{'SERVICES'}}) {

        #       print FILE "SERVICE,$key,$entry->{'SERVICE_NAME'},$entry->{'SERVICE_TYP'},$entry->{'ENABLED'}\n";
        if ($entry->{'ENABLED'} eq 'on') {
            $gif    = 'on';
            $toggle = 'off';
        }
        else {
            $gif    = 'off';
            $toggle = 'on';
        }
        print "<tr class='table".int(($id % 2) + 1)."colour'>";
        if ($entry->{'SERVICE_TYP'} eq 'default') {
            $typ = $Lang::tr{'typ default'};
        }
        else {
            $typ = $Lang::tr{'typ custom'};
        }

        print <<END;
    <td align='center' width='50%'>$entry->{'SERVICE_NAME'}</td>
    <td align='center' width='50%'>$typ</td>
END

        if ($serviceCount < 2) {
            print "<td align='center'><img src='/images/$gif.gif' width='20' height='20' border='0' alt='$gif' /></td>";
            print "<td align='center'><img src='/images/null.gif' width='20' height='20' border='0' alt='' /></td>";
        }
        else {
            print <<END;
    <td align='center'>
    <form method='post' name='frm$group' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif.gif' alt='$Lang::tr{'toggle enable disable'}' title='$Lang::tr{'toggle enable disable'}' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
        <input type='hidden' name='GROUP' value='$group' />
        <input type='hidden' name='SERVICE_ID' value='$id' />
        <input type='hidden' name='ENABLED' value='$toggle' />
    </form>
    </td>
    <td align='center'>
    <form method='post' name='frm$group' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='TYP' value='service' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
        <input type='hidden' name='GROUP' value='$group' />
        <input type='hidden' name='SERVICE_ID' value='$id' />
    </form>
    </td>
END
        }
        print "</tr>\n";
        $id++;
    }
    print <<END;
</table>
</div>
<br/>
END
}

&Header::closebox();
&Header::closebigbox();
&Header::closepage();

sub validateServiceGroupingParams {
    my $serviceGroupConfRef = shift;

    my $group = $cgiparams{'GROUP_EXISTING'};

    # Strip out commas which will break CSV config file.
    $cgiparams{'GROUP_NEW'} = &Header::cleanhtml($cgiparams{'GROUP_NEW'});
    $cgiparams{'REMARK'} = &Header::cleanhtml($cgiparams{'REMARK'});

    if ($cgiparams{'GROUP_TYP'} eq 'new') {

        # a new group has to have a different name
        if (defined($serviceGroupConfRef->{$cgiparams{'GROUP_NEW'}})) {

            # when this is an update, the old name is allowed
            unless ($cgiparams{'ACTION'} eq $Lang::tr{'update'}
                && $cgiparams{'GROUP_NEW'} eq $cgiparams{'OLD_GROUP'})
            {
                $errormessage .= "$Lang::tr{'service group exists already'} <br />";
            }
        }

        if ($cgiparams{'GROUP_NEW'} eq '') {
            $errormessage .= "$Lang::tr{'service group not be empty'} <br />";
        }
        $group = $cgiparams{'GROUP_NEW'};
        return if ($cgiparams{'ACTION'} eq $Lang::tr{'update'});
    }
    elsif ($cgiparams{'GROUP_TYP'} eq 'existing') {
        if ($cgiparams{'GROUP_EXISTING'} eq '') {
            $errormessage .= "$Lang::tr{'select service group'} <br />";
        }
    }
    else {
        $errormessage .= "$Lang::tr{'select service group typ'} <br />";
    }

    my $typ = $cgiparams{'SERVICE_TYP'};
    if ($typ eq 'default' || $typ eq 'custom') {
        if (
            (
                $typ eq 'default' && ($cgiparams{'SERVICE_NAME_DEFAULT'} eq ''
                    || $cgiparams{'SERVICE_NAME_DEFAULT'} eq 'BLANK')
            )
            || ($typ eq 'custom' && $cgiparams{'SERVICE_NAME_CUSTOM'} eq '')
            )
        {
            $errormessage .= "$Lang::tr{'invalid service'}<br />";
        }
        elsif ($group ne '') {    # we only have to check for existing service in group
                                  # when group and service names are ok
            my $found       = 0;
            my $serviceName = $cgiparams{'SERVICE_NAME_DEFAULT'};
            if ($typ eq 'custom') {
                $serviceName = $cgiparams{'SERVICE_NAME_CUSTOM'};
            }

            foreach my $entry (@{$serviceGroupConfRef->{$group}{'SERVICES'}}) {
                if (   $entry->{'SERVICE_TYP'} eq $typ
                    && $entry->{'SERVICE_NAME'} eq $serviceName)
                {
                    $found = 1;
                    last;
                }
            }

            if ($found) {
                $errormessage .= "$Lang::tr{'service already in group'} <br />";
            }
        }
    }
    else {
        $errormessage .= "$Lang::tr{'none service type'} <br />";
    }

    if ($cgiparams{'ENABLED'} ne 'on') {
        $cgiparams{'ENABLED'} = 'off';
    }
}
