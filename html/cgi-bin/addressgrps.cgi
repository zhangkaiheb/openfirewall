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
# MENUENTRY firewall 060 "address groups" "address groups"

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

my %addressGroupConf;
my %custAddresses = ();

&DATA::readAddressGroupConf(\%addressGroupConf);
&DATA::readCustAddresses(\%custAddresses);

my (%radio, %selected, %checked);

my @customAddresses = sort(keys %custAddresses);

$cgiparams{'GROUP_TYP'}            = 'existing';
$cgiparams{'GROUP_NEW'}            = '';
$cgiparams{'GROUP_EXISTING'}       = '';
$cgiparams{'REMARK'}               = '';
$cgiparams{'ADDRESS_TYP'}          = 'default';
$cgiparams{'ADDRESS_NAME_CUSTOM'}  = '';
$cgiparams{'ADDRESS_NAME_DEFAULT'} = '';
$cgiparams{'ENABLED'}              = '';

&General::getcgihash(\%cgiparams);

$cgiparams{'GROUP_NEW'} = &Header::cleanConfNames($cgiparams{'GROUP_NEW'});

if ($cgiparams{'ACTION'} eq $Lang::tr{'add'}) {
    &validateAddressGroupingParams(\%addressGroupConf);
    unless ($errormessage) {
        my %newEntry = ();
        if ($cgiparams{'GROUP_TYP'} eq 'existing') {
            $newEntry{'GROUP_NAME'} = $cgiparams{'GROUP_EXISTING'};
            $newEntry{'ENABLED'}    = $cgiparams{'ENABLED'};
        }
        else {
            $newEntry{'GROUP_NAME'}                                  = $cgiparams{'GROUP_NEW'};
            $addressGroupConf{$newEntry{'GROUP_NAME'}}{'USED_COUNT'} = 0;
            $addressGroupConf{$newEntry{'GROUP_NAME'}}{'REMARK'}     = $cgiparams{'REMARK'};
            $addressGroupConf{$newEntry{'GROUP_NAME'}}{'ADDRESSES'}  = ();

            # we have to be sure that at least one address is enabled,
            # this is the first address -> enable it
            $newEntry{'ENABLED'} = 'on';
        }

        $newEntry{'ADDRESS_TYP'} = $cgiparams{'ADDRESS_TYP'};
        if ($cgiparams{'ADDRESS_TYP'} eq 'default') {
            $newEntry{'ADDRESS_NAME'} = $cgiparams{'ADDRESS_NAME_DEFAULT'};
        }
        else {
            $newEntry{'ADDRESS_NAME'} = $cgiparams{'ADDRESS_NAME_CUSTOM'};
            &FW::changeUsedCountAdr($newEntry{'ADDRESS_NAME'}, "", "add");
        }

        push(@{$addressGroupConf{$newEntry{'GROUP_NAME'}}{'ADDRESSES'}}, \%newEntry);
        &DATA::saveAddressGroupConf(\%addressGroupConf);
        &General::log("$Lang::tr{'address added to group'}: $newEntry{'ADDRESS_NAME'} -> $newEntry{'GROUP_NAME'}");

        # submit the changes to iptables rules
        if (   $addressGroupConf{$newEntry{'GROUP_NAME'}}{'USED_COUNT'} > 0
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
    &validateAddressGroupingParams(\%addressGroupConf);

    unless ($errormessage) {
        my $group    = $cgiparams{'GROUP_NEW'};
        my $groupOld = $cgiparams{'OLD_GROUP'};
        $addressGroupConf{$groupOld}{'REMARK'} = $cgiparams{'REMARK'};

        # if the name (==Key) has changed, we have to copy/move the old data to new key
        if ($group ne $groupOld) {
            $addressGroupConf{$group}{'REMARK'}     = $addressGroupConf{$groupOld}{'REMARK'};
            $addressGroupConf{$group}{'USED_COUNT'} = $addressGroupConf{$groupOld}{'USED_COUNT'};
            $addressGroupConf{$group}{'ADDRESSES'}  = ();

            foreach my $address (@{$addressGroupConf{$groupOld}{'ADDRESSES'}}) {
                push(@{$addressGroupConf{$group}{'ADDRESSES'}}, $address);
            }
            delete($addressGroupConf{$groupOld});
        }
        &DATA::saveAddressGroupConf(\%addressGroupConf);

        &General::log("$Lang::tr{'address group updated'}: $group");
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
    $cgiparams{'REMARK'}    = $addressGroupConf{$group}{'REMARK'};
    $cgiparams{'REMARK'}    = $tmpRemark if (defined $tmpRemark);
    $cgiparams{'GROUP_TYP'} = 'new';
    $disabled               = "disabled='disabled'";
    if ($addressGroupConf{$group}{'USED_COUNT'} > 0) {
        $disabledNameTxt = "disabled='disabled'";
        $hiddenGroupName = "<input type='hidden' name='GROUP_NEW' value='$cgiparams{'GROUP_NEW'}' />";
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    my $group = $cgiparams{'GROUP'};

    if ($cgiparams{'TYP'} eq 'group') {
        foreach my $address (@{$addressGroupConf{$group}{'ADDRESSES'}}) {
            if ($address->{'ADDRESS_TYP'} ne 'default') {
                &FW::changeUsedCountAdr($address->{'ADDRESS_NAME'}, "", "remove");
            }
        }
        delete($addressGroupConf{$group});
        &DATA::saveAddressGroupConf(\%addressGroupConf);
        &General::log("$Lang::tr{'address group deleted'}: $group");

        # A group can only be removed when it is not used
        # -> no need to run setfwrules
    }
    else {
        my $address = $addressGroupConf{$group}{'ADDRESSES'}[ $cgiparams{'ADDRESS_ID'} ];
        if ($address->{'ADDRESS_TYP'} ne 'default') {
            &FW::changeUsedCountAdr($address->{'ADDRESS_NAME'}, "", "remove");
        }

        &General::log("$Lang::tr{'address from group deleted'}: $address->{'ADDRESS_NAME'} -> $group");
        splice(@{$addressGroupConf{$group}{'ADDRESSES'}}, $cgiparams{'ADDRESS_ID'}, 1);

        # we have to be sure, that at least one address is enabled
        my $addressCount = @{$addressGroupConf{$group}{'ADDRESSES'}};
        if ($addressCount < 2) {
            $addressGroupConf{$group}{'ADDRESSES'}[0]->{'ENABLED'} = 'on';
            &General::log(
"$Lang::tr{'address in group enabled'}: $addressGroupConf{$group}{'ADDRESSES'}[0]->{'ADDRESS_NAME'} -> on"
            );
        }
        &DATA::saveAddressGroupConf(\%addressGroupConf);
        `/usr/local/bin/setfwrules --user < /dev/null > /dev/null 2>&1 &`;
    }
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'toggle enable disable'}) {
    my $group            = $cgiparams{'GROUP'};
    my $isEnabledAddress = 0;

    if ($cgiparams{'ENABLED'} ne 'on') {

        # we have to be sure, that at least one address is enabled
        my $id = 0;
        foreach my $entry (@{$addressGroupConf{$group}{'ADDRESSES'}}) {
            if ($entry->{'ENABLED'} eq 'on' && $id != $cgiparams{'ADDRESS_ID'}) {
                $isEnabledAddress = 1;
                last;
            }
            $id++;
        }
    }
    else {

        # user want to enable a address, no need to check for another address beeing enabled
        $isEnabledAddress = 1;
    }

    if ($isEnabledAddress) {
        $addressGroupConf{$group}{'ADDRESSES'}[ $cgiparams{'ADDRESS_ID'} ]->{'ENABLED'} = $cgiparams{'ENABLED'};
        &DATA::saveAddressGroupConf(\%addressGroupConf);
        &General::log(
"$Lang::tr{'address in group enabled'}: $addressGroupConf{$group}{'ADDRESSES'}[$cgiparams{'ADDRESS_ID'}]->{'ADDRESS_NAME'} -> $cgiparams{'ENABLED'}"
        );
        `/usr/local/bin/setfwrules --user < /dev/null > /dev/null 2>&1 &`;
    }
    else {
        $errormessage .= "$Lang::tr{'at least one address enabled'} <br />";
    }
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'reset'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

&Header::openpage($Lang::tr{'address grouping settings'}, 1, '');
&Header::openbigbox('100%', 'left');

if (   $cgiparams{'ACTION'} eq ''
    || $cgiparams{'ACTION'} eq $Lang::tr{'show adv config'})
{
    $cgiparams{'GROUP_TYP'}            = 'existing';
    $cgiparams{'GROUP_NEW'}            = '';
    $cgiparams{'GROUP_EXISTING'}       = '';
    $cgiparams{'REMARK'}               = '';
    $cgiparams{'ADDRESS_TYP'}          = 'default';
    $cgiparams{'ADDRESS_NAME_CUSTOM'}  = '';
    $cgiparams{'ADDRESS_NAME_DEFAULT'} = '';
    $cgiparams{'ENABLED'}              = 'on';
    $cgiparams{'DEFAULT_ADDRESS'}      = '';
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

&Header::openbox('100%', 'left', "$Lang::tr{'add address grouping'}:", $error);

$radio{'GROUP_TYP'}{'new'}                   = '';
$radio{'GROUP_TYP'}{'existing'}              = '';
$radio{'GROUP_TYP'}{$cgiparams{'GROUP_TYP'}} = "checked='checked'";

$radio{'ADDRESS_TYP'}{'default'}                 = '';
$radio{'ADDRESS_TYP'}{'custom'}                  = '';
$radio{'ADDRESS_TYP'}{$cgiparams{'ADDRESS_TYP'}} = "checked='checked'";

$cgiparams{'ENABLED'} = 'off' if ($cgiparams{'ENABLED'} ne 'on');
$checked{'ENABLED'}{'off'}                 = '';
$checked{'ENABLED'}{'on'}                  = '';
$checked{'ENABLED'}{$cgiparams{'ENABLED'}} = "checked='checked'";

my @existingGroups      = sort(keys(%addressGroupConf));
my $existingGroupsCount = @existingGroups;

print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<div align='center'>
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr align="left">
    <td width='25%' class='base'>
END

if($existingGroupsCount > 0) {
    print"<input type='radio' name='GROUP_TYP' value='new' $radio{'GROUP_TYP'}{'new'} />\n";
}
else
{
    print"<input type='hidden' name='GROUP_TYP' value='new' />\n";
}

print <<END;
        $Lang::tr{'address group name'}:
    </td>
    <td width='25%' class='base'>
        <input type='text' name='GROUP_NEW' value='$cgiparams{'GROUP_NEW'}' size='20' maxlength='18' $disabledNameTxt />
        $hiddenGroupName
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
END

if ($existingGroupsCount > 0) {
    print <<END;
    <tr>
    <td align='left' class='base'>
        <input type='radio' name='GROUP_TYP' value='existing' $radio{'GROUP_TYP'}{'existing'} $disabled/>
        $Lang::tr{'address group name'}:&nbsp;
    </td>
    <td colspan='3' align='left' class='base'>
        <select name='GROUP_EXISTING' $disabled>
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
</tr><tr>
    <td>
END

if($#customAddresses >= 0) {
    print"<input type='radio' name='ADDRESS_TYP' value='default' $radio{'ADDRESS_TYP'}{'default'} $disabled/>\n";
}
else
{
    print"<input type='hidden' name='ADDRESS_TYP' value='default' />\n";
}

print <<END;

        $Lang::tr{'default networks'}:
    </td>
    <td colspan='3'>
        <select name='ADDRESS_NAME_DEFAULT' $disabled>
END

my %networks = ();
&DATA::setup_default_networks(\%networks);

print "<option value='BLANK'";
print "selected='selected'" unless (defined $cgiparams{'DEFAULT_ADDRESS'});
print ">-- $Lang::tr{'default networks'} --</option>";
foreach my $defAddress (sort keys %networks) {
    print "<option value='$defAddress'";
    print " selected='selected'" if ($cgiparams{'ADDRESS_NAME_DEFAULT'} eq $defAddress);
    print ">$defAddress</option>";
}
print <<END;
        </select>
    </td>
</tr>
END

if ($#customAddresses >= 0) {
    print <<END;
<tr align="left">
    <td class='base'>
        <input type='radio' name='ADDRESS_TYP' value='custom' $radio{'ADDRESS_TYP'}{'custom'} $disabled />
        $Lang::tr{'custom addresses'}:
    </td>
    <td colspan='3' class='base'>
        <select name='ADDRESS_NAME_CUSTOM' $disabled>
END
    print "<option value='BLANK' selected='selected'>N/A</option>" if ($#customAddresses < 0);
    foreach my $address (@customAddresses) {
        print "<option value='$address'";
        print " selected='selected'" if ($cgiparams{'ADDRESS_NAME_CUSTOM'} eq $address);
        print ">$address</option>";

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
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td class='comment2buttons'>
        <strong>$Lang::tr{'note'}</strong>:&nbsp;$Lang::tr{'mac adr not as dest'}
        <br />
    </td>
    <td colspan='3'>&nbsp;</td>
</tr>
<tr>
    <td class='comment2buttons'>
        <img src='/blob.gif' alt='*' align='top' />&nbsp;
        <font class='base'>$Lang::tr{'this field may be blank'}</font>
    </td>
END

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
    print "<td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'update'}' />\n";
    print "<input type='hidden' name='OLD_GROUP' value='$cgiparams{'GROUP'}' /></td>\n";
    print "<td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'reset'}' /></td>\n";
}
else {
    print "<td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'add'}' /></td>\n";
    print "<td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'reset'}' /></td>\n";
}
print <<END;
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/firewall-addressgroups.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</div>
</form>
END

&Header::closebox();

&Header::openbox('100%', 'left', "$Lang::tr{'address groups'}:");

foreach my $group (sort keys %addressGroupConf) {
    my $remark = "";
    if (defined($addressGroupConf{$group}{'REMARK'}) && $addressGroupConf{$group}{'REMARK'} ne "") {
        $remark = " - " . $addressGroupConf{$group}{'REMARK'};
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
            $group $remark - $Lang::tr{'used'}&nbsp;$addressGroupConf{$group}{'USED_COUNT'}x :
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

    if ($addressGroupConf{$group}{'USED_COUNT'} > 0) {
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
    my $addressCount = @{$addressGroupConf{$group}{'ADDRESSES'}};
    foreach my $entry (@{$addressGroupConf{$group}{'ADDRESSES'}}) {

        #       print FILE "ADDRESS,$key,$entry->{'ADDRESS_NAME'},$entry->{'ADDRESS_TYP'},$entry->{'ENABLED'}\n";
        if ($entry->{'ENABLED'} eq 'on') {
            $gif    = 'on';
            $toggle = 'off';
        }
        else {
            $gif    = 'off';
            $toggle = 'on';
        }
        print "<tr class='table".int(($id % 2) + 1)."colour'>";
        if ($entry->{'ADDRESS_TYP'} eq 'default') {
            $typ = $Lang::tr{'typ default'};
        }
        else {
            $typ = $Lang::tr{'typ custom'};
        }

        print <<END;
    <td align='center' width='50%'>$entry->{'ADDRESS_NAME'}</td>
    <td align='center' width='50%'>$typ</td>
END

        if ($addressCount < 2) {
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
        <input type='hidden' name='ADDRESS_ID' value='$id' />
        <input type='hidden' name='ENABLED' value='$toggle' />
    </form>
    </td>
    <td align='center'>
    <form method='post' name='frm$group' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='TYP' value='address' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
        <input type='hidden' name='GROUP' value='$group' />
        <input type='hidden' name='ADDRESS_ID' value='$id' />
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

sub validateAddressGroupingParams {
    my $addressGroupConfRef = shift;

    my $group = $cgiparams{'GROUP_EXISTING'};

    # Strip out commas which will break CSV config file.
    $cgiparams{'GROUP_NEW'} = &Header::cleanhtml($cgiparams{'GROUP_NEW'});
    $cgiparams{'REMARK'} = &Header::cleanhtml($cgiparams{'REMARK'});

    if ($cgiparams{'GROUP_TYP'} eq 'new') {

        # a new group has to have a different name
        if (defined($addressGroupConfRef->{$cgiparams{'GROUP_NEW'}})) {

            # when this is an update, the old name is allowed
            unless ($cgiparams{'ACTION'} eq $Lang::tr{'update'}
                && $cgiparams{'GROUP_NEW'} eq $cgiparams{'OLD_GROUP'})
            {
                $errormessage .= "$Lang::tr{'address group exists already'} <br />";
            }
        }

        if ($cgiparams{'GROUP_NEW'} eq '') {
            $errormessage .= "$Lang::tr{'address group not be empty'} <br />";
        }
        $group = $cgiparams{'GROUP_NEW'};
        return if ($cgiparams{'ACTION'} eq $Lang::tr{'update'});
    }
    elsif ($cgiparams{'GROUP_TYP'} eq 'existing') {
        if ($cgiparams{'GROUP_EXISTING'} eq '') {
            $errormessage .= "$Lang::tr{'select address group'} <br />";
        }
    }
    else {
        $errormessage .= "$Lang::tr{'select address group typ'} <br />";
    }

    my $typ = $cgiparams{'ADDRESS_TYP'};
    if ($typ eq 'default' || $typ eq 'custom') {
        if (
            (
                $typ eq 'default' && ($cgiparams{'ADDRESS_NAME_DEFAULT'} eq ''
                    || $cgiparams{'ADDRESS_NAME_DEFAULT'} eq 'BLANK')
            )
            || ($typ eq 'custom' && $cgiparams{'ADDRESS_NAME_CUSTOM'} eq '')
            )
        {
            $errormessage .= "$Lang::tr{'invalid address'}<br />";
        }
        elsif ($group ne '') {

            # we only have to check for existing address in group
            # when group and address names are ok
            my $found       = 0;
            my $addressName = $cgiparams{'ADDRESS_NAME_DEFAULT'};
            if ($typ eq 'custom') {
                $addressName = $cgiparams{'ADDRESS_NAME_CUSTOM'};
            }

            foreach my $entry (@{$addressGroupConfRef->{$group}{'ADDRESSES'}}) {
                if (   $entry->{'ADDRESS_TYP'} eq $typ
                    && $entry->{'ADDRESS_NAME'} eq $addressName)
                {
                    $found = 1;
                    last;
                }
            }

            if ($found) {
                $errormessage .= "$Lang::tr{'address already in group'} <br />";
            }
        }
    }
    else {
        $errormessage .= "$Lang::tr{'none address type'} <br />";
    }

    if ($cgiparams{'ENABLED'} ne 'on') {
        $cgiparams{'ENABLED'} = 'off';
    }
}

