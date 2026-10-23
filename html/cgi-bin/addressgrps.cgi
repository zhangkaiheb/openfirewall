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
# MENUTHRDLVL "addresses" 020 "address groups" "address groups"

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
        my $groupName = $cgiparams{'GROUP_NEW'};
        $addressGroupConf{$groupName}{'USED_COUNT'} = 0;
        $addressGroupConf{$groupName}{'REMARK'}     = $cgiparams{'REMARK'};
        $addressGroupConf{$groupName}{'ADDRESSES'}  = [];

        # Process selected addresses (pipe-separated from dual-listbox)
        my %networks = ();
        &DATA::setup_default_networks(\%networks);

        if ($cgiparams{'SELECTED_ADDRESSES'} ne '') {
            my @addrs = split(/\|/, $cgiparams{'SELECTED_ADDRESSES'});
            my %seen;
            foreach my $addr (@addrs) {
                next if $addr eq '';
                next if $seen{$addr}++;
                my %entry = ();
                if (exists $networks{$addr}) {
                    $entry{'ADDRESS_TYP'}  = 'default';
                } else {
                    $entry{'ADDRESS_TYP'}  = 'custom';
                    &FW::changeUsedCountAdr($addr, "", "add");
                }
                $entry{'ADDRESS_NAME'} = $addr;
                $entry{'ENABLED'}      = 'on';
                push(@{$addressGroupConf{$groupName}{'ADDRESSES'}}, \%entry);
                &General::log("$Lang::tr{'address added to group'}: $addr -> $groupName");
            }
        }

        &DATA::saveAddressGroupConf(\%addressGroupConf);

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

        # Remove old custom address used counts
        foreach my $oldAddr (@{$addressGroupConf{$groupOld}{'ADDRESSES'}}) {
            if ($oldAddr->{'ADDRESS_TYP'} ne 'default') {
                &FW::changeUsedCountAdr($oldAddr->{'ADDRESS_NAME'}, "", "remove");
            }
        }

        # Build new address list from SELECTED_ADDRESSES
        my @newAddresses = ();
        my %networks = ();
        &DATA::setup_default_networks(\%networks);

        if ($cgiparams{'SELECTED_ADDRESSES'} ne '') {
            my @addrs = split(/\|/, $cgiparams{'SELECTED_ADDRESSES'});
            my %seen;
            foreach my $addr (@addrs) {
                next if $addr eq '';
                next if $seen{$addr}++;
                my %entry = ();
                if (exists $networks{$addr}) {
                    $entry{'ADDRESS_TYP'}  = 'default';
                } else {
                    $entry{'ADDRESS_TYP'}  = 'custom';
                    &FW::changeUsedCountAdr($addr, "", "add");
                }
                $entry{'ADDRESS_NAME'} = $addr;
                $entry{'ENABLED'}      = 'on';
                push(@newAddresses, \%entry);
            }
        }

        # Update group
        $addressGroupConf{$groupOld}{'REMARK'}   = $cgiparams{'REMARK'};
        $addressGroupConf{$groupOld}{'ADDRESSES'} = \@newAddresses;

        # Rename group if name changed
        if ($group ne $groupOld) {
            $addressGroupConf{$group}{'REMARK'}     = $addressGroupConf{$groupOld}{'REMARK'};
            $addressGroupConf{$group}{'USED_COUNT'} = $addressGroupConf{$groupOld}{'USED_COUNT'};
            $addressGroupConf{$group}{'ADDRESSES'}  = \@newAddresses;
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
        # Support batch delete: GROUP may contain multiple names joined by ','
        my @groupsToDelete = split(/,/, $group);
        foreach my $g (@groupsToDelete) {
            next unless defined $addressGroupConf{$g}{'ADDRESSES'};
            foreach my $address (@{$addressGroupConf{$g}{'ADDRESSES'}}) {
                if ($address->{'ADDRESS_TYP'} ne 'default') {
                    &FW::changeUsedCountAdr($address->{'ADDRESS_NAME'}, "", "remove");
                }
            }
            delete($addressGroupConf{$g});
            &General::log("$Lang::tr{'address group deleted'}: $g");
        }
        &DATA::saveAddressGroupConf(\%addressGroupConf);

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

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

# Prepare data for DataTable
my @jsData;
my $rowId = 0;
foreach my $group (sort keys %addressGroupConf) {
    my $remark = defined($addressGroupConf{$group}{'REMARK'}) ? $addressGroupConf{$group}{'REMARK'} : '';
    my $addressCount = scalar(@{$addressGroupConf{$group}{'ADDRESSES'}});
    my $usedCount = $addressGroupConf{$group}{'USED_COUNT'};

    # Build addresses list for edit modal
    my @addrNames = ();
    foreach my $addr (@{$addressGroupConf{$group}{'ADDRESSES'}}) {
        my $name = $addr->{'ADDRESS_NAME'};
        $name =~ s/(['\\])/\\$1/g;
        push @addrNames, $name;
    }
    my $addressesStr = join(',', @addrNames);

    # Escape special characters for JavaScript
    $group =~ s/(['\\])/\\$1/g;
    $remark =~ s/(['\\])/\\$1/g;

    push @jsData, sprintf(
        "{id:'%d',group:'%s',remark:'%s',addressCount:%d,usedCount:%d,addresses:'%s'}",
        $rowId, $group, $remark, $addressCount, $usedCount, $addressesStr
    );
    $rowId++;
}
my $tableDataJs = join(",\n", @jsData);

# Build address group data for edit modal
my %addressGroupData = ();
foreach my $group (keys %addressGroupConf) {
    my @addrNames = ();
    foreach my $addr (@{$addressGroupConf{$group}{'ADDRESSES'}}) {
        push @addrNames, $addr->{'ADDRESS_NAME'};
    }
    $addressGroupData{$group} = join(',', @addrNames);
}

my @agEntries = ();
foreach my $group (keys %addressGroupData) {
    my $jsGroup = $group;
    $jsGroup =~ s/'/\\'/g;
    my $jsAddrs = $addressGroupData{$group};
    push @agEntries, "'$jsGroup':'$jsAddrs'";
}
my $addressGroupDataJs = "{" . join(',', @agEntries) . "}";

# Prepare translation strings for JavaScript
my $trSequence = $Lang::tr{'sequence'};
my $trAddressGroupName = $Lang::tr{'address group name'};
my $trRemark = $Lang::tr{'remark'};
my $trAddresses = $Lang::tr{'addresses'};
my $trUsed = $Lang::tr{'used'};
my $trAddAddressToGroup = $Lang::tr{'add address to group'};
my $trAdd = $Lang::tr{'add'};
my $trAddressGroupNameLabel = $Lang::tr{'address group name'};
my $trRemarkLabel = $Lang::tr{'remark'};
my $trAddressType = $Lang::tr{'address type'};
my $trDefaultNetworks = $Lang::tr{'default networks'};
my $trCustomAddresses = $Lang::tr{'custom addresses'};
my $trAddress = $Lang::tr{'address'};
my $trSelect = $Lang::tr{'select'};
my $trEnabled = $Lang::tr{'enabled'};
my $trCancel = $Lang::tr{'cancel'};
my $trUpdate = $Lang::tr{'update'};
my $trRemove = $Lang::tr{'remove'};
my $trEditAddressGroup = $Lang::tr{'edit address group'};
my $trEditAddressToGroup = $Lang::tr{'edit address to group'};
my $trAvailableAddresses = $Lang::tr{'available addresses'};
my $trSelectedAddresses = $Lang::tr{'selected addresses'};
my $trDeleteConfirm = $Lang::tr{'are you sure you want to delete this address group'};
my $trDeleteConfirmPlural = $Lang::tr{'are you sure you want to delete these address groups'};
my $scriptName = $ENV{'SCRIPT_NAME'};

print <<END;
<script src="/include/datatable.js"></script>
<script>
var addressGroupData = $addressGroupDataJs;
var tableData = [
$tableDataJs
];

document.addEventListener('DOMContentLoaded', function() {
    window.addressGroupsTable = new DataTable('#addressGroupsTable', {
        data: tableData,
        columns: [
            { key: 'id', title: '$trSequence', sortable: true },
            { key: 'group', title: '$trAddressGroupName', sortable: true },
            { key: 'remark', title: '$trRemark', sortable: true },
            { key: 'addressCount', title: '$trAddresses', sortable: true },
            { key: 'usedCount', title: '$trUsed', sortable: true }
        ],
        selectable: true,
        actions: ['create', 'edit', 'delete', 'refresh'],
        onAddModal: function() {
            openAddAddressModal();
        },
        onEditModal: function(row) {
            openEditGroupModal(row);
        },
        onDeleteConfirm: function(selectedRows) {
            deleteGroups(selectedRows);
        }
    });
});

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
        var x = e.clientX - offsetX;
        var y = e.clientY - offsetY;
        dialog.style.left = x + 'px';
        dialog.style.top = y + 'px';
    });

    document.addEventListener('mouseup', function() {
        isDragging = false;
    });
}

function openAddAddressModal() {
    // Prevent duplicate modals
    if (document.querySelector('#addAddressModal')) return;

    var modalHtml = '<div class="ofw_modal_overlay" id="addAddressModal">' +
        '<div class="ofw_modal_dialog" style="width:680px;">' +
        '<div class="ofw_modal_header" style="cursor:move;">' +
        '<span class="ofw_modal_title">$trAddAddressToGroup</span>' +
        '<button type="button" class="ofw_modal_close" onclick="closeAddAddressModal()">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' +
        '<form id="addAddressForm" method="post" action="$scriptName">' +
        '<input type="hidden" name="ACTION" value="$trAdd">' +
        '<input type="hidden" name="GROUP_TYP" value="new">' +
        '<table width="100%" cellpadding="5" cellspacing="0" border="0">' +
        '<tr>' +
        '<td width="30%" align="right">$trAddressGroupNameLabel</td>' +
        '<td><input type="text" name="GROUP_NEW" style="width:300px;" maxlength="18" required></td>' +
        '</tr>' +
        '<tr>' +
        '<td align="right">$trRemarkLabel</td>' +
        '<td><input type="text" name="REMARK" style="width:300px;" maxlength="50"></td>' +
        '</tr>' +
        '<tr>' +
        '<td align="right" valign="top">$trAddresses</td>' +
        '<td>' +
        '<div style="display:flex;gap:10px;align-items:center;">' +
        '<div style="flex:1;display:flex;flex-direction:column;">' +
        '<div style="margin-bottom:5px;font-weight:bold;">$trAvailableAddresses</div>' +
        '<select id="availableAddressSelect" multiple size="8" style="width:100%;min-height:160px;">';
END

# Build combined list of all addresses
my %allAddressesMap = ();
foreach my $addr (@customAddresses) {
    $allAddressesMap{$addr} = 'custom';
}
my %networks = ();
&DATA::setup_default_networks(\%networks);
foreach my $addr (keys %networks) {
    $allAddressesMap{$addr} = 'default';
}

# Output default networks group
print "modalHtml += '<optgroup label=\\\"$trDefaultNetworks\\\">';\n";
foreach my $addr (sort keys %allAddressesMap) {
    next unless $allAddressesMap{$addr} eq 'default';
    my $jsAddr = $addr;
    $jsAddr =~ s/'/\\'/g;
    print "modalHtml += '<option value=\\\"$jsAddr\\\">$jsAddr</option>';\n";
}
print "modalHtml += '</optgroup>';\n";
# Output custom addresses group
print "modalHtml += '<optgroup label=\\\"$trCustomAddresses\\\">';\n";
foreach my $addr (sort keys %allAddressesMap) {
    next unless $allAddressesMap{$addr} eq 'custom';
    my $jsAddr = $addr;
    $jsAddr =~ s/'/\\'/g;
    print "modalHtml += '<option value=\\\"$jsAddr\\\">$jsAddr</option>';\n";
}
print "modalHtml += '</optgroup>';\n";

print <<END;
        modalHtml += '</select>' +
        '</div>' +
        '<div style="display:flex;flex-direction:column;gap:5px;justify-content:center;">' +
        '<button type="button" onclick="moveSelectedToRight()" style="padding:4px 12px;">&gt;&gt;</button>' +
        '<button type="button" onclick="moveSelectedToLeft()" style="padding:4px 12px;">&lt;&lt;</button>' +
        '</div>' +
        '<div style="flex:1;display:flex;flex-direction:column;">' +
        '<div style="margin-bottom:5px;font-weight:bold;">$trSelectedAddresses</div>' +
        '<select id="selectedAddressSelect" multiple size="8" style="width:100%;min-height:160px;"></select>' +
        '</div>' +
        '</div>' +
        '</td>' +
        '</tr>' +
        '<tr>' +
        '<td align="right">$trEnabled:</td>' +
        '<td><input type="checkbox" name="ENABLED" value="on" checked></td>' +
        '</tr>' +
        '</table>' +
        '</form>' +
        '</div>' +
        '<div class="ofw_modal_footer">' +
        '<button type="button" class="ofw_btn" onclick="closeAddAddressModal()">$trCancel</button>' +
        '<button type="button" class="ofw_btn ofw_btn_primary" onclick="submitAddAddressForm()">$trAdd</button>' +
        '</div>' +
        '</div>' +
        '</div>';

    document.body.insertAdjacentHTML('beforeend', modalHtml);
    makeModalDraggable('addAddressModal');
}

function closeAddAddressModal() {
    var modal = document.getElementById('addAddressModal');
    if (modal) {
        modal.remove();
    }
}

function moveSelectedToRight() {
    var available = document.getElementById('availableAddressSelect');
    var selected = document.getElementById('selectedAddressSelect');
    var options = Array.from(available.selectedOptions);
    for (var i = 0; i < options.length; i++) {
        selected.appendChild(options[i]);
    }
}

function moveSelectedToLeft() {
    var available = document.getElementById('availableAddressSelect');
    var selected = document.getElementById('selectedAddressSelect');
    var options = Array.from(selected.selectedOptions);
    for (var i = 0; i < options.length; i++) {
        available.appendChild(options[i]);
    }
}

function submitAddAddressForm() {
    var form = document.getElementById('addAddressForm');
    // Collect selected addresses into hidden field
    var selected = document.getElementById('selectedAddressSelect');
    var values = [];
    for (var i = 0; i < selected.options.length; i++) {
        values.push(selected.options[i].value);
    }
    // Remove old hidden field if exists
    var oldHidden = document.getElementById('selectedAddressesHidden');
    if (oldHidden) oldHidden.remove();
    var hidden = document.createElement('input');
    hidden.type = 'hidden';
    hidden.name = 'SELECTED_ADDRESSES';
    hidden.id = 'selectedAddressesHidden';
    hidden.value = values.join('|');
    form.appendChild(hidden);
    if (form.checkValidity()) {
        form.submit();
    } else {
        form.reportValidity();
    }
}

function openEditGroupModal(row) {
    // Prevent duplicate modals
    if (document.querySelector('#editGroupModal')) return;

    var modalHtml = '<div class="ofw_modal_overlay" id="editGroupModal">' +
        '<div class="ofw_modal_dialog" style="width:680px;">' +
        '<div class="ofw_modal_header" style="cursor:move;">' +
        '<span class="ofw_modal_title">$trEditAddressToGroup</span>' +
        '<button type="button" class="ofw_modal_close" onclick="closeEditGroupModal()">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' +
        '<form id="editGroupForm" method="post" action="$scriptName">' +
        '<input type="hidden" name="ACTION" value="$trUpdate">' +
        '<input type="hidden" name="GROUP_TYP" value="new">' +
        '<input type="hidden" name="OLD_GROUP" value="' + row.group + '">' +
        '<table width="100%" cellpadding="5" cellspacing="0" border="0">' +
        '<tr>' +
        '<td width="30%" align="right">$trAddressGroupNameLabel</td>' +
        '<td><input type="text" name="GROUP_NEW" value="' + row.group + '" style="width:300px;" maxlength="18" required></td>' +
        '</tr>' +
        '<tr>' +
        '<td align="right">$trRemarkLabel</td>' +
        '<td><input type="text" name="REMARK" value="' + row.remark + '" style="width:300px;" maxlength="50"></td>' +
        '</tr>' +
        '<tr>' +
        '<td align="right" valign="top">$trAddresses</td>' +
        '<td>' +
        '<div style="display:flex;gap:10px;align-items:center;">' +
        '<div style="flex:1;display:flex;flex-direction:column;">' +
        '<div style="margin-bottom:5px;font-weight:bold;">$trAvailableAddresses</div>' +
        '<select id="availableAddressSelectEdit" multiple size="8" style="width:100%;min-height:160px;">';
END

# Build combined list of all addresses for edit modal
my %allAddressesMapEdit = ();
foreach my $addr (@customAddresses) {
    $allAddressesMapEdit{$addr} = 'custom';
}
my %networksEdit = ();
&DATA::setup_default_networks(\%networksEdit);
foreach my $addr (keys %networksEdit) {
    $allAddressesMapEdit{$addr} = 'default';
}

# Output default networks group
print "modalHtml += '<optgroup label=\\\"$trDefaultNetworks\\\">';\n";
foreach my $addr (sort keys %allAddressesMapEdit) {
    next unless $allAddressesMapEdit{$addr} eq 'default';
    my $jsAddr = $addr;
    $jsAddr =~ s/'/\\'/g;
    print "modalHtml += '<option value=\\\"$jsAddr\\\">$jsAddr</option>';\n";
}
print "modalHtml += '</optgroup>';\n";
# Output custom addresses group
print "modalHtml += '<optgroup label=\\\"$trCustomAddresses\\\">';\n";
foreach my $addr (sort keys %allAddressesMapEdit) {
    next unless $allAddressesMapEdit{$addr} eq 'custom';
    my $jsAddr = $addr;
    $jsAddr =~ s/'/\\'/g;
    print "modalHtml += '<option value=\\\"$jsAddr\\\">$jsAddr</option>';\n";
}
print "modalHtml += '</optgroup>';\n";

print <<END;
        modalHtml += '</select>' +
        '</div>' +
        '<div style="display:flex;flex-direction:column;gap:5px;justify-content:center;">' +
        '<button type="button" onclick="moveSelectedToRightEdit()" style="padding:4px 12px;">&gt;&gt;</button>' +
        '<button type="button" onclick="moveSelectedToLeftEdit()" style="padding:4px 12px;">&lt;&lt;</button>' +
        '</div>' +
        '<div style="flex:1;display:flex;flex-direction:column;">' +
        '<div style="margin-bottom:5px;font-weight:bold;">$trSelectedAddresses</div>' +
        '<select id="selectedAddressSelectEdit" multiple size="8" style="width:100%;min-height:160px;"></select>' +
        '</div>' +
        '</div>' +
        '</td>' +
        '</tr>' +
        '<tr>' +
        '<td align="right">$trEnabled:</td>' +
        '<td><input type="checkbox" name="ENABLED" value="on" checked></td>' +
        '</tr>' +
        '</table>' +
        '</form>' +
        '</div>' +
        '<div class="ofw_modal_footer">' +
        '<button type="button" class="ofw_btn" onclick="closeEditGroupModal()">$trCancel</button>' +
        '<button type="button" class="ofw_btn ofw_btn_primary" onclick="submitEditGroupForm()">$trUpdate</button>' +
        '</div>' +
        '</div>' +
        '</div>';

    document.body.insertAdjacentHTML('beforeend', modalHtml);
    makeModalDraggable('editGroupModal');

    // Pre-fill selected addresses from row data
    setTimeout(function() {
        var addresses = (row.addresses || '').split(',');
        var available = document.getElementById('availableAddressSelectEdit');
        var selected = document.getElementById('selectedAddressSelectEdit');

        for (var i = 0; i < addresses.length; i++) {
            var addrName = addresses[i].trim();
            if (!addrName) continue;

            // Find and move option from available to selected
            for (var j = 0; j < available.options.length; j++) {
                if (available.options[j].value === addrName) {
                    selected.appendChild(available.options[j].cloneNode(true));
                    available.remove(j);
                    break;
                }
            }
        }
    }, 100);
}

function closeEditGroupModal() {
    var modal = document.getElementById('editGroupModal');
    if (modal) {
        modal.remove();
    }
}

function moveSelectedToRightEdit() {
    var available = document.getElementById('availableAddressSelectEdit');
    var selected = document.getElementById('selectedAddressSelectEdit');
    var options = Array.from(available.selectedOptions);
    for (var i = 0; i < options.length; i++) {
        selected.appendChild(options[i]);
    }
}

function moveSelectedToLeftEdit() {
    var available = document.getElementById('availableAddressSelectEdit');
    var selected = document.getElementById('selectedAddressSelectEdit');
    var options = Array.from(selected.selectedOptions);
    for (var i = 0; i < options.length; i++) {
        available.appendChild(options[i]);
    }
}

function submitEditGroupForm() {
    var form = document.getElementById('editGroupForm');
    var selected = document.getElementById('selectedAddressSelectEdit');
    var values = [];
    for (var i = 0; i < selected.options.length; i++) {
        values.push(selected.options[i].value);
    }
    var oldHidden = document.getElementById('selectedAddressesHiddenEdit');
    if (oldHidden) oldHidden.remove();
    var hidden = document.createElement('input');
    hidden.type = 'hidden';
    hidden.name = 'SELECTED_ADDRESSES';
    hidden.id = 'selectedAddressesHiddenEdit';
    hidden.value = values.join('|');
    form.appendChild(hidden);
    if (form.checkValidity()) {
        form.submit();
    } else {
        form.reportValidity();
    }
}

var pendingDeleteRows = [];

function deleteGroups(selectedRows) {
    if (!selectedRows || selectedRows.length === 0) return;

    // Prevent duplicate modals
    if (document.querySelector('#deleteConfirmModal')) return;

    var confirmMsg = selectedRows.length === 1 ?
        '$trDeleteConfirm' :
        '$trDeleteConfirmPlural';

    // Build list of group names to display
    var listHtml = '<ul style="margin:0;padding-left:20px;">';
    selectedRows.forEach(function(row) {
        listHtml += '<li>' + row.group + '</li>';
    });
    listHtml += '</ul>';

    var modalHtml = '<div class="ofw_modal_overlay" id="deleteConfirmModal">' +
        '<div class="ofw_modal_dialog" style="width:480px;">' +
        '<div class="ofw_modal_header" style="cursor:move;">' +
        '<span class="ofw_modal_title">$trDeleteConfirm</span>' +
        '<button type="button" class="ofw_modal_close" onclick="closeDeleteConfirmModal()">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' +
        '<p style="padding:10px 0;">' + confirmMsg + '</p>' +
        '<div style="margin-top:12px;padding:8px 12px;background:#f5f5f5;border-radius:4px;">' +
        listHtml +
        '</div>' +
        '</div>' +
        '<div class="ofw_modal_footer">' +
        '<button type="button" class="ofw_btn" onclick="closeDeleteConfirmModal()">$trCancel</button>' +
        '<button type="button" class="ofw_btn ofw_btn_primary" onclick="doDeleteGroups()">OK</button>' +
        '</div>' +
        '</div>' +
        '</div>';

    pendingDeleteRows = selectedRows;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    makeModalDraggable('deleteConfirmModal');
}

function closeDeleteConfirmModal() {
    var modal = document.getElementById('deleteConfirmModal');
    if (modal) {
        modal.remove();
    }
}

function doDeleteGroups() {
    closeDeleteConfirmModal();
    var groups = [];
    pendingDeleteRows.forEach(function(row) {
        if (row.usedCount === 0) {
            groups.push(row.group);
        }
    });
    if (groups.length === 0) return;

    var form = document.createElement('form');
    form.method = 'post';
    form.action = '$scriptName';

    var actionInput = document.createElement('input');
    actionInput.type = 'hidden';
    actionInput.name = 'ACTION';
    actionInput.value = '$trRemove';
    form.appendChild(actionInput);

    var typInput = document.createElement('input');
    typInput.type = 'hidden';
    typInput.name = 'TYP';
    typInput.value = 'group';
    form.appendChild(typInput);

    var groupInput = document.createElement('input');
    groupInput.type = 'hidden';
    groupInput.name = 'GROUP';
    groupInput.value = groups.join(',');
    form.appendChild(groupInput);

    document.body.appendChild(form);
    form.submit();
}
</script>

<div id="addressGroupsTable"></div>

END

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

    # Validate that at least one address is selected
    unless ($cgiparams{'SELECTED_ADDRESSES'} ne '') {
        $errormessage .= "$Lang::tr{'invalid address'}<br />";
    }

    if ($cgiparams{'ENABLED'} ne 'on') {
        $cgiparams{'ENABLED'} = 'off';
    }
}
