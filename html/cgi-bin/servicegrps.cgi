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
# (c) 2017-2020, the Openfirewall Team
#

# Add entry in menu
# MENUTHRDLVL "alt services" 020 "service groups" "service groups"

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
        my $groupName = $cgiparams{'GROUP_NEW'};
        $serviceGroupConf{$groupName}{'USED_COUNT'} = 0;
        $serviceGroupConf{$groupName}{'REMARK'}     = $cgiparams{'REMARK'};
        $serviceGroupConf{$groupName}{'SERVICES'}   = [];

        # Process selected services (pipe-separated from dual-listbox)
        my %ofwSvcs = ();
        &DATA::readOfwServices(\%ofwSvcs);
        my %defSvcs = ();
        &DATA::readDefaultServices(\%defSvcs);

        if ($cgiparams{'SELECTED_SERVICES'} ne '') {
            my @svcs = split(/\|/, $cgiparams{'SELECTED_SERVICES'});
            my %seen;
            foreach my $svc (@svcs) {
                next if $svc eq '';
                next if $seen{$svc}++;
                my %entry = ();
                if (exists $ofwSvcs{$svc} || exists $defSvcs{$svc}) {
                    $entry{'SERVICE_TYP'}  = 'default';
                } else {
                    $entry{'SERVICE_TYP'}  = 'custom';
                    &FW::changeUsedCountService($svc, "add");
                }
                $entry{'SERVICE_NAME'} = $svc;
                $entry{'ENABLED'}      = 'on';
                push(@{$serviceGroupConf{$groupName}{'SERVICES'}}, \%entry);
                &General::log("$Lang::tr{'service added to group'}: $svc -> $groupName");
            }
        }

        &DATA::saveServiceGroupConf(\%serviceGroupConf);

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

        # Remove old custom service used counts
        foreach my $oldService (@{$serviceGroupConf{$groupOld}{'SERVICES'}}) {
            if ($oldService->{'SERVICE_TYP'} ne 'default') {
                &FW::changeUsedCountService($oldService->{'SERVICE_NAME'}, "remove");
            }
        }

        # Build new service list from SELECTED_SERVICES
        my @newServices = ();
        my %ofwSvcs = ();
        &DATA::readOfwServices(\%ofwSvcs);
        my %defSvcs = ();
        &DATA::readDefaultServices(\%defSvcs);

        if ($cgiparams{'SELECTED_SERVICES'} ne '') {
            my @svcs = split(/\|/, $cgiparams{'SELECTED_SERVICES'});
            my %seen;
            foreach my $svc (@svcs) {
                next if $svc eq '';
                next if $seen{$svc}++;
                my %entry = ();
                if (exists $ofwSvcs{$svc} || exists $defSvcs{$svc}) {
                    $entry{'SERVICE_TYP'}  = 'default';
                } else {
                    $entry{'SERVICE_TYP'}  = 'custom';
                    &FW::changeUsedCountService($svc, "add");
                }
                $entry{'SERVICE_NAME'} = $svc;
                $entry{'ENABLED'}      = 'on';
                push(@newServices, \%entry);
            }
        }

        # Update group
        $serviceGroupConf{$groupOld}{'REMARK'}   = $cgiparams{'REMARK'};
        $serviceGroupConf{$groupOld}{'SERVICES'} = \@newServices;

        # Rename group if name changed
        if ($group ne $groupOld) {
            $serviceGroupConf{$group}{'REMARK'}     = $serviceGroupConf{$groupOld}{'REMARK'};
            $serviceGroupConf{$group}{'USED_COUNT'} = $serviceGroupConf{$groupOld}{'USED_COUNT'};
            $serviceGroupConf{$group}{'SERVICES'}   = \@newServices;
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
        # Support batch delete: GROUP may contain multiple names joined by ','
        my @groupsToDelete = split(/,/, $group);
        foreach my $g (@groupsToDelete) {
            next unless defined $serviceGroupConf{$g}{'SERVICES'};
            foreach my $service (@{$serviceGroupConf{$g}{'SERVICES'}}) {
                if ($service->{'SERVICE_TYP'} ne 'default') {
                    &FW::changeUsedCountService($service->{'SERVICE_NAME'}, "remove");
                }
            }
            delete($serviceGroupConf{$g});
            &General::log("$Lang::tr{'service group deleted'}: $g");
        }
        &DATA::saveServiceGroupConf(\%serviceGroupConf);

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

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

# Prepare data for DataTable
my @jsData;
my $rowId = 0;
foreach my $group (sort keys %serviceGroupConf) {
    my $remark = defined($serviceGroupConf{$group}{'REMARK'}) ? $serviceGroupConf{$group}{'REMARK'} : '';
    my $serviceCount = scalar(@{$serviceGroupConf{$group}{'SERVICES'}});
    my $usedCount = $serviceGroupConf{$group}{'USED_COUNT'};
    
    # Build services list for edit modal
    my @serviceNames = ();
    foreach my $svc (@{$serviceGroupConf{$group}{'SERVICES'}}) {
        my $name = $svc->{'SERVICE_NAME'};
        $name =~ s/(['\\])/\\$1/g;
        push @serviceNames, $name;
    }
    my $servicesStr = join(',', @serviceNames);
    
    # Escape special characters for JavaScript
    $group =~ s/(['\\])/\\$1/g;
    $remark =~ s/(['\\])/\\$1/g;
    
    push @jsData, sprintf(
        "{id:'%d',group:'%s',remark:'%s',serviceCount:%d,usedCount:%d,services:'%s'}",
        $rowId, $group, $remark, $serviceCount, $usedCount, $servicesStr
    );
    $rowId++;
}
my $tableDataJs = join(",\n", @jsData);

# Build service group data for edit modal
my %serviceGroupData = ();
foreach my $group (keys %serviceGroupConf) {
    my @svcNames = ();
    foreach my $svc (@{$serviceGroupConf{$group}{'SERVICES'}}) {
        push @svcNames, $svc->{'SERVICE_NAME'};
    }
    $serviceGroupData{$group} = join(',', @svcNames);
}

my @sgEntries = ();
foreach my $group (keys %serviceGroupData) {
    my $jsGroup = $group;
    $jsGroup =~ s/'/\\'/g;
    my $jsSvcs = $serviceGroupData{$group};
    push @sgEntries, "'$jsGroup':'$jsSvcs'";
}
my $serviceGroupDataJs = "{" . join(',', @sgEntries) . "}";

# Prepare translation strings for JavaScript
my $trSequence = $Lang::tr{'sequence'};
my $trServiceGroupName = $Lang::tr{'service group name'};
my $trRemark = $Lang::tr{'remark'};
my $trServices = $Lang::tr{'services'};
my $trUsed = $Lang::tr{'used'};
my $trAddServiceToGroup = $Lang::tr{'add service to group'};
my $trAdd = $Lang::tr{'add'};
my $trServiceGroupNameLabel = $Lang::tr{'service group name'};
my $trRemarkLabel = $Lang::tr{'remark'};
my $trServiceType = $Lang::tr{'service type'};
my $trDefaultServices = $Lang::tr{'default services'};
my $trCustomServices = $Lang::tr{'custom services'};
my $trService = $Lang::tr{'service'};
my $trSelect = $Lang::tr{'select'};
my $trEnabled = $Lang::tr{'enabled'};
my $trCancel = $Lang::tr{'cancel'};
my $trUpdate = $Lang::tr{'update'};
my $trRemove = $Lang::tr{'remove'};
my $trEditServiceGroup = $Lang::tr{'edit service group'};
my $trEditServiceToGroup = $Lang::tr{'edit service to group'};
my $trAvailableServices = $Lang::tr{'available services'};
my $trSelectedServices = $Lang::tr{'selected services'};
my $trDeleteConfirm = $Lang::tr{'are you sure you want to delete this service group'};
my $trDeleteConfirmPlural = $Lang::tr{'are you sure you want to delete these service groups'};
my $scriptName = $ENV{'SCRIPT_NAME'};

print <<END;
<script src="/include/datatable.js"></script>
<script>
var serviceGroupData = $serviceGroupDataJs;
var tableData = [
$tableDataJs
];

document.addEventListener('DOMContentLoaded', function() {
    window.serviceGroupsTable = new DataTable('#serviceGroupsTable', {
        data: tableData,
        columns: [
            { key: 'id', title: '$trSequence', sortable: true },
            { key: 'group', title: '$trServiceGroupName', sortable: true },
            { key: 'remark', title: '$trRemark', sortable: true },
            { key: 'serviceCount', title: '$trServices', sortable: true },
            { key: 'usedCount', title: '$trUsed', sortable: true }
        ],
        selectable: true,
        actions: ['create', 'edit', 'delete', 'refresh'],
        onAddModal: function() {
            openAddServiceModal();
        },
        onEditModal: function(row) {
            openEditGroupModal(row);
        },
        onDeleteConfirm: function(selectedIds) {
            deleteGroups(selectedIds);
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

function openAddServiceModal() {
    // Prevent duplicate modals
    if (document.querySelector('#addServiceModal')) return;
    
    var modalHtml = '<div class="ofw_modal_overlay" id="addServiceModal">' +
        '<div class="ofw_modal_dialog" style="width:680px;">' +
        '<div class="ofw_modal_header" style="cursor:move;">' +
        '<span class="ofw_modal_title">$trAddServiceToGroup</span>' +
        '<button type="button" class="ofw_modal_close" onclick="closeAddServiceModal()">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' +
        '<form id="addServiceForm" method="post" action="$scriptName">' +
        '<input type="hidden" name="ACTION" value="$trAdd">' +
        '<input type="hidden" name="GROUP_TYP" value="new">' +
        '<table width="100%" cellpadding="5" cellspacing="0" border="0">' +
        '<tr>' +
        '<td width="30%" align="right">$trServiceGroupNameLabel</td>' +
        '<td><input type="text" name="GROUP_NEW" style="width:300px;" maxlength="18" required></td>' +
        '</tr>' +
        '<tr>' +
        '<td align="right">$trRemarkLabel</td>' +
        '<td><input type="text" name="REMARK" style="width:300px;" maxlength="50"></td>' +
        '</tr>' +
        '<tr>' +
        '<td align="right" valign="top">$trServices</td>' +
        '<td>' +
        '<div style="display:flex;gap:10px;align-items:center;">' +
        '<div style="flex:1;display:flex;flex-direction:column;">' +
        '<div style="margin-bottom:5px;font-weight:bold;">$trAvailableServices</div>' +
        '<select id="availableServiceSelect" multiple size="8" style="width:100%;min-height:160px;">';
END

# Build combined list of all services
my %allServicesMap = ();
foreach my $svc (@customServices) {
    $allServicesMap{$svc} = 'custom';
}
my %ofwServices = ();
&DATA::readOfwServices(\%ofwServices);
foreach my $svc (keys %ofwServices) {
    $allServicesMap{$svc} = 'default';
}
my %defaultServices = ();
&DATA::readDefaultServices(\%defaultServices);
foreach my $svc (keys %defaultServices) {
    $allServicesMap{$svc} = 'default';
}

# Output default services group
print "modalHtml += '<optgroup label=\\\"$trDefaultServices\\\">';\n";
foreach my $svc (sort keys %allServicesMap) {
    next unless $allServicesMap{$svc} eq 'default';
    my $label = $svc;
    if (exists $ofwServices{$svc}) {
        $label .= " ($ofwServices{$svc}{'PORT_NR'})";
    } elsif (exists $defaultServices{$svc}) {
        $label .= " ($defaultServices{$svc}{'PORT_NR'})";
    }
    my $jsLabel = $label;
    $jsLabel =~ s/'/\\'/g;
    my $jsSvc = $svc;
    $jsSvc =~ s/'/\\'/g;
    print "modalHtml += '<option value=\\\"$jsSvc\\\">$jsLabel</option>';\n";
}
print "modalHtml += '</optgroup>';\n";
# Output custom services group
print "modalHtml += '<optgroup label=\\\"$trCustomServices\\\">';\n";
foreach my $svc (sort keys %allServicesMap) {
    next unless $allServicesMap{$svc} eq 'custom';
    my $label = $svc;
    my $jsLabel = $label;
    $jsLabel =~ s/'/\\'/g;
    my $jsSvc = $svc;
    $jsSvc =~ s/'/\\'/g;
    print "modalHtml += '<option value=\\\"$jsSvc\\\">$jsLabel</option>';\n";
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
        '<div style="margin-bottom:5px;font-weight:bold;">$trSelectedServices</div>' +
        '<select id="selectedServiceSelect" multiple size="8" style="width:100%;min-height:160px;"></select>' +
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
        '<button type="button" class="ofw_btn" onclick="closeAddServiceModal()">$trCancel</button>' +
        '<button type="button" class="ofw_btn ofw_btn_primary" onclick="submitAddServiceForm()">$trAdd</button>' +
        '</div>' +
        '</div>' +
        '</div>';
    
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    makeModalDraggable('addServiceModal');
}

function closeAddServiceModal() {
    var modal = document.getElementById('addServiceModal');
    if (modal) {
        modal.remove();
    }
}

function moveSelectedToRight() {
    var available = document.getElementById('availableServiceSelect');
    var selected = document.getElementById('selectedServiceSelect');
    var options = Array.from(available.selectedOptions);
    for (var i = 0; i < options.length; i++) {
        selected.appendChild(options[i]);
    }
}

function moveSelectedToLeft() {
    var available = document.getElementById('availableServiceSelect');
    var selected = document.getElementById('selectedServiceSelect');
    var options = Array.from(selected.selectedOptions);
    for (var i = 0; i < options.length; i++) {
        available.appendChild(options[i]);
    }
}

function submitAddServiceForm() {
    var form = document.getElementById('addServiceForm');
    // Collect selected services into hidden field
    var selected = document.getElementById('selectedServiceSelect');
    var values = [];
    for (var i = 0; i < selected.options.length; i++) {
        values.push(selected.options[i].value);
    }
    // Remove old hidden field if exists
    var oldHidden = document.getElementById('selectedServicesHidden');
    if (oldHidden) oldHidden.remove();
    var hidden = document.createElement('input');
    hidden.type = 'hidden';
    hidden.name = 'SELECTED_SERVICES';
    hidden.id = 'selectedServicesHidden';
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
        '<span class="ofw_modal_title">$trEditServiceToGroup</span>' +
        '<button type="button" class="ofw_modal_close" onclick="closeEditGroupModal()">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' +
        '<form id="editGroupForm" method="post" action="$scriptName">' +
        '<input type="hidden" name="ACTION" value="$trUpdate">' +
        '<input type="hidden" name="GROUP_TYP" value="new">' +
        '<input type="hidden" name="OLD_GROUP" value="' + row.group + '">' +
        '<table width="100%" cellpadding="5" cellspacing="0" border="0">' +
        '<tr>' +
        '<td width="30%" align="right">$trServiceGroupNameLabel</td>' +
        '<td><input type="text" name="GROUP_NEW" value="' + row.group + '" style="width:300px;" maxlength="18" required></td>' +
        '</tr>' +
        '<tr>' +
        '<td align="right">$trRemarkLabel</td>' +
        '<td><input type="text" name="REMARK" value="' + row.remark + '" style="width:300px;" maxlength="50"></td>' +
        '</tr>' +
        '<tr>' +
        '<td align="right" valign="top">$trServices</td>' +
        '<td>' +
        '<div style="display:flex;gap:10px;align-items:center;">' +
        '<div style="flex:1;display:flex;flex-direction:column;">' +
        '<div style="margin-bottom:5px;font-weight:bold;">$trAvailableServices</div>' +
        '<select id="availableServiceSelectEdit" multiple size="8" style="width:100%;min-height:160px;">';
END

# Build combined list of all services for edit modal
my %allServicesMapEdit = ();
foreach my $svc (@customServices) {
    $allServicesMapEdit{$svc} = 'custom';
}
my %ofwServicesEdit = ();
&DATA::readOfwServices(\%ofwServicesEdit);
foreach my $svc (keys %ofwServicesEdit) {
    $allServicesMapEdit{$svc} = 'default';
}
my %defaultServicesEdit = ();
&DATA::readDefaultServices(\%defaultServicesEdit);
foreach my $svc (keys %defaultServicesEdit) {
    $allServicesMapEdit{$svc} = 'default';
}

# Output default services group
print "modalHtml += '<optgroup label=\\\"$trDefaultServices\\\">';\n";
foreach my $svc (sort keys %allServicesMapEdit) {
    next unless $allServicesMapEdit{$svc} eq 'default';
    my $label = $svc;
    if (exists $ofwServicesEdit{$svc}) {
        $label .= " ($ofwServicesEdit{$svc}{'PORT_NR'})";
    } elsif (exists $defaultServicesEdit{$svc}) {
        $label .= " ($defaultServicesEdit{$svc}{'PORT_NR'})";
    }
    my $jsLabel = $label;
    $jsLabel =~ s/'/\\'/g;
    my $jsSvc = $svc;
    $jsSvc =~ s/'/\\'/g;
    print "modalHtml += '<option value=\\\"$jsSvc\\\">$jsLabel</option>';\n";
}
print "modalHtml += '</optgroup>';\n";
# Output custom services group
print "modalHtml += '<optgroup label=\\\"$trCustomServices\\\">';\n";
foreach my $svc (sort keys %allServicesMapEdit) {
    next unless $allServicesMapEdit{$svc} eq 'custom';
    my $label = $svc;
    my $jsLabel = $label;
    $jsLabel =~ s/'/\\'/g;
    my $jsSvc = $svc;
    $jsSvc =~ s/'/\\'/g;
    print "modalHtml += '<option value=\\\"$jsSvc\\\">$jsLabel</option>';\n";
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
        '<div style="margin-bottom:5px;font-weight:bold;">$trSelectedServices</div>' +
        '<select id="selectedServiceSelectEdit" multiple size="8" style="width:100%;min-height:160px;"></select>' +
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
    
    // Pre-fill selected services from row data
    setTimeout(function() {
        var services = (row.services || '').split(',');
        var available = document.getElementById('availableServiceSelectEdit');
        var selected = document.getElementById('selectedServiceSelectEdit');
        
        for (var i = 0; i < services.length; i++) {
            var svcName = services[i].trim();
            if (!svcName) continue;
            
            // Find and move option from available to selected
            for (var j = 0; j < available.options.length; j++) {
                if (available.options[j].value === svcName) {
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
    var available = document.getElementById('availableServiceSelectEdit');
    var selected = document.getElementById('selectedServiceSelectEdit');
    var options = Array.from(available.selectedOptions);
    for (var i = 0; i < options.length; i++) {
        selected.appendChild(options[i]);
    }
}

function moveSelectedToLeftEdit() {
    var available = document.getElementById('availableServiceSelectEdit');
    var selected = document.getElementById('selectedServiceSelectEdit');
    var options = Array.from(selected.selectedOptions);
    for (var i = 0; i < options.length; i++) {
        available.appendChild(options[i]);
    }
}

function submitEditGroupForm() {
    var form = document.getElementById('editGroupForm');
    var selected = document.getElementById('selectedServiceSelectEdit');
    var values = [];
    for (var i = 0; i < selected.options.length; i++) {
        values.push(selected.options[i].value);
    }
    var oldHidden = document.getElementById('selectedServicesHiddenEdit');
    if (oldHidden) oldHidden.remove();
    var hidden = document.createElement('input');
    hidden.type = 'hidden';
    hidden.name = 'SELECTED_SERVICES';
    hidden.id = 'selectedServicesHiddenEdit';
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

<div id="serviceGroupsTable"></div>

END

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

    # Validate that at least one service is selected
    unless ($cgiparams{'SELECTED_SERVICES'} ne '') {
        $errormessage .= "$Lang::tr{'invalid service'}<br />";
    }

    if ($cgiparams{'ENABLED'} ne 'on') {
        $cgiparams{'ENABLED'} = 'off';
    }
}
