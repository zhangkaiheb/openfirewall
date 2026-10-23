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
# MENUTHRDLVL "addresses" 010 "addresses" "addresses"
#
# Make sure translation exists $Lang::tr{'addresses'}

use strict;

# enable only the following on debugging purpose
use warnings;
no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';

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

my %custAddresses = ();
&DATA::readCustAddresses(\%custAddresses);

$cgiparams{'ADR_NAME'}     = '';
$cgiparams{'ADDRESS_TXT'}  = '';
$cgiparams{'NETMASK'}      = '';
$cgiparams{'ADDRESS_TYPE'} = 'ip';
&General::getcgihash(\%cgiparams);

$cgiparams{'ADR_NAME'} = &Header::cleanConfNames($cgiparams{'ADR_NAME'});

# Handle POST actions before sending HTTP headers (redirect must come before any output)
my $redirectAfterPost = 0;

if ($cgiparams{'ACTION'} eq $Lang::tr{'add'}) {
    &validateAddressParams(\%custAddresses);

    unless ($errormessage) {
        $custAddresses{$cgiparams{'ADR_NAME'}}{'ADDRESS_TYPE'} = $cgiparams{'ADDRESS_TYPE'};
        $custAddresses{$cgiparams{'ADR_NAME'}}{'ADDRESS'}      = $cgiparams{'ADDRESS_TXT'};
        $custAddresses{$cgiparams{'ADR_NAME'}}{'NETMASK'}      = $cgiparams{'NETMASK'};
        $custAddresses{$cgiparams{'ADR_NAME'}}{'USED_COUNT'}   = 0;

        &DATA::saveCustAddresses(\%custAddresses);

        &General::log("$Lang::tr{'address added'}: $cgiparams{'ADR_NAME'}");
        $redirectAfterPost = 1;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'update'} && !$redirectAfterPost) {
    &validateAddressParams(\%custAddresses);

    if ($errormessage) {
        $cgiparams{'ACTION'} = $Lang::tr{'edit'};
    }
    else {
        my $adrName    = $cgiparams{'ADR_NAME'};
        my $adrNameOld = $cgiparams{'OLD_ADR_NAME'};
        $custAddresses{$adrNameOld}{'ADDRESS_TYPE'} = $cgiparams{'ADDRESS_TYPE'};
        $custAddresses{$adrNameOld}{'ADDRESS'}      = $cgiparams{'ADDRESS_TXT'};
        $custAddresses{$adrNameOld}{'NETMASK'}      = $cgiparams{'NETMASK'};

        # if the name (==Key) has changed, we have to copy/move the old data to new key
        if ($adrName ne $adrNameOld) {
            $custAddresses{$adrName}{'ADDRESS_TYPE'} = $custAddresses{$adrNameOld}{'ADDRESS_TYPE'};
            $custAddresses{$adrName}{'ADDRESS'}      = $custAddresses{$adrNameOld}{'ADDRESS'};
            $custAddresses{$adrName}{'NETMASK'}      = $custAddresses{$adrNameOld}{'NETMASK'};
            $custAddresses{$adrName}{'USED_COUNT'}   = $custAddresses{$adrNameOld}{'USED_COUNT'};

            delete($custAddresses{$adrNameOld});
        }
        &DATA::saveCustAddresses(\%custAddresses);

        &General::log("$Lang::tr{'address updated'}: $cgiparams{'ADR_NAME'}");
        $redirectAfterPost = 1;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'} && !$redirectAfterPost) {
    # Support batch delete: ADR_NAME may contain multiple names joined by ','
    my @addressesToDelete = split(/,/, $cgiparams{'ADR_NAME'});
    foreach my $adrName (@addressesToDelete) {
        delete($custAddresses{$adrName});
        &General::log("$Lang::tr{'address removed'}: $adrName");
    }

    &DATA::saveCustAddresses(\%custAddresses);
    $redirectAfterPost = 1;
}

if ($redirectAfterPost) {
    &Header::showhttpheaders();
    print "Location: $ENV{'SCRIPT_NAME'}\n\n";
    exit;
}

&Header::showhttpheaders();

if ($cgiparams{'ACTION'} eq $Lang::tr{'reset'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

if ($cgiparams{'ACTION'} eq '') {
    $cgiparams{'ADDRESS_TXT'}  = '';
    $cgiparams{'NETMASK'}      = '';
    $cgiparams{'ADR_NAME'}     = '';
    $cgiparams{'ADDRESS_TYPE'} = 'ip';
}

&Header::openpage($Lang::tr{'address settings'}, 1, '');

&Header::openbigbox('100%', 'left');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

# Convert addresses to JavaScript format
my @jsData;
my @sortedKeys = sort keys %custAddresses;
foreach my $adrName (@sortedKeys) {
    my $addr = $custAddresses{$adrName};

    # Escape special characters for JavaScript
    my $jsName = $adrName;
    $jsName =~ s/(['\\])/\\$1/g;
    my $jsAddress = $addr->{'ADDRESS'};
    $jsAddress =~ s/(['\\])/\\$1/g;
    my $jsNetmask = $addr->{'NETMASK'};
    $jsNetmask =~ s/(['\\])/\\$1/g;

    push @jsData, sprintf(
        "{id:'%s',name:'%s',addressType:'%s',address:'%s',netmask:'%s',usedCount:%d}",
        $jsName, $jsName, $addr->{'ADDRESS_TYPE'}, $jsAddress, $jsNetmask, $addr->{'USED_COUNT'}
    );
}
my $jsDataStr = join(",\n", @jsData);

# Prepare translation strings for JavaScript
my $trSequence = $Lang::tr{'sequence'};
my $trName = $Lang::tr{'name'};
my $trAddressType = $Lang::tr{'addressformat'};
my $trAddress = $Lang::tr{'address'};
my $trNetmask = $Lang::tr{'netmask'};
my $trUsed = $Lang::tr{'used'};
my $trAddAddress = $Lang::tr{'add address'};
my $trEditAddress = $Lang::tr{'edit address'};
my $trAddressName = $Lang::tr{'name'};
my $trAddressFormat = $Lang::tr{'addressformat'};
my $trNetmaskLabel = $Lang::tr{'netmask'};
my $trCancel = $Lang::tr{'cancel'};
my $trUpdate = $Lang::tr{'update'};
my $trRemove = $Lang::tr{'remove'};
my $trAdd = $Lang::tr{'add'};
my $trDeleteConfirm = $Lang::tr{'are you sure you want to delete this address'};
my $trDeleteConfirmPlural = $Lang::tr{'are you sure you want to delete these addresses'};
my $scriptName = $ENV{'SCRIPT_NAME'};

print <<END;
<script src="/include/datatable.js"></script>
<script>
var tableData = [
$jsDataStr
];

document.addEventListener('DOMContentLoaded', function() {
    window.addressesTable = new DataTable('#addressesTable', {
        data: tableData,
        columns: [
            { key: 'id', title: '$trSequence', sortable: true },
            { key: 'name', title: '$trName', sortable: true },
            { key: 'addressType', title: '$trAddressType', sortable: true },
            { key: 'address', title: '$trAddress', sortable: true },
            { key: 'netmask', title: '$trNetmask', sortable: true },
            { key: 'usedCount', title: '$trUsed', sortable: true }
        ],
        selectable: true,
        actions: ['create', 'edit', 'delete', 'refresh'],
        onAddModal: function() {
            openAddAddressModal();
        },
        onEditModal: function(row) {
            openEditAddressModal(row);
        },
        onDeleteConfirm: function(selectedRows) {
            deleteAddresses(selectedRows);
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
        '<div class="ofw_modal_dialog" style="width:500px;">' +
        '<div class="ofw_modal_header" style="cursor:move;">' +
        '<span class="ofw_modal_title">$trAddAddress</span>' +
        '<button type="button" class="ofw_modal_close" onclick="closeAddAddressModal()">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' +
        '<form id="addAddressForm" method="post" action="$scriptName">' +
        '<input type="hidden" name="ACTION" value="$trAdd">' +
        '<table style="width:100%;border-collapse:collapse;">' +
        '<tr>' +
        '<td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>$trAddressName:</label></td>' +
        '<td><input type="text" name="ADR_NAME" style="width:200px;" required maxlength="20"></td>' +
        '</tr>' +
        '<tr>' +
        '<td style="padding:8px 12px 8px 0;text-align:right;"><label>$trAddressFormat:</label></td>' +
        '<td>' +
        '<select name="ADDRESS_TYPE" style="width:200px;">' +
        '<option value="ip" selected>IP</option>' +
        '<option value="mac">MAC</option>' +
        '</select>' +
        '</td>' +
        '</tr>' +
        '<tr>' +
        '<td style="padding:8px 12px 8px 0;text-align:right;"><label>$trAddress:</label></td>' +
        '<td><input type="text" name="ADDRESS_TXT" style="width:200px;" maxlength="17"></td>' +
        '</tr>' +
        '<tr>' +
        '<td style="padding:8px 12px 8px 0;text-align:right;"><label>$trNetmaskLabel:</label></td>' +
        '<td><input type="text" name="NETMASK" style="width:200px;" maxlength="15"></td>' +
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

function submitAddAddressForm() {
    var form = document.getElementById('addAddressForm');
    if (!form.checkValidity()) {
        form.reportValidity();
        return;
    }
    var formData = new FormData(form);
    fetch('$scriptName', {
        method: 'POST',
        body: formData
    }).then(function() {
        window.location.href = '$scriptName';
    }).catch(function(error) {
        alert('Error: ' + error.message);
    });
}

function openEditAddressModal(row) {
    // Prevent duplicate modals
    if (document.querySelector('#editAddressModal')) return;

    var modalHtml = '<div class="ofw_modal_overlay" id="editAddressModal">' +
        '<div class="ofw_modal_dialog" style="width:500px;">' +
        '<div class="ofw_modal_header" style="cursor:move;">' +
        '<span class="ofw_modal_title">$trEditAddress</span>' +
        '<button type="button" class="ofw_modal_close" onclick="closeEditAddressModal()">&times;</button>' +
        '</div>' +
        '<div class="ofw_modal_body">' +
        '<form id="editAddressForm" method="post" action="$scriptName">' +
        '<input type="hidden" name="ACTION" value="$trUpdate">' +
        '<input type="hidden" name="OLD_ADR_NAME" value="' + row.id + '">' +
        '<table style="width:100%;border-collapse:collapse;">' +
        '<tr>' +
        '<td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>$trAddressName:</label></td>' +
        '<td><input type="text" name="ADR_NAME" value="' + row.name + '" style="width:200px;" required maxlength="20"></td>' +
        '</tr>' +
        '<tr>' +
        '<td style="padding:8px 12px 8px 0;text-align:right;"><label>$trAddressFormat:</label></td>' +
        '<td>' +
        '<select name="ADDRESS_TYPE" style="width:200px;">' +
        '<option value="ip"' + (row.addressType === 'ip' ? ' selected' : '') + '>IP</option>' +
        '<option value="mac"' + (row.addressType === 'mac' ? ' selected' : '') + '>MAC</option>' +
        '</select>' +
        '</td>' +
        '</tr>' +
        '<tr>' +
        '<td style="padding:8px 12px 8px 0;text-align:right;"><label>$trAddress:</label></td>' +
        '<td><input type="text" name="ADDRESS_TXT" value="' + row.address + '" style="width:200px;" maxlength="17"></td>' +
        '</tr>' +
        '<tr>' +
        '<td style="padding:8px 12px 8px 0;text-align:right;"><label>$trNetmaskLabel:</label></td>' +
        '<td><input type="text" name="NETMASK" value="' + row.netmask + '" style="width:200px;" maxlength="15"></td>' +
        '</tr>' +
        '</table>' +
        '</form>' +
        '</div>' +
        '<div class="ofw_modal_footer">' +
        '<button type="button" class="ofw_btn" onclick="closeEditAddressModal()">$trCancel</button>' +
        '<button type="button" class="ofw_btn ofw_btn_primary" onclick="submitEditAddressForm()">$trUpdate</button>' +
        '</div>' +
        '</div>' +
        '</div>';

    document.body.insertAdjacentHTML('beforeend', modalHtml);
    makeModalDraggable('editAddressModal');
}

function closeEditAddressModal() {
    var modal = document.getElementById('editAddressModal');
    if (modal) {
        modal.remove();
    }
}

function submitEditAddressForm() {
    var form = document.getElementById('editAddressForm');
    if (!form.checkValidity()) {
        form.reportValidity();
        return;
    }
    var formData = new FormData(form);
    fetch('$scriptName', {
        method: 'POST',
        body: formData
    }).then(function() {
        window.location.href = '$scriptName';
    }).catch(function(error) {
        alert('Error: ' + error.message);
    });
}

var pendingDeleteRows = [];

function deleteAddresses(selectedRows) {
    if (!selectedRows || selectedRows.length === 0) return;

    // Prevent duplicate modals
    if (document.querySelector('#deleteConfirmModal')) return;

    var confirmMsg = selectedRows.length === 1 ?
        '$trDeleteConfirm' :
        '$trDeleteConfirmPlural';

    // Build list of address names to display
    var listHtml = '<ul style="margin:0;padding-left:20px;">';
    selectedRows.forEach(function(row) {
        listHtml += '<li>' + row.name + '</li>';
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
        '<button type="button" class="ofw_btn ofw_btn_primary" onclick="doDeleteAddresses()">OK</button>' +
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

function doDeleteAddresses() {
    closeDeleteConfirmModal();
    var addresses = [];
    pendingDeleteRows.forEach(function(row) {
        if (row.usedCount === 0) {
            addresses.push(row.name);
        }
    });
    if (addresses.length === 0) return;

    var formData = new FormData();
    formData.append('ACTION', '$trRemove');
    formData.append('ADR_NAME', addresses.join(','));

    fetch('$scriptName', {
        method: 'POST',
        body: formData
    }).then(function() {
        window.location.href = '$scriptName';
    }).catch(function(error) {
        alert('Error: ' + error.message);
    });
}
</script>

<div id="addressesTable"></div>

END

&Header::closebigbox();
&Header::closepage();

# Validate Field Entries
sub validateAddressParams {
    my $addressesRef = shift;

    if ($cgiparams{'ADR_NAME'} eq '') {
        $errormessage = $Lang::tr{'nonetworkname'};
        return;
    }

    # Strip out commas which will break CSV config file.
    $cgiparams{'ADR_NAME'} = &Header::cleanhtml($cgiparams{'ADR_NAME'});

    my $usedAsDest = &DATA::isUsedAsDestAdr($cgiparams{'ADR_NAME'});

    if ($cgiparams{'ADDRESS_TYPE'} eq 'ip') {
        unless (&General::validip($cgiparams{'ADDRESS_TXT'})) {
            $errormessage .= "$Lang::tr{'invalid ip'} <br />";
        }
        unless ($errormessage) {
            my @tmp = split(/\./, $cgiparams{'ADDRESS_TXT'});
            if ($cgiparams{'NETMASK'} eq '' && $tmp[3] ne '255' && $tmp[3] ne '0') {
                $cgiparams{'NETMASK'} = "255.255.255.255";
            }
        }
        unless (&General::validmask($cgiparams{'NETMASK'})) {
            $errormessage .= "$Lang::tr{'invalid netmask'} <br />";
        }

        # check if it is used in portforwardiing
        if($usedAsDest == 2) {
            if($cgiparams{'NETMASK'} ne '32' && $cgiparams{'NETMASK'} ne '255.255.255.255') {
                $errormessage .= "$Lang::tr{'adr is used in portfw'}:<br />";
                $errormessage .= "$Lang::tr{'only host ip adr allowed in portfw'}<br />";
            }
        }
    }
    elsif ($cgiparams{'ADDRESS_TYPE'} eq 'mac') {

        # change '-' in mac to ':'
        $cgiparams{'ADDRESS_TXT'} =~ s/-/:/g;

        unless (&General::validmac($cgiparams{'ADDRESS_TXT'})) {
            $errormessage .= "$Lang::tr{'invalid mac'} <br />";
        }

        # check if it is used as destination
        if($usedAsDest == 1) {
           $errormessage .= "$Lang::tr{'adr is used as dest'}:<br />";
           $errormessage .= "$Lang::tr{'mac adr not as dest'}<br />";
        }

        # we don't need a mask when MAC is selected
        $cgiparams{'NETMASK'} = '';
    }
    else {
        $errormessage .= "$Lang::tr{'none address type'} <br />";
    }

    # a new address has to have a different name
    if (defined($addressesRef->{$cgiparams{'ADR_NAME'}})) {

        # when this is an update, the old name is allowed
        unless ($cgiparams{'ACTION'} eq $Lang::tr{'update'}
            && $cgiparams{'ADR_NAME'} eq $cgiparams{'OLD_ADR_NAME'})
        {
            $errormessage .= "$Lang::tr{'duplicate name'} <br />";
        }
    }
}
