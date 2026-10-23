#!/usr/bin/perl
#
# This code is distributed under the terms of the GPL
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
# MENUTHRDLVL "neigh table" 010 "static neigh table" "static neigh table"
#
# Make sure translation exists $Lang::tr{'static neigh table'}

use strict;

# enable only the following on debugging purpose
use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';

our $custNeighboursFile = "/var/ofw/ethernet/customNeighbours";

my $output='';
&Header::showhttpheaders();

my %cgiparams    = ();
my $errormessage = '';
my $error        = '';
$cgiparams{'ACTION'}     = '';
$cgiparams{'NEIGH_ID'}     = 0;
$cgiparams{'STATUS'} = 0;
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

my @custNeighbours = ();
&readCustNeighbours(\@custNeighbours);

$cgiparams{'IP'}       = '';
$cgiparams{'IF_NAME'}  = '';
$cgiparams{'MAC_ADDRESS'} = '';
$cgiparams{'STATUS'}   = 0;
$cgiparams{'ACTION'}   = '';
$cgiparams{'NEIGH_ID'} = 0;
&General::getcgihash(\%cgiparams);

if ($cgiparams{'ACTION'} eq $Lang::tr{'add'}) {
    &validateNeighbourParams(\@custNeighbours);

    unless ($errormessage) {
        my $neighbour = $cgiparams{'IP'}.",".$cgiparams{'IF_NAME'}.",".$cgiparams{'MAC_ADDRESS'}.",".$cgiparams{'STATUS'};

        # Add to system neigh table (no nud parameter - defaults to PERMANENT)
        my $cmd = "/sbin/ip neigh add $cgiparams{'IP'} dev $cgiparams{'IF_NAME'} lladdr $cgiparams{'MAC_ADDRESS'} 2>&1";
        my $output = `$cmd`;
        my $res = $? >> 8;
        if ($res != 0) {
            $errormessage = "Failed to add neigh entry: $output";
            return;
        }

        push(@custNeighbours, $neighbour);
        &saveCustNeighbours(\@custNeighbours);

        &General::log("$Lang::tr{'neighbour added'}: $cgiparams{'IP'} $cgiparams{'MAC_ADDRESS'}");
        print "Location: $ENV{'SCRIPT_NAME'}\n\n";
        exit;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'update'}) {
    &validateNeighbourParams(\@custNeighbours);
    if ($errormessage) {
        $cgiparams{'ACTION'} = $Lang::tr{'edit'};
    } else {
        my $neighbour = $cgiparams{'IP'}.",".$cgiparams{'IF_NAME'}.",".$cgiparams{'MAC_ADDRESS'}.",".$cgiparams{'STATUS'};

        # Update system neigh table (no nud parameter - defaults to PERMANENT)
        system("/sbin/ip neigh change $cgiparams{'IP'} dev $cgiparams{'IF_NAME'} lladdr $cgiparams{'MAC_ADDRESS'} 2>/dev/null");

        $custNeighbours[$cgiparams{NEIGH_ID}] = $neighbour;
        &saveCustNeighbours(\@custNeighbours);

        &General::log("$Lang::tr{'neighbour updated'}: $cgiparams{'IP'} $cgiparams{'MAC_ADDRESS'}");
        print "Location: $ENV{'SCRIPT_NAME'}\n\n";
        exit;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
    # on an update error we use the entered data, we do not re-read from stored config
    unless ($errormessage) {
        if (defined($custNeighbours[$cgiparams{'NEIGH_ID'}])) {
            my $tmpline = $custNeighbours[$cgiparams{'NEIGH_ID'}];
            chomp($tmpline);
            my @tmp = split(/\,/, $tmpline);

            $cgiparams{'IP'} = $tmp[0];
            $cgiparams{'IF_NAME'} = $tmp[1];
            $cgiparams{'MAC_ADDRESS'} = $tmp[2];
            $cgiparams{'STATUS'} = $tmp[3];
        }
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    # Support batch delete: NEIGH_ID may contain multiple IDs joined by ','
    my @neighIds = split(/,/, $cgiparams{'NEIGH_ID'});
    # Sort in descending order to delete from end first (preserves indices)
    @neighIds = sort { $b <=> $a } @neighIds;
    foreach my $nid (@neighIds) {
        next unless defined($custNeighbours[$nid]);
        my $tmpline = $custNeighbours[$nid];
        chomp($tmpline);
        my @tmp = split(/\,/, $tmpline);
        my $neighbour = $tmp[0].",".$tmp[1].",".$tmp[2].",".$tmp[3];

        # Delete from system neigh table
        system("/sbin/ip neigh del $tmp[0] dev $tmp[1] 2>/dev/null");

        splice(@custNeighbours, $nid, 1);
        &General::log("$Lang::tr{'neighbour removed'}: $neighbour");
    }
    &saveCustNeighbours(\@custNeighbours);
    print "Location: $ENV{'SCRIPT_NAME'}\n\n";
    exit;
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'reset'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}



&Header::openpage($Lang::tr{'network status information'}, 1, '');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

my %selected = ();

my $disabled        = '';
my $hiddenIfaceName = '';

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} || $cgiparams{'ACTION'} eq $Lang::tr{'add neigh'}) {
    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        if ($cgiparams{'USED_COUNT'} > 0) {
            $disabled        = "disabled='disabled'";
            $hiddenIfaceName = "<input type='hidden' name='IFACE_NAME' value='$cgiparams{'IFACE_NAME'}' />";
        }
    }

    print <<END;
<table width='100%' height='33px' bgcolor='#69C'>
<tr align='center'>
    <td><strong>$cgiparams{'ACTION'}</strong></td>
</tr>
</table>
END

    print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<div align='center'>
<table width='100%'>
<tr>
    <td width='1%'></td>
    <td width='25%'>$Lang::tr{'ip address'}</td>
    <td width='25%'>
        <input type='text' name='IP' value='$cgiparams{'IP'}' size='20' maxlength='20' $disabled />
        $hiddenIfaceName
    </td>
    <td width='49%'></td>
</tr><tr>
    <td width='1%'></td>
    <td width='25%'>$Lang::tr{'mac address'}</td>
    <td width='25%'>
        <input type='text' name='MAC_ADDRESS' value='$cgiparams{'MAC_ADDRESS'}' size='20' maxlength='20' $disabled />
        $hiddenIfaceName
    </td>
    <td width='49%'></td>
</tr><tr>
    <td width='1%'></td>
    <td width='25%'>$Lang::tr{'interface'}</td>
    <td width='25%'>
        <select name='IF_NAME'>
END

foreach my $iface (sort keys %FW::interfaces) {
##    print "<option value='ip' $selected{'IFACE'}{$iface}>$iface</option>";
    print "<option value=$FW::interfaces{$iface}{'IFACE'} $selected{'IFACE'}{$FW::interfaces{$iface}{'IFACE'}}>$FW::interfaces{$iface}{'IFACE'}</option>";
}
print <<END;
        </select>
    </td>
</tr>
</table>
<hr />
<table width='100%'>
<tr><td width='5%'></td>
<td>
<div class='footerbuttons'>
END
    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        print "<input type='submit' class='footbutton' name='ACTION' value='$Lang::tr{'update'}' />\n";
        print "<input type='hidden' name='STATUS' value='$cgiparams{'STATUS'}' />\n";
    } else {
        print "<input type='submit' class='footbutton' name='ACTION' value='$Lang::tr{'add'}' />\n";
        print "<input type='hidden' name='STATUS' value='$cgiparams{'STATUS'}' />\n";
    }
    print <<END;
        &nbsp&nbsp
        <input type='submit' class='footbutton' name='ACTION' value='$Lang::tr{'cancel'}' />
</div>
</td>
    <td  class='onlinehelp'>
        <a href='${General::adminmanualurl}/firewall-interfaces.html#section' target='_blank'><img src='/images/web-support.png    ' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
</td>
</table>
</div>
</form>
END

#    &Header::closebox();
} else {

#######################################################################################
#  static neigh list - DataTable version
#######################################################################################

    # Convert neighbours data to JavaScript format
    my @jsData;
    my $id = 0;
    foreach my $tmpline (@custNeighbours) {
        chomp($tmpline);
        my @tmp = split(/\,/, $tmpline);
        my $ip = $tmp[0];
        my $iface = $tmp[1];
        my $mac = $tmp[2];
        my $status = $tmp[3] || '0';
        
        push @jsData, sprintf(
            "{id:'%d',ip:'%s',iface:'%s',mac:'%s',status:'%s'}",
            $id, $ip, $iface, $mac, $status
        );
        $id++;
    }
    my $jsDataStr = join(",\n", @jsData);
    
    # Get available interfaces for the modal - pre-build HTML options
    my @ifaceOptions;
    foreach my $iface (sort keys %FW::interfaces) {
        my $ifaceName = $FW::interfaces{$iface}{'IFACE'};
        push @ifaceOptions, "<option value=\"$ifaceName\">$ifaceName</option>";
    }
    my $ifaceOptionsStr = join('', @ifaceOptions);
    
    my $jsAddAction = $Lang::tr{'add'};
    my $jsUpdateAction = $Lang::tr{'update'};
    my $jsRemoveAction = $Lang::tr{'remove'};
    
    # Status options
    my $statusOptionsStr = '<option value="0">PERMANENT</option><option value="1">NOARP</option>';

    print <<END;
<script src="/include/datatable.js"></script>
<style>
.ofw_modal_overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.5);
    z-index: 9998;
}
.ofw_modal_dialog {
    position: fixed;
    background: #fff;
    border-radius: 4px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    min-width: 400px;
    z-index: 9999;
}
.ofw_modal_header {
    background: #5B9BD5;
    color: #fff;
    padding: 4px 16px;
    display: flex;
    justify-content: flex-start;
    align-items: center;
    cursor: move;
    user-select: none;
    border-radius: 4px 4px 0 0;
}
.ofw_modal_title {
    font-weight: bold;
    font-size: 14px;
}
.ofw_modal_close {
    cursor: pointer;
    font-size: 18px;
    line-height: 1;
    padding: 0 5px;
}
.ofw_modal_close:hover {
    color: #ff0;
}
.ofw_modal_body {
    padding: 20px;
}
.ofw_modal_footer {
    padding: 12px 15px;
    text-align: right;
    border-top: 1px solid #ddd;
    background: #f5f5f5;
    border-radius: 0 0 4px 4px;
}
.ofw_modal_message {
    margin-bottom: 15px;
    font-size: 14px;
}
</style>
<script>
// Neighbour data
const neighData = [
$jsDataStr
];

// Make modal draggable
function makeModalDraggable(modal, handle) {
    let isDragging = false;
    let offsetX = 0, offsetY = 0;
    
    handle.addEventListener('mousedown', (e) => {
        isDragging = true;
        const rect = modal.getBoundingClientRect();
        offsetX = e.clientX - rect.left;
        offsetY = e.clientY - rect.top;
        handle.style.cursor = 'grabbing';
        e.preventDefault();
    });
    
    document.addEventListener('mousemove', (e) => {
        if (!isDragging) return;
        modal.style.left = (e.clientX - offsetX) + 'px';
        modal.style.top = (e.clientY - offsetY) + 'px';
        modal.style.transform = 'none';
    });
    
    document.addEventListener('mouseup', () => {
        isDragging = false;
        handle.style.cursor = 'move';
    });
}

// Add Neighbour modal
function openAddNeighModal() {
    if (document.getElementById('addNeighModal')) return;
    
    const overlay = document.createElement('div');
    overlay.className = 'ofw_modal_overlay';
    overlay.id = 'addNeighModal';
    overlay.innerHTML = `
        <div class="ofw_modal_dialog" style="left:50%;top:50%;transform:translate(-50%,-50%);width:450px;">
            <div class="ofw_modal_header">
                <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>
                <span class="ofw_modal_title">$jsAddAction Neighbour</span>
                <button class="ofw_modal_close">&times;</button>
            </div>
            <form id="addNeighForm" method="post" action="/cgi-bin/neighstatic.cgi">
                <div class="ofw_modal_body">
                    <table style="width:100%;border-collapse:collapse;">
                        <tr>
                            <td style="width:140px;padding:8px 12px 8px 0;text-align:right;"><label>IP Address</label></td>
                            <td><input type="text" name="IP" style="width:200px;" required></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>MAC Address</label></td>
                            <td><input type="text" name="MAC_ADDRESS" style="width:200px;" required></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>Interface</label></td>
                            <td>
                                <select name="IF_NAME" style="width:200px;">
                                    $ifaceOptionsStr
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>Status</label></td>
                            <td>
                                <select name="STATUS" style="width:200px;">
                                    $statusOptionsStr
                                </select>
                            </td>
                        </tr>
                    </table>
                    <input type="hidden" name="ACTION" value="$jsAddAction">
                </div>
                <div class="ofw_modal_footer">
                    <button type="button" class="ofw_btn ofw_btn_cancel" onclick="this.closest('.ofw_modal_overlay').remove()">Cancel</button>
                    <button type="button" class="ofw_btn ofw_btn_primary" onclick="submitAddNeighForm()">Save</button>
                </div>
            </form>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    overlay.querySelector('.ofw_modal_close').addEventListener('click', () => overlay.remove());
    
    makeModalDraggable(overlay.querySelector('.ofw_modal_dialog'), overlay.querySelector('.ofw_modal_header'));
}

// Edit Neighbour modal
function openEditNeighModal(rowData) {
    if (document.getElementById('editNeighModal')) return;
    
    const overlay = document.createElement('div');
    overlay.className = 'ofw_modal_overlay';
    overlay.id = 'editNeighModal';
    overlay.innerHTML = `
        <div class="ofw_modal_dialog" style="left:50%;top:50%;transform:translate(-50%,-50%);width:450px;">
            <div class="ofw_modal_header">
                <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1 1 0 000-1.41l-2.34-2.34a1 1 0 00-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
                <span class="ofw_modal_title">$jsUpdateAction Neighbour</span>
                <button class="ofw_modal_close">&times;</button>
            </div>
            <form id="editNeighForm" method="post" action="/cgi-bin/neighstatic.cgi">
                <div class="ofw_modal_body">
                    <table style="width:100%;border-collapse:collapse;">
                        <tr>
                            <td style="width:140px;padding:8px 12px 8px 0;text-align:right;"><label>IP Address</label></td>
                            <td><input type="text" name="IP" style="width:200px;" value="\${rowData.ip}" required></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>MAC Address</label></td>
                            <td><input type="text" name="MAC_ADDRESS" style="width:200px;" value="\${rowData.mac}" required></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>Interface</label></td>
                            <td>
                                <select name="IF_NAME" style="width:200px;" id="editIfaceSelect">
                                    $ifaceOptionsStr
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>Status</label></td>
                            <td>
                                <select name="STATUS" style="width:200px;" id="editStatusSelect">
                                    $statusOptionsStr
                                </select>
                            </td>
                        </tr>
                    </table>
                    <input type="hidden" name="ACTION" value="$jsUpdateAction">
                    <input type="hidden" name="NEIGH_ID" value="\${rowData.id}">
                </div>
                <div class="ofw_modal_footer">
                    <button type="button" class="ofw_btn ofw_btn_cancel" onclick="this.closest('.ofw_modal_overlay').remove()">Cancel</button>
                    <button type="button" class="ofw_btn ofw_btn_primary" onclick="submitEditNeighForm()">Save</button>
                </div>
            </form>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    // Set selected interface and status
    const ifaceSelect = overlay.querySelector('#editIfaceSelect');
    if (ifaceSelect) {
        ifaceSelect.value = rowData.iface;
    }
    const statusSelect = overlay.querySelector('#editStatusSelect');
    if (statusSelect) {
        statusSelect.value = rowData.status;
    }
    
    overlay.querySelector('.ofw_modal_close').addEventListener('click', () => overlay.remove());
    
    makeModalDraggable(overlay.querySelector('.ofw_modal_dialog'), overlay.querySelector('.ofw_modal_header'));
}

// Delete confirm modal
function openDeleteNeighConfirm(selectedRows) {
    if (document.getElementById('deleteNeighConfirm')) return;
    
    let neighHtml = '<ul style="margin:0;padding-left:20px;">';
    selectedRows.forEach(r => {
        neighHtml += `<li>\${r.ip} (\${r.iface}) - \${r.mac}</li>`;
    });
    neighHtml += '</ul>';
    
    const overlay = document.createElement('div');
    overlay.className = 'ofw_modal_overlay';
    overlay.id = 'deleteNeighConfirm';
    overlay.innerHTML = `
        <div class="ofw_modal_dialog" style="left:50%;top:50%;transform:translate(-50%,-50%);width:400px;">
            <div class="ofw_modal_header">
                <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                <span class="ofw_modal_title">Confirm Delete</span>
                <button class="ofw_modal_close">&times;</button>
            </div>
            <div class="ofw_modal_body">
                <div class="ofw_modal_message">Are you sure you want to delete the following neighbours?</div>
                <div style="margin-top:12px;padding:8px 12px;background:#f5f5f5;border-radius:4px;">
                    \${neighHtml}
                </div>
            </div>
            <div class="ofw_modal_footer">
                <button type="button" class="ofw_btn ofw_btn_cancel" onclick="this.closest('.ofw_modal_overlay').remove()">Cancel</button>
                <button type="button" class="ofw_btn ofw_btn_primary" id="confirmDeleteBtn">Delete</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    overlay.querySelector('.ofw_modal_close').addEventListener('click', () => overlay.remove());
    overlay.querySelector('.ofw_btn_cancel').addEventListener('click', () => overlay.remove());
    overlay.querySelector('#confirmDeleteBtn').addEventListener('click', () => {
        // Batch delete via AJAX
        const neighIds = selectedRows.map(r => r.id).join(',');
        const formData = new URLSearchParams();
        formData.append('ACTION', '$jsRemoveAction');
        formData.append('NEIGH_ID', neighIds);
        
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/cgi-bin/neighstatic.cgi', true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onload = function() {
            if (xhr.status === 200 || xhr.status === 302) {
                overlay.remove();
                window.location.reload();
            } else if (xhr.status !== 0) {
                alert('Delete failed: ' + xhr.statusText);
            }
        };
        xhr.send(formData.toString());
    });
    
    makeModalDraggable(overlay.querySelector('.ofw_modal_dialog'), overlay.querySelector('.ofw_modal_header'));
}

function submitAddNeighForm() {
    const form = document.getElementById('addNeighForm');
    const formData = new FormData(form);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', form.action, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {
        if (xhr.status === 200 || xhr.status === 302) {
            document.getElementById('addNeighModal').remove();
            window.location.reload();
        } else if (xhr.status !== 0) {
            alert('Add failed: ' + xhr.statusText);
        }
    };
    const params = new URLSearchParams(formData).toString();
    xhr.send(params);
}

function submitEditNeighForm() {
    const form = document.getElementById('editNeighForm');
    const formData = new FormData(form);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', form.action, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {
        if (xhr.status === 200 || xhr.status === 302) {
            document.getElementById('editNeighModal').remove();
            window.location.reload();
        } else if (xhr.status !== 0) {
            alert('Update failed: ' + xhr.statusText);
        }
    };
    const params = new URLSearchParams(formData).toString();
    xhr.send(params);
}

// Initialize DataTable
document.addEventListener('DOMContentLoaded', function() {
    const table = new DataTable('#neighTable', {
        data: neighData,
        columns: [
            { key: 'ip', title: 'IP Address', sortable: true },
            { key: 'iface', title: 'Interface', sortable: true },
            { key: 'mac', title: 'MAC Address', sortable: true },
            { key: 'status', title: 'Status', sortable: true }
        ],
        defaultSort: { key: 'ip', direction: 'asc' },
        pageSize: 20,
        disableDeleteCheck: true,
        onAddModal: function() { openAddNeighModal(); },
        onEditModal: function(row) { openEditNeighModal(row); },
        onDeleteConfirm: function(rows) { openDeleteNeighConfirm(rows); }
    });
    table.render();
});
</script>
<div id="neighTable"></div>
END

#    &Header::closebox();
}

#&Header::closebigbox();

&Header::closepage();


#######################################################
# custom neighbours
#######################################################

sub validateNeighbourParams
{
    my $custNeighboursRef = shift;

    if ($cgiparams{'IP'} eq '') {
        $errormessage = $Lang::tr{'noAddressNet'};
        return;
    } else {
        if (!(&General::validip($cgiparams{'IP'}))) {
            $errormessage = $Lang::tr{'invalid ip address'};
            return;
        }
    }

    if ($cgiparams{'IF_NAME'} eq '') {
        $errormessage = $Lang::tr{'noIFace'};
        return;
    }
    if ($cgiparams{'MAC_ADDRESS'} eq '') {
        $errormessage = $Lang::tr{'noIFace'};
        return;
    }

    my $new = $cgiparams{'IP'}.",".$cgiparams{'IF_NAME'}.",".$cgiparams{'MAC_ADDRESS'}.",".$cgiparams{'STATUS'};
    foreach my $neighbour (@$custNeighboursRef) {
        # strip the end space charactor
        chomp($neighbour);
        if ($neighbour eq $new) {
            $errormessage = "duplicate neighbour";
            return;
        }
    }
}
sub readCustNeighbours
{
    my $custNeighboursRef = shift;
    open(NEIGHS, "$custNeighboursFile") or die 'Unable to open custom neighbour file.';
    @$custNeighboursRef = <NEIGHS>;
    close(NEIGHS);
}

sub saveCustNeighbours
{
    my $sNeighboursRef = shift;

    open(FILE, ">$custNeighboursFile") or die 'Unable to open custom neighbour file.';
    flock FILE, 2;
    foreach my $neighbour (@$sNeighboursRef) {
        chomp($neighbour);
        print FILE "$neighbour\n";
    }
    close(FILE);
}
