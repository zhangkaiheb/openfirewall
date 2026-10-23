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
# MENUTHRDLVL "routing table" 010 "static route table" "static route table"
#
# Make sure translation exists $Lang::tr{'static route table'}
#

use strict;

# enable only the following on debugging purpose
use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';

our $staticRoutesFile = "/var/ofw/ethernet/staticRoutes";

my $output='';

&Header::showhttpheaders();

my %cgiparams    = ();
my $errormessage = '';
my $error        = '';
$cgiparams{'ACTION'}     = '';
$cgiparams{'ROUTE_ID'}     = 0;
&General::getcgihash(\%cgiparams);

# vars for setting up sort order
my $sort_col  = '1';
my $sort_type = 'a';
my $sort_dir  = 'asc';
my $junk;
my $lineNumber = 0;

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


my @staticRoutes = ();
&readStaticRoutes(\@staticRoutes);

$cgiparams{'ADDRESS'}  = '';
$cgiparams{'NETMASK'}  = '';
$cgiparams{'GATEWAY'}  = '';
$cgiparams{'IFACE'}    = '';
$cgiparams{'ACTION'}    = '';
$cgiparams{'ROUTE_ID'} = 0;
&General::getcgihash(\%cgiparams);

#$cgiparams{'IFACE_NAME'} = &Header::cleanConfNames($cgiparams{'IFACE_NAME'});

if ($cgiparams{'ACTION'} eq $Lang::tr{'add'}) {
    &validateStaticRoutesParams(\@staticRoutes);

    unless ($errormessage) {
        my $route = $cgiparams{'ADDRESS'}.",".$cgiparams{'NETMASK'}.",".$cgiparams{'GATEWAY'}.",".$cgiparams{'IFACE'};

        my $res = system("/sbin/ip route add $cgiparams{'ADDRESS'}/$cgiparams{'NETMASK'} via $cgiparams{'GATEWAY'} dev $cgiparams{'IFACE'}");
        if ($res eq '0') {
            push(@staticRoutes, $route);
            &saveStaticRoutes(\@staticRoutes);
            &General::log("$Lang::tr{'static route added'}: $route");
            print "Location: $ENV{'SCRIPT_NAME'}\n\n";
            exit;
        }
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'update'}) {
    &validateStaticRoutesParams(\@staticRoutes);
    if ($errormessage) {
        $cgiparams{'ACTION'} = $Lang::tr{'edit'};
    }
    else {
        my $route = $cgiparams{'ADDRESS'}.",".$cgiparams{'NETMASK'}.",".$cgiparams{'GATEWAY'}.",".$cgiparams{'IFACE'};

        my $tmpline = $staticRoutes[$cgiparams{'ROUTE_ID'}];
        my @tmp = split(/\,/, $tmpline);
        my $route = $tmp[0].",".$tmp[1].",".$tmp[2].",".$tmp[3];

        my $res = system("/sbin/ip route del $tmp[0]/$tmp[1] via $tmp[2] dev $tmp[3]");
        if ($res eq '0') {
            my $res2 = system("/sbin/ip route add $cgiparams{'ADDRESS'}/$cgiparams{'NETMASK'} via $cgiparams{'GATEWAY'} dev $cgiparams{'IFACE'}");
            if ($res2 eq '0') {
                $staticRoutes[$cgiparams{ROUTE_ID}] = $route;
                &saveStaticRoutes(\@staticRoutes);
                &General::log("$Lang::tr{'static route updated'}: $route");
                print "Location: $ENV{'SCRIPT_NAME'}\n\n";
                exit;
            }
        }
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {

    # on an update error we use the entered data, we do not re-read from stored config
    unless ($errormessage) {

        if (defined($staticRoutes[$cgiparams{'ROUTE_ID'}])) {
            my $tmpline = $staticRoutes[$cgiparams{'ROUTE_ID'}];
            chomp($tmpline);
            my @tmp = split(/\,/, $tmpline);

            $cgiparams{'ADDRESS'} = $tmp[0];
            $cgiparams{'NETMASK'} = $tmp[1];
            $cgiparams{'GATEWAY'} = $tmp[2];
            $cgiparams{'IFACE'} = $tmp[3];
        }
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    # Support batch delete: ROUTE_ID may contain multiple IDs joined by ','
    my @routeIds = split(/,/, $cgiparams{'ROUTE_ID'});
    # Sort in descending order to delete from end first (preserves indices)
    @routeIds = sort { $b <=> $a } @routeIds;
    foreach my $rid (@routeIds) {
        next unless defined($staticRoutes[$rid]);
        my $tmpline = $staticRoutes[$rid];
        chomp($tmpline);
        my @tmp = split(/\,/, $tmpline);
        my $route = $tmp[0].",".$tmp[1].",".$tmp[2].",".$tmp[3];

        # Try to delete from system, but always remove from config
        system("/sbin/ip route del $tmp[0]/$tmp[1] via $tmp[2] dev $tmp[3] 2>/dev/null");
        splice(@staticRoutes, $rid, 1);
        &General::log("$Lang::tr{'iface removed'}: $route");
    }
    &saveStaticRoutes(\@staticRoutes);
    print "Location: $ENV{'SCRIPT_NAME'}\n\n";
    exit;
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'reset'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}




&Header::openpage($Lang::tr{'network status information'}, 1, '');

#&Header::openbigbox('100%', 'left');

if ($cgiparams{'ACTION'} eq '') {
    $cgiparams{'ADDRESS'}   = '';
    $cgiparams{'NETMASK'}   = '';
    $cgiparams{'GATEWAY'}   = '';
    $cgiparams{'IFACE'}     = '';
    $cgiparams{'ROUTE_ID'}  = '';
}

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

my %selected = ();

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} || $cgiparams{'ACTION'} eq $Lang::tr{'add static route'}) {
    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
#        &Header::openbox('100%', 'left', "$Lang::tr{'edit static route'}:", $error);
    } else {
#        &Header::openbox('100%', 'left', "$Lang::tr{'add static route'}:", $error);
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
    <td width='25%'>$Lang::tr{'destination ip or subnet'}</td>
    <td width='25%'>
        <input type='text' name='ADDRESS' value='$cgiparams{'ADDRESS'}' size='20' maxlength='20' />
    </td>
    <td width='49%'></td>
</tr><tr>
    <td width='1%'></td>
    <td width='25%'>$Lang::tr{'netmask'}</td>
    <td width='25%'>
        <input type='text' name='NETMASK' value='$cgiparams{'NETMASK'}' size='20' maxlength='20' />
    </td>
</tr>
<tr>
    <td width='1%'></td>
    <td width='25%'>$Lang::tr{'gateway ip'}</td>
    <td width='25%'>
        <input type='text' name='GATEWAY' value='$cgiparams{'GATEWAY'}' size='20' maxlength='20' />
    </td>
</tr><tr>
    <td width='1%'></td>
    <td width='25%'>$Lang::tr{'interface'}</td>
    <td width='25%'>
        <select name='IFACE'>
END
foreach my $iface (sort keys %FW::interfaces) {
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
        print "<input type='hidden' name='OLD_IF_NAME' value='$cgiparams{'IF_NAME'}' />\n";
    } else {
        print "<input type='submit' class='footbutton' name='ACTION' value='$Lang::tr{'add'}' />\n";
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

#################################################################################
#  static routing table
#################################################################################

#    &Header::openbox('100%', 'left', "$Lang::tr{'static route table'}:");

    # Convert static routes data to JavaScript format
    my @jsData;
    my $id = 0;
    foreach my $tmpline (@staticRoutes) {
        chomp($tmpline);
        my @tmp = split(/\,/, $tmpline);
        my $destination = "$tmp[0]/$tmp[1]";
        my $gateway = $tmp[2];
        my $iface = $tmp[3];
        
        push @jsData, sprintf(
            "{id:'%d',destination:'%s',gateway:'%s',iface:'%s',address:'%s',netmask:'%s'}",
            $id, $destination, $gateway, $iface, $tmp[0], $tmp[1]
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

    print <<END;
<div id='staticRouteTable'></div>
<script type='text/javascript'>
function openAddRouteModal() {
    if (document.querySelector('.ofw_modal_overlay')) return;
    
    const overlay = document.createElement('div');
    overlay.className = 'ofw_modal_overlay';
    overlay.innerHTML = `
        <div class="ofw_modal_dialog" style="width:500px;">
            <div class="ofw_modal_header">
                <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>
                <span class="ofw_modal_title">Add Static Route</span>
                <button class="ofw_modal_close">&times;</button>
            </div>
            <div class="ofw_modal_body">
                <form id="addRouteForm" method="post" action="/cgi-bin/routestatic.cgi">
                    <input type="hidden" name="ACTION" value="$jsAddAction">
                    <table style="width:100%;border-collapse:collapse;">
                        <tr>
                            <td style="width:140px;padding:8px 12px 8px 0;text-align:right;"><label>Destination</label></td>
                            <td><input type="text" name="ADDRESS" style="width:200px;" required placeholder="192.168.1.0"></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>Netmask</label></td>
                            <td><input type="text" name="NETMASK" style="width:200px;" required placeholder="255.255.255.0"></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>Gateway</label></td>
                            <td><input type="text" name="GATEWAY" style="width:200px;" required placeholder="192.168.1.1"></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>Interface</label></td>
                            <td>
                                <select name="IFACE" style="width:200px;">
                                    $ifaceOptionsStr
                                </select>
                            </td>
                        </tr>
                    </table>
                </form>
            </div>
            <div class="ofw_modal_footer">
                <button class="ofw_btn ofw_btn_cancel">Cancel</button>
                <button class="ofw_btn ofw_btn_primary" onclick="submitAddRouteForm()">Add</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    overlay.querySelector('.ofw_modal_close').addEventListener('click', () => overlay.remove());
    overlay.querySelector('.ofw_btn_cancel').addEventListener('click', () => overlay.remove());
    
    makeModalDraggable(overlay.querySelector('.ofw_modal_dialog'), overlay.querySelector('.ofw_modal_header'));
}

function openEditRouteModal(rowData) {
    if (!rowData || document.querySelector('.ofw_modal_overlay')) return;
    
    const overlay = document.createElement('div');
    overlay.className = 'ofw_modal_overlay';
    overlay.innerHTML = `
        <div class="ofw_modal_dialog" style="width:500px;">
            <div class="ofw_modal_header">
                <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
                <span class="ofw_modal_title">Edit Static Route</span>
                <button class="ofw_modal_close">&times;</button>
            </div>
            <div class="ofw_modal_body">
                <form id="editRouteForm" method="post" action="/cgi-bin/routestatic.cgi">
                    <input type="hidden" name="ACTION" value="$jsUpdateAction">
                    <input type="hidden" name="ROUTE_ID" value="\${rowData.id}">
                    <table style="width:100%;border-collapse:collapse;">
                        <tr>
                            <td style="width:140px;padding:8px 12px 8px 0;text-align:right;"><label>Destination</label></td>
                            <td><input type="text" name="ADDRESS" style="width:200px;" value="\${rowData.address}" required></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>Netmask</label></td>
                            <td><input type="text" name="NETMASK" style="width:200px;" value="\${rowData.netmask}" required></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>Gateway</label></td>
                            <td><input type="text" name="GATEWAY" style="width:200px;" value="\${rowData.gateway}" required></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>Interface</label></td>
                            <td>
                                <select name="IFACE" style="width:200px;" id="editIfaceSelect">
                                    $ifaceOptionsStr
                                </select>
                            </td>
                        </tr>
                    </table>
                </form>
            </div>
            <div class="ofw_modal_footer">
                <button class="ofw_btn ofw_btn_cancel">Cancel</button>
                <button class="ofw_btn ofw_btn_primary" onclick="submitEditRouteForm()">Save</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    // Set the selected interface
    const ifaceSelect = overlay.querySelector('#editIfaceSelect');
    if (ifaceSelect) {
        ifaceSelect.value = rowData.iface;
    }
    
    overlay.querySelector('.ofw_modal_close').addEventListener('click', () => overlay.remove());
    overlay.querySelector('.ofw_btn_cancel').addEventListener('click', () => overlay.remove());
    
    makeModalDraggable(overlay.querySelector('.ofw_modal_dialog'), overlay.querySelector('.ofw_modal_header'));
}

function openDeleteRouteConfirm(selectedRows) {
    if (!selectedRows || !selectedRows.length || document.querySelector('.ofw_modal_overlay')) return;
    
    const count = selectedRows.length;
    const msg = count === 1
        ? 'Are you sure you want to delete this static route?'
        : 'Are you sure you want to delete these ' + count + ' static routes?';
    const routesHtml = selectedRows.map(r => '<div style="padding:2px 0;">' + r.destination + ' via ' + r.gateway + '</div>').join('');
    
    const overlay = document.createElement('div');
    overlay.className = 'ofw_modal_overlay';
    overlay.innerHTML = `
        <div class="ofw_modal_dialog" style="width:400px;">
            <div class="ofw_modal_header">
                <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                <span class="ofw_modal_title">Confirm Delete</span>
                <button class="ofw_modal_close">&times;</button>
            </div>
            <div class="ofw_modal_body">
                <div class="ofw_modal_message">\${msg}</div>
                <div style="margin-top:12px;padding:8px 12px;background:#f5f5f5;border-radius:4px;">
                    \${routesHtml}
                </div>
            </div>
            <div class="ofw_modal_footer">
                <button class="ofw_btn ofw_btn_cancel">Cancel</button>
                <button class="ofw_btn ofw_btn_primary" id="confirmDeleteBtn">Delete</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    overlay.querySelector('.ofw_modal_close').addEventListener('click', () => overlay.remove());
    overlay.querySelector('.ofw_btn_cancel').addEventListener('click', () => overlay.remove());
    overlay.querySelector('#confirmDeleteBtn').addEventListener('click', () => {
        // Batch delete via AJAX
        const routeIds = selectedRows.map(r => r.id).join(',');
        const formData = new URLSearchParams();
        formData.append('ACTION', '$jsRemoveAction');
        formData.append('ROUTE_ID', routeIds);
        
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/cgi-bin/routestatic.cgi', true);
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

function submitAddRouteForm() {
    const form = document.getElementById('addRouteForm');
    const formData = new FormData(form);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', form.action, true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                window.location.reload();
            } else if (xhr.status !== 0) {
                alert('Error: ' + xhr.status);
            }
        }
    };
    xhr.send(formData);
}

function submitEditRouteForm() {
    const form = document.getElementById('editRouteForm');
    const formData = new FormData(form);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', form.action, true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                window.location.reload();
            } else if (xhr.status !== 0) {
                alert('Error: ' + xhr.status);
            }
        }
    };
    xhr.send(formData);
}

function makeModalDraggable(element, handle) {
    let isDragging = false;
    let startX, startY, initialX, initialY;
    
    handle.addEventListener('mousedown', (e) => {
        isDragging = true;
        startX = e.clientX;
        startY = e.clientY;
        const transform = element.style.transform || 'translate(0px, 0px)';
        const match = transform.match(/translate\\(([^,]+)px,\\s*([^)]+)px\\)/);
        initialX = match ? parseFloat(match[1]) : 0;
        initialY = match ? parseFloat(match[2]) : 0;
        document.body.style.userSelect = 'none';
    });
    
    document.addEventListener('mousemove', (e) => {
        if (!isDragging) return;
        const dx = e.clientX - startX;
        const dy = e.clientY - startY;
        element.style.transform = `translate(\${initialX + dx}px, \${initialY + dy}px)`;
    });
    
    document.addEventListener('mouseup', () => {
        isDragging = false;
        document.body.style.userSelect = '';
    });
}

document.addEventListener('DOMContentLoaded', function() {
    var tableData = [
        $jsDataStr
    ];
    
    var dt = new DataTable('#staticRouteTable', {
        tableKey: 'staticRoutes',
        columns: [
            {key: 'destination', title: 'Destination'},
            {key: 'gateway', title: 'Gateway'},
            {key: 'iface', title: 'Interface'}
        ],
        defaultSort: {key: 'destination', order: 'asc'},
        data: tableData,
        rowKey: 'id',
        selectable: true,
        pageSize: 20,
        actions: ['create', 'edit', 'delete', 'refresh'],
        disableDeleteCheck: true,
        onAddModal: openAddRouteModal,
        onEditModal: openEditRouteModal,
        onDeleteConfirm: openDeleteRouteConfirm,
        onAction: function(action) {
            if (action === 'refresh') {
                document.location.reload();
            }
        }
    });
});
</script>
END
#    &Header::closebox();
}

#&Header::closebigbox();
&Header::closepage();


sub display_static_routes {
    my $staticRoutesRef = shift;

    my $id = 0;
    my $tmpline;
    foreach my $tmpline (@$staticRoutesRef) {
        chomp($tmpline);
        my @tmp = split(/\,/, $tmpline);

        # highlight the row we are editing
        if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} && $cgiparams{'ROUTE_ID'} eq $id) {
            print "<tr class='selectcolour'>\n";
        } else {
            print "<tr class='table".int(($id % 2) + 1)."colour'>";
        }
        print <<END;
    <td>$tmp[0]/$tmp[1]</td>
    <td align='center'>$tmp[2]</td>
    <td align='center'>$tmp[3]</td>
    <td align='center'>
    <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
        <input type='hidden' name='ROUTE_ID' value='$id' />
        <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
    </form>
    </td>
END
            print <<END;
    <td align='center'>
    <form method='post' name='frmb$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        <input type='hidden' name='ROUTE_ID' value='$id' />
        <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
    </form>
    </td>
END
        print "</tr>\n";
        $id++;
    }
}

#######################################################
# Static Routes
#######################################################
sub readStaticRoutes
{
    my $staticRoutesRef = shift;
    open(ROUTES, "$staticRoutesFile") or die 'Unable to open static routes file.';
    @$staticRoutesRef = <ROUTES>;
    close(ROUTES);
}

sub saveStaticRoutes
{
    my $sRoutesRef = shift;

    open(FILE, ">$staticRoutesFile") or die 'Unable to open static routes file.';
    flock FILE, 2;
    foreach my $route (@$sRoutesRef) {
        chomp($route);
        print FILE "$route\n";
    }
    close(FILE);
}

# Validate Field Entries
sub validateStaticRoutesParams {
    my $staticRoutesRef = shift;

    # Strip out commas which will break CSV config file.
#    $cgiparams{'IFACE_NAME'} = &Header::cleanhtml($cgiparams{'IFACE_NAME'});

    if ($cgiparams{'ADDRESS'} eq '') {
        $errormessage = $Lang::tr{'noAddressNet'};
        return;
    } else {
        if (!(&General::validip($cgiparams{'ADDRESS'}))) {
            $errormessage = $Lang::tr{'invalid ip address'};
            return;
        }
    }
    if ($cgiparams{'NETMASK'} eq '') {
        $errormessage = $Lang::tr{'noNetmask'};
        return;
    } else {
        if (!(&General::validip($cgiparams{'NETMASK'}))) {
            $errormessage = $Lang::tr{'invalid netmask'};
            return;
        }
    }
    if ($cgiparams{'GATEWAY'} eq '') {
        $errormessage = $Lang::tr{'noGateway'};
        return;
    } else {
        if (!(&General::validip($cgiparams{'GATEWAY'}))) {
            $errormessage = $Lang::tr{'invalid gateway address'};
            return;
        }
        # should check the reachable of the gateway
    }
    if ($cgiparams{'IFACE'} eq '') {
        $errormessage = $Lang::tr{'noIFace'};
        return;
    }

    my $new = $cgiparams{'ADDRESS'}.",".$cgiparams{'NETMASK'}.",".$cgiparams{'GATEWAY'}.",".$cgiparams{'IFACE'};
    foreach my $route (@$staticRoutesRef) {
        # strip the end space charactor
        chomp($route);
        if ($route eq $new) {
            $errormessage = "duplicate route";
            return;
        }
    }
}

