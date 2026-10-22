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
# MENUTHRDLVL "interfaces" 010 "interfaces" "interfaces"
#
# Make sure translation exists $Lang::tr{'interfaces'}

use strict;

# enable only the following on debugging purpose
use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';

# Enable output buffering
$| = 1;

my %cgiparams    = ();
my $errormessage = '';
my $error        = '';
$cgiparams{'ACTION'}     = '';
$cgiparams{'USED_COUNT'} = 0;
&General::getcgihash(\%cgiparams);

# Read interface data early for POST processing
my %custIfaces = ();
&DATA::readCustIfaces(\%custIfaces);

# Check if this is a POST request that needs redirect
my $needs_redirect = 0;
if ($ENV{'REQUEST_METHOD'} eq 'POST' && $cgiparams{'ACTION'} ne '') {
    $needs_redirect = 1;

    # Process add interface action
    if ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'}) {
        &validateIFaceParams(\%custIfaces);
        &ip_link_add_cmd();

        unless ($errormessage) {
            $custIfaces{$cgiparams{'IF_NAME'}}{'TYPE'}        = $cgiparams{'TYPE'};
            $custIfaces{$cgiparams{'IF_NAME'}}{'DESCRIPTION'} = $cgiparams{'DESCRIPTION'};
            $custIfaces{$cgiparams{'IF_NAME'}}{'IFACE'}       = $cgiparams{'IFACE'};
            $custIfaces{$cgiparams{'IF_NAME'}}{'ADDRESSING_MODE'} = $cgiparams{'ADDRESSING_MODE'};
            if ($cgiparams{'IPADDR_MASK'} ne '0.0.0.0/0.0.0.0') {
               my @tmp = split(/\//, $cgiparams{'IPADDR_MASK'});
               $custIfaces{$cgiparams{'IF_NAME'}}{'IPADDRESS'} = $tmp[0];
               $custIfaces{$cgiparams{'IF_NAME'}}{'NETMASK'} = $tmp[1];
            }
            $custIfaces{$cgiparams{'IF_NAME'}}{'MTU'}         = $cgiparams{'MTU'};
            $custIfaces{$cgiparams{'IF_NAME'}}{'VLANID'}      = $cgiparams{'VLANID'};
            $custIfaces{$cgiparams{'IF_NAME'}}{'ACCESSMODE'}  = $cgiparams{'ACCESSMODE'};

            $custIfaces{$cgiparams{'IF_NAME'}}{'BR_MEMBERS'} = $cgiparams{'BR_MEMBERS'};
            if ($cgiparams{'BR_MEMBERS'} ne '') {
               my @mbrs = split(/\#/, $cgiparams{'BR_MEMBERS'});
               foreach my $intf (@mbrs) {
                    $custIfaces{$cgiparams{'$intf'}}{'USED_BR'} = 1;
               }
            }

            $custIfaces{$cgiparams{'IF_NAME'}}{'BOND_MEMBERS'} = $cgiparams{'BOND_MEMBERS'};
            if ($cgiparams{'BOND_MEMBERS'} ne '') {
               my @mbrs = split(/\#/, $cgiparams{'BOND_MEMBERS'});
               foreach my $intf (@mbrs) {
                    $custIfaces{$cgiparams{'$intf'}}{'USED_BOND'} = 1;
               }
            }

            $custIfaces{$cgiparams{'IF_NAME'}}{'EXTERNAL'}    = $cgiparams{'EXTERNAL'};
            $custIfaces{$cgiparams{'IF_NAME'}}{'USED_COUNT'}  = 0;

            &DATA::saveCustIfaces(\%custIfaces);

            &General::log("$Lang::tr{'iface added'}: $cgiparams{'IF_NAME'}");
            `/usr/local/bin/setfwrules --ofw < /dev/null > /dev/null 2>&1 &`;
        }
    }

    &General::log("DEBUG - ACTION received: '$cgiparams{'ACTION'}'");
    &General::log("DEBUG - edit action string: '$Lang::tr{'edit'}'");

    if (lc($cgiparams{'ACTION'}) eq lc($Lang::tr{'edit'})) {
        # Debug: log received parameters
        &General::log("DEBUG EDIT - IF_NAME: $cgiparams{'IF_NAME'}");
        &General::log("DEBUG EDIT - OLD_IF_NAME: $cgiparams{'OLD_IF_NAME'}");
        &General::log("DEBUG EDIT - TYPE: $cgiparams{'TYPE'}");
        &General::log("DEBUG EDIT - ADDRESSING_MODE: $cgiparams{'ADDRESSING_MODE'}");
        &General::log("DEBUG EDIT - IPADDR_MASK: $cgiparams{'IPADDR_MASK'}");
        &General::log("DEBUG EDIT - DESCRIPTION: $cgiparams{'DESCRIPTION'}");
        &General::log("DEBUG EDIT - BR_MEMBERS: $cgiparams{'BR_MEMBERS'}");

        &validateIFaceParams(\%custIfaces);
        &General::log("DEBUG EDIT - After validation, errormessage: '$errormessage'");
        if ($errormessage) {
            &General::log("DEBUG EDIT - Validation error: $errormessage");
            $cgiparams{'ACTION'} = $Lang::tr{'edit'};
        }
        else {
            my $ifaceName    = $cgiparams{'IF_NAME'};
            my $oldIfaceName = $cgiparams{'OLD_IF_NAME'} || $ifaceName;
            &General::log("DEBUG EDIT - ifaceName=$ifaceName, oldIfaceName=$oldIfaceName");

            # Update IP address
            if ($cgiparams{'ADDRESSING_MODE'} eq '0') {
                # Static mode: update IP from form
                &General::log("DEBUG EDIT - Static mode, IPADDR_MASK: '$cgiparams{'IPADDR_MASK'}'");
                if ($cgiparams{'IPADDR_MASK'} ne '' && $cgiparams{'IPADDR_MASK'} ne '0.0.0.0/0.0.0.0') {
                    my @tmp = split(/\//, $cgiparams{'IPADDR_MASK'});
                    if (scalar(@tmp) == 2) {
                        $custIfaces{$oldIfaceName}{'IPADDRESS'} = $tmp[0];
                        $custIfaces{$oldIfaceName}{'NETMASK'}   = $tmp[1];
                        &General::log("DEBUG EDIT - Updated IP to $tmp[0] / $tmp[1]");
                    }
                }
            } else {
                # DHCP mode: clear IP address
                &General::log("DEBUG EDIT - DHCP mode, clearing IP address");
                $custIfaces{$oldIfaceName}{'IPADDRESS'} = '0.0.0.0';
                $custIfaces{$oldIfaceName}{'NETMASK'}   = '0.0.0.0';
            }
            $custIfaces{$oldIfaceName}{'DESCRIPTION'} = $cgiparams{'DESCRIPTION'};
            $custIfaces{$oldIfaceName}{'MTU'}         = $cgiparams{'MTU'};
            $custIfaces{$oldIfaceName}{'ADDRESSING_MODE'} = $cgiparams{'ADDRESSING_MODE'};

            # Update BR_MEMBERS
            $custIfaces{$oldIfaceName}{'BR_MEMBERS'} = $cgiparams{'BR_MEMBERS'};

            # Update BOND_MEMBERS
            $custIfaces{$oldIfaceName}{'BOND_MEMBERS'} = $cgiparams{'BOND_MEMBERS'};

            # Update VLAN fields
            $custIfaces{$oldIfaceName}{'VLANID'} = $cgiparams{'VLANID'};
            $custIfaces{$oldIfaceName}{'IFACE'}  = $cgiparams{'IFACE'};

            &General::log("DEBUG EDIT - Before saveCustIfaces, IPADDRESS=$custIfaces{$oldIfaceName}{'IPADDRESS'}");
            &DATA::saveCustIfaces(\%custIfaces);
            &General::log("DEBUG EDIT - After saveCustIfaces");

            # Apply IP address changes to the system
            if ($cgiparams{'ADDRESSING_MODE'} eq '0' && $cgiparams{'IPADDR_MASK'} ne '' && $cgiparams{'IPADDR_MASK'} ne '0.0.0.0/0.0.0.0') {
                # Static mode: apply IP address
                my $ip_cmd = "ip addr add $cgiparams{'IPADDR_MASK'} dev $ifaceName";
                &General::log("DEBUG EDIT - Applying IP address to system");
                &General::log("DEBUG EDIT - Full command: $ip_cmd");
                my $ip_result = `$ip_cmd 2>&1`;
                my $exit_code = $? >> 8;
                &General::log("DEBUG EDIT - ip addr add result: $ip_result, exit code: $exit_code");
            }

            &General::log("$Lang::tr{'iface updated'}: $oldIfaceName");
            `/usr/local/bin/setfwrules --all < /dev/null > /dev/null 2>&1 &`;
        }
    }

    if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
        # Get all IF_NAME parameters (support multiple deletions)
        my @ifaceNames;
        if (ref $cgiparams{'IF_NAME'} eq 'ARRAY') {
            @ifaceNames = @{$cgiparams{'IF_NAME'}};
        } elsif ($cgiparams{'IF_NAME'} =~ /\|/) {
            # Multiple values joined by pipe
            @ifaceNames = split(/\|/, $cgiparams{'IF_NAME'});
        } else {
            @ifaceNames = ($cgiparams{'IF_NAME'});
        }

        &General::log("DEBUG REMOVE - Interfaces to delete: " . join(', ', @ifaceNames));

        foreach my $ifaceName (@ifaceNames) {
            next unless $ifaceName;

            # Delete system interface
            my $del_cmd = "ip link delete $ifaceName";
            &General::log("DEBUG REMOVE - Deleting system interface: $ifaceName");
            &General::log("DEBUG REMOVE - Full command: $del_cmd");
            my $del_result = `$del_cmd 2>&1`;
            my $exit_code = $? >> 8;
            &General::log("DEBUG REMOVE - ip link delete result: $del_result, exit code: $exit_code");

            # Delete from config file
            delete($custIfaces{$ifaceName});
            &General::log("$Lang::tr{'iface removed'}: $ifaceName");
        }

        &DATA::saveCustIfaces(\%custIfaces);
        `/usr/local/bin/setfwrules --ofw < /dev/null > /dev/null 2>&1 &`;
    }

    if ($cgiparams{'ACTION'} eq $Lang::tr{'cancel'}) {
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
        # Redirect to avoid form resubmission on refresh
        print "Status: 302 Found\n";
        print "Location: /cgi-bin/interfaces.cgi\n\n";
        exit 0;
    }

    # Send redirect after processing POST request
    if ($needs_redirect) {
        print "Status: 302 Found\n";
        print "Location: /cgi-bin/interfaces.cgi\n\n";
        exit 0;
    }
}

&Header::showhttpheaders();

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

# Only process GET parameters if not a POST request
if ($ENV{'REQUEST_METHOD'} ne 'POST') {
    $cgiparams{'KEY'}            = '';
    $cgiparams{'IFACE'}          = '';
    $cgiparams{'IF_NAME'}     = '';
    &General::getcgihash(\%cgiparams);

    $cgiparams{'IF_NAME'} = &Header::cleanConfNames($cgiparams{'IF_NAME'});
}

&Header::openpage($Lang::tr{'interfaces settings'}, 1, '');

if ($cgiparams{'ACTION'} eq '') {
    $cgiparams{'KEY'}            = '';
    $cgiparams{'IFACE'}          = 'ip';
    $cgiparams{'IF_NAME'}     = '';
}

# DEBUG DEBUG
#&Header::openbox('100%', 'left', 'DEBUG');
#foreach my $line (keys %cgiparams) {
#   print "$line = $cgiparams{$line}<br />\n";
#}
#print "$ENV{'QUERY_STRING'}\n";
#print "-$cgiparams{'ACTION'}-\n";
#&Header::closebox();

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

##
# We are in advanced mode, show custom interfaces
##
my $disabled        = '';
my $hiddenIfaceName = '';


#############################################################
# interface list                                            #
#############################################################

if ($cgiparams{'ACTION'} eq '') {
    # Convert interface data to JavaScript format
    my @jsData;
    foreach my $ifaceName (keys %custIfaces) {
        my $iface = $custIfaces{$ifaceName};
        my $type = '';
        if ($iface->{'TYPE'} eq '0') {
            $type = 'PHYSICAL';
        } elsif ($iface->{'TYPE'} eq '1') {
            $type = 'VLAN';
        } elsif ($iface->{'TYPE'} eq '2') {
            $type = 'BRIDGE';
        } elsif ($iface->{'TYPE'} eq '3') {
            $type = 'BOND';
        }

        my $ipAddr = $iface->{'IPADDRESS'} || '0.0.0.0';
        my $netmask = $iface->{'NETMASK'} || '0.0.0.0';
        my $mtu = $iface->{'MTU'} || '1500';
        my $brMembers = $iface->{'BR_MEMBERS'} || '';
        my $vlanId = $iface->{'VLANID'} || '';
        my $usedCount = $iface->{'USED_COUNT'} || 0;

        # Escape single quotes for JavaScript
        my $desc = $iface->{'DESCRIPTION'} || '';
        $desc =~ s/'/\\'/g;
        $brMembers =~ s/'/\\'/g;

        my $addressingMode = $iface->{'ADDRESSING_MODE'} || '0';
        my $parentIface = $iface->{'IFACE'} || '';
        my $bondMembers = $iface->{'BOND_MEMBERS'} || '';
        $bondMembers =~ s/'/\\'/g;

        push @jsData, sprintf(
            "{id:'%s',name:'%s',description:'%s',ipaddress:'%s',netmask:'%s',type:'%s',typeCode:'%s',status:'%s',used:%d,mtu:'%s',brMembers:'%s',vlanId:'%s',addressingMode:'%s',iface:'%s',bondMembers:'%s'}",
            $ifaceName, $ifaceName, $desc, $ipAddr, $netmask, $type, $iface->{'TYPE'}, $iface->{'ADMSTATUS'}, $usedCount, $mtu, $brMembers, $vlanId, $addressingMode, $parentIface, $bondMembers
        );
    }
    my $jsDataStr = join(",\n", @jsData);

    my $jsAddAction = $Lang::tr{'add interface'};
    my $jsEditAction = $Lang::tr{'edit'};
    my $jsRemoveAction = $Lang::tr{'remove'};

    # Get available interfaces for the add modal
    my @jsInterfaces;
    foreach my $iface (sort keys %FW::interfaces) {
        push @jsInterfaces, "'$FW::interfaces{$iface}{'IFACE'}'";
    }
    my $jsInterfacesStr = join(',', @jsInterfaces);

    print <<END;
<div id='interfaceTable'></div>
<script type='text/javascript'>
function toggleAddressMode() {
    var staticMode = document.getElementById('mode_static');
    var ipaddrRow = document.getElementById('ipaddr_row');
    var ipaddrInput = document.querySelector('input[name="IPADDR_MASK"]');
    
    if (staticMode && ipaddrRow) {
        if (staticMode.checked) {
            ipaddrRow.style.display = '';
            if (ipaddrInput) ipaddrInput.disabled = false;
        } else {
            ipaddrRow.style.display = 'none';
            if (ipaddrInput) {
                ipaddrInput.disabled = true;
                ipaddrInput.value = '';
            }
        }
    }
}

function toggleAddTypeFields(type) {
    var vlanIfRow = document.getElementById('vlan_if_row');
    var vlanIdRow = document.getElementById('vlan_id_row');
    var bondRow = document.getElementById('bond_members_row');
    var bridgeRow = document.getElementById('bridge_members_row');
    
    if (vlanIfRow) vlanIfRow.style.display = (type === '1') ? '' : 'none';
    if (vlanIdRow) vlanIdRow.style.display = (type === '1') ? '' : 'none';
    if (bondRow) bondRow.style.display = (type === '3') ? '' : 'none';
    if (bridgeRow) bridgeRow.style.display = (type === '2') ? '' : 'none';
}

function moveOption(fromSelect, toSelect) {
    for (var i = 0; i < fromSelect.options.length; i++) {
        if (fromSelect.options[i].selected) {
            var option = fromSelect.options[i];
            var newOption = new Option(option.text, option.value);
            toSelect.options[toSelect.options.length] = newOption;
            fromSelect.options[i] = null;
            i--;
        }
    }
}

function prepareAddFormSubmit() {
    var form = document.getElementById('addInterfaceForm');
    var type = form.TYPE.value;
    var staticMode = document.getElementById('mode_static');
    
    // 如果是 DHCP 模式，清空 IP 地址字段
    if (!staticMode.checked) {
        var ipaddrInput = form.querySelector('input[name="IPADDR_MASK"]');
        if (ipaddrInput) ipaddrInput.value = '';
    }
    
    // 处理 BOND_MEMBERS
    if (type === '3') {
        var bondSelected = document.getElementById('bond_selected');
        var bondValues = [];
        for (var i = 0; i < bondSelected.options.length; i++) {
            bondValues.push(bondSelected.options[i].value);
        }
        // 创建隐藏字段存储选中的值
        var hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'BOND_MEMBERS';
        hiddenInput.value = bondValues.join('#');
        form.appendChild(hiddenInput);
        // 移除多选框的 name 属性，避免重复提交
        bondSelected.name = '';
    }
    
    // 处理 BR_MEMBERS
    if (type === '2') {
        var bridgeSelected = document.getElementById('bridge_selected');
        var bridgeValues = [];
        for (var i = 0; i < bridgeSelected.options.length; i++) {
            bridgeValues.push(bridgeSelected.options[i].value);
        }
        // 创建隐藏字段存储选中的值
        var hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'BR_MEMBERS';
        hiddenInput.value = bridgeValues.join('#');
        form.appendChild(hiddenInput);
        // 移除多选框的 name 属性，避免重复提交
        bridgeSelected.name = '';
    }
    
    // Use AJAX to submit form
    var formData = new FormData(form);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', form.action, true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                // Close modal and refresh page
                var overlay = document.querySelector('.ofw_modal_overlay');
                if (overlay) overlay.remove();
                window.location.reload();
            } else if (xhr.status !== 0) {
                // Only show error if status is not 0 (request cancelled)
                alert('Error: ' + xhr.status);
            }
        }
    };
    xhr.send(formData);
}

function prepareEditFormSubmit() {
    var form = document.getElementById('editInterfaceForm');
    var type = form.querySelector('input[name="TYPE"]').value;
    var staticMode = document.getElementById('mode_static');
    
    // 如果是静态模式，确保 IP 地址字段被启用
    if (staticMode && staticMode.checked) {
        var ipaddrInput = form.querySelector('input[name="IPADDR_MASK"]');
        if (ipaddrInput) ipaddrInput.disabled = false;
    } else {
        // 如果是 DHCP 模式，清空 IP 地址字段
        var ipaddrInput = form.querySelector('input[name="IPADDR_MASK"]');
        if (ipaddrInput) ipaddrInput.value = '';
    }
    
    // 处理 BOND_MEMBERS
    if (type === '3') {
        var bondSelected = document.getElementById('bond_selected');
        var bondValues = [];
        for (var i = 0; i < bondSelected.options.length; i++) {
            bondValues.push(bondSelected.options[i].value);
        }
        var hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'BOND_MEMBERS';
        hiddenInput.value = bondValues.join('#');
        form.appendChild(hiddenInput);
        bondSelected.name = '';
    }
    
    // 处理 BR_MEMBERS
    if (type === '2') {
        var bridgeSelected = document.getElementById('bridge_selected');
        var bridgeValues = [];
        for (var i = 0; i < bridgeSelected.options.length; i++) {
            bridgeValues.push(bridgeSelected.options[i].value);
        }
        var hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'BR_MEMBERS';
        hiddenInput.value = bridgeValues.join('#');
        form.appendChild(hiddenInput);
        bridgeSelected.name = '';
    }
    
    // Use AJAX to submit form
    var formData = new FormData(form);
    
    // Debug: log all form data
    console.log('Edit form data:');
    for (var pair of formData.entries()) {
        console.log(pair[0] + ': ' + pair[1]);
    }
    
    var xhr = new XMLHttpRequest();
    xhr.open('POST', form.action, true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                var overlay = document.querySelector('.ofw_modal_overlay');
                if (overlay) overlay.remove();
                window.location.reload();
            } else {
                alert('Error: ' + xhr.status);
            }
        }
    };
    xhr.send(formData);
}

document.addEventListener('DOMContentLoaded', function() {
    var tableData = [
        $jsDataStr
    ];

    var dt = new DataTable('#interfaceTable', {
        tableKey: 'interfaces',
        columns: [
            {key: 'name', title: 'Name'},
            {key: 'description', title: 'Description'},
            {key: 'ipaddress', title: 'IP Address', render: function(val, row) { return row.ipaddress + '/' + row.netmask; }},
            {key: 'addressingMode', title: 'Address Mode', render: function(val) { return val === '1' ? 'DHCP' : 'Static'; }},
            {key: 'type', title: 'Type'},
            {key: 'vlanId', title: 'VLAN ID'},
            {key: 'mtu', title: 'MTU'},
            {key: 'status', title: 'Status'}
        ],
        defaultSort: {key: 'name', order: 'asc'},
        data: tableData,
        rowKey: 'id',
        selectable: true,
        pageSize: 20,
        actions: ['create', 'edit', 'delete', 'refresh'],
        addAction: '$jsAddAction',
        interfaces: [$jsInterfacesStr],
        onAction: function(action, data) {
            if (action === 'delete') {
                // Create form with all selected interfaces
                var form = document.createElement('form');
                form.method = 'post';
                form.action = '/cgi-bin/interfaces.cgi';
                
                // Add ACTION field
                var actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'ACTION';
                actionInput.value = '$jsRemoveAction';
                form.appendChild(actionInput);
                
                // Add all selected interface names
                for (var i = 0; i < data.length; i++) {
                    var input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'IF_NAME';
                    input.value = data[i];
                    form.appendChild(input);
                }
                
                document.body.appendChild(form);
                form.submit();
            } else if (action === 'refresh') {
                document.location.reload();
            }
        }
    });
});
</script>
END

}


#############################################################
# add / edit interface                                      #
#############################################################


if ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'} ||
    $cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {

    my %selected = ();
    my $action = $cgiparams{'ACTION'};

    if ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'}) {
        $cgiparams{'MTU'} = '1500';
        $cgiparams{'BR_MEMBERS'} = '';
        $cgiparams{'BOND_MEMBERS'} = '';
        $cgiparams{'IPADDR_MASK'} = '0.0.0.0/0.0.0.0';
    } else {
        $cgiparams{'IPADDR_MASK'} = "$cgiparams{'IPADDRESS'}/$cgiparams{'NETMASK'}";
    }
#    &Header::openbigbox('100%', 'centor');
    print <<END
<table width='100%' height='33px' bgcolor='#69C'>
<tr align='center'>
    <td><strong>$action</strong></td>
</tr>
</table>
END
    ;

    print <<END;
<div class='input'>
<form method='post' action='$ENV{'SCRIPT_NAME'}' onsubmit='if (!form_check()) return false; if (thisForm.submitFlag) return false; thisForm.submitFlag = true;' autocomplete='nope'>
<table width='100%' cellspacing='5'>
<tbody>
<tr>
    <td class='label'>$Lang::tr{'name'}</td>
    <td width='75%'>
END

# interface name can not be edited.

    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        print "$cgiparams{'IF_NAME'}";
    } else {
        print "<input style='width:200px' type='text' name='IF_NAME' value='$cgiparams{'IF_NAME'}' size='20' maxlength='20' $disabled />";
    }
    print <<END;
    </td>
</tr>
<tr>
    <td class='label'>$Lang::tr{'description'}</td>
    <td width='75%'>
        <input style='width:260px' type='text' name='DESCRIPTION' value="$cgiparams{'DESCRIPTION'}" size='20' maxlength='20' $disabled />
    </td>
</tr>
<tr>
    <td class='label'>$Lang::tr{'type'}</td>
    <td width='75%'>
END

# interface type can not be edited.

        if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
            print "<select name='TYPE' style='width:200px' onchange='chg_intf_type(this.value)' disabled autocomplete='nope'>"
        } else {
            print "<select name='TYPE' style='width:200px' onchange='chg_intf_type(this.value)' autocomplete='nope'>";
        }

        if ($cgiparams{'TYPE'} eq '0') {
            print "<option value='0' selected>PHYSICAL</option>";
            print "<option value='1'>VLAN</option>";
            print "<option value='2'>BRIDGE</option>";
            print "<option value='3'>BOND</option>";
        } elsif (($cgiparams{'TYPE'} eq '1') || ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'})) {
            print "<option value='0'>PHYSICAL</option>";
            print "<option value='1' selected>VLAN</option>";
            print "<option value='2'>BRIDGE</option>";
            print "<option value='3'>BOND</option>";
        } else {
            print "<option value='0'>PHYSICAL</option>";
            print "<option value='1'>VLAN</option>";
            if ($cgiparams{'TYPE'} eq '2') {
                print "<option value='2' selected>BRIDGE</option>";
                print "<option value='3'>BOND</option>";
            } else {
                print "<option value='2'>BRIDGE</option>";
                print "<option value='3' selected>BOND</option>";
            }
        }
print "</td></tr>";

      if (($cgiparams{'TYPE'} eq '1') || ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'})) {
print <<END;
<tr id='row_vlan_if'>
    <td width='25%'>$Lang::tr{'interface'}</td>
    <td width='25%'>
        <select name='IFACE' style='width:200px'
END
    if ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'}) {
        print ">";
    } else {
        print " disabled>";
    }

foreach my $iface (sort keys %FW::interfaces) {
    print "<option value=$FW::interfaces{$iface}{'IFACE'} $selected{'IFACE'}{$FW::interfaces{$iface}{'IFACE'}}>$FW::interfaces{$iface}{'IFACE'}</option>";
}
print <<END;
        </select>
    </td>
</tr>
<tr id='row_vlan_id'>
    <td class='label'>$Lang::tr{'vlan id'}</td>
    <td><input style='width:200px' type='text' name='VLANID' id='vlan_id' maxlength='5' size='20' value='$cgiparams{'VLANID'}' validate='ValidationType.INTEGER'
END
    if ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'}) {
        print "";
    } else {
        print " disabled";
    }
print <<END;
></td>
</tr>
END
    }

    if (($cgiparams{'TYPE'} eq '3') || ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'})) {
print <<END;
<tr id='row_bond_line'><td class='splitline' colspan='4'><hr /></td></tr>
<tr id='row_bond_mbr_label'><td colspan='4'><strong>sub interface:</strong></td></tr>
<tr id='row_bond_member'>
    <td colspan='4' width='100%'>
        <table width='50%'>
            <tr><td>interfaces</td><td></td><td>selected interfaces</td><td></td></tr>
            <tr><td width='30%'><select name='agg_intf_av' size='5' style='width:100%' ondblclick='moveOptionField(document.forms[0].agg_intf_av, document.forms[0].agg_intf_mem);'>
END
            foreach my $iface (sort keys %FW::interfaces) {
                if ($FW::interfaces{$iface}{'BOND'} eq '') {
                print "<option value=$FW::interfaces{$iface}{'IFACE'}>$FW::interfaces{$iface}{'IFACE'}</option>";
                }
            }
print <<END;
                </select></td>
            <td valign='middle' align='center'>
                <a href='javascript:moveOptionField(document.forms[0].agg_intf_av, document.forms[0].agg_intf_mem);'>
                <i class='fa fa-arrow-circle-right'></i></a>
                <br><br>
                <a href='javascript:moveOptionField(document.forms[0].agg_intf_mem, document.forms[0].agg_intf_av);'>
                <i class='fa fa-arrow-circle-left'></i></a>
            </td>
            <td width='30%'><select name='agg_intf_mem' size='5' style='width:100%' ondblclick='moveOptionField(document.forms[0].agg_intf_mem, document.forms[0].agg_intf_av);'>
END
        if ($cgiparams{'BOND_MEMBERS'} ne '') {
           my @mbrs = split(/\#/, $cgiparams{'BOND_MEMBERS'});
           foreach my $opt (@mbrs) {
               print "<option value='$opt'>$opt</option>";
           }
        }
print <<END;
</select></td>
            <td width='40%'></td>
            </tr>
        </table>
    </td>
</tr>
            <input type=hidden name='BOND_MEMBERS' value=''>
END
    }

    if (($cgiparams{'TYPE'} eq '2') || ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'})) {
print <<END;
<tr id='row_br_line'><td class='splitline' colspan='4'><hr /></td></tr>
<tr id='row_br_mbr_label'><td colspan='4'><strong>bridge slaves:</strong></td></tr>
<tr id='row_br_member'>
    <td colspan='4' width='100%'>
        <table width='50%'>
            <tr><td>interfaces</td><td></td><td>selected interfaces</td><td></td></tr>
            <tr><td width='30%'><select name='br_intf_av' size='5' style='width:100%' ondblclick='moveOptionField(document.forms[0].br_intf_av, document.forms[0].BR_INTF_MEM);'>
END
            foreach my $iface (sort keys %FW::interfaces) {
                if ($FW::interfaces{$iface}{'BRIDGE'} eq '') {
                print "<option value=$FW::interfaces{$iface}{'IFACE'}>$FW::interfaces{$iface}{'IFACE'}</option>";
                }
            }
print <<END;
                </select></td>
            <td valign='middle' align='center'>
                <a href='javascript:moveOptionField(document.forms[0].br_intf_av, document.forms[0].BR_INTF_MEM);'>
                <i class='fa fa-arrow-circle-right'></i></a>
                <br><br>
                <a href='javascript:moveOptionField(document.forms[0].BR_INTF_MEM, document.forms[0].br_intf_av);'>
                <i class='fa fa-arrow-circle-left'></i></a>
            </td>
            <td width='30%'><select name='BR_INTF_MEM' size='5' style='width:100%' ondblclick='moveOptionField(document.forms[0].BR_INTF_MEM, document.forms[0].br_intf_av);'>
END
        if ($cgiparams{'BR_MEMBERS'} ne '') {
           my @mbrs = split(/\#/, $cgiparams{'BR_MEMBERS'});
           foreach my $opt (@mbrs) {
               print "<option value='$opt'>$opt</option>";
           }
        }
print <<END;
</select></td>
            <td width='40%'></td>
            </tr>
        </table>
    </td>
            <input type=hidden name='BR_MEMBERS' value=''>
</tr>
END
     }
print <<END;
</tbody>
<tbody id='addressing'>
<tr><td class='splitline' colspan='4'><hr /></td>
</tr>
<tr id='addressing_mode_title'>
<td colspan='4' nowrap><strong>Address Mode</strong></td>
</tr>
<tr id='addressing_mode_select'>
    <td colspan='4' nowrap>
        <input id='addressing_mode_manual' type='radio' name='ADDRESSING_MODE' value='0' onclick='change_mode()' checked=''><label for='addressing_mode_manual'>Static</label>&nbsp;&nbsp;&nbsp;
        <input id='addressing_mode_dhcp' type='radio' name='ADDRESSING_MODE' value='1' onclick='change_mode()'><label for='addressing_mode_dhcp'>DHCP</label>&nbsp;&nbsp;&nbsp;
    </td>
</tr>
<tr id='addressing_mode_ip_netmask'>
    <td class='intf_col'>$Lang::tr{'ip address'}/$Lang::tr{'netmask'}:</td>
    <td><input type='text' name='IPADDR_MASK' value='$cgiparams{'IPADDR_MASK'}' size='31' maxlength='31' onfocus='this.select()'></td>
</tr>
</tbody>

<tbody>
<tr><td class='splitline' colspan='4'><hr /></td>
<tr id='row_mtu'>
    <td><nobr><input type=checkbox id='mode_mtu' name='flag_mtu' onclick='thisForm.MTU.disabled = !this.checked' value='1">
    <td><label for='mode_mtu'>MTU</label></nobr></td>
    <td><input type='text' name='MTU' size='6' maxlength='5' value='$cgiparams{'MTU'}' validate='ValidationType.INTEGER' disabled> (bytes)</td>
</tr>
</tbody>

</table>
<table width='100%'>
<tr><td width='5%'></td>
<td>
<div class='footerbuttons'>
END
    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        print "<input type='submit' class='footbutton' name='ACTION' value='$Lang::tr{'update'}' />\n";
        print "<input type='hidden' name='OLD_IF_NAME' value='$cgiparams{'IF_NAME'}' />\n";
    }
    else {
        print "<input type='submit' class='footbutton' name='ACTION' value='$Lang::tr{'add'}' />\n";
    }
    print <<END;
        &nbsp&nbsp
        <input type='submit' class='footbutton' name='ACTION' value='$Lang::tr{'cancel'}' />
</div>
</td>
    <td  class='onlinehelp'>
        <a href='${General::adminmanualurl}/firewall-interfaces.html#section' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
</td>
</table>
</form>
</div>
END

    print <<END;
    <script type="text/javascript">
        function chg_intf_type(type) {
            var row_vlan_if = document.getElementById('row_vlan_if');
            var row_vlan_id = document.getElementById('row_vlan_id');
            var vlan_id = document.getElementById('vlan_id');
            var row_bond_line = document.getElementById('row_bond_line');
            var row_bond_mbr_label = document.getElementById('row_bond_mbr_label');
            var row_bond_member = document.getElementById('row_bond_member');
            var row_br_line = document.getElementById('row_br_line');
            var row_br_mbr_label = document.getElementById('row_br_mbr_label');
            var row_br_member = document.getElementById('row_br_member');

            if (row_vlan_if) row_vlan_if.style.display = 'none';
            if (row_vlan_id) {
                row_vlan_id.style.display = 'none';
                vlan_id.disabled = true;
            }
            if (row_bond_line) row_bond_line.style.display = 'none';
            if (row_bond_mbr_label) row_bond_mbr_label.style.display = 'none';
            if (row_bond_member) row_bond_member.style.display = 'none';
            if (row_br_line) row_br_line.style.display = 'none';
            if (row_br_mbr_label) row_br_mbr_label.style.display = 'none';
            if (row_br_member) row_br_member.style.display = 'none';

            if (type == 3) {
                if (row_bond_line) row_bond_line.style.display = '';
                if (row_bond_mbr_label) row_bond_mbr_label.style.display = '';
                if (row_bond_member) row_bond_member.style.display = '';
            } else if (type == 2) {
                if (row_br_line) row_br_line.style.display = '';
                if (row_br_mbr_label) row_br_mbr_label.style.display = '';
                if (row_br_member) row_br_member.style.display = '';
            } else if (type == 1) {
                if (row_vlan_if)  row_vlan_if.style.display = '';
                if (row_vlan_id) {
                    row_vlan_id.style.display = '';
END
                if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
                    print 'vlan_id.disabled = true;';
                } else {
                    print 'vlan_id.disabled = false;';
                }
print <<END;
                }
            }
        }
    </script>
    <script type="text/javascript">
         var mode = 0;
         var thisForm = document.forms[0];
         var row_ip_netmask = document.getElementById('addressing_mode_ip_netmask');

         change_mode();
END
         if ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'}) {
             print "chg_intf_type(1);";
         } else {
             print "chg_intf_type($cgiparams{'TYPE'});";
         }
print <<END;
         function addr_mode() {
             var obj = thisForm.ADDRESSING_MODE;
             if (obj.checked) return 0;
             return getRadioValue(obj);
         }
         function change_mode() {
             var val;
             var obj = thisForm.ADDRESSING_MODE;
             if (!obj) return;
             val = addr_mode();
             if (val == 0 || parseInt(obj.value) == 0) {
                  if (row_ip_netmask) row_ip_netmask.style.display = '';
             } else {
                  if (row_ip_netmask) row_ip_netmask.style.display = 'none';
             }
         }
         function form_check() {
             if (addr_mode() == 0) {
                 if (thisForm.IPADDR_MASK.value != '0.0.0.0/0.0.0.0') {
                      if (!verifyIPAndMask(thisForm.IPADDR_MASK, 'err_ip')) {
                          return false;
                      }
                 }
             }
             if (thisForm.MTU) {
                 var mtu_value = parseInt(thisForm.MTU.value);
                 if (mode == 0) {
                     if (thisForm.flag_mtu.checked && ((mtu_value < 68) || (mtu_value > 1500))) {
                         window.alert('err_mtu');
                         thisForm.MTU.select();
                         return false;
                     }
                 } else if (mode == 1) {
                     if (thisForm.flag_mtu.checked && ((mtu_value < 576) || (mtu_value > 1500))) {
                         window.alert('err_mtu');
                         thisForm.MTU.select();
                         return false;
                     }
                 }
             }

             var intf_type = document.forms[0].TYPE;

             if (intf_type && (intf_type.value & 0xff) == 2) {
                 cat_members(document.forms[0].BR_INTF_MEM, document.forms[0].BR_MEMBERS);
             }
             if (intf_type && (intf_type.value & 0xff) == 3) {
                 cat_members(document.forms[0].agg_intf_mem, document.forms[0].BOND_MEMBERS);
             }

             return true;
         }
    </script>
END

         #if (val == 1 || parseInt(obj.value) == 1) {
             #if ($('addressing_mode_ip_netmask')) $('addressing_mode_ip_netmask').style.display = '';
         #} else {
             #if ($('addressing_mode_ip_netmask')) $('addressing_mode_ip_netmask').style.display = 'none';
         #}
#    &Header::closebigbox();
}

&Header::closepage();

sub display_default_interfaces {
    my $id = 0;
    foreach my $iface (sort keys %FW::interfaces) {
        print "<tr class='table".int(($id % 2) + 1)."colour'>";
        my $ifaceColor = '';
        if ($FW::interfaces{$iface}{'COLOR'} eq 'GREEN_COLOR') {
            $ifaceColor = 'ofw_iface_bg_green';
        }
        elsif ($FW::interfaces{$iface}{'COLOR'} eq 'BLUE_COLOR') {
            $ifaceColor = 'ofw_iface_bg_blue';
        }
        elsif ($FW::interfaces{$iface}{'COLOR'} eq 'ORANGE_COLOR') {
            $ifaceColor = 'ofw_iface_bg_orange';
        }
        elsif ($FW::interfaces{$iface}{'COLOR'} eq 'RED_COLOR') {
            $ifaceColor = 'ofw_iface_bg_red';
        }
        elsif ($FW::interfaces{$iface}{'COLOR'} eq 'IPSEC_COLOR') {
            $ifaceColor = 'ofw_iface_bg_ipsec';
        }
        elsif ($FW::interfaces{$iface}{'COLOR'} eq 'OVPN_COLOR') {
            $ifaceColor = 'ofw_iface_bg_ovpn';
        }

        print "<td><strong>".&General::translateinterface($iface)."</strong></td>\n";
        print "<td align='center'>description</td>\n";
        print "<td align='center'>0.0.0.0/0</td>\n";
        print "<td align='center'>PHYSICAL</td>\n";
        print "<td align='center'></td>\n";
        print <<END
    <td align='center'><form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
        <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
        <input type='hidden' name='IF_NAME' value='&General::translateinterface($iface)' />
    </form>
    </td>
    <td></td>
END
        ;

        print "</tr>\n";
        $id++;
    }
}

# Validate Field Entries
sub validateIFaceParams {
    my $ifaceConfRef = shift;

    # Strip out commas which will break CSV config file.
    $cgiparams{'IF_NAME'} = &Header::cleanhtml($cgiparams{'IF_NAME'});

    if ($cgiparams{'IF_NAME'} eq '' && $cgiparams{'OLD_IF_NAME'} eq '') {
        $errormessage = $Lang::tr{'noIFacename'};
        return;
    }
    my $ifaceType = $cgiparams{'TYPE'};
    if ($ifaceType eq '' && $cgiparams{'OLD_IF_NAME'} ne '' && defined($ifaceConfRef->{$cgiparams{'OLD_IF_NAME'}})) {
        $ifaceType = $ifaceConfRef->{$cgiparams{'OLD_IF_NAME'}}{'TYPE'};
    }

    # Only VLAN (type 1) requires IFACE field
    if ($ifaceType eq '1') {
        if ($cgiparams{'IFACE'} eq '') {
            $errormessage = $Lang::tr{'noIFace'};
            return;
        }

        if ($cgiparams{'IFACE'} !~ /^[a-zA-Z0-9]([a-zA-Z0-9:_\-\.])*$/) {
            $errormessage = $Lang::tr{'falseIFace'};
            return;
        }
    }

    # a new interface has to have a different name
    if (defined($ifaceConfRef->{$cgiparams{'IF_NAME'}})) {

        # when this is an update, the old name is allowed
        unless (lc($cgiparams{'ACTION'}) eq lc($Lang::tr{'edit'}))
        {
            $errormessage .= "$Lang::tr{'iface name exists already'} <br />";
        }
    }
}

# ip link command
sub ip_link_add_cmd {
    &General::log("DEBUG ip_link_add_cmd - TYPE: $cgiparams{'TYPE'}");
    &General::log("DEBUG ip_link_add_cmd - IF_NAME: $cgiparams{'IF_NAME'}");
    &General::log("DEBUG ip_link_add_cmd - IFACE: $cgiparams{'IFACE'}");
    &General::log("DEBUG ip_link_add_cmd - VLANID: $cgiparams{'VLANID'}");

    my $cmd_result;
    my $exit_code;

    # Check if interface already exists
    my $check_cmd = "ip link show $cgiparams{'IF_NAME'}";
    my $check_result = `$check_cmd 2>&1`;
    my $check_exit = $? >> 8;
    &General::log("DEBUG ip_link_add_cmd - Check if exists: $check_result, exit code: $check_exit");

    if ($check_exit == 0) {
        # Interface exists, delete it first
        &General::log("DEBUG ip_link_add_cmd - Interface $cgiparams{'IF_NAME'} already exists, deleting first");
        my $del_cmd = "ip link delete $cgiparams{'IF_NAME'}";
        my $del_result = `$del_cmd 2>&1`;
        my $del_exit = $? >> 8;
        &General::log("DEBUG ip_link_add_cmd - Delete result: $del_result, exit code: $del_exit");
    }

    if ($cgiparams{'TYPE'} eq '1') {
        my $vlan_cmd = "ip link add link $cgiparams{'IFACE'} name $cgiparams{'IF_NAME'} type vlan id $cgiparams{'VLANID'}";
        &General::log("DEBUG ip_link_add_cmd - Creating VLAN");
        &General::log("DEBUG ip_link_add_cmd - Full command: $vlan_cmd");
        $cmd_result = `$vlan_cmd 2>&1`;
        $exit_code = $? >> 8;
        &General::log("DEBUG ip_link_add_cmd - VLAN result: $cmd_result, exit code: $exit_code");
        $errormessage = $cmd_result if $exit_code != 0;
    }
    if ($cgiparams{'TYPE'} eq '2') {
        my $bridge_cmd = "ip link add name $cgiparams{'IF_NAME'} type bridge";
        &General::log("DEBUG ip_link_add_cmd - Creating BRIDGE");
        &General::log("DEBUG ip_link_add_cmd - Full command: $bridge_cmd");
        $cmd_result = `$bridge_cmd 2>&1`;
        $exit_code = $? >> 8;
        &General::log("DEBUG ip_link_add_cmd - BRIDGE result: $cmd_result, exit code: $exit_code");
        $errormessage = $cmd_result if $exit_code != 0;
    }
    if ($cgiparams{'TYPE'} eq '3') {
        my $bond_cmd = "ip link add name $cgiparams{'IF_NAME'} type bond";
        &General::log("DEBUG ip_link_add_cmd - Creating BOND");
        &General::log("DEBUG ip_link_add_cmd - Full command: $bond_cmd");
        $cmd_result = `$bond_cmd 2>&1`;
        $exit_code = $? >> 8;
        &General::log("DEBUG ip_link_add_cmd - BOND result: $cmd_result, exit code: $exit_code");
        $errormessage = $cmd_result if $exit_code != 0;
    }

    # Enable interface if no error
    unless ($errormessage) {
        my $up_cmd = "ip link set $cgiparams{'IF_NAME'} up";
        &General::log("DEBUG ip_link_add_cmd - Enabling interface");
        &General::log("DEBUG ip_link_add_cmd - Full command: $up_cmd");
        my $up_result = `$up_cmd 2>&1`;
        $exit_code = $? >> 8;
        &General::log("DEBUG ip_link_add_cmd - ip link set up result: $up_result, exit code: $exit_code");

        # Configure IP if static mode and IP is provided
        if ($cgiparams{'ADDRESSING_MODE'} eq '0' && $cgiparams{'IPADDR_MASK'} ne '' && $cgiparams{'IPADDR_MASK'} ne '0.0.0.0/0.0.0.0') {
            my $ip_cmd = "ip addr add $cgiparams{'IPADDR_MASK'} dev $cgiparams{'IF_NAME'}";
            &General::log("DEBUG ip_link_add_cmd - Configuring IP");
            &General::log("DEBUG ip_link_add_cmd - Full command: $ip_cmd");
            my $ip_result = `$ip_cmd 2>&1`;
            $exit_code = $? >> 8;
            &General::log("DEBUG ip_link_add_cmd - ip addr add result: $ip_result, exit code: $exit_code");
        }
    }
}

