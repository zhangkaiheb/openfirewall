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
# MENUTHRDLVL "alt services" 010 "alt services" "alt services"
#
# Make sure translation exists $Lang::tr{'alt services'}

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

my %custServices = ();
&DATA::readCustServices(\%custServices);

my %icmpTypeHash = ();
my @icmptypes    = &DATA::read_icmptypes(\%icmpTypeHash);

my (%selected, %checked);

# Sort options
$sort_col = 'SERVICE_NAME' if ($sort_col eq '1');

$cgiparams{'SERVICE_NAME'}    = '';
$cgiparams{'PORTS'}           = '';
$cgiparams{'PROTOCOL'}        = '6';
$cgiparams{'PORT_INVERT'}     = 'off';
$cgiparams{'PROTOCOL_INVERT'} = 'off';
$cgiparams{'ICMP_TYPE'}       = 'BLANK';
&General::getcgihash(\%cgiparams);

$cgiparams{'SERVICE_NAME'} = &Header::cleanConfNames($cgiparams{'SERVICE_NAME'});

if ($cgiparams{'ACTION'} eq $Lang::tr{'add'}) {
    &validateServiceParams(\%custServices);

    unless ($errormessage) {
        $custServices{$cgiparams{'SERVICE_NAME'}}{'PORT_NR'}         = $cgiparams{'PORTS'};
        $custServices{$cgiparams{'SERVICE_NAME'}}{'PROTOCOL'}        = $cgiparams{'PROTOCOL'};
        $custServices{$cgiparams{'SERVICE_NAME'}}{'PORT_INVERT'}     = $cgiparams{'PORT_INVERT'};
        $custServices{$cgiparams{'SERVICE_NAME'}}{'PROTOCOL_INVERT'} = $cgiparams{'PROTOCOL_INVERT'};
        $custServices{$cgiparams{'SERVICE_NAME'}}{'ICMP_TYPE'}       = $cgiparams{'ICMP_TYPE'};
        $custServices{$cgiparams{'SERVICE_NAME'}}{'USED_COUNT'}      = 0;

        &DATA::saveCustServices(\%custServices);

        &General::log("$Lang::tr{'service added'}: $cgiparams{'SERVICE_NAME'}");
        
        # Send redirect to avoid form resubmission
        print "Location: $ENV{'SCRIPT_NAME'}\n\n";
        exit;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'update'}) {
    &validateServiceParams(\%custServices);

    if ($errormessage) {
        $cgiparams{'ACTION'} = $Lang::tr{'edit'};
    }
    else {
        my $serviceName    = $cgiparams{'SERVICE_NAME'};
        my $serviceNameOld = $cgiparams{'OLD_SERVICE_NAME'};
        $custServices{$serviceNameOld}{'PORT_NR'}         = $cgiparams{'PORTS'};
        $custServices{$serviceNameOld}{'PROTOCOL'}        = $cgiparams{'PROTOCOL'};
        $custServices{$serviceNameOld}{'PORT_INVERT'}     = $cgiparams{'PORT_INVERT'};
        $custServices{$serviceNameOld}{'PROTOCOL_INVERT'} = $cgiparams{'PROTOCOL_INVERT'};
        $custServices{$serviceNameOld}{'ICMP_TYPE'}       = $cgiparams{'ICMP_TYPE'};

        # if the name (==Key) has changed, we have to copy/move the old data to new key
        if ($serviceName ne $serviceNameOld) {
            $custServices{$serviceName}{'PORT_NR'}         = $custServices{$serviceNameOld}{'PORT_NR'};
            $custServices{$serviceName}{'PROTOCOL'}        = $custServices{$serviceNameOld}{'PROTOCOL'};
            $custServices{$serviceName}{'PORT_INVERT'}     = $custServices{$serviceNameOld}{'PORT_INVERT'};
            $custServices{$serviceName}{'PROTOCOL_INVERT'} = $custServices{$serviceNameOld}{'PROTOCOL_INVERT'};
            $custServices{$serviceName}{'ICMP_TYPE'}       = $custServices{$serviceNameOld}{'ICMP_TYPE'};
            $custServices{$serviceName}{'USED_COUNT'}      = $custServices{$serviceNameOld}{'USED_COUNT'};

            delete($custServices{$serviceNameOld});
        }
        &DATA::saveCustServices(\%custServices);

        &General::log("$Lang::tr{'service updated'}: $cgiparams{'SERVICE_NAME'}");
        
        # Send redirect to avoid form resubmission
        print "Location: $ENV{'SCRIPT_NAME'}\n\n";
        exit;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    delete($custServices{$cgiparams{'SERVICE_NAME'}});

    &DATA::saveCustServices(\%custServices);
    &General::log("$Lang::tr{'service removed'}: $cgiparams{'SERVICE_NAME'}");

    # Send redirect to avoid form resubmission
    print "Location: $ENV{'SCRIPT_NAME'}\n\n";
    exit;
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'reset'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

if ($cgiparams{'ACTION'} eq '') {
    $cgiparams{'KEY'}             = '';
    $cgiparams{'PORTS'}           = '';
    $cgiparams{'PROTOCOL'}        = '6';
    $cgiparams{'SERVICE_NAME'}    = '';
    $cgiparams{'PORT_INVERT'}     = 'off';
    $cgiparams{'PROTOCOL_INVERT'} = 'off';
    $cgiparams{'ICMP_TYPE'}       = 'BLANK';
}

# Bring in the protocols file built from /etc/protocols into hash %protocol
require '/usr/lib/ofw/protocols.pl';

&Header::openpage($Lang::tr{'services settings'}, 1, '');

&Header::openbigbox('100%', 'left');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

# Convert services to JavaScript format
my @jsData;
my @sortedKeys = sort keys %custServices;
foreach my $serviceName (@sortedKeys) {
    my $svc = $custServices{$serviceName};
    my $port_inv = '';
    my $prot_inv = '';
    my $icmp_inv = '';
    
    if ($svc->{'PORT_INVERT'} eq 'on') {
        $port_inv = "! ";
    }
    
    if ($svc->{'PROTOCOL_INVERT'} eq 'on') {
        $prot_inv = "! ";
    }
    
    my $ports = $port_inv . &cleanport($svc->{'PORT_NR'});
    my $protocol = &cleanprotocol($svc->{'PROTOCOL'});
    if ($prot_inv) {
        $protocol = $prot_inv . $protocol;
    }
    
    my $icmpType = 'N/A';
    if ($svc->{'ICMP_TYPE'} ne 'BLANK') {
        $icmpType = $icmpTypeHash{$svc->{'ICMP_TYPE'}} . " (" . $svc->{'ICMP_TYPE'} . ")";
        if ($svc->{'PROTOCOL_INVERT'} eq 'on' && $svc->{'PROTOCOL'} =~ /icmp/ && $svc->{'ICMP_TYPE'} ne 'ALL') {
            $icmpType = "! " . $icmpType;
        }
    }
    
    push @jsData, sprintf(
        "{id:'%s',name:'%s',ports:'%s',protocol:'%s',icmpType:'%s',usedCount:%d}",
        $serviceName, $serviceName, $ports, $protocol, $icmpType, $svc->{'USED_COUNT'}
    );
}
my $jsDataStr = join(",\n", @jsData);

# Build protocol options
my $protocolOptions = '';
foreach my $line (sort keys %Protocols::protocols) {
    my $label = uc($line);
    if ($Protocols::protocols{$line} ne '6' && 
        $Protocols::protocols{$line} ne '17' && 
        $Protocols::protocols{$line} ne '1' && 
        $Protocols::protocols{$line} ne '47') {
        $label .= "&nbsp;(#&nbsp;$Protocols::protocols{$line})";
    }
    $protocolOptions .= "<option value='$line'>$label</option>\n";
}

# Build ICMP type options
my $icmpTypeOptions = "<option value='BLANK'>-- $Lang::tr{'valid icmp types'} --</option>\n";
$icmpTypeOptions .= "<option value='ALL'>$Lang::tr{'all icmp types'}</option>\n";
foreach my $line (@icmptypes) {
    $icmpTypeOptions .= "<option value='$line'>$icmpTypeHash{$line} ($line)</option>\n";
}

print <<END;
<script src="/include/datatable.js"></script>
<script>
const servicesData = [
$jsDataStr
];

document.addEventListener('DOMContentLoaded', function() {
    const table = new DataTable('#servicesTable', {
        data: servicesData,
        columns: [
            { key: 'name', title: '$Lang::tr{'servicename'}', sortable: true },
            { key: 'ports', title: '$Lang::tr{'ports'}', sortable: true },
            { key: 'protocol', title: '$Lang::tr{'protocol'}', sortable: true },
            { key: 'icmpType', title: '$Lang::tr{'icmp type'}', sortable: true },
            { key: 'usedCount', title: '$Lang::tr{'used'}', sortable: true }
        ],
        defaultSort: { key: 'name', order: 'asc' },
        pageSize: 20,
        selectable: true,
        actions: ['create', 'edit', 'delete', 'refresh'],
        disabledActions: [],
        onAddModal: function() {
            openAddServiceModal();
        },
        onEditModal: function(rowData) {
            openEditServiceModal(rowData);
        },
        onDeleteConfirm: function(selectedIds) {
            deleteServices(selectedIds);
        }
    });
    table.render();
});

function openAddServiceModal() {
    const overlay = document.createElement('div');
    overlay.className = 'ofw_modal_overlay';
    overlay.innerHTML = \`
        <div class="ofw_modal_dialog" style="width:500px;">
            <div class="ofw_modal_header">
                <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>
                <span class="ofw_modal_title">$Lang::tr{'add service'}</span>
                <button class="ofw_modal_close">&times;</button>
            </div>
            <div class="ofw_modal_body">
                <form id="addServiceForm" method="post" action="$ENV{'SCRIPT_NAME'}">
                    <input type="hidden" name="ACTION" value="$Lang::tr{'add'}">
                    <table style="width:100%;border-collapse:collapse;">
                        <tr>
                            <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>$Lang::tr{'servicename'}:</label></td>
                            <td><input type="text" name="SERVICE_NAME" style="width:200px;" required maxlength="20"></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>$Lang::tr{'protocol'}:</label></td>
                            <td>
                                <select name="PROTOCOL" style="width:200px;">
                                    <option value="tcp" selected>TCP</option>
                                    <option value="udp">UDP</option>
                                    <option value="tcpudp">TCP &amp; UDP</option>
                                    <option value="icmp">ICMP</option>
                                    <option value="gre">GRE</option>
                                    $protocolOptions
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>$Lang::tr{'ports'}:</label></td>
                            <td><input type="text" name="PORTS" style="width:200px;" maxlength="11"></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>$Lang::tr{'invert'}:</label></td>
                            <td>
                                <input type="checkbox" name="PORT_INVERT" value="on"> $Lang::tr{'ports'}
                                &nbsp;&nbsp;
                                <input type="checkbox" name="PROTOCOL_INVERT" value="on"> $Lang::tr{'protocol'}
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>$Lang::tr{'icmp type'}:</label></td>
                            <td>
                                <select name="ICMP_TYPE" style="width:200px;">
                                    $icmpTypeOptions
                                </select>
                            </td>
                        </tr>
                    </table>
                </form>
            </div>
            <div class="ofw_modal_footer">
                <button class="ofw_btn ofw_btn_cancel">Cancel</button>
                <button class="ofw_btn ofw_btn_primary" onclick="submitAddServiceForm()">Add</button>
            </div>
        </div>
    \`;
    
    document.body.appendChild(overlay);
    
    overlay.querySelector('.ofw_modal_close').addEventListener('click', () => {
        overlay.remove();
    });
    
    overlay.querySelector('.ofw_btn_cancel').addEventListener('click', () => {
        overlay.remove();
    });
}

function submitAddServiceForm() {
    const form = document.getElementById('addServiceForm');
    const formData = new FormData(form);
    
    fetch('$ENV{'SCRIPT_NAME'}', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.redirected) {
            window.location.href = response.url;
        } else {
            window.location.reload();
        }
    })
    .catch(error => {
        alert('Error: ' + error.message);
    });
}

function openEditServiceModal(rowData) {
    if (!rowData) return;
    
    const overlay = document.createElement('div');
    overlay.className = 'ofw_modal_overlay';
    overlay.innerHTML = \`
        <div class="ofw_modal_dialog" style="width:500px;">
            <div class="ofw_modal_header">
                <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
                <span class="ofw_modal_title">$Lang::tr{'edit service'}</span>
                <button class="ofw_modal_close">&times;</button>
            </div>
            <div class="ofw_modal_body">
                <form id="editServiceForm" method="post" action="$ENV{'SCRIPT_NAME'}">
                    <input type="hidden" name="ACTION" value="$Lang::tr{'update'}">
                    <input type="hidden" name="OLD_SERVICE_NAME" value="\${rowData.id}">
                    <table style="width:100%;border-collapse:collapse;">
                        <tr>
                            <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>$Lang::tr{'servicename'}:</label></td>
                            <td><input type="text" name="SERVICE_NAME" value="\${rowData.id}" style="width:200px;" required maxlength="20"></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>$Lang::tr{'protocol'}:</label></td>
                            <td>
                                <select name="PROTOCOL" style="width:200px;">
                                    <option value="tcp">TCP</option>
                                    <option value="udp">UDP</option>
                                    <option value="tcpudp">TCP &amp; UDP</option>
                                    <option value="icmp">ICMP</option>
                                    <option value="gre">GRE</option>
                                    $protocolOptions
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>$Lang::tr{'ports'}:</label></td>
                            <td><input type="text" name="PORTS" value="\${rowData.ports}" style="width:200px;" maxlength="11"></td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>$Lang::tr{'invert'}:</label></td>
                            <td>
                                <input type="checkbox" name="PORT_INVERT" value="on"> $Lang::tr{'ports'}
                                &nbsp;&nbsp;
                                <input type="checkbox" name="PROTOCOL_INVERT" value="on"> $Lang::tr{'protocol'}
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:8px 12px 8px 0;text-align:right;"><label>$Lang::tr{'icmp type'}:</label></td>
                            <td>
                                <select name="ICMP_TYPE" style="width:200px;">
                                    $icmpTypeOptions
                                </select>
                            </td>
                        </tr>
                    </table>
                </form>
            </div>
            <div class="ofw_modal_footer">
                <button class="ofw_btn ofw_btn_cancel">Cancel</button>
                <button class="ofw_btn ofw_btn_primary" onclick="submitEditServiceForm()">Save</button>
            </div>
        </div>
    \`;
    
    document.body.appendChild(overlay);
    
    overlay.querySelector('.ofw_modal_close').addEventListener('click', () => {
        overlay.remove();
    });
    
    overlay.querySelector('.ofw_btn_cancel').addEventListener('click', () => {
        overlay.remove();
    });
}

function submitEditServiceForm() {
    const form = document.getElementById('editServiceForm');
    const formData = new FormData(form);
    
    fetch('$ENV{'SCRIPT_NAME'}', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.redirected) {
            window.location.href = response.url;
        } else {
            window.location.reload();
        }
    })
    .catch(error => {
        alert('Error: ' + error.message);
    });
}

function deleteServices(selectedIds) {
    if (selectedIds.length === 0) return;
    
    const msg = selectedIds.length === 1 
        ? 'Are you sure you want to delete this service?'
        : 'Are you sure you want to delete ' + selectedIds.length + ' services?';
    
    if (!confirm(msg)) return;
    
    // Delete services one by one
    let deleteCount = 0;
    selectedIds.forEach(id => {
        const formData = new FormData();
        formData.append('ACTION', '$Lang::tr{'remove'}');
        formData.append('SERVICE_NAME', id);
        
        fetch('$ENV{'SCRIPT_NAME'}', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            deleteCount++;
            if (deleteCount === selectedIds.length) {
                window.location.reload();
            }
        })
        .catch(error => {
            alert('Error deleting service: ' + error.message);
        });
    });
}
</script>
<div id="servicesTable"></div>
END

&Header::closebigbox();
&Header::closepage();

sub cleanprotocol {
    my $prtcl = $_[0];
    chomp($prtcl);
    if ($prtcl eq 'tcpudp') {
        $prtcl = 'TCP &amp; UDP';
    }
    else {
        $prtcl = uc($prtcl);
    }
    return $prtcl;
}

sub cleanport {
    my $prt = $_[0];
    chomp($prt);

    # Format the ports
    $prt =~ s/-/ - /;
    $prt =~ s/:/ - /;
    return $prt;
}

# Validate Field Entries
sub validateServiceParams {
    my $cServicesRef = shift;

    if ($cgiparams{'SERVICE_NAME'} eq '') {
        $errormessage = $Lang::tr{'noservicename'};
        return;
    }

    # Strip out commas which will break CSV config file.
    $cgiparams{'SERVICE_NAME'} = &Header::cleanhtml($cgiparams{'SERVICE_NAME'});

    if (   $cgiparams{'PROTOCOL'} eq 'tcp'
        || $cgiparams{'PROTOCOL'} eq 'udp'
        || $cgiparams{'PROTOCOL'} eq 'tcpudp')
    {

        # Get rid of dashes in port ranges
        $cgiparams{'PORTS'} =~ tr/-/:/;

        # code to substitue wildcards
        if ($cgiparams{'PORTS'} eq "*") {
            $cgiparams{'PORTS'} = "1:65535";
        }
        if ($cgiparams{'PORTS'} =~ /^(\D)\:(\d+)$/) {
            $cgiparams{'PORTS'} = "1:$2";
        }
        if ($cgiparams{'PORTS'} =~ /^(\d+)\:(\D)$/) {
            $cgiparams{'PORTS'} = "$1:65535";
        }

        # watch the order here, the validportrange sets errormessage=''
        $errormessage = &General::validportrange($cgiparams{'PORTS'}, 'src');
        if ($errormessage) { return; }
    }
    else {
        $cgiparams{'PORTS'} = "";
    }
    if ($cgiparams{'PROTOCOL'} ne 'icmp') {
        $cgiparams{'ICMP_TYPE'} = "BLANK";
    }

    if ($cgiparams{'PORTS'} eq '' && $cgiparams{'PORT_INVERT'} ne 'off') {
        $cgiparams{'PORT_INVERT'} = 'off';
    }
    if ($cgiparams{'SERVICE_NAME'} eq '') {
        $errormessage = $Lang::tr{'noservicename'};
        return;
    }
    if ($cgiparams{'PROTOCOL'} eq 'icmp' && $cgiparams{'ICMP_TYPE'} eq 'BLANK') {
        $errormessage = $Lang::tr{'icmp selected but no type'};
        return;
    }

    # if we have more than one protocol, we can't inverte protocol
    if ($cgiparams{'PROTOCOL'} eq 'tcpudp') {
        $cgiparams{'PROTOCOL_INVERT'} = 'off';
    }

    # a new service has to have a different name
    if (defined($cServicesRef->{$cgiparams{'SERVICE_NAME'}})) {

        # when this is an update, the old name is allowed
        unless ($cgiparams{'ACTION'} eq $Lang::tr{'update'}
            && $cgiparams{'SERVICE_NAME'} eq $cgiparams{'OLD_SERVICE_NAME'})
        {
            $errormessage .= "$Lang::tr{'service name exists already'} <br />";
        }
    }

    my %service = ();
    $service{'PROTOCOL'} = $cgiparams{'PROTOCOL'};
    $service{'PORT_INVERT'} = $cgiparams{'PORT_INVERT'};
    $service{'PROTOCOL_INVERT'} = $cgiparams{'PROTOCOL_INVERT'};
    $service{'PORT'} = $cgiparams{'PORTS'};
    $service{'IS_RANGE'} = 0;
    if($service{'PORT'} =~ /^(\d+)\:(\d+)$/) {
        $service{'IS_RANGE'} = 1;
    }

    $errormessage .= &DATA::isUsedInPortfwOk($cgiparams{'SERVICE_NAME'}, \%service);

}
