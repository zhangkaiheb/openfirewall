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
# MENUTHRDLVL "interfaces" 010 "interface group" "interface group"
#
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

my %custIfaces = ();
&DATA::readCustIfaces(\%custIfaces);

$cgiparams{'KEY'}            = '';
$cgiparams{'IFACE'}          = '';
$cgiparams{'IF_NAME'}     = '';
&General::getcgihash(\%cgiparams);

$cgiparams{'IF_NAME'} = &Header::cleanConfNames($cgiparams{'IF_NAME'});

if ($cgiparams{'ACTION'} eq $Lang::tr{'add'}) {
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
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
        `/usr/local/bin/setfwrules --ofw < /dev/null > /dev/null 2>&1 &`;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'update'}) {
    &validateIFaceParams(\%custIfaces);
    if ($errormessage) {
        $cgiparams{'ACTION'} = $Lang::tr{'edit'};
    }
    else {
        my $ifaceName    = $cgiparams{'IF_NAME'};

        $custIfaces{$cgiparams{'OLD_IF_NAME'}}{'IPADDRESS'}   = $cgiparams{'IPADDRESS'};
        $custIfaces{$cgiparams{'OLD_IF_NAME'}}{'NETMASK'}     = $cgiparams{'NETMASK'};
        $custIfaces{$cgiparams{'OLD_IF_NAME'}}{'DESCRIPTION'} = $cgiparams{'DESCRIPTION'};
        $custIfaces{$cgiparams{'OLD_IF_NAME'}}{'MTU'}         = $cgiparams{'MTU'};
        $custIfaces{$cgiparams{'IF_NAME'}}{'MBR_CNT'}         = $cgiparams{'MBR_CNT'};
        for (my $i; $i < $cgiparams{'MBR_CNT'}; $i++) {
            my $key = 'MEMBER'.'$i';
            $custIfaces{$cgiparams{'IF_NAME'}}{'key'}   = $cgiparams{'key'};
        }

        &DATA::saveCustIfaces(\%custIfaces);

        &General::log("$Lang::tr{'iface updated'}: $cgiparams{'IF_NAME'}");
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
        `/usr/local/bin/setfwrules --all < /dev/null > /dev/null 2>&1 &`;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    delete($custIfaces{$cgiparams{'IF_NAME'}});

    &DATA::saveCustIfaces(\%custIfaces);

    &General::log("$Lang::tr{'iface removed'}: $cgiparams{'IF_NAME'}");
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
    `/usr/local/bin/setfwrules --ofw < /dev/null > /dev/null 2>&1 &`;
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'cancel'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
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
#    &Header::openbigbox('100%', 'left');
#    &Header::openbox('100%', 'left', "$Lang::tr{'custom interfaces'}:");
    print <<END;
<div align='center' style='margin-top:0px'>
<div align='left' tyle='margin-top:5px'>
<table width='100%' height='33px' align='center'>
<tr style='background-color: #F2F2F2;'>
    <td align='right'>
       <form method='post' action='$ENV{'SCRIPT_NAME'}'>
       <input style='background-color: #F2F2F2;' class='buttons' type='submit' name='ACTION' value='$Lang::tr{'add interface'}' />
       </form>
    </td>
</tr>
</table>
<table width='100%' height='33px' align='center'>
<tr class='headbar' align="center">
    <td width='15%'><strong>$Lang::tr{'name'}</strong></td>
    <td width='20%'><strong>$Lang::tr{'description'}</strong></td>
    <td width='40%'><strong>$Lang::tr{'ip address'}</strong></td>
    <td width='10%'><strong>$Lang::tr{'type'}</strong></td>
    <td width='10%'><strong>$Lang::tr{'status'}</strong></td>
    <td width='10px'>&nbsp;</td>
    <td width='10px'>&nbsp;</td>
</tr>
END

    &display_custom_interfaces(\%custIfaces);

#    &display_default_interfaces();
    print <<END;
</table>
</div>
END

#    &Header::closebigbox();
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

        if (($cgiparams{'TYPE'} eq '1') || ($cgiparams{'ACTION'} eq $Lang::tr{'add interface'})) {
            print "<option value='1' selected>VLAN</option>";
            print "<option value='2'>BRIDGE</option>";
            print "<option value='3'>BOND</option>";
        } else {
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

sub display_custom_interfaces {
    my $custIfaceRef = shift;
    my @sortedKeys = &General::sortHashArray($sort_col, $sort_type, $sort_dir, $custIfaceRef);
    my $id = 0;

    foreach my $ifaceName (@sortedKeys) {

    my $type = '';
    if ($custIfaceRef->{$ifaceName}{'TYPE'} eq '0') {
        $type = 'PHYSICAL';
    }
    if ($custIfaceRef->{$ifaceName}{'TYPE'} eq '1') {
        $type = 'VLAN';
    }
    if ($custIfaceRef->{$ifaceName}{'TYPE'} eq '2') {
        $type = 'BRIDGE';
    }
    if ($custIfaceRef->{$ifaceName}{'TYPE'} eq '3') {
        $type = 'BOND';
    }

    if ($custIfaceRef->{$ifaceName}{'IPADDRESS'} eq '') {
        $custIfaceRef->{$ifaceName}{'IPADDRESS'} = '0.0.0.0';
    }
    if ($custIfaceRef->{$ifaceName}{'NETMASK'} eq '') {
        $custIfaceRef->{$ifaceName}{'NETMASK'} = '0.0.0.0';
    }

    print "<tr class='table".int(($id % 2) + 1)."colour'>";
    print <<END;
    <td><strong>$ifaceName</strong></td>
    <td align='center'>$custIfaceRef->{$ifaceName}{'DESCRIPTION'}</td>
    <td align='center'>$custIfaceRef->{$ifaceName}{'IPADDRESS'}/$custIfaceRef->{$ifaceName}{'NETMASK'}</td>
    <td align='center'>$type</td>
    <td align='center'>$custIfaceRef->{$ifaceName}{'ADMSTATUS'}</td>
    <td align='center'>
    <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
        <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
        <input type='hidden' name='IF_NAME' value='$ifaceName' />
        <input type='hidden' name='TYPE' value=$custIfaceRef->{$ifaceName}{'TYPE'} />
        <input type='hidden' name='DESCRIPTION' value=$custIfaceRef->{$ifaceName}{'DESCRIPTION'} />
        <input type='hidden' name='IPADDRESS' value=$custIfaceRef->{$ifaceName}{'IPADDRESS'} />
        <input type='hidden' name='NETMASK' value=$custIfaceRef->{$ifaceName}{'NETMASK'} />
        <input type='hidden' name='MTU' value=$custIfaceRef->{$ifaceName}{'MTU'} />
        <input type='hidden' name='BR_MEMBERS' value=$custIfaceRef->{$ifaceName}{'BR_MEMBERS'} />
        <input type='hidden' name='VLANID' value=$custIfaceRef->{$ifaceName}{'VLANID'} />
        <input type='hidden' name='USED_COUNT' value='$custIfaceRef->{$ifaceName}{'USED_COUNT'}' />
    </form>
    </td>
END
        if ($custIfaceRef->{$ifaceName}{'USED_COUNT'} > 0) {
            print "<td align='center'></td>";
        }
        else {
            print <<END;
    <td align='center'>
    <form method='post' name='frmb$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
        <input type='hidden' name='IF_NAME' value='$ifaceName' />
    </form>
    </td>
END
        }
        print "</tr>\n";
        $id++;
    }
}

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
    if ($cgiparams{'IFACE'} eq '') {
        $errormessage = $Lang::tr{'noIFace'};
        return;
    }

    if ($cgiparams{'IFACE'} !~ /^[a-zA-Z0-9]([a-zA-Z0-9:_\-\.])*$/) {
        $errormessage = $Lang::tr{'falseIFace'};
        return;
    }

    # a new interface has to have a different name
    if (defined($ifaceConfRef->{$cgiparams{'IF_NAME'}})) {

        # when this is an update, the old name is allowed
        unless ($cgiparams{'ACTION'} eq $Lang::tr{'update'})
        {
            $errormessage .= "$Lang::tr{'iface name exists already'} <br />";
        }
    }
}

# ip link command
sub ip_link_add_cmd {

    if ($cgiparams{'TYPE'} eq 'VLAN') {
        $errormessage = `ip link add link $cgiparams{'IFACE'} name $cgiparams{'IF_NAME'} type vlan id $cgiparams{'IFACE'}`;
    }
    if ($cgiparams{'TYPE'} eq 'BRIDGE') {
        $errormessage = `ip link add name $cgiparams{'IF_NAME'} type bridge`;
    }
    if ($cgiparams{'TYPE'} eq 'BOND') {
        $errormessage = `ip link add name $cgiparams{'IF_NAME'} type bond`;
    }
}

