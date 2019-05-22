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

$cgiparams{'NEIGH_ID'} = 0;
$cgiparams{'STATUS'} = 0;
&General::getcgihash(\%cgiparams);

if ($cgiparams{'ACTION'} eq $Lang::tr{'add'}) {
    &validateNeighbourParams(\@custNeighbours);

    unless ($errormessage) {
        my $neighbour = $cgiparams{'IP'}.",".$cgiparams{'IF_NAME'}.",".$cgiparams{'MAC_ADDRESS'}.",".$cgiparams{'STATUS'};

        push(@custNeighbours, $neighbour);
        &saveCustNeighbours(\@custNeighbours);

        &General::log("$Lang::tr{'neighbour added'}: $cgiparams{'IP'} $cgiparams{'MAC_ADDRESS'}");
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'update'}) {
    &validateNeighbourParams(\@custNeighbours);
    if ($errormessage) {
        $cgiparams{'ACTION'} = $Lang::tr{'edit'};
    } else {
        my $neighbour = $cgiparams{'IP'}.",".$cgiparams{'IF_NAME'}.",".$cgiparams{'MAC_ADDRESS'}.",".$cgiparams{'STATUS'};

        $custNeighbours[$cgiparams{NEIGH_ID}] = $neighbour;
        &saveCustNeighbours(\@custNeighbours);

        &General::log("$Lang::tr{'neighbour updated'}: $cgiparams{'IP'} $cgiparams{'MAC_ADDRESS'}");
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
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
    my $tmpline = $custNeighbours[$cgiparams{'NEIGH_ID'}];
    my @tmp = split(/\,/, $tmpline);
    my $neighbour = $tmp[0].",".$tmp[1].",".$tmp[2].",".$tmp[3];

    if (1) {
        @custNeighbours = grep { $_ ne "$neighbour" } @custNeighbours;
        &saveCustNeighbours(\@custNeighbours);
        &General::log("$Lang::tr{'neighbour removed'}: $neighbour");
    }

    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'reset'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}



&Header::openpage($Lang::tr{'network status information'}, 1, '');

#&Header::openbigbox('100%', 'left');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

my %selected = ();

my $disabled        = '';
my $hiddenIfaceName = '';

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} || $cgiparams{'ACTION'} eq $Lang::tr{'add interface'}) {
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
#  static neigh list
#######################################################################################

#    &Header::openbox('100%', 'left', "$Lang::tr{'custom interfaces'}:");

    print <<END;
<div align='left' tyle='margin-top:0px'>
<table width='100%' width='100%' height='33px' align='center'>
<tr style='background-color: #F2F2F2;'>
    <td align='left'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'>
            <input type='submit' name='ACTION' value='$Lang::tr{'add interface'}' />
        </form>
    </td>
    <td align='left' width='90%'></td>
</table>
END

    print <<END;
<div align='center'>
<table width='100%' align='center'>
<tr align="center" class='headbar'>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'ip address'}</td>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'interface'}</td>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'mac address'}</td>
    <td width='25%' class='boldbase'>$Lang::tr{'status'}</td>
    <td width='5%'>&nbsp;</td>
    <td width='5%'>&nbsp;</td>
</tr>
END

    &display_custom_neighbours(\@custNeighbours);
    print <<END;
</table>
</div>
END

    #&Header::closebox();
}

#&Header::closebigbox();

&Header::closepage();

sub display_custom_neighbours {
    my $custNeighbourRef = shift;

    my $id = 0;
    foreach my $tmpline (@$custNeighbourRef) {
        chomp($tmpline);
        my @tmp = split(/\,/, $tmpline);

        # highlight the row we are editing
        if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} && $cgiparams{'ROUTE_ID'} eq $id) {
            print "<tr class='selectcolour'>\n";
        } else {
            print "<tr class='table".int(($id % 2) + 1)."colour'>";
        }
        print <<END;
    <td>$tmp[0]</td>
    <td align='center'>$tmp[1]</td>
    <td align='center'>$tmp[2]</td>
    <td align='center'>$tmp[3]</td>
    <td align='center'>
    <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
        <input type='hidden' name='NEIGH_ID' value='$id' />
        <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
    </form>
    </td>
END
       print <<END;
    <td align='center'>
    <form method='post' name='frmb$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        <input type='hidden' name='NEIGH_ID' value='$id' />
        <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
    </form>
    </td>
END
        print "</tr>\n";
        $id++;
    }
}


#######################################################
# custom neigbours
#######################################################

sub validateNeighbourParams
{
    my $custNeighboursRef = shift;

    if ($cgiparams{'IP'} eq '') {
        $errormessage = $Lang::tr{'noAddressNet'};
        return;
    } else {
        if (!(&General::validip($cgiparams{'ADDRESS'}))) {
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

