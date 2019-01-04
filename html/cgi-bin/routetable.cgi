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
# MENUENTRY network 060 "routing table" "routing table"
#
# Make sure translation exists $Lang::tr{'routing table'}

use strict;

# enable only the following on debugging purpose
use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';

our $staticRoutesFile = "/var/ofw/firewall/staticRoutes";

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
        }
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
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
            }
        }
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
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
    my $tmpline = $staticRoutes[$cgiparams{'ROUTE_ID'}];
    my @tmp = split(/\,/, $tmpline);
    my $route = $tmp[0].",".$tmp[1].",".$tmp[2].",".$tmp[3];

    my $res = system("/sbin/ip route del $tmp[0]/$tmp[1] via $tmp[2] dev $tmp[3]");
    if ($res eq '0') {
        @staticRoutes = grep { $_ ne "$route" } @staticRoutes;
        &saveStaticRoutes(\@staticRoutes);
        &General::log("$Lang::tr{'iface removed'}: $route");
    }
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'reset'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}




&Header::openpage($Lang::tr{'network status information'}, 1, '');

&Header::openbigbox('100%', 'left');

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

    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        &Header::openbox('100%', 'left', "$Lang::tr{'edit static route'}:", $error);
    }
    else {
        &Header::openbox('100%', 'left', "$Lang::tr{'add static route'}:", $error);
    }
    print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<div align='center'>
<table width='100%'>
<tr>
    <td width='25%'>$Lang::tr{'destination ip or subnet'}:</td>
    <td width='25%'>
        <input type='text' name='ADDRESS' value='$cgiparams{'ADDRESS'}' size='20' maxlength='20' />
    </td>
    <td width='25%'>$Lang::tr{'netmask'}:</td>
    <td width='25%'>
        <input type='text' name='NETMASK' value='$cgiparams{'NETMASK'}' size='20' maxlength='20' />
    </td>
</tr>
<tr>
    <td width='25%'>$Lang::tr{'gateway ip'}:</td>
    <td width='25%'>
        <input type='text' name='GATEWAY' value='$cgiparams{'GATEWAY'}' size='20' maxlength='20' />
    </td>
    <td width='25%'>$Lang::tr{'interface'}:</td>
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
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
<td class='comment2button'>&nbsp;</td>
END

    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        print "<td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'update'}' />\n";
    }
    else {
        print "<td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'add'}' /></td>\n";
    }
    print <<END;
    <td class='button2buttons'>
        <input type='submit' name='ACTION' value='$Lang::tr{'reset'}' />
    </td>
    <td  class='onlinehelp'>
        <a href='${General::adminmanualurl}/firewall-interfaces.html#section' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a></td>
</tr>
</table>
</div>
</form>
END


    &Header::closebox();

    &Header::openbox('100%', 'left', "$Lang::tr{'static routes'}:");
    print <<END;
<div align='center'>
<table width='100%' align='center'>
<tr align="center">
    <td width='40%'><strong>$Lang::tr{'destination ip or net'}</strong></td>
    <td width='40%'><strong>$Lang::tr{'gateway ip'}</strong></td>
    <td width='10%'><strong>$Lang::tr{'interface'}</strong></td>
    <td width='5%'>&nbsp;</td>
    <td width='5%'>&nbsp;</td>
</tr>
END

    &display_static_routes(\@staticRoutes);
    print <<END;
</table>
</div>
END
    &Header::closebox();


print "<a name='routing'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'routing table entries'}:");
$output = `/sbin/ip route list`;
$output = &Header::cleanhtml($output,"y");
print <<END
<div align='center'>
<table width='100%'>
<tr>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'destination ip or net'}</td>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'gateway ip'}</td>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'interface'}</td>
    <td width='25%' class='boldbase'>$Lang::tr{'remark'}</td>
</tr>
END
;
my $count = 0;
foreach my $line (split(/\n/, $output))
{
    print "<tr class='table".int(($count % 2) + 1)."colour'>";
    if ($line =~ m/^(.*) dev ([^ ]+) (.*) src (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>$4</td>";
        print "<td align='center'>".&General::color_devices($2)."</td><td>$3</td></tr>";
    }
    elsif ($line =~ m/^(.*) via (.*) dev (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>$2</td>";
        print "<td align='center'>".&General::color_devices($3)."</td><td>&nbsp;</td></tr>";
    }
    elsif ($line =~ m/^(.*) dev ipsec(\d*)  (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>&nbsp;</td>";
        print "<td align='center'>".&General::color_devices("ipsec$2")."</td><td>$3</td></tr>";
    }
    else {
        print "<td colspan='4'>$line</td></tr>";
    }
    
    $count++;
}
print "</table> </div>";
&Header::closebox();

&Header::closebigbox();
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
        }
        else {
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
    @$staticRoutesRef = <routes>;
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

