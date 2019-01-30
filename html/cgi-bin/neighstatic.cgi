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

my $output='';
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
$cgiparams{'IFACE_NAME'}     = '';
$cgiparams{'EXTERNAL'}     = 'off';
$cgiparams{'OLD_IFACE_NAME'} = '';
&General::getcgihash(\%cgiparams);

$cgiparams{'IFACE_NAME'} = &Header::cleanConfNames($cgiparams{'IFACE_NAME'});

if ($cgiparams{'ACTION'} eq $Lang::tr{'add'}) {
    &validateIFaceParams(\%custIfaces);

    unless ($errormessage) {
        $custIfaces{$cgiparams{'IFACE_NAME'}}{'IFACE'}      = $cgiparams{'IFACE'};
        $custIfaces{$cgiparams{'IFACE_NAME'}}{'EXTERNAL'}      = $cgiparams{'EXTERNAL'};
        $custIfaces{$cgiparams{'IFACE_NAME'}}{'USED_COUNT'} = 0;

        &DATA::saveCustIfaces(\%custIfaces);

        &General::log("$Lang::tr{'iface added'}: $cgiparams{'IFACE_NAME'}");
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
        my $ifaceName    = $cgiparams{'IFACE_NAME'};
        my $ifaceNameOld = $cgiparams{'OLD_IFACE_NAME'};
        $custIfaces{$ifaceNameOld}{'IFACE'} = $cgiparams{'IFACE'};

        # if the name (==Key) has changed, we have to copy/move the old data to new key
        if ($ifaceName ne $ifaceNameOld) {
            $custIfaces{$ifaceName}{'IFACE'}      = $custIfaces{$ifaceNameOld}{'IFACE'};
            $custIfaces{$ifaceName}{'EXTERNAL'}      = $custIfaces{$ifaceNameOld}{'EXTERNAL'};
            $custIfaces{$ifaceName}{'USED_COUNT'} = $custIfaces{$ifaceNameOld}{'USED_COUNT'};

            delete($custIfaces{$ifaceNameOld});
        }
        &DATA::saveCustIfaces(\%custIfaces);

        &General::log("$Lang::tr{'iface updated'}: $cgiparams{'IFACE_NAME'}");
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
        `/usr/local/bin/setfwrules --all < /dev/null > /dev/null 2>&1 &`;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {

    # on an update error we use the entered data, we do not re-read from stored config
    unless ($errormessage) {
        if (defined($custIfaces{$cgiparams{'IFACE_NAME'}}{'IFACE'})) {
            $cgiparams{'IFACE'} = $custIfaces{$cgiparams{'IFACE_NAME'}}{'IFACE'};
        }
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    delete($custIfaces{$cgiparams{'IFACE_NAME'}});

    &DATA::saveCustIfaces(\%custIfaces);

    &General::log("$Lang::tr{'iface removed'}: $cgiparams{'IFACE_NAME'}");
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
    `/usr/local/bin/setfwrules --ofw < /dev/null > /dev/null 2>&1 &`;
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'reset'}) {
    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
}



&Header::openpage($Lang::tr{'network status information'}, 1, '');

#&Header::openbigbox('100%', 'left');

if ($cgiparams{'ACTION'} eq '') {
    $cgiparams{'KEY'}            = '';
    $cgiparams{'IFACE'}          = 'ip';
    $cgiparams{'IFACE_NAME'}     = '';
    $cgiparams{'EXTERNAL'}     = 'off';
    $cgiparams{'OLD_IFACE_NAME'} = '';
}

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

my %selected = ();

    my $disabled        = '';
    my $hiddenIfaceName = '';
    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        &Header::openbox('100%', 'left', "$Lang::tr{'edit interface'}:", $error);
        if ($cgiparams{'USED_COUNT'} > 0) {
            $disabled        = "disabled='disabled'";
            $hiddenIfaceName = "<input type='hidden' name='IFACE_NAME' value='$cgiparams{'IFACE_NAME'}' />";
        }
    }
    else {
        &Header::openbox('100%', 'left', "$Lang::tr{'add interface'}:", $error);
    }
    print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<div align='center'>
<table width='100%'>
<tr>
    <td width='25%'>$Lang::tr{'name'}:</td>
    <td width='25%'>
        <input type='text' name='IFACE_NAME' value='$cgiparams{'IFACE_NAME'}' size='20' maxlength='20' $disabled />
        $hiddenIfaceName
    </td>
    <td width='25%'>$Lang::tr{'interface'}:</td>
    <td width='25%'>
        <select name='IFACE'>
END

foreach my $iface (sort keys %FW::interfaces) {
##    print "<option value='ip' $selected{'IFACE'}{$iface}>$iface</option>";
    print "<option value=$FW::interfaces{$iface}{'IFACE'} $selected{'IFACE'}{$FW::interfaces{$iface}{'IFACE'}}>$FW::interfaces{$iface}{'IFACE'}</option>";
}
print <<END;
        </select>
        <input type='hidden' name='EXTERNAL' value='$cgiparams{'EXTERNAL'}' />
    </td>
</tr>
</table>
<hr />
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
<td class='comment2button'>&nbsp;</td>
END

    if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
        print "<td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'update'}' />\n";
        print "<input type='hidden' class='commonbuttons' name='OLD_IFACE_NAME' value='$cgiparams{'IFACE_NAME'}' /></td>\n";
    }
    else {
        print "<td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' /></td>\n";
    }
    print <<END;
    <td class='button2buttons'>
        <input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'reset'}' />
    </td>
    <td  class='onlinehelp'>
        <a href='${General::adminmanualurl}/firewall-interfaces.html#section' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</div>
</form>
END

    &Header::closebox();

    &Header::openbox('100%', 'left', "$Lang::tr{'custom interfaces'}:");
    print <<END;
<div align='center'>
<table width='100%' align='center'>
<tr align="center">
    <td width='40%'><strong>$Lang::tr{'name'}</strong></td>
    <td width='40%'><strong>$Lang::tr{'interface'}</strong></td>
    <td width='20%'><strong>$Lang::tr{'used'}</strong></td>
    <td width='5%'>&nbsp;</td>
    <td width='5%'>&nbsp;</td>
</tr>
END

    &display_custom_interfaces(\%custIfaces);
    print <<END;
</table>
</div>
END

    &Header::closebox();

#&Header::closebigbox();

&Header::closepage();

sub display_custom_interfaces {
    my $custIfaceRef = shift;

    my @sortedKeys = &General::sortHashArray($sort_col, $sort_type, $sort_dir, $custIfaceRef);

    my $id = 0;
    foreach my $ifaceName (@sortedKeys) {

        # highlight the row we are editing
        if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} && $cgiparams{'IFACE_NAME'} eq $ifaceName) {
            print "<tr class='selectcolour'>\n";
        } else {
            print "<tr class='table".int(($id % 2) + 1)."colour'>";
        }
        print <<END;
    <td>$ifaceName</td>
    <td align='center'>$custIfaceRef->{$ifaceName}{'IFACE'}</td>
    <td align='center'>$custIfaceRef->{$ifaceName}{'USED_COUNT'}x</td>
    <td align='center'>
    <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
        <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
        <input type='hidden' name='IFACE_NAME' value='$ifaceName' />
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
        <input type='hidden' name='IFACE_NAME' value='$ifaceName' />
    </form>
    </td>
END
        }
        print "</tr>\n";
        $id++;
    }
}

