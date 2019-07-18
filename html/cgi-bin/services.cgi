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
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
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
        undef %cgiparams;
        $cgiparams{'ACTION'} = '';
        `/usr/local/bin/setfwrules --user < /dev/null > /dev/null 2>&1 &`;
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {

    # on an update error we use the entered data, we do not re-read from stored config
    unless ($errormessage) {
        if (defined($custServices{$cgiparams{'SERVICE_NAME'}}{'PROTOCOL'})) {
            $cgiparams{'PORTS'}            = $custServices{$cgiparams{'SERVICE_NAME'}}{'PORT_NR'};
            $cgiparams{'PROTOCOL'}         = $custServices{$cgiparams{'SERVICE_NAME'}}{'PROTOCOL'};
            $cgiparams{'PORT_INVERT'}      = $custServices{$cgiparams{'SERVICE_NAME'}}{'PORT_INVERT'};
            $cgiparams{'PROTOCOL_INVERT'}  = $custServices{$cgiparams{'SERVICE_NAME'}}{'PROTOCOL_INVERT'};
            $cgiparams{'ICMP_TYPE'}        = $custServices{$cgiparams{'SERVICE_NAME'}}{'ICMP_TYPE'};
            $cgiparams{'OLD_SERVICE_NAME'} = $cgiparams{'SERVICE_NAME'};
        }
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'remove'}) {
    delete($custServices{$cgiparams{'SERVICE_NAME'}});

    &DATA::saveCustServices(\%custServices);
    &General::log("$Lang::tr{'service removed'}: $cgiparams{'SERVICE_NAME'}");

    undef %cgiparams;
    $cgiparams{'ACTION'} = '';
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

# figure out which protocol is selected
$selected{'PROTOCOL'}{'tcp'}    = '';
$selected{'PROTOCOL'}{'udp'}    = '';
$selected{'PROTOCOL'}{'tcpudp'} = '';
$selected{'PROTOCOL'}{'icmp'}   = '';
$selected{'PROTOCOL'}{'gre'}    = '';
foreach my $line (keys %Protocols::protocols) {

    #   $selected{'PROTOCOL'}{"$Protocols::protocols{$line}"}= '';
    $selected{'PROTOCOL'}{$line} = '';
}
$selected{'PROTOCOL'}{$cgiparams{'PROTOCOL'}} = "selected='selected'";

# figure out which icmptype is selected
$selected{'ICMP_TYPE'}{'BLANK'}                 = '';
$selected{'ICMP_TYPE'}{'ALL'}                   = '';
$selected{'ICMP_TYPE'}{$cgiparams{'ICMP_TYPE'}} = "selected='selected'";

$checked{'PORT_INVERT'}{'off'}                             = '';
$checked{'PORT_INVERT'}{'on'}                              = '';
$checked{'PORT_INVERT'}{$cgiparams{'PORT_INVERT'}}         = "checked='checked'";
$checked{'PROTOCOL_INVERT'}{'off'}                         = '';
$checked{'PROTOCOL_INVERT'}{'on'}                          = '';
$checked{'PROTOCOL_INVERT'}{$cgiparams{'PROTOCOL_INVERT'}} = "checked='checked'";

&Header::openpage($Lang::tr{'services settings'}, 1, '');

&Header::openbigbox('100%', 'left');

# DEBUG DEBUG
#&Header::openbox('100%', 'left', 'DEBUG');
#foreach my $line (keys %cgiparams) {
#   print "$line = $cgiparams{$line}<br />\n";
#}
#print "SortCol: $sort_col<br />\n";
#print "Query: $ENV{'QUERY_STRING'}<br />\n";
#print "Script: $ENV{'SCRIPT_NAME'}<br />\n";
#&Header::closebox();

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}

my $disabled          = '';
my $hiddenServiceName = '';
if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
    &Header::openbox('100%', 'left', "$Lang::tr{'edit service'}:", $error);
    if ($cgiparams{'USED_COUNT'} > 0) {
        $disabled          = "disabled='disabled'";
        $hiddenServiceName = "<input type='hidden' name='SERVICE_NAME' value='$cgiparams{'SERVICE_NAME'}' />";
    }
}
else {
    &Header::openbox('100%', 'left', "$Lang::tr{'add service'}:", $error);
}

# Show protocols with TCP, UDP, etc at the top of the list.
print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td width='25%'>$Lang::tr{'servicename'}:</td>
    <td width='25%'>
        <input type='text' name='SERVICE_NAME' value='$cgiparams{'SERVICE_NAME'}' size='20' maxlength='20' $disabled />
        $hiddenServiceName
    </td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr><tr>
    <td colspan='4'>&nbsp;</td>
</tr><tr>
    <td>$Lang::tr{'protocol'}:</td>
    <td>
        <select name='PROTOCOL'>
            <option value='tcp' $selected{'PROTOCOL'}{'tcp'}>TCP</option>
            <option value='udp' $selected{'PROTOCOL'}{'udp'}>UDP</option>
            <option value='tcpudp' $selected{'PROTOCOL'}{'tcpudp'}>TCP &amp; UDP</option>
            <option value='icmp' $selected{'PROTOCOL'}{'icmp'}>ICMP</option>
            <option value='gre' $selected{'PROTOCOL'}{'gre'}>GRE</option>
END

foreach my $line (sort keys %Protocols::protocols) {

    # do not have duplicates in the list
    if (   $Protocols::protocols{$line} ne '6'
        && $Protocols::protocols{$line} ne '17'
        && $Protocols::protocols{$line} ne '1'
        && $Protocols::protocols{$line} ne '47')
    {

        #       print "<option value='$line' $selected{'PROTOCOL'}{$Protocols::protocols{$line}}>".uc($line)."</option>\n";
        print "<option value='$line' $selected{'PROTOCOL'}{$line}>"
            . uc($line)
            . "&nbsp;(#&nbsp;$Protocols::protocols{$line})</option>\n";
    }
}
print <<END;
        </select>
    </td>
    <td>$Lang::tr{'invert'}:</td>
    <td><input type='checkbox' name='PROTOCOL_INVERT' $checked{'PROTOCOL_INVERT'}{'on'} /></td>
</tr><tr>
    <td>$Lang::tr{'ports'}:</td>
    <td><input type='text' name='PORTS' value='$cgiparams{'PORTS'}' size='15' maxlength='11' /></td>
    <td>$Lang::tr{'invert'}:</td>
    <td><input type='checkbox' name='PORT_INVERT' $checked{'PORT_INVERT'}{'on'} /></td>
</tr><tr>
    <td>$Lang::tr{'icmp type'}:</td>
    <td>
        <select name='ICMP_TYPE'>
            <option value='BLANK' $selected{'ICMP_TYPE'}{'BLANK'}>-- $Lang::tr{'valid icmp types'} --</option>
            <option value='ALL' $selected{'ICMP_TYPE'}{'ALL'}>$Lang::tr{'all icmp types'}</option>
END

foreach my $line (@icmptypes) {
    if ($cgiparams{'ICMP_TYPE'} eq $line) {
        print "<option value='$line' selected='selected'>$icmpTypeHash{$line} ($line)</option>\n";
    }
    else {
        print "<option value='$line' >$icmpTypeHash{$line} ($line)</option>\n";
    }
}
print <<END;
        </select>
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
</table>
<hr />
<table width='100%' cellpadding='0' cellspacing='5' border='0'>
<tr>
    <td class='comment2buttons'>&nbsp;</td>
END

if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'}) {
    print <<END;
    <td class='button2buttons'>
        <input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'update'}' />
        <input type='hidden' name='OLD_SERVICE_NAME' value='$cgiparams{'OLD_SERVICE_NAME'}' />
    </td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'reset'}' /></td>
END
}
else {
    print <<END;
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' /></td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'reset'}' /></td>
END
}
print <<END;
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/firewall-services.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
END

&Header::closebox();

&Header::openbox('100%', 'left', "$Lang::tr{'custom services'}:");
print <<END;
<div align='center'>
<table width='100%' align='center'>
<tr align="center">
END

# Add visual indicators to column headings to show sort order
my $sortarrow;
if ($sort_dir eq 'asc') {
    $sortarrow = $Header::sortup;
}
else {
    $sortarrow = $Header::sortdn;
}

my %sortCols = ();
$sortCols{'SERVICE_NAME'}{'asc'} = '';
$sortCols{'SERVICE_NAME'}{'dsc'} = '';
$sortCols{'PORT_NR'}{'asc'}      = '';
$sortCols{'PORT_NR'}{'dsc'}      = '';
$sortCols{'PROTOCOL'}{'asc'}     = '';
$sortCols{'PROTOCOL'}{'dsc'}     = '';
$sortCols{'USED_COUNT'}{'asc'}   = '';
$sortCols{'USED_COUNT'}{'dsc'}   = '';
$sortCols{$sort_col}{$sort_dir}  = $sortarrow;

if ($sort_dir eq 'asc' && $sort_col eq 'SERVICE_NAME') {
    print
"<td width='20%'><strong><a href='$ENV{'SCRIPT_NAME'}?sortcol=SERVICE_NAME&amp;srtype=a&amp;srtdir=dsc' title='$Lang::tr{'sort descending'}'>$Lang::tr{'servicename'}</a></strong> $sortCols{'SERVICE_NAME'}{'asc'}</td>\n";
}
else {
    print
"<td width='20%'><strong><a href='$ENV{'SCRIPT_NAME'}?sortcol=SERVICE_NAME&amp;srtype=a&amp;srtdir=asc' title='$Lang::tr{'sort ascending'}'>$Lang::tr{'servicename'}</a></strong> $sortCols{'SERVICE_NAME'}{'dsc'}</td>\n";
}
if ($sort_dir eq 'asc' && $sort_col eq 'PORT_NR') {
    print
"<td width='20%'><strong><a href='$ENV{'SCRIPT_NAME'}?sortcol=PORT_NR&amp;srtype=n&amp;srtdir=dsc' title='$Lang::tr{'sort descending'}'>$Lang::tr{'ports'}</a></strong> $sortCols{'PORT_NR'}{'asc'}</td>\n";
}
else {
    print
"<td width='20%'><strong><a href='$ENV{'SCRIPT_NAME'}?sortcol=PORT_NR&amp;srtype=n&amp;srtdir=asc' title='$Lang::tr{'sort ascending'}'>$Lang::tr{'ports'}</a></strong> $sortCols{'PORT_NR'}{'dsc'}</td>\n";
}
if ($sort_dir eq 'asc' && $sort_col eq 'PROTOCOL') {
    print
"<td width='20%'><strong><a href='$ENV{'SCRIPT_NAME'}?sortcol=PROTOCOL&amp;srtype=a&amp;srtdir=dsc' title='$Lang::tr{'sort descending'}'>$Lang::tr{'protocol'}</a></strong> $sortCols{'PROTOCOL'}{'asc'}</td>\n";
}
else {
    print
"<td width='20%'><strong><a href='$ENV{'SCRIPT_NAME'}?sortcol=PROTOCOL&amp;srtype=a&amp;srtdir=asc' title='$Lang::tr{'sort ascending'}'>$Lang::tr{'protocol'}</a></strong> $sortCols{'PROTOCOL'}{'dsc'}</td>\n";
}

print "<td width='25%'><strong>$Lang::tr{'icmp type'}</strong></td>";

if ($sort_dir eq 'asc' && $sort_col eq 'USED_COUNT') {
    print
"<td width='15%'><strong><a href='$ENV{'SCRIPT_NAME'}?sortcol=USED_COUNT&amp;srtype=n&amp;srtdir=dsc' title='$Lang::tr{'sort descending'}'>$Lang::tr{'used'}</a></strong> $sortCols{'USED_COUNT'}{'asc'}</td>\n";
}
else {
    print
"<td width='15%'><strong><a href='$ENV{'SCRIPT_NAME'}?sortcol=USED_COUNT&amp;srtype=n&amp;srtdir=asc' title='$Lang::tr{'sort ascending'}'>$Lang::tr{'used'}</a></strong> $sortCols{'USED_COUNT'}{'dsc'}</td>\n";
}
print <<END;
    <td width='5%'>&nbsp;</td>
    <td width='5%'>&nbsp;</td>
</tr>
END

&display_custom_services(\%custServices, \%icmpTypeHash);
print <<END;
</table>
</div>
END
&Header::closebox();

&Header::openbox('100%', 'left', "$Lang::tr{'default services'}:");
print <<END;
<div align='center'>
<table width='100%' align='center'>
<tr align="center">
    <td><strong>$Lang::tr{'servicename'}</strong></td>
    <td><strong>$Lang::tr{'ports'}</strong></td>
    <td><strong>$Lang::tr{'protocol'}</strong></td>
</tr>
END

&display_default_services();
print <<END;
</table>
</div>
END

&Header::closebox();
&Header::closebigbox();
&Header::closepage();

# $cServicesRef->{$serviceName}{'PORT_NR'}
# $cServicesRef->{$serviceName}{'PROTOCOL'}
# $cServicesRef->{$serviceName}{'PORT_INVERT'}
# $cServicesRef->{$serviceName}{'PROTOCOL_INVERT'}
# $cServicesRef->{$serviceName}{'ICMP_TYPE'}
# $cServicesRef->{$serviceName}{'USED_COUNT'}
sub display_custom_services {
    my $cServicesRef = shift;
    my $icmpTypes    = shift;

    my @sortedKeys = &General::sortHashArray($sort_col, $sort_type, $sort_dir, $cServicesRef);

    my $id = 0;
    foreach my $serviceName (@sortedKeys) {
        my $port_inv      = '';
        my $prot_inv      = '';
        my $port_inv_tail = '';
        my $prot_inv_tail = '';
        my $icmp_inv      = '';
        my $icmp_inv_tail = '';

        # highlight the row we are editing
        if ($cgiparams{'ACTION'} eq $Lang::tr{'edit'} && $cgiparams{'SERVICE_NAME'} eq $serviceName) {
            print "<tr class='selectcolour'>";
        }
        else {
            print "<tr class='table".int(($id % 2) + 1)."colour'>";
        }
        print "<td>$serviceName</td>\n";

        if ($cServicesRef->{$serviceName}{'PORT_INVERT'} eq 'on') {
            $port_inv      = " <strong><font color='RED'>! (</font></strong>";
            $port_inv_tail = "<strong><font color='RED'>)</font></strong>";
        }

        if ($cServicesRef->{$serviceName}{'PROTOCOL_INVERT'} eq 'on') {
            if ($cServicesRef->{$serviceName}{'PROTOCOL'} =~ /tcp|udp/) {
                $port_inv      = " <strong><font color='RED'>! (</font></strong>";
                $port_inv_tail = "<strong><font color='RED'>)</font></strong>";
            }
            elsif ($cServicesRef->{$serviceName}{'PROTOCOL'} =~ /icmp/) {
                if ($cServicesRef->{$serviceName}{'ICMP_TYPE'} ne 'ALL') {
                    $icmp_inv      = " <strong><font color='RED'>! (</font></strong>";
                    $icmp_inv_tail = "<strong><font color='RED'>)</font></strong>";
                }
                else {
                    $prot_inv      = " <strong><font color='RED'>! (</font></strong>";
                    $prot_inv_tail = "<strong><font color='RED'>)</font></strong>";
                }
            }
            else {
                $prot_inv      = " <strong><font color='RED'>! (</font></strong>";
                $prot_inv_tail = "<strong><font color='RED'>)</font></strong>";
            }
        }

        print "<td align='center'>"
            . $port_inv
            . &cleanport($cServicesRef->{$serviceName}{'PORT_NR'})
            . $port_inv_tail
            . "</td>\n";
        print "<td align='center'>"
            . $prot_inv
            . &cleanprotocol($cServicesRef->{$serviceName}{'PROTOCOL'})
            . $prot_inv_tail
            . "</td>\n";
        if ($cServicesRef->{$serviceName}{'ICMP_TYPE'} eq 'BLANK') {
            print "<td align='center'>N/A</td>\n";
        }
        else {
            print "<td align='center'>"
                . $icmp_inv
                . " $icmpTypes->{$cServicesRef->{$serviceName}{'ICMP_TYPE'}} ($cServicesRef->{$serviceName}{'ICMP_TYPE'})"
                . $icmp_inv_tail
                . "</td>\n";
        }
        print <<END;
    <td align='center'>$cServicesRef->{$serviceName}{'USED_COUNT'}x</td>
    <td align='center'>
    <form method='post' name='frm$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
        <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}'/>
        <input type='hidden' name='SERVICE_NAME' value='$serviceName' />
        <input type='hidden' name='USED_COUNT' value='$cServicesRef->{$serviceName}{'USED_COUNT'}' />
    </form>
    </td>
END
        if ($cServicesRef->{$serviceName}{'USED_COUNT'} > 0) {
            print "<td><img src='/images/null.gif' width='20' height='20' alt='' /></td>";
        }
        else {
            print <<END;
    <td align='center'>
    <form method='post' name='frmb$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}'/>
        <input type='hidden' name='SERVICE_NAME' value='$serviceName' />
    </form>
    </td>
END
        }
        print "</tr>\n";
        $id++;
    }
}

sub display_default_services {
    my $prev    = "";
    my $newline = "";

    my %defaultServices = ();
    &DATA::readDefaultServices(\%defaultServices);

    my %ofwServices = ();
    &DATA::readOfwServices(\%ofwServices);

    my $id = 0;
    foreach my $defService (sort keys %ofwServices) {
        print "<tr class='table".int(($id % 2) + 1)."colour'>";
        print "<td>$defService</td>\n";
        print "<td align='center'>$ofwServices{$defService}{'PORT_NR'}</td>\n";
        print "<td align='center'>" . &cleanprotocol($ofwServices{$defService}{'PROTOCOL'}) . "</td>\n";
        print "</tr>\n";
        $id++;
    }

    print
"<tr><td colspan='3' bgcolor='#000000'><img src='/images/null.gif' width='1' height='1' border='0' alt='--------' /></td></tr>\n";

    foreach my $defService (sort keys %defaultServices) {
        print "<tr class='table".int(($id % 2) + 1)."colour'>";
        print "<td>$defService</td>\n";
        print "<td align='center'>$defaultServices{$defService}{'PORT_NR'}</td>\n";
        print "<td align='center'>" . &cleanprotocol($defaultServices{$defService}{'PROTOCOL'}) . "</td>\n";
        print "</tr>\n";
        $id++;
    }
}

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
