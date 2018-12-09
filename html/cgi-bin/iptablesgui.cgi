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
# Copyright (C) 2007 Olaf (weizen_42) Westrik
# (c) 2008-2014, the Openfirewall Team
#
# $Id: iptablesgui.cgi 7452 2014-04-11 06:08:12Z owes $
#

# Add entry in menu
# MENUENTRY status 090 "IPtables" "IPTables"
#
# Do not translate IPTables

use strict;

# enable only the following on debugging purpose
use warnings; no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

use LWP::UserAgent;

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my $option_table = '';
my $errormessage = '';

my %cgiparams=();
$cgiparams{'ACTION'} = '';              # refresh
$cgiparams{'TABLE'} = 'filter';         # filter / mangle / nat / raw
$cgiparams{'CHAIN'} = '';
&General::getcgihash(\%cgiparams);


if ( $cgiparams{'ACTION'} eq $Lang::tr{'refresh'} ) {
}

&Header::showhttpheaders();
&Header::openpage('IPTables', 1, '');
&Header::openbigbox('100%', 'left');

#&Header::openbox('100%', 'left', 'DEBUG');
#foreach my $line (keys %cgiparams) {
#   print "$line = $cgiparams{$line}<br />\n";
#}
#print "$ENV{'QUERY_STRING'}\n";
#&Header::closebox();


if (($cgiparams{'TABLE'} ne 'filter') && ($cgiparams{'TABLE'} ne 'mangle') && ($cgiparams{'TABLE'} ne 'nat') && ($cgiparams{'TABLE'} ne 'raw')) {
    # Silently return to filter table
    $cgiparams{'TABLE'} = 'filter';
}

foreach my $table ( ('filter', 'mangle', 'nat', 'raw') ) {
  if ( $cgiparams{'TABLE'} eq $table ) {
    $option_table = $option_table ."<option value='$table' selected='selected'>$table</option>";
  }
  else {
    $option_table = $option_table ."<option value='$table'>$table</option>";
  }
}

if ($cgiparams{'CHAIN'} !~ /^[A-Z_]*$/) {
    $errormessage = $Lang::tr{'invalid input'};
}

if ($errormessage) {
    &Header::openbox('100%', 'left', 'IPTables:', 'error');
}
else {
    &Header::openbox('100%', 'left', 'IPTables:');
}

print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td width='25%' class='base'>Table:</td>
    <td colspan='3'><select name='TABLE' onchange='this.form.submit()'>$option_table</select></td>
</tr><tr>
    <td width='25%' class='base'>Chain:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td width='25%'><input type='text' name='CHAIN' value='$cgiparams{'CHAIN'}' size='20' /></td>
    <td width='25%'>&nbsp;$errormessage</td>
    <td width='25%'>&nbsp;</td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button1button'><input type='submit' name='ACTION' value='$Lang::tr{'refresh'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/status-iptables.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table></form>
<hr />
END
;

my $output = '';
if (($cgiparams{'CHAIN'} eq '') || $errormessage) {
    $output = `/usr/local/bin/iptableswrapper $cgiparams{'TABLE'} 2>&1`;
}
else {
    $output = `/usr/local/bin/iptableswrapper chain $cgiparams{'TABLE'} $cgiparams{'CHAIN'} 2>&1`;
}
$output = &Header::cleanhtml($output);

(my @lines) = split(/\n/, $output);

print "<table width='100%'>\n";
foreach my $line ( @lines )
{
    if ($line eq '') {
        print "<tr><td colspan='12'>&nbsp;</td></tr>\n"
    }
    elsif ($line =~ m/^Chain ([A-Z_]+) (.*)$/) {
        print "<tr class='table1colour'><td colspan='12' class='boldbase'><a name='$1'>$1</a> $2</td></tr>\n"
    }
    elsif ($line =~ m/^num + pkts/ ) {
        print "<tr><td>&nbsp;</td><td>num</td><td>pkts</td><td>bytes</td><td>target</td><td>prot</td><td>opt</td><td>in</td><td>out</td><td>src</td><td>dest</td><td>&nbsp;</td></tr>\n"
    }
    elsif ($line =~ m/^([0-9]+)\s+([0-9]+[KMGT]?)\s+([0-9]+[KMGT]?)\s+([A-Z_]+)\s+([a-z]+|[0-9]+)+\s+([a-z-]+)\s+([a-z0-9-:.*]+)\s+([a-z0-9-:.*]+)\s+(!{0,1}[0-9.\/]+)\s+(!{0,1}[0-9.\/]+)+(.*)/) {
        print "<tr><td>&nbsp;</td><td>$1</td><td>$2</td><td>$3</td><td>".&formattarget($4)."</td><td>$5</td><td>$6</td><td>".&General::color_devices("$7")."</td><td>".&General::color_devices("$8")."</td><td>$9</td><td>$10</td><td>$11</td></tr>\n"
    }
    else {
        print "<tr><td>&nbsp;</td><td colspan='11'>$line</td></tr>\n";
    }
}
print "</table>\n";

&Header::closebox();

&Header::closebigbox();
&Header::closepage();


sub formattarget
{
  my $target = shift;

    if ($target eq 'ACCEPT') {
        return "<font class='ofw_iface_green'>$target</font>";
    }
    elsif ($target =~ m/^(DROP|REJECT)$/) {
        return "<font class='ofw_iface_red'>$target</font>";
    }
    elsif ($target =~ m/^(DNAT|SNAT|MASQUERADE|LOG|MARK|RETURN)$/) {
        return $target;
    }
    else {
        if ($cgiparams{'CHAIN'} eq '') {
            return "<a href='#$target'>$target</a>";
        }
        else {
            return "$target";
        }
    }
}
