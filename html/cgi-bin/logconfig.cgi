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
# (c) -2011 The Openfirewall Team
#
# Over the years many people have changed and contributed to this file.
# Check CVS and SVN for specifics.
#
# $Id: logconfig.cgi 7797 2015-01-08 08:45:27Z owes $
#

# Add entry in menu
# MENUENTRY logs 010 "log settings" "log settings"
#
# Make sure translation exists $Lang::tr{'log'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my %logsettings  = ();
my %checked      = ();
my %selected     = ();
my $errormessage = '';
my $error        = '';

&Header::showhttpheaders();

$logsettings{'LOGVIEW_REVERSE'}  = 'off';
$logsettings{'LOGVIEW_VIEWSIZE'} = '150';
$logsettings{'LOGWATCH_LEVEL'}   = 'Low';
$logsettings{'LOGWATCH_KEEP'}    = '56';
my @VS = ('15', '50', '100', '150', '250', '500');
$logsettings{'ENABLE_REMOTELOG'} = 'off';
$logsettings{'REMOTELOG_ADDR'}   = '';
$logsettings{'REMOTELOG_PROTO'}  = 'udp';
$logsettings{'LOG_KEEP'}         = (-f '/etc/FLASH') ? 14 : 56;
$logsettings{'ACTION'}           = '';
&General::getcgihash(\%logsettings);

if ($logsettings{'ACTION'} eq $Lang::tr{'save'}) {
    if ($logsettings{'ENABLE_REMOTELOG'} eq 'on') {
        unless (&General::validiporfqdn($logsettings{'REMOTELOG_ADDR'})) {
            $errormessage = $Lang::tr{'invalid logserver address'};
        }
    }
    unless ($logsettings{'LOGWATCH_KEEP'} =~ /^\d+$/) {
        $errormessage = $Lang::tr{'invalid keep time'};
    }
    unless ($logsettings{'LOGWATCH_LEVEL'} =~ /^Low|Med|High$/) {
        $errormessage = $Lang::tr{'invalid input'};
    }
    unless ($errormessage) {
        &General::writehash('/var/ofw/logging/settings', \%logsettings);
        system('/usr/local/bin/restartsyslogd') == 0
            or $errormessage = "$Lang::tr{'bad return code'} " . $? / 256;
    }

}

&General::readhash('/var/ofw/logging/settings', \%logsettings);

$checked{'ENABLE_REMOTELOG'}{'off'}                            = '';
$checked{'ENABLE_REMOTELOG'}{'on'}                             = '';
$checked{'ENABLE_REMOTELOG'}{$logsettings{'ENABLE_REMOTELOG'}} = "checked='checked'";

$selected{'REMOTELOG_PROTO'}{'udp'}                           = '';
$selected{'REMOTELOG_PROTO'}{'tcp'}                           = '';
$selected{'REMOTELOG_PROTO'}{$logsettings{'REMOTELOG_PROTO'}} = "selected='selected'";

$checked{'LOGVIEW_REVERSE'}{'off'}                           = '';
$checked{'LOGVIEW_REVERSE'}{'on'}                            = '';
$checked{'LOGVIEW_REVERSE'}{$logsettings{'LOGVIEW_REVERSE'}} = "checked='checked'";

$selected{'LOGWATCH_LEVEL'}{'Low'}                          = '';
$selected{'LOGWATCH_LEVEL'}{'Med'}                          = '';
$selected{'LOGWATCH_LEVEL'}{'High'}                         = '';
$selected{'LOGWATCH_LEVEL'}{$logsettings{'LOGWATCH_LEVEL'}} = "selected='selected'";

map ($selected{'LOGVIEW_VIEWSIZE'}{$_} = '', @VS);
$selected{'LOGVIEW_VIEWSIZE'}{$logsettings{'LOGVIEW_VIEWSIZE'}} = "selected='selected'";

&Header::openpage($Lang::tr{'log settings'}, 1, '');

&Header::openbigbox('100%', 'left', '');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>\n";
    &Header::closebox();

    $error = 'error';
}

print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";

&Header::openbox('100%', 'left', $Lang::tr{'log settings'}, $error);
print <<END
<table width='100%'>
<tr>
	<td colspan='4' class='base'><b>$Lang::tr{'log viewing options'}</b></td>
</tr><tr>
	<td width='25%' class='base'>$Lang::tr{'reverse sort'}:</td>
	<td width='25%'><input type='checkbox' name='LOGVIEW_REVERSE' $checked{'LOGVIEW_REVERSE'}{'on'} /></td>
	<td width='25%' class='base'>$Lang::tr{'log lines per page'}:</td>
	<td width='25%'><select name='LOGVIEW_VIEWSIZE'>
END
    ;
foreach my $vs (@VS) {
    print "\t<option value='$vs' $selected{'LOGVIEW_VIEWSIZE'}{$vs}>$vs</option>\n";
}
print <<END
	</select></td>
</tr><tr>
    <td colspan='4'><hr /><b>$Lang::tr{'log archive'}</b></td>
</tr><tr>
    <td width='25%' class='base'>$Lang::tr{'logs kept'}:</td>
    <td width='25%' class='base'><input type='text' name='LOG_KEEP' value='$logsettings{'LOG_KEEP'}' size='4' />&nbsp;$Lang::tr{'days'}</td>
    <td width='25%' class='base'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr><tr>
	<td colspan='4'><hr /><b>$Lang::tr{'log summaries'}</b></td>
</tr><tr>
	<td width='25%' class='base'>$Lang::tr{'summaries kept'}:</td>
	<td width='25%' class='base'><input type='text' name='LOGWATCH_KEEP' value='$logsettings{'LOGWATCH_KEEP'}' size='4' />&nbsp;$Lang::tr{'days'}</td>
	<td width='25%' class='base'>$Lang::tr{'detail level'}:</td>
	<td  width='25%'>
		<select name='LOGWATCH_LEVEL'>
		<option value='Low' $selected{'LOGWATCH_LEVEL'}{'Low'}>$Lang::tr{'low'}</option>
		<option value='Med' $selected{'LOGWATCH_LEVEL'}{'Med'}>$Lang::tr{'medium'}</option>
		<option value='High' $selected{'LOGWATCH_LEVEL'}{'High'}>$Lang::tr{'high'}</option>
		</select>
	</td>
</tr><tr>
	<td colspan='4'><hr /><b>$Lang::tr{'remote logging'}</b></td>
</tr><tr>
	<td width='25%' class='base'>$Lang::tr{'enabled'}:</td>
	<td width='25%'><input type='checkbox' name='ENABLE_REMOTELOG' $checked{'ENABLE_REMOTELOG'}{'on'} /></td>
	<td width='25%' class='base'>$Lang::tr{'log server address'}:</td>
	<td width='25%'><input type='text' name='REMOTELOG_ADDR' value='$logsettings{'REMOTELOG_ADDR'}' /></td>
</tr><tr>
    <td width='25%' class='base'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
    <td width='25%' class='base'>$Lang::tr{'protocol'}:</td>
    <td width='25%'>
        <select name='REMOTELOG_PROTO'>
            <option value='udp' $selected{'REMOTELOG_PROTO'}{'udp'}>UDP</option>
            <option value='tcp' $selected{'REMOTELOG_PROTO'}{'tcp'}>TCP</option>
        </select>
    </td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'> &nbsp; </td>
    <td class='button1button'><input type='submit' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/logs-settings.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
    ;
&Header::closebox();

print "</form>\n";

&Header::closebigbox();

&Header::closepage();
