#!/usr/bin/perl
#
# SmoothWall CGIs
#
# This code is distributed under the terms of the GPL
#
# (c) The SmoothWall Team
#
# $Id: modem.cgi 3122 2009-06-25 10:55:55Z owes $
#

# Add entry in menu
# MENUENTRY network 030 "modem" "modem configuration"
#
# Make sure translation exists $Lang::tr{'modem'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

my %modemsettings = ();
my $errormessage  = '';
my $error_modem   = '';

&Header::showhttpheaders();

$modemsettings{'ACTION'} = '';
$modemsettings{'VALID'}  = '';

&General::getcgihash(\%modemsettings);

if ($modemsettings{'ACTION'} eq $Lang::tr{'save'}) {
    if (!($modemsettings{'TIMEOUT'} =~ /^\d+$/)) {
        $errormessage = $Lang::tr{'timeout must be a number'};
        goto ERROR;
    }
ERROR:
    if ($errormessage) {
        $modemsettings{'VALID'} = 'no';
        $error_modem = 'error';
    }
    else {
        $modemsettings{'VALID'} = 'yes';
    }

    &General::writehash('/var/ipcop/modem/settings', \%modemsettings);
}

if ($modemsettings{'ACTION'} eq $Lang::tr{'restore defaults'}) {
    system('/bin/cp', '/var/ipcop/modem/defaults', '/var/ipcop/modem/settings', '-f');
}

&General::readhash('/var/ipcop/modem/settings', \%modemsettings);

&Header::openpage($Lang::tr{'modem configuration'}, 1, '');

&Header::openbigbox('100%', 'left', '');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>\n";
    &Header::closebox();
}

print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";

&Header::openbox('100%', 'left', "$Lang::tr{'modem configuration'}:", $error_modem);
print <<END
<table width='100%'>
<tr>
    <td width='25%' class='base'>$Lang::tr{'init string'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td width='25%'><input type='text' name='INIT' value='$modemsettings{'INIT'}' /></td>
    <td width='25%' class='base'>$Lang::tr{'hangup string'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td width='25%'><input type='text' name='HANGUP' value='$modemsettings{'HANGUP'}' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'speaker on'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='SPEAKER_ON' value='$modemsettings{'SPEAKER_ON'}' /></td>
    <td class='base'>$Lang::tr{'speaker off'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='SPEAKER_OFF' value='$modemsettings{'SPEAKER_OFF'}' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'tone dial'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='TONE_DIAL' value='$modemsettings{'TONE_DIAL'}' /></td>
    <td class='base'>$Lang::tr{'pulse dial'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='PULSE_DIAL' value='$modemsettings{'PULSE_DIAL'}' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'connect timeout'}:</td>
    <td><input type='text' name='TIMEOUT' value='$modemsettings{'TIMEOUT'}' /></td>
    <td class='base'>&nbsp;</td>
    <td>&nbsp;</td>
</tr>

</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment2buttons'><img src='/blob.gif' align='top' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'restore defaults'}' /></td>
    <td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/network-modem.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
    ;
&Header::closebox();

print "</form>\n";

&Header::closebigbox();

&Header::closepage();
