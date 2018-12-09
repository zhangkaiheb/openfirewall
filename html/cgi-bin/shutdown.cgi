#!/usr/bin/perl
#
# SmoothWall CGIs
#
# This code is distributed under the terms of the GPL
#
# (c) The SmoothWall Team
#
# $Id: shutdown.cgi 5417 2011-02-09 06:42:26Z dotzball $
#

# Add entry in menu
# MENUENTRY system 080 "shutdown" "shutdown"

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my %cgiparams    = ();
my $death        = 0;
my $rebirth      = 0;

&Header::showhttpheaders();

$cgiparams{'ACTION'} = '';
&General::getcgihash(\%cgiparams);

if ($cgiparams{'ACTION'} eq $Lang::tr{'shutdown'}) {
    $death = 1;
    # run in background
    system('/usr/local/bin/ofwreboot --down GUI shutdown &');
}
elsif ($cgiparams{'ACTION'} eq $Lang::tr{'reboot'}) {
    $rebirth = 1;
    # run in background
    system('/usr/local/bin/ofwreboot --boot GUI reboot &');
}

if ($death == 0 && $rebirth == 0) {

    &Header::openpage($Lang::tr{'shutdown control'}, 1, '');
    &Header::openbigbox('100%', 'left');
    &Header::openbox('100%', 'left', "$Lang::tr{'shutdown'}:");
    print <<END
<table width='100%'>
<tr>
    <td width='20%' align='center'><form method='post' name='frmrebootimg' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'reboot'}' />
        <input type='image' src='/images/reboot_cgi.png' alt='$Lang::tr{'reboot'}' />
    </form></td>
    <td width='30%' align='center' valign='middle'><form method='post' name='frmrebootbutton' action='$ENV{'SCRIPT_NAME'}'>
        <input type='submit' name='ACTION' value='$Lang::tr{'reboot'}' />
    </form></td>
    <td width='30%' align='center' valign='middle'><form method='post' name='frmshutdownimg' action='$ENV{'SCRIPT_NAME'}'>
        <input type='submit' name='ACTION' value='$Lang::tr{'shutdown'}' />
    </form></td>
    <td width='20%' align='center'><form method='post' name='frmshutdownbutton' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'shutdown'}' />
        <input type='image' src='/images/shutdown_cgi.png' alt='$Lang::tr{'shutdown'}' />
    </form></td>
</tr>
</table><hr /><table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'>&nbsp;</td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/system-shutdown.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a></td>
</tr>
</table>
END
    ;
    &Header::closebox();
}
else {
    my $message = '';
    my $title   = '';
    my $refresh = "<meta http-equiv='refresh' content='3; URL=/cgi-bin/index.cgi' />";
    if ($death) {
        $title   = $Lang::tr{'shutting down'};
        $message = $Lang::tr{'openfirewall will now shutdown'};
    }
    else {
        $title   = $Lang::tr{'rebooting'};
        $message = $Lang::tr{'openfirewall will now reboot'};
    }
    &Header::openpage($title, 0, $refresh);

    &Header::openbigbox('100%', 'center');
    &Header::openbox('100%', 'left', '');
    print <<END
<div align='center'>
<table width='100%'>
<tr><td align='center'>
<br /><br /><img src='/openfirewall_big.gif' alt='ipcop' /><br /><br /><br />
</td></tr>
</table>
<br />
<font size='6'>$message</font>
</div>
END
        ;
    &Header::closebox();
}

&Header::closebigbox();
&Header::closepage();
