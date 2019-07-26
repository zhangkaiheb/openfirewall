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
# (c) 2018-2020 The Openfirewall Team
#

# Add entry in menu
# MENUTHRDLVL "sys settings" 010 "gui settings" "gui settings"

use strict;

# enable only the following on debugging purpose
#use warnings; no warnings 'once';# 'redefine', 'uninitialized';
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my %cgiparams    = ();
my %mainsettings = ();
my %checked      = ();
my %selected     = ();
my $errormessage = '';

$cgiparams{'JAVASCRIPT'}         = 'off';
$cgiparams{'WINDOWWITHHOSTNAME'} = 'off';
$cgiparams{'REFRESHINDEX'}       = 'off';
$cgiparams{'PPPUPDOWNBEEP'}      = 'off';
$cgiparams{'OFWUPDOWNBEEP'}    = 'off';
$cgiparams{'ACTION'}             = '';
&General::getcgihash(\%cgiparams);

&Header::showhttpheaders();
&General::readhash('/var/ofw/main/settings', \%mainsettings);

if ($cgiparams{'ACTION'} eq "$Lang::tr{'save'}") {
    open(FILE, '/var/ofw/main/language.lst');
    my $found = 0;
    while (<FILE>) {
        my $lang    = '';
        my $engname = '';
        chomp;
        ($lang, $engname) = split(/:/, $_, 3);
        if ($cgiparams{'LANGUAGE'} eq $lang) {
            $found = 1;
            $cgiparams{'LOCALE'} = $engname;
            last;    # out of while loop
        }
    }
    close(FILE);
    if ($found == 0) {
        $errormessage = $Lang::tr{'invalid input'};
        goto SAVE_ERROR;
    }

    if (   ($cgiparams{'JAVASCRIPT'} !~ /^(on|off)$/)
        || ($cgiparams{'WINDOWWITHHOSTNAME'} !~ /^(on|off)$/)
        || ($cgiparams{'REFRESHINDEX'} !~ /^(on|off)$/)
        || ($cgiparams{'PPPUPDOWNBEEP'} !~ /^(on|off)$/)
        || ($cgiparams{'OFWUPDOWNBEEP'} !~ /^(on|off)$/))
    {
        $errormessage = $Lang::tr{'invalid input'};
        goto SAVE_ERROR;
    }

    my $changedlang = 0;
    $changedlang = 1 if (($mainsettings{'LANGUAGE'} ne $cgiparams{'LANGUAGE'}) || ($mainsettings{'LOCALE'} ne $cgiparams{'LOCALE'}));

    # write cgi vars to the file.
    $mainsettings{'LANGUAGE'}           = $cgiparams{'LANGUAGE'};
    $mainsettings{'LOCALE'}             = $cgiparams{'LOCALE'};
    $mainsettings{'JAVASCRIPT'}         = $cgiparams{'JAVASCRIPT'};
    $mainsettings{'WINDOWWITHHOSTNAME'} = $cgiparams{'WINDOWWITHHOSTNAME'};
    $mainsettings{'PPPUPDOWNBEEP'}      = $cgiparams{'PPPUPDOWNBEEP'};
    $mainsettings{'OFWUPDOWNBEEP'}    = $cgiparams{'OFWUPDOWNBEEP'};
    $mainsettings{'REFRESHINDEX'}       = $cgiparams{'REFRESHINDEX'};
    &General::writehash('/var/ofw/main/settings', \%mainsettings);

    if ($changedlang == 1) {
        &General::log("Changing language to: $mainsettings{'LANGUAGE'} ($mainsettings{'LOCALE'})");
        system('/usr/local/bin/rebuildlangtexts');
        &Lang::reload(1);
    }
SAVE_ERROR:
}
else {
    if ($mainsettings{'JAVASCRIPT'}) {
        $cgiparams{'JAVASCRIPT'} = $mainsettings{'JAVASCRIPT'};
    }
    else {
        $cgiparams{'JAVASCRIPT'} = 'on';
    }

    if ($mainsettings{'WINDOWWITHHOSTNAME'}) {
        $cgiparams{'WINDOWWITHHOSTNAME'} = $mainsettings{'WINDOWWITHHOSTNAME'};
    }
    else {
        $cgiparams{'WINDOWWITHHOSTNAME'} = 'off';
    }

    if ($mainsettings{'PPPUPDOWNBEEP'}) {
        $cgiparams{'PPPUPDOWNBEEP'} = $mainsettings{'PPPUPDOWNBEEP'};
    }
    else {
        $cgiparams{'PPPUPDOWNBEEP'} = 'on';
    }

    if ($mainsettings{'OFWUPDOWNBEEP'}) {
        $cgiparams{'OFWUPDOWNBEEP'} = $mainsettings{'OFWUPDOWNBEEP'};
    }
    else {
        $cgiparams{'OFWUPDOWNBEEP'} = 'on';
    }

    if ($mainsettings{'REFRESHINDEX'}) {
        $cgiparams{'REFRESHINDEX'} = $mainsettings{'REFRESHINDEX'};
    }
    else {
        $cgiparams{'REFRESHINDEX'} = 'off';
    }

    if ($mainsettings{'LANGUAGE'}) {
        $cgiparams{'LANGUAGE'} = $mainsettings{'LANGUAGE'};
    }
    else {
        $cgiparams{'LANGUAGE'} = 'en';
    }
}

# Default settings
if ($cgiparams{'ACTION'} eq "$Lang::tr{'restore defaults'}") {
    $cgiparams{'JAVASCRIPT'}         = 'on';
    $cgiparams{'WINDOWWITHHOSTNAME'} = 'off';
    $cgiparams{'PPPUPDOWNBEEP'}      = 'on';
    $cgiparams{'OFWUPDOWNBEEP'}    = 'on';
    $cgiparams{'REFRESHINDEX'}       = 'off';
}

$checked{'JAVASCRIPT'}{'off'}                    = '';
$checked{'JAVASCRIPT'}{'on'}                     = '';
$checked{'JAVASCRIPT'}{$cgiparams{'JAVASCRIPT'}} = "checked='checked'";

$checked{'WINDOWWITHHOSTNAME'}{'off'}                            = '';
$checked{'WINDOWWITHHOSTNAME'}{'on'}                             = '';
$checked{'WINDOWWITHHOSTNAME'}{$cgiparams{'WINDOWWITHHOSTNAME'}} = "checked='checked'";

$checked{'PPPUPDOWNBEEP'}{'off'}                       = '';
$checked{'PPPUPDOWNBEEP'}{'on'}                        = '';
$checked{'PPPUPDOWNBEEP'}{$cgiparams{'PPPUPDOWNBEEP'}} = "checked='checked'";

$checked{'OFWUPDOWNBEEP'}{'off'}                         = '';
$checked{'OFWUPDOWNBEEP'}{'on'}                          = '';
$checked{'OFWUPDOWNBEEP'}{$cgiparams{'OFWUPDOWNBEEP'}} = "checked='checked'";

$checked{'REFRESHINDEX'}{'off'}                      = '';
$checked{'REFRESHINDEX'}{'on'}                       = '';
$checked{'REFRESHINDEX'}{$cgiparams{'REFRESHINDEX'}} = "checked='checked'";

open(FILE, '/var/ofw/main/language.lst');
my $optionlist = '';
while (<FILE>) {
    my $lang      = '';
    my $engname   = '';
    my $natname   = '';
    my $transname = '';
    my $selected  = '';
    chomp;
    ($lang, $engname, $natname, $transname) = split(/:/, $_, 5);
    if ($lang eq $cgiparams{'LANGUAGE'}) { $selected = "selected='selected'"; }
    $optionlist .= "\t<option value='$lang' $selected >$engname ($natname:$transname)</option>\n";
}

&Header::openpage($Lang::tr{'gui settings'}, 1, '');
&Header::openbigbox('100%', 'left', '');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", "error");
    print "<font class='base'>${errormessage}&nbsp;</font>\n";
    &Header::closebox();
}

&Header::openbox('100%', 'left', "$Lang::tr{'gui settings'}:");

print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td colspan='2'><b>$Lang::tr{'display'}</b></td>
</tr><tr>
    <td><input type='checkbox' name='JAVASCRIPT' $checked{'JAVASCRIPT'}{'on'} /></td>
    <td width='100%'>$Lang::tr{'enable javascript'}</td>
</tr><tr>
    <td><input type='checkbox' name='WINDOWWITHHOSTNAME' $checked{'WINDOWWITHHOSTNAME'}{'on'} /></td>
    <td>$Lang::tr{'display hostname in window title'}</td>
</tr><tr>
    <td><input type='checkbox' name='REFRESHINDEX' $checked{'REFRESHINDEX'}{'on'} /></td>
    <td>$Lang::tr{'refresh index page while connected'}</td>
</tr><tr>
    <td>&nbsp;</td>
    <td>$Lang::tr{'languagepurpose'}:</td>
</tr><tr>
    <td>&nbsp;</td>
    <td><select name='LANGUAGE'>\n$optionlist\t</select></td>
</tr>
<tr>
    <td colspan='2'><hr /><b>$Lang::tr{'beep on ...'}</b></td>
</tr>
<tr>
    <td><input type ='checkbox' name='PPPUPDOWNBEEP' $checked{'PPPUPDOWNBEEP'}{'on'}  /></td>
    <td>$Lang::tr{'beep on ... ppp connects or disconnects'}</td>
</tr>
<tr>
    <td><input type ='checkbox' name='OFWUPDOWNBEEP' $checked{'OFWUPDOWNBEEP'}{'on'} /></td>
    <td>$Lang::tr{'beep on ... system start or stop'}</td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
<!--    <td class='comment2buttons'>&nbsp;</td> -->
    <td class='button2buttons'>
        <input type='submit' name='ACTION' class='commonbuttons' value='$Lang::tr{'restore defaults'}' />
    </td>
    <td class='button2buttons'>
        <input type='submit' name='ACTION' class='commonbuttons' value='$Lang::tr{'save'}' />
    </td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/system-gui-settings.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
END
    ;
&Header::closebox();
&Header::closebigbox();
&Header::closepage();
