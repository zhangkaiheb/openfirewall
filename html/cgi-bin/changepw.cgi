#!/usr/bin/perl
#
# This file is part of the IPCop Firewall.
#
# IPCop is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# IPCop is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IPCop.  If not, see <http://www.gnu.org/licenses/>.
#
# (c) The SmoothWall Team
# (c) 2001-2014, the IPCop team
#
# $Id: changepw.cgi 7558 2014-05-22 13:03:59Z owes $
#

# Add entry in menu
# MENUENTRY system 040 "sspasswords" "sspasswords"
#
# Make sure translation exists $Lang::tr{'sspasswords'}

use strict;
use Apache::Htpasswd;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

my %cgiparams    = ();
my $errormessage = '';
my $error_admin  = '';
my $error_dial   = '';

&Header::showhttpheaders();

$cgiparams{'ACTION_ADMIN'} = '';
$cgiparams{'ACTION_DIAL'}  = '';

&General::getcgihash(\%cgiparams);

if ($cgiparams{'ACTION_ADMIN'} eq $Lang::tr{'save'}) {
    my $password1 = $cgiparams{'ADMIN_PASSWORD1'};
    my $password2 = $cgiparams{'ADMIN_PASSWORD2'};
    if ($password1 eq $password2) {
        if ($password1 =~ m/[\s\"']/) {
            $errormessage = $Lang::tr{'password contains illegal characters'} . ": [ &#92;s&#92; &#34; &#39; ]";
            $error_admin  = 'error';
        }
        elsif (length($password1) >= 6) {
            my $htpasswd = new Apache::Htpasswd({passwdFile => '/var/ipcop/auth/users', UseMD5 => 1});
            $htpasswd->htDelete('admin');
            if (!$htpasswd->htpasswd('admin', $cgiparams{'ADMIN_PASSWORD1'})) {
                $errormessage = $Lang::tr{'errmsg change fail'};
                $error_admin  = 'error';
            }
            else {
                &General::log($Lang::tr{'admin user password has been changed'});
            }
        }
        else {
            $errormessage = $Lang::tr{'passwords must be at least 6 characters in length'};
            $error_admin  = 'error';
        }
    }
    else {
        $errormessage = $Lang::tr{'passwords do not match'};
        $error_admin  = 'error';
    }
}

if ($cgiparams{'ACTION_DIAL'} eq $Lang::tr{'save'}) {
    my $password1 = $cgiparams{'DIAL_PASSWORD1'};
    my $password2 = $cgiparams{'DIAL_PASSWORD2'};
    if ($password1 eq $password2) {
        if ($password1 =~ m/[\s\"']/) {
            $errormessage = $Lang::tr{'password contains illegal characters'} . ": [ &#92;s&#92; &#34; &#39; ]";
            $error_dial   = 'error';
        }
        elsif (length($password1) >= 6) {
            my $htpasswd = new Apache::Htpasswd({passwdFile => '/var/ipcop/auth/users', UseMD5 => 1});
            $htpasswd->htDelete('dial');
            if (!$htpasswd->htpasswd('dial', $cgiparams{'DIAL_PASSWORD1'})) {
                $errormessage = $Lang::tr{'errmsg change fail'};
                $error_dial  = 'error';
            }
            else {
                &General::log($Lang::tr{'dial user password has been changed'});
            }
        }
        else {
            $errormessage = $Lang::tr{'passwords must be at least 6 characters in length'};
            $error_dial   = 'error';
        }
    }
    else {
        $errormessage = $Lang::tr{'passwords do not match'};
        $error_dial   = 'error';
    }
}

&Header::openpage($Lang::tr{'change passwords'}, 1, '');

&Header::openbigbox('100%', 'left', '');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();
}

print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";

&Header::openbox('100%', 'left', "$Lang::tr{'administrator user password'}:", $error_admin);
print <<END
<table width='100%'>
<tr>
    <td width='20%' class='base'>$Lang::tr{'username'}:&nbsp;'admin'</td>
    <td width='15%' class='base' align='right'>$Lang::tr{'password'}:&nbsp;</td>
    <td><input type='password' name='ADMIN_PASSWORD1' size='20' maxlength='40'/></td>
</tr><tr>
    <td width='20%' class='base'>&nbsp;</td>
    <td width='15%' class='base' align='right'>$Lang::tr{'again'}:&nbsp;</td>
    <td><input type='password' name='ADMIN_PASSWORD2' size='20' maxlength='40'/></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'> &nbsp; </td>
    <td class='button1button'><input type='submit' name='ACTION_ADMIN' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/system-passwords.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
    ;
&Header::closebox();

&Header::openbox('100%', 'left', "$Lang::tr{'dial user password'}:", $error_dial);
print <<END
<table width='100%'>
<tr>
    <td width='20%' class='base'>$Lang::tr{'username'}:&nbsp;'dial'</td>
    <td width='15%' class='base' align='right'>$Lang::tr{'password'}:&nbsp;</td>
    <td><input type='password' name='DIAL_PASSWORD1' size='20' maxlength='40'/></td>
</tr><tr>
    <td width='20%' class='base'>&nbsp;</td>
    <td width='15%' class='base' align='right'>$Lang::tr{'again'}:&nbsp;</td>
    <td><input type='password' name='DIAL_PASSWORD2' size='20' maxlength='40'/></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'> &nbsp; </td>
    <td class='button1button'><input type='submit' name='ACTION_DIAL' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/system-passwords.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
    ;
&Header::closebox();

print "</form>\n";

&Header::closebigbox();

&Header::closepage();
