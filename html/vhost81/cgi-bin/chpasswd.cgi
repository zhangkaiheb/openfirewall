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
# (c) 2005 marco.s - http://www.advproxy.net
# (c) 2010-2014 The Openfirewall Team
#
# $Id: chpasswd.cgi 7558 2014-05-22 13:03:59Z owes $
#

use strict;
use Apache::Htpasswd;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';

my %cgiparams;
my %proxysettings;

$proxysettings{'NCSA_MIN_PASS_LEN'} = 6;

### Initialize environment
&General::readhash("/var/ofw/proxy/settings", \%proxysettings);

my $userdb = '/var/ofw/proxy/ncsa/passwd';

my @users = ();
my @temp = ();

my $success = 0;
my $errormessage = '';
my $username = '';
my $cryptpwd = '';
my $returncode = '';

$cgiparams{'SUBMIT'} = '';
&General::getcgihash(\%cgiparams);

if ($cgiparams{'SUBMIT'} eq $Lang::tr{'change password'})
{
    if (! -e $userdb) {
        $errormessage = $Lang::tr{'errmsg change fail'};
        goto ERROR;
    }

    if ($cgiparams{'USERNAME'} eq '') {
        $errormessage = $Lang::tr{'errmsg no username'};
        goto ERROR;
    }
    if (($cgiparams{'OLD_PASSWORD'} eq '') || ($cgiparams{'NEW_PASSWORD_1'} eq '') || ($cgiparams{'NEW_PASSWORD_2'} eq '')) {
        $errormessage = $Lang::tr{'errmsg no password'};
        goto ERROR;
    }
    if (!($cgiparams{'NEW_PASSWORD_1'} eq $cgiparams{'NEW_PASSWORD_2'})) {
        $errormessage = $Lang::tr{'errmsg passwords different'};
        goto ERROR;
    }
    if (length($cgiparams{'NEW_PASSWORD_1'}) < $proxysettings{'NCSA_MIN_PASS_LEN'}) {
        $errormessage = $Lang::tr{'errmsg password length 1'}.' '.$proxysettings{'NCSA_MIN_PASS_LEN'}.' '.$Lang::tr{'errmsg password length 2'};
        goto ERROR;
    }

    my $htpasswd = new Apache::Htpasswd({passwdFile => $userdb, UseMD5 => 1});
    $cryptpwd = $htpasswd->fetchPass($cgiparams{'USERNAME'});
    if (!$cryptpwd) {
        $errormessage = $Lang::tr{'errmsg invalid user'};
        goto ERROR;
    }
    if (!$htpasswd->htpasswd($cgiparams{'USERNAME'}, $cgiparams{'NEW_PASSWORD_1'}, $cgiparams{'OLD_PASSWORD'})) {
        $errormessage = $Lang::tr{'incorrect password'};
        goto ERROR;
    }

    $success = 1;
    undef %cgiparams;
}

ERROR:

# Can't use showhttpheaders, it will redirect to https on GUI port
print "Pragma: no-cache\n";
print "Cache-control: no-cache\n";
print "Connection: close\n";
print "Content-type: text/html\n\n";

print <<END
<!DOCTYPE html
     PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
     "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <title>Openfirewall - $Lang::tr{'change web access password'}</title>
    
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <link rel="shortcut icon" href="/favicon.ico" />
    <style type="text/css">\@import url(/include/openfirewall.css);</style>
</head>
 
<body>

<!-- OPENFIREWALL CONTENT -->

  <table width='100%' border='0'>
    <tr>
      <td valign='top' align='center'>
        <table width='100%' cellspacing='0' cellpadding='10' border='0'>
          <tr>
            <td align='left' valign='top'>
              <form method='post' action='/cgi-bin/chpasswd.cgi'>
                 <table cellspacing='0' cellpadding='0' width='100%' border='0'>
                  <col width='18' />
                  <col width='12' />
                  <col width='100%' />
                  <col width='145' />
                  <col width='18' />

                  <tr>
                    <td width='18'><img src='/images/null.gif' width='18' height='1' alt='' /></td>

                    <td width='12'><img src='/images/null.gif' width='12' height='1' alt='' /></td>

                    <td width='100%'><img src='/images/null.gif' width='257' height='1' alt='' /></td>

                    <td width='145'><img src='/images/null.gif' width='145' height='1' alt='' /></td>

                    <td width='18'><img src='/images/null.gif' width='18' height='1' alt='' /></td>
                  </tr>

                  <tr>
                    <td colspan='2'><img src='/images/boxtop1.png' width='30' height='53' alt='' /></td>

                    <td style='background: url(/images/boxtop2.png);'><b>$Lang::tr{'change web access password'}:</b></td>

                    <td colspan='2'><img src='/images/boxtop3.png' width='163' height='53' alt='' /></td>
                  </tr>
                </table>

                <table cellspacing='0' cellpadding='0' width='100%' border='0'>
                  <tr>
                    <td style='background: url(/images/boxleft.png);'><img src='/images/null.gif' width='18' height='1' alt='' /></td>

                    <td colspan='3' style='background-color: #E0E0E0;' width='100%'>
                      <table width='100%' cellpadding='5'>
                        <tr>
                          <td align='left' valign='top'>
                            <table width='100%'>
                              <tr><td>&nbsp;</td></tr>
                              <tr>
                                <td width='15%' class='base'>&nbsp;</td>
                                <td width='25%' class='base' align='right'>$Lang::tr{'username'}:</td>
                                <td width='5%'>&nbsp;</td>
                                <td><input type='text' name='USERNAME' size='19' maxlength='40' /></td>
                              </tr>
                              <tr><td>&nbsp;</td></tr>
                              <tr>
                                <td width='15%' class='base'>&nbsp;</td>
                                <td width='25%' class='base' align='right'>$Lang::tr{'current password'}:</td>
                                <td width='5%'>&nbsp;</td>
                                <td><input type='password' name='OLD_PASSWORD' size='20' maxlength='128' /></td>
                              </tr>
                              <tr><td>&nbsp;</td></tr>
                              <tr>
                                <td width='15%' class='base'>&nbsp;</td>
                                <td width='25%' class='base' align='right'>$Lang::tr{'new password'}:</td>
                                <td width='5%'>&nbsp;</td>
                                <td><input type='password' name='NEW_PASSWORD_1' size='20' maxlength='128' /></td>
                              </tr>
                              <tr><td>&nbsp;</td></tr>
                              <tr>
                                <td width='15%' class='base'>&nbsp;</td>
                                <td width='25%' class='base' align='right'>$Lang::tr{'confirm new password'}:</td>
                                <td width='5%'>&nbsp;</td>
                                <td><input type='password' name='NEW_PASSWORD_2' size='20' maxlength='128' /></td>
                              </tr>
                              <tr><td>&nbsp;</td></tr>
                        </table>
                            <hr />
                            <table width='100%'>
END
;

if ($errormessage) {
    print "<tr><td width='5%'></td><td bgcolor='#CC0000'><center><b><font color='white'>$Lang::tr{'capserror'}: $errormessage</font></b></center></td><td width='5%'></td></tr>\n";
}
else {
    if ($success) {
        print "<tr><td width='5%'></td><td bgcolor='#339933'><center><b><font color='white'>$Lang::tr{'password changed'}</font></b></center></td><td width='5%'></td></tr>\n";
    }
    else {
        print "<tr><td><center>$Lang::tr{'web access password hint'}</center></td></tr>\n";
    }
}


# manual page reference, not in user page
# http://www.openfirewall.org/2.0.0/en/admin/html/webaccess-passwords.html

print <<END
                            </table>
                            <hr />
                            <table width='100%'>
                              <tr>
                                <td class='comment1button'>&nbsp;</td>
                                <td class='button1button'><input type='submit' name='SUBMIT' value='$Lang::tr{'change password'}' /></td>
                                <td class='onlinehelp'>&nbsp;</td>
                              </tr>
                            </table>
                          </td>
                        </tr>
                      </table>
                    </td>

                    <td style='background: url(/images/boxright.png);'><img src='/images/null.gif' width='12' alt='' /></td>
                  </tr>

                  <tr>
                    <td style='background: url(/images/boxbottom1.png);background-repeat:no-repeat;'><img src=
                    '/images/null.gif' width='18' height='18' alt='' /></td>

                    <td style='background: url(/images/boxbottom2.png);background-repeat:repeat-x;' colspan='3'><img src=
                    '/images/null.gif' width='1' height='18' alt='' /></td>

                    <td style='background: url(/images/boxbottom3.png);background-repeat:no-repeat;'><img src=
                    '/images/null.gif' width='18' height='18' alt='' /></td>
                  </tr>

                  <tr>
                    <td colspan='5'><img src='/images/null.gif' width='1' height='5' alt='' /></td>
                  </tr>
                </table>
              </form>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>

END
;
