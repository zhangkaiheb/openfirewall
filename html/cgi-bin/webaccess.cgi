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
# (c) 2004-2008 marco.s - http://www.advproxy.net
# (c) 2018-2019 The Openfirewall Team
#
#

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my $apdir = "/var/ofw/proxy";
my $group_def_file = "$apdir/cre/classrooms";
my $svhosts_file = "$apdir/cre/supervisors";
my $acl_src_noaccess_ips = "$apdir/acls/src_noaccess_ip.acl";
my $acl_src_noaccess_mac = "$apdir/acls/src_noaccess_mac.acl";

my %cgiparams;
my %proxysettings;

my %acl=();
my @group_defs=();
my @groups=();

### Initialize environment
&General::readhash("/var/ofw/proxy/settings", \%proxysettings);

&General::getcgihash(\%cgiparams);

&read_all_groups;
&read_acl_groups;

foreach (@groups)
{
    if ($cgiparams{$_} eq $Lang::tr{'deny'})  { $acl{$_}='on'; }
    if ($cgiparams{$_} eq $Lang::tr{'allow'}) { $acl{$_}='off'; }
}
&read_all_groups;

my $is_supervisor=0;

if ((-e $svhosts_file) && (!-z $svhosts_file))
{
    open (FILE, $svhosts_file);
    while (<FILE>)
    {
        chomp;
        if ($ENV{'REMOTE_ADDR'} eq $_) { $is_supervisor=1; }
    }
    close (FILE);

} else { $is_supervisor=1; }

if (($cgiparams{'ACTION'} eq 'submit') && ($is_supervisor))
{
    if (($cgiparams{'PASSWORD'} eq $proxysettings{'SUPERVISOR_PASSWORD'}) && (!($proxysettings{'SUPERVISOR_PASSWORD'} eq '')) || 
       ((defined($proxysettings{'SUPERVISOR_PASSWORD'})) && ($proxysettings{'SUPERVISOR_PASSWORD'} eq '')))
    {
        &write_acl;
        system('/usr/local/bin/restartsquid');
    }
}

&read_acl_groups;

&Header::showhttpheaders();

print <<END
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <title>Openfirewall - Web Access Manager</title>
    
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <link rel="shortcut icon" href="/favicon.ico" />
    <style type="text/css">\@import url(/include/openfirewall.css);</style>
    <style type="text/css">\@import url(/css/main.css);</style>
</head>
 
<body>

<!-- OPENFIREWALL CONTENT -->

  <table width='100%' border='0'>
    <tr>
      <td valign='top' align='center'>
        <table width='100%' cellspacing='0' cellpadding='10' border='0'>
          <tr>
            <td align='left' valign='top'>
              <form method='post' action='$ENV{'SCRIPT_NAME'}'>
                <table cellspacing='0' cellpadding='0' width='100%' border='0'>
                  <tr>
                    <td width='18'><img src='/images/null.gif' width='18' height='1' alt='' /></td>

                    <td width='12'><img src='/images/null.gif' width='12' height='1' alt='' /></td>

                    <td width='100%'><img src='/images/null.gif' width='257' height='1' alt='' /></td>

                    <td width='145'><img src='/images/null.gif' width='145' height='1' alt='' /></td>

                    <td width='18'><img src='/images/null.gif' width='18' height='1' alt='' /></td>
                  </tr>

                  <tr>
                    <td colspan='2'><img src='/images/boxtop1.png' width='30' height='53' alt='' /></td>

                    <td style='background: url(/images/boxtop2.png);'><b>Openfirewall Web Access Manager</b></td>

                    <td colspan='2'><img src='/images/boxtop3.png' width='163' height='53' alt='' /></td>
                  </tr>
                </table>
                <table cellspacing='0' cellpadding='0' width='100%'>
                  <tr>
                    <td style='background: url(/images/boxleft.png);'><img src='/images/null.gif' width='18' height='1' alt='' /></td>

                    <td colspan='3' style='background-color: #E0E0E0;' width='100%'>

                      <table width='100%' cellpadding='5' border='0'>
                        <tr>
                          <td align='left' valign='top'>
END
;

if ($proxysettings{'CLASSROOM_EXT'} eq 'on')
{
    if (@groups)
    {
        print <<END
                            <table width='70%' cellspacing='2' cellpadding='2' align='center' border='0'>
END
;
if (($is_supervisor) && ((defined($proxysettings{'SUPERVISOR_PASSWORD'})) && (!($proxysettings{'SUPERVISOR_PASSWORD'} eq ''))))
{
print <<END
                              <tr>
                                <td>
                                  <font face='verdana,arial,helvetica' color='#000000' size='2'>$Lang::tr{'supervisor password'}:</font>&nbsp;&nbsp;
                                  <input type='password' name='PASSWORD' size='15'>
                                </td>
                              </tr>
                              <tr><td>&nbsp;</td></tr>
END
;
}
print <<END
                              <tr><td><input type='hidden' name='ACTION' value='submit' /></td></tr>
                            </table>
END
;
        foreach (@groups)
        {
            if ($is_supervisor)
            {
                print"<table width='70%' cellspacing='2' cellpadding='2' align='center' rules='groups' border='0'>";
            } else {
                print"<table width='70%' cellspacing='2' cellpadding='6' align='center' rules='groups' border='0'>";
            }
            print "<tr>\n";
            if ((defined($acl{$_})) && ($acl{$_} eq 'on'))
            {
                print " <td bgcolor='#CC0000' align='center'><font face='verdana,arial,helvetica' color='#FFFFFF' size='2'>$_</font>";
            } else {
                print " <td bgcolor='#009900' align='center'><font face='verdana,arial,helvetica' color='#FFFFFF' size='2'>$_</font>";
            }
            if ($is_supervisor)
            {
                if ((defined($acl{$_})) && ($acl{$_} eq 'on'))
                {
                     print "</td><td width='120' bgcolor='#A0A0A0' align='center'>";
                     print "<input type='submit' name='$_' value=' $Lang::tr{'allow'} ' />";
                     print "</td><td width='16' bgcolor='#CC0000'>&nbsp;</td>\n";
                 } else {
                     print "</td><td width='120' bgcolor='#A0A0A0' align='center'>";
                     print "<input type='submit' name='$_' value=' $Lang::tr{'deny'} ' />";
                     print "</td><td width='16' bgcolor='#009900'>&nbsp;</td>\n";
                }
            }
            print "</tr>\n";
            print "</table>\n";
            print"<table width='70%' cellspacing='2' cellpadding='2' align='center'>";
            print "<tr><td>&nbsp;</td></tr>\n";
            print "</table>\n";
        }
    } else {
        print "$Lang::tr{'cre no groups'}\n";
    }
} else {
    print "$Lang::tr{'cre management disabled'}\n";
}

print <<END
                          </td>
                        </tr>
                      </table>
                    </td>
                    <td style='background: url(/images/boxright.png);'><img src='/images/null.gif' width='12' alt='' /></td>
                  </tr>
                  <tr>
                    <td style='background: url(/images/boxbottom1.png);background-repeat:no-repeat;'>
                      <img src='/images/null.gif' width='18' height='18' alt='' /></td>
                    <td style='background: url(/images/boxbottom2.png);background-repeat:repeat-x;' colspan='3'>
                      <img src='/images/null.gif' width='1' height='18' alt='' /></td>
                    <td style='background: url(/images/boxbottom3.png);background-repeat:no-repeat;'>
                      <img src='/images/null.gif' width='18' height='18' alt='' /></td>
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

&Header::closepage('skip_connected');

# -------------------------------------------------------------------

sub read_acl_groups
{
    undef(%acl);
    open (FILE,"$acl_src_noaccess_ips");
    my @aclgroups = <FILE>;
    close (FILE);
    foreach (@aclgroups)
    {
        chomp;
        if (/^\#/)
        {
            s/^\# //;
            $acl{$_}='on';
        }
    }
}

# -------------------------------------------------------------------

sub read_all_groups
{
    my $grpstr;

    open (FILE,"$group_def_file");
    @group_defs = <FILE>;
    close (FILE);

    undef(@groups);
    foreach (@group_defs)
    {
        chomp;
        if (/^\s*\[.*\]\s*$/)
        {
            $grpstr=$_;
            $grpstr =~ s/^\s*\[\s*//;
            $grpstr =~ s/\s*\]\s*$//;
            push(@groups,$grpstr);
        }
    }
}

# -------------------------------------------------------------------

sub write_acl
{
    my $is_blocked=0;

    open (FILE_IPS,">$acl_src_noaccess_ips");
    open (FILE_MAC,">$acl_src_noaccess_mac");
    flock (FILE_IPS, 2);
    flock (FILE_MAC, 2);
    foreach (@group_defs)
    {
        if (/^\s*\[.*\]\s*$/)
        {
            s/^\s*\[\s*//;
            s/\s*\]\s*$//;
            if ((defined($acl{$_})) && ($acl{$_} eq 'on'))
            {
                 print FILE_IPS "# $_\n";
                 print FILE_MAC "# $_\n";
                 $is_blocked=1;
             } else {
                 $is_blocked=0;
             }
        } elsif (($is_blocked) && ($_)) {
            s/^\s+//g; s/\s+$//g;
            /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i ? print FILE_MAC "$_\n" : print FILE_IPS "$_\n";
        }
    }
    close (FILE_IPS);
    close (FILE_MAC);
}

# -------------------------------------------------------------------
