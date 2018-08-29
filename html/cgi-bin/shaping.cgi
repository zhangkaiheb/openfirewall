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
#  Copyright 2003-04-06 David Kilpatrick <dave@thunder.com.au>
#
# $Id: shaping.cgi 6356 2012-02-17 13:08:32Z dotzball $
#

# Add entry in menu
# MENUENTRY services 070 "traffic shaping" "traffic shaping settings"

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my %shapingsettings = ();
my $configfile      = '/var/ofw/shaping/config';
my $settingsfile    = '/var/ofw/shaping/settings';
my $errormessage    = '';
my $error_settings  = '';
my $error_config    = '';

&Header::showhttpheaders();

$shapingsettings{'ACTION'}          = '';
$shapingsettings{'ENABLE'}          = 'off';
$shapingsettings{'VALID'}           = '';
$shapingsettings{'UPLINK'}          = '';
$shapingsettings{'DOWNLINK'}        = '';
$shapingsettings{'SERVICE_ENABLED'} = '';
$shapingsettings{'SERVICE_PROT'}    = '';
$shapingsettings{'SERVICE_PRIO'}    = '';
$shapingsettings{'SERVICE_PORT'}    = '';

&General::getcgihash(\%shapingsettings);

open(FILE, "$configfile") or die 'Unable to open shaping config file.';
my @current = <FILE>;
close(FILE);

if ($shapingsettings{'ACTION'} eq $Lang::tr{'save'}) {
    if (!($shapingsettings{'UPLINK'} =~ /^\d+$/) || ($shapingsettings{'UPLINK'} < 2)) {
        $errormessage = $Lang::tr{'invalid uplink speed'};
        goto ERROR;
    }

    if (!($shapingsettings{'DOWNLINK'} eq '') && (!($shapingsettings{'DOWNLINK'} =~ /^\d+$/) || ($shapingsettings{'DOWNLINK'} < 2))) {
        $errormessage = $Lang::tr{'invalid downlink speed'};
        goto ERROR;
    }

ERROR:
    if ($errormessage) {
        $shapingsettings{'VALID'} = 'no';
        $error_settings = 'error';
    }
    else {
        $shapingsettings{'VALID'} = 'yes';
    }

    open(FILE, ">$settingsfile") or die 'Unable to open shaping settings file.';
    flock FILE, 2;
    print FILE "VALID=$shapingsettings{'VALID'}\n";
    print FILE "ENABLE=$shapingsettings{'ENABLE'}\n";
    print FILE "UPLINK=$shapingsettings{'UPLINK'}\n";
    print FILE "DOWNLINK=$shapingsettings{'DOWNLINK'}\n";
    close FILE;

    if ($shapingsettings{'VALID'} eq 'yes') {
        system('/usr/local/bin/restartshaping');
    }
}
if ($shapingsettings{'ACTION'} eq $Lang::tr{'add'}) {
    unless ($shapingsettings{'SERVICE_PROT'} =~ /^(tcp|udp)$/)  { $errormessage = $Lang::tr{'invalid input'}; }
    unless ($shapingsettings{'SERVICE_PRIO'} =~ /^(10|20|30)$/) { $errormessage = $Lang::tr{'invalid input'}; }
    unless (&General::validport($shapingsettings{'SERVICE_PORT'})) { $errormessage = $Lang::tr{'invalid port'}; }

    if (!$errormessage) {
        if ($shapingsettings{'EDITING'} eq 'no') {
            open(FILE, ">>$configfile") or die 'Unable to open shaping config file';
            flock FILE, 2;
            print FILE
"$shapingsettings{'SERVICE_PROT'},$shapingsettings{'SERVICE_PORT'},$shapingsettings{'SERVICE_PRIO'},$shapingsettings{'SERVICE_ENABLED'}\n";
        }
        else {
            open(FILE, ">$configfile") or die 'Unable to open shaping config file';
            flock FILE, 2;
            my $id = 0;
            foreach my $line (@current) {
                $id++;
                chomp($line);
                my @temp = split(/\,/, $line);
                if ($shapingsettings{'EDITING'} eq $id) {
                    print FILE
"$shapingsettings{'SERVICE_PROT'},$shapingsettings{'SERVICE_PORT'},$shapingsettings{'SERVICE_PRIO'},$shapingsettings{'SERVICE_ENABLED'}\n";
                }
                else {
                    print FILE "$line\n";
                }
            }
        }
        close FILE;
        &sortconfigfile;
        undef %shapingsettings;
        system('/usr/local/bin/restartshaping');
    }
    else {
        $error_config = 'error';

        # stay on edit mode if an error occur
        if ($shapingsettings{'EDITING'} ne 'no') {
            $shapingsettings{'ACTION'} = $Lang::tr{'edit'};
            $shapingsettings{'ID'}     = $shapingsettings{'EDITING'};
        }
    }
}

if ($shapingsettings{'ACTION'} eq $Lang::tr{'edit'}) {
    my $id = 0;
    foreach my $line (@current) {
        $id++;
        if ($shapingsettings{"ID"} eq $id) {
            chomp($line);
            my @temp = split(/\,/, $line);
            $shapingsettings{'SERVICE_PROT'}    = $temp[0];
            $shapingsettings{'SERVICE_PORT'}    = $temp[1];
            $shapingsettings{'SERVICE_PRIO'}    = $temp[2];
            $shapingsettings{'SERVICE_ENABLED'} = $temp[3];
        }
    }
}

if (   $shapingsettings{'ACTION'} eq $Lang::tr{'remove'}
    || $shapingsettings{'ACTION'} eq $Lang::tr{'toggle enable disable'})
{
    open(FILE, ">$configfile") or die 'Unable to open config file.';
    flock FILE, 2;
    my $id = 0;
    foreach my $line (@current) {
        $id++;
        unless ($shapingsettings{"ID"} eq $id) {
            print FILE "$line";
        }
        elsif ($shapingsettings{'ACTION'} eq $Lang::tr{'toggle enable disable'}) {
            chomp($line);
            my @temp = split(/\,/, $line);
            if ($temp[3] eq "on") {
                print FILE "$temp[0],$temp[1],$temp[2],off\n";
            }
            else {
                print FILE "$temp[0],$temp[1],$temp[2],on\n";
            }
        }
    }
    close(FILE);
    system('/usr/local/bin/restartshaping');
}

&General::readhash($settingsfile, \%shapingsettings);

if ($shapingsettings{'ACTION'} eq '') {
    $shapingsettings{'SERVICE_ENABLED'} = 'on';
    $shapingsettings{'SERVICE_PROT'}    = 'tcp';
    $shapingsettings{'SERVICE_PRIO'}    = '20';
    $shapingsettings{'SERVICE_PORT'}    = '';
}

my %checked = ();
$checked{'ENABLE'}{'off'}                      = '';
$checked{'ENABLE'}{'on'}                       = '';
$checked{'ENABLE'}{$shapingsettings{'ENABLE'}} = "checked='checked'";

my %service_checked = ();
$service_checked{'SERVICE_ENABLED'}{'off'}                               = '';
$service_checked{'SERVICE_ENABLED'}{'on'}                                = '';
$service_checked{'SERVICE_ENABLED'}{$shapingsettings{'SERVICE_ENABLED'}} = "checked='checked'";

my %service_selected = ();
$service_selected{'SERVICE_PROT'}{'udp'}                            = '';
$service_selected{'SERVICE_PROT'}{'tcp'}                            = '';
$service_selected{'SERVICE_PROT'}{$shapingsettings{'SERVICE_PROT'}} = "selected='selected'";

$service_selected{'SERVICE_PRIO'}{'10'}                             = '';
$service_selected{'SERVICE_PRIO'}{'20'}                             = '';
$service_selected{'SERVICE_PRIO'}{'30'}                             = '';
$service_selected{'SERVICE_PRIO'}{$shapingsettings{'SERVICE_PRIO'}} = "selected='selected'";

&Header::openpage($Lang::tr{'traffic shaping settings'}, 1, '');

&Header::openbigbox('100%', 'left', '');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>\n";
    &Header::closebox();
}

print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";

&Header::openbox('100%', 'left', "$Lang::tr{'settings'}:", $error_settings);
print <<END
<table width='100%'>
<tr>
    <td><input type='checkbox' name='ENABLE' $checked{'ENABLE'}{'on'} /></td>
    <td class='base' colspan='2'>$Lang::tr{'traffic shaping'}</td>
</tr>
<tr>
    <td>&nbsp;</td>
    <td width='30%' class='base'>$Lang::tr{'downlink speed'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td width='70%'><input type='text' name='DOWNLINK' value='$shapingsettings{'DOWNLINK'}' size='5' /></td>
</tr>
<tr>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'uplink speed'}:&nbsp;</td>
    <td><input type='text' name='UPLINK' value='$shapingsettings{'UPLINK'}' size='5' /></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' align='top' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button1button'><input type='submit' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-shaping.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
    ;
&Header::closebox;

print "</form>\n";
print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";

my $buttontext = $Lang::tr{'add'};
if ($shapingsettings{'ACTION'} eq $Lang::tr{'edit'}) {
    $buttontext = $Lang::tr{'update'};
    &Header::openbox('100%', 'left', $Lang::tr{'edit service'}, $error_config);
}
else {
    &Header::openbox('100%', 'left', $Lang::tr{'add service'}, $error_config);
}

print <<END

<table width='100%'>
<tr>
    <td class='base'>$Lang::tr{'priority'}:&nbsp;</td>
    <td><select name='SERVICE_PRIO'>
        <option value='10' $service_selected{'SERVICE_PRIO'}{'10'}>$Lang::tr{'high'}</option>
        <option value='20' $service_selected{'SERVICE_PRIO'}{'20'}>$Lang::tr{'medium'}</option>
        <option value='30' $service_selected{'SERVICE_PRIO'}{'30'}>$Lang::tr{'low'}</option>
    </select></td>
    <td width='20%' class='base' align='right'>$Lang::tr{'port'}:&nbsp;</td>
    <td><input type='text' name='SERVICE_PORT' value='$shapingsettings{'SERVICE_PORT'}' size='5' /></td>
    <td width='20%' class='base' align='right'>$Lang::tr{'protocol'}:&nbsp;</td>
    <td><select name='SERVICE_PROT'>
                <option value='tcp' $service_selected{'SERVICE_PROT'}{'tcp'}>TCP</option>
                <option value='udp' $service_selected{'SERVICE_PROT'}{'udp'}>UDP</option>
            </select></td>
    <td width='20%' class='base' align='right'>$Lang::tr{'enabled'}:&nbsp;</td>
    <td width='20%'><input type='checkbox' name='SERVICE_ENABLED' $service_checked{'SERVICE_ENABLED'}{'on'} /></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'><input type='submit' name='SUBMIT' value='$buttontext' /><input type='hidden' name='ACTION' value='$Lang::tr{'add'}' /></td>
    <td class='onlinehelp'>&nbsp;</td>
</tr>
</table>
END
    ;
&Header::closebox;

if ($shapingsettings{'ACTION'} eq $Lang::tr{'edit'}) {
    print "<input type='hidden' name='EDITING' value='$shapingsettings{'ID'}' />\n";
}
else {
    print "<input type='hidden' name='EDITING' value='no' />\n";
}

print "</form>\n";

&Header::openbox('100%', 'left', $Lang::tr{'shaping list options'});
print <<END
<table width='100%' align='center'>
<tr>
    <td width='33%' align='center' class='boldbase'><b>$Lang::tr{'priority'}</b> $Header::sortdn</td>
    <td width='33%' align='center' class='boldbase'><b>$Lang::tr{'port'}</b></td>
    <td width='33%' align='center' class='boldbase'><b>$Lang::tr{'protocol'}</b></td>
    <td align='center' class='boldbase' colspan='3'><b>$Lang::tr{'action'}</b></td>
</tr>
END
    ;

my $id = 0;
open(SERVICES, "$configfile") or die 'Unable to open shaping config file.';
while (<SERVICES>) {
    my $gif   = '';
    my $prio  = '';
    my $gdesc = '';
    $id++;
    chomp($_);
    my @temp = split(/\,/, $_);
    if ($temp[3] eq "on") {
        $gif   = 'on.gif';
        $gdesc = $Lang::tr{'click to disable'};
    }
    else {
        $gif   = 'off.gif';
        $gdesc = $Lang::tr{'click to enable'};
    }
    if ($shapingsettings{'ACTION'} eq $Lang::tr{'edit'} && $shapingsettings{'ID'} eq $id) {
        print "<tr class='selectcolour'>";
    }
    else {
        print "<tr class='table".int((($id-1) % 2)+1)."colour'>";
    }
    if ($temp[2] eq "10") {
        $prio = $Lang::tr{'high'};
    }
    if ($temp[2] eq "20") {
        $prio = $Lang::tr{'medium'};
    }
    if ($temp[2] eq "30") {
        $prio = $Lang::tr{'low'};
    }

    print <<END
<td align='center'>$prio</td>
<td align='center'>$temp[1]</td>
<td align='center'>$temp[0]</td>

<td align='center'>
    <form method='post' action='$ENV{'SCRIPT_NAME'}' name='frma$id'>
    <input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif' alt='$gdesc' title='$gdesc' />
    <input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
    <input type='hidden' name='ID' value='$id' />
    </form>
</td>

<td align='center'>
    <form method='post' name='frmb$id' action='$ENV{'SCRIPT_NAME'}'>
    <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' title='$Lang::tr{'edit'}' alt='$Lang::tr{'edit'}' />
    <input type='hidden' name='ID' value='$id' />
    <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
    </form>
</td>

<td align='center'>
    <form method='post' name='frmc$id' action='$ENV{'SCRIPT_NAME'}'>
    <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' title='$Lang::tr{'remove'}' alt='$Lang::tr{'remove'}' />
    <input type='hidden' name='ID' value='$id' />
    <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
    </form>
</td>

</tr>
END
        ;
}
close(SERVICES);

print <<END
</table>
END
    ;
&Header::closebox;

&Header::closebigbox();

&Header::closepage;

sub sortconfigfile
{
    # Sort by Priority, then Port, then Protocol
    system "/usr/bin/sort -n -t ',' -k 3,3 -k 2,2 -k 1,1 $configfile -o $configfile";
}
