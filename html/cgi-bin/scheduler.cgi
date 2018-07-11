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
# along with IPCop; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
# 
# $Id: scheduler.cgi 5120 2010-11-13 12:51:33Z eoberlander $
#

# Add entry in menu
# MENUENTRY system 020 "scheduler" "scheduler"

use strict;

# enable only the following on debugging purpose
#use warnings;
#no warnings 'once';
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';
require '/usr/lib/ipcop/scheduler-lib.pl';


my %selected = ();
my %checked = ();
my $day;
my $hour;
my $minute;
my $comment = '';

my %cgiparams  = ();
my $buttontext = $Lang::tr{'add'};
my $hiddentext = 'add';
my $boxtext = "$Lang::tr{'scheduler add action'}:";
my $errormessage = '';

my $line = '';
my $id = 0;

# read the profile names
my @profilenames=();
my $i = 0;
for ($i = 1; $i <= $SCHEDULER::maxprofiles; $i++) {
    my %temppppsettings = ();
    $temppppsettings{'PROFILENAME'} = $Lang::tr{'empty'};
    &General::readhash("/var/ipcop/ppp/settings-$i", \%temppppsettings);
    $profilenames[$i] = $temppppsettings{'PROFILENAME'};
    $selected{$i} = '';
}
foreach my $a (@SCHEDULER::actions) {
    $selected{$a} = '';
}
foreach my $d (@General::weekDays) {
    $cgiparams{$d} = '';
    $checked{$d} = "checked='checked'";
}
$selected{'hour'}     = '00';
$selected{'minute'}   = '00';
$selected{'daystart'} = 1;
$selected{'dayend'}   = 31;
$checked{'days'}      = "checked='checked'";
$checked{'weekdays'}  = '';
$checked{'connect'}   = "checked='checked'";
$checked{'profile'}   = '';

$cgiparams{'ACTION'}          = '';
$cgiparams{'ID'}              = '';
$cgiparams{'UPDATE_ID'}       = '';
$cgiparams{'ACTION_TYPE'}     = '';
$cgiparams{'ACTION_HOUR'}     = '00';
$cgiparams{'ACTION_MINUTE'}   = '00';
$cgiparams{'ACTION_DAYSTYPE'} = '';
$cgiparams{'ACTION_DAYSTART'} = '1';
$cgiparams{'ACTION_DAYEND'}   = '31';
$cgiparams{'ACTION_OPTIONS'}  = '';
$cgiparams{'ACTION_PROFILENR'}  = '';
$cgiparams{'ACTION_COMMENT'}  = '';

&Header::showhttpheaders();

&General::getcgihash(\%cgiparams);
$id = $cgiparams{'ID'};

&Header::openpage($Lang::tr{'scheduler'}, 1, '');
&Header::openbigbox('100%', 'left');

if ($cgiparams{'ACTION'} eq 'toggle') {
    if ($SCHEDULER::list[$id]{'ACTIVE'} eq 'on') {
        $SCHEDULER::list[$id]{'ACTIVE'} = 'off';
    } else {
        $SCHEDULER::list[$id]{'ACTIVE'} = 'on';
    }
  
    &SCHEDULER::writeSettings();
}
elsif ($cgiparams{'ACTION'} eq 'remove')
{
    # simply set ACTIVE to empty, writeSettings will handle the gory details
    $SCHEDULER::list[$id]{'ACTIVE'} = '';
    &SCHEDULER::writeSettings;
}
elsif ( ($cgiparams{'ACTION'} eq 'add') || ($cgiparams{'ACTION'} eq 'update') ) {
    my $l_weekdays = '';
    my $l_days = '';

    # If we add an event, set the ID to last event+1
    if ($cgiparams{'ACTION'} eq 'add')  {
        $id = $#SCHEDULER::list + 1;
        $SCHEDULER::list[$id]{'ACTIVE'} = 'on';
    }

    # fill the day fields
    foreach my $d (@General::weekDays) {
        $l_weekdays .= "$d " if ($cgiparams{$d} eq 'on');
    }

    # if start day is after end day, swap them
    if ($cgiparams{'ACTION_DAYSTART'} > $cgiparams{'ACTION_DAYEND'}) {
        $l_days = "$cgiparams{'ACTION_DAYEND'} - $cgiparams{'ACTION_DAYSTART'}";
    }
    else {
        $l_days = "$cgiparams{'ACTION_DAYSTART'} - $cgiparams{'ACTION_DAYEND'}";
    }

    if ($cgiparams{'ACTION_ACTION'} eq 'profile') {
        $SCHEDULER::list[$id]{'ACTION'}   = 'profile';
        $SCHEDULER::list[$id]{'OPTIONS'}  = $cgiparams{'ACTION_PROFILENR'};
    } 
    elsif ($cgiparams{'ACTION_ACTION'} eq 'connect') {
        $SCHEDULER::list[$id]{'ACTION'}   = $cgiparams{'ACTION_TYPE'};
        $SCHEDULER::list[$id]{'OPTIONS'}  = $cgiparams{'ACTION_OPTIONS'};
    }
    $SCHEDULER::list[$id]{'TIME'}     = "$cgiparams{'ACTION_HOUR'}:$cgiparams{'ACTION_MINUTE'}";
    $SCHEDULER::list[$id]{'DAYSTYPE'} = $cgiparams{'ACTION_DAYSTYPE'};
    $SCHEDULER::list[$id]{'DAYS'}     = $l_days;
    $SCHEDULER::list[$id]{'WEEKDAYS'} = $l_weekdays;
    $SCHEDULER::list[$id]{'COMMENT'}  = &Header::cleanhtml($cgiparams{'ACTION_COMMENT'});

    &SCHEDULER::writeSettings();
}
elsif ( $cgiparams{'ACTION'} eq 'edit' ) {
    if ($SCHEDULER::list[$id]{'ACTION'} eq 'profile') {
        $selected{$SCHEDULER::list[$id]{'OPTIONS'}} = "selected='selected'";
        $checked{'profile'}  = "checked='checked'";
        $checked{'connect'}  = '';
    }
    else {
        $selected{$SCHEDULER::list[$id]{'ACTION'}} = "selected='selected'";
    }
    $selected{'hour'}   = substr($SCHEDULER::list[$id]{'TIME'}, 0, 2);
    $selected{'minute'} = substr($SCHEDULER::list[$id]{'TIME'}, 3, 2);

    my @l_days = split(/-/, $SCHEDULER::list[$id]{'DAYS'}, 2);
    $selected{'daystart'} = substr($l_days[0], 0, -1);
    $selected{'dayend'} = substr($l_days[1], 1);

    foreach my $d (@General::weekDays) {
        $checked{$d} = '' if (index($SCHEDULER::list[$id]{'WEEKDAYS'}, $d) == -1);
    }

    if ($SCHEDULER::list[$id]{'DAYSTYPE'} eq 'weekdays') {
        $checked{'days'} = '';
        $checked{'weekdays'} = "checked='checked'";
    }

    $comment = $SCHEDULER::list[$cgiparams{'ID'}]{'COMMENT'};

    $buttontext = $Lang::tr{'update'};
    $hiddentext = 'update';
    $boxtext = "$Lang::tr{'scheduler update action'}:";
}


#
# Error Box
#
if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();
}


#
# Add / Edit Box
#
&Header::openbox('100%', 'left', $boxtext);

print <<END
<form method='post' name='addaction' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td width='25%' class='base'>$Lang::tr{'action'}:</td>
    <td width='25%' colspan='3'><input type='radio' value='connect' name='ACTION_ACTION' $checked{'connect'} />&nbsp;<select name='ACTION_TYPE'>
END
;

foreach my $a (@SCHEDULER::actions) {
    print "<option value='$a' $selected{$a}>".$Lang::tr{$a}."</option>";
}

print <<END
        </select></td>
</tr><tr>
    <td width='25%' class='base'>&nbsp;</td>
    <td width='25%' colspan='3'><input type='radio' value='profile' name='ACTION_ACTION' $checked{'profile'} />&nbsp;$Lang::tr{'change to profile'}&nbsp;
        <select name='ACTION_PROFILENR'>
END
;

for ($i = 1; $i <= $SCHEDULER::maxprofiles; $i++) {
    print "<option value='$i' $selected{$i}>$i. $profilenames[$i]</option>";
}

print <<END
        </select></td>
</tr><tr>
    <td width='25%' class='base'>$Lang::tr{'remark'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td width='25%'><input type='text' name='ACTION_COMMENT' size='40' value='$comment' /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'time'}:</td>
    <td><select name='ACTION_HOUR'>
END
;
for ($hour = 0; $hour <= 23; $hour++)
{
  my $hour00 = $hour < 10 ? "0$hour" : $hour;
  if ( $hour00 eq $selected{'hour'} )
  {
    print "<option value='$hour00' selected='selected'>$hour00</option>";
  }
  else
  {
    print "<option value='$hour00'>$hour00</option>";
  }
}
print "</select>&nbsp;:&nbsp;<select name='ACTION_MINUTE'>";
for ($minute = 0; $minute <= 55; $minute += 5)
{
  my $minute00 = $minute < 10 ? "0$minute" : $minute;
  if ( $minute00 eq $selected{'minute'} )
  {
    print "<option value='$minute00' selected='selected'>$minute00</option>";
  }
  else
  {
    print "<option value='$minute00'>$minute00</option>";
  }
}

print <<END
</select></td>
</tr><tr>
    <td colspan='4'><hr /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'day'}:</td>
    <td><input type='radio' value='days' name='ACTION_DAYSTYPE' $checked{'days'} />&nbsp;<select name='ACTION_DAYSTART'>
END
;
for ($day = 1; $day <= 31; $day++)
{
  if ( $day == $selected{'daystart'} )
  {
    print "<option value='$day' selected='selected'>$day</option>";
  }
  else
  {
    print "<option value='$day'>$day</option>";
  }
}
print "</select>&nbsp;-&nbsp;<select name='ACTION_DAYEND'>";
for ($day = 1; $day <= 31; $day++)
{
  if ( $day == $selected{'dayend'} )
  {
    print "<option value='$day' selected='selected'>$day</option>";
  }
  else
  {
    print "<option value='$day'>$day</option>";
  }
}

print <<END
    </select></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr><tr>
    <td>&nbsp;</td>
    <td><input type='radio' value='weekdays' name='ACTION_DAYSTYPE' $checked{'weekdays'} />&nbsp;$Lang::tr{'days of the week'}<br />
END
;
foreach my $d (@General::weekDays) {
    print "&nbsp; &nbsp; &nbsp; &nbsp;<input type='checkbox' name='$d' $checked{$d} />&nbsp;$Lang::tr{$d}<br />\n";
}
print <<END
    </td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' align='top' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button1button'><input type='hidden' name='ACTION' value='$hiddentext' />
        <input type='submit' name='SUBMIT' value='$buttontext' />
        <input type='hidden' name='ID' value='$cgiparams{'ID'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/system-scheduler.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
END
;
&Header::closebox();


#
# Box with list of actions
#
&Header::openbox('100%', 'left', "$Lang::tr{'scheduled actions'}:");
print <<END
<table width='100%'>
<tr>
    <td width='10%' class='boldbase' align='center'>$Lang::tr{'time'}</td>
    <td width='25%' class='boldbase' align='center'>&nbsp;</td>
    <td width='55%' class='boldbase' align='center'>$Lang::tr{'remark'}</td>
    <td width='10%' class='boldbase' align='center' colspan='3'>$Lang::tr{'action'}</td>
</tr>
END
;

for $id (0 .. $#SCHEDULER::list) {
    my $trcolor;
    my $a = $Lang::tr{$SCHEDULER::list[$id]{'ACTION'}};

    if ($SCHEDULER::list[$id]{'ACTION'} eq 'profile') {
        $i = $SCHEDULER::list[$id]{'OPTIONS'};
        $a .= " $i. $profilenames[$i]";
    }

    if ( ($cgiparams{'ACTION'} eq 'edit') && ($id == $cgiparams{'ID'}) ) {
        $trcolor = "<tr class='selectcolour'>";
    } else {
        $trcolor = "<tr class='table".int(($id % 2) + 1)."colour'>"; 
    }

    print <<END
$trcolor
<td align='center' rowspan='2'>$SCHEDULER::list[$id]{'TIME'}</td>
<td>$a</td>
<td>$SCHEDULER::list[$id]{'COMMENT'}</td>
<td align='center'>
    <form method='post' name='frma$id' action='$ENV{'SCRIPT_NAME'}'>
    <input type='hidden' name='ACTION' value='toggle' />
    <input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$SCHEDULER::list[$id]{'ACTIVE'}.gif' alt='$Lang::tr{'toggle enable disable'}' title='$Lang::tr{'toggle enable disable'}' />
    <input type='hidden' name='ID' value='$id' />
    </form>
</td>
<td align='center'>
    <form method='post' name='frmb$id' action='$ENV{'SCRIPT_NAME'}'>
    <input type='hidden' name='ACTION' value='edit' />
    <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
    <input type='hidden' name='ID' value='$id' />
    </form>
</td>
<td align='center'>
    <form method='post' name='frmc$id' action='$ENV{'SCRIPT_NAME'}'>
    <input type='hidden' name='ACTION' value='remove' />
    <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
    <input type='hidden' name='ID' value='$id' />
    </form>
</td>
</tr>
$trcolor
<td colspan='5'>$SCHEDULER::list[$id]{'DAYS_FORMATTED'}</td>
</tr>
END
    ;
}

print "</table>";

&Header::closebox();

&Header::closebigbox();
&Header::closepage();
