#!/usr/bin/perl
#
# This file is part of the Openfirewall.
# Openfirewall CGI's - backup.cgi: manage import/export of configuration files
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
# (c) 2018-2019 The Openfirewall Team
#
#

# Add entry in menu
# MENUTHRDLVL "maintenance" 010 "backup" "backup"

use strict;

# enable only the following on debugging purpose
use warnings; no warnings 'once';
#use CGI::Carp 'fatalsToBrowser';

# to fully troubleshot your code, uncomment diagnostics, Carp and cluck lines
# use diagnostics; # need to add the file /usr/lib/perl5/5.8.x/pods/perldiag.pod before to work
# next look at /var/log/httpd/error_log , http://www.perl.com/pub/a/2002/05/07/mod_perl.html may help
#use Carp ();
#local $SIG{__WARN__} = \&Carp::cluck;
use File::Copy;
use Sys::Hostname;
use File::Temp qw(tempfile tempdir);
use Scalar::Util qw(blessed reftype);

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my $errormessage = '';
my $warnmessage  = '';
my $setdir       = '/usr/local/apache/html/backup';    # location where sets are stored and imported
my $datafile     = hostname() . '.dat';          # file containing data backup after upload
my $disabled     = '';                           # without key to disable many buttons
my %settings     = ();
$settings{'ACTION'} = '';                        # define to suppress all warnings when form is empty
my $umountdisabled = '';                         # usb mass-storage only need umount
my $hostfilter     = '([\w-]+\.)+[\w-]+';        # regex for hostname

# Get GUI values
&General::getcgihash(\%settings, {'wantfile' => 1, 'filevar' => 'FH'});

# Return device name of what is mounted under 'backup'
sub findmounted() {
    my $mounted = `/bin/mount | /bin/grep " $setdir "`;
    if ($mounted) {

        # extract device name
        $mounted =~ m!^/dev/(.*) on!;    # device on mountmoint options
        return $1;
    }
    else {

        # it's the normal subdir
        return $Lang::tr{'local hard disk'};
    }
}

# return a date/time and comment string from a time file
sub read_timefile($) {
    my $fname = shift;                   # name of data file

    my $dt;
    if (defined(open(FH, "<$fname.time"))) {
        $dt = <FH>;
        chomp $dt;
        close(FH);

        # change format for display
        $dt =~ s/(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})(.*)/$1 $2:$3:$4 | $5/;
    }
    else {

        # This should really never happen as helper now import a backup
        $dt = 'Do not suppress a .dat.time file manually, export and import again to fix';
    }
    return &Header::cleanhtml($dt);
}

# get backup error text
sub get_bk_error() {
    my $exit_code = shift || return '';
    if ($exit_code == 0) {
        return '';
    }
    elsif ($exit_code == 2) {
        return $Lang::tr{'err bk 2 key'};
    }
    elsif ($exit_code == 3) {
        return $Lang::tr{'err bk 3 tar'};
    }
    elsif ($exit_code == 4) {
        return $Lang::tr{'err bk 4 gz'};
    }
    elsif ($exit_code == 5) {
        return $Lang::tr{'err bk 5 encrypt'};
    }
    elsif ($exit_code == 10) {
        return $Lang::tr{'incorrect password'};
    }
    else {
        return $Lang::tr{'err bk 1'} . " ($exit_code)";
    }
}

# show any restore errors
sub get_rs_error($) {
    my $exit_code = shift || return '';
    if ($exit_code == 0) {
        return '';
    }
    elsif ($exit_code == 6) {
        return $Lang::tr{'err rs 6 decrypt'};
    }
    elsif ($exit_code == 7) {
        return $Lang::tr{'err rs 7 untartst'};
    }
    elsif ($exit_code == 8) {
        return $Lang::tr{'err rs 8 untar'};
    }
    elsif ($exit_code == 9) {
        return $Lang::tr{'missing dat'};
    }
    elsif ($exit_code == 12) {
        return $Lang::tr{'err rs 12 version'};
    }
    else {
        return $Lang::tr{'err rs 1'} . " ($exit_code)";
    }
}

sub kmgt($) {
    my ($value, $length, $opt_U) = @_;
    $opt_U = '' if not defined($opt_U);
    if ($value > 10**($length + 8) or $opt_U eq 'T') {
        return sprintf("%d%s", int(($value / 1024**4) + .5), 'T');
    }
    elsif ($value > 10**($length + 5) or $opt_U eq 'G') {
        return sprintf("%d%s", int(($value / 1024**3) + .5), 'G');
    }
    elsif ($value > 10**($length + 2) or $opt_U eq 'M') {
        return sprintf("%d%s", int(($value / 1024**2) + .5), 'M');
    }
    elsif ($value > 10**($length) or $opt_U eq 'K') {
        return sprintf("%d%s", int(($value / 1024) + .5), 'K');
    }
    else {
        return $value;
    }
}

# Export the key.
# backup password is required to disallow user 'noboby' to export the key
# and create a fake backup.
if ($settings{'ACTION'} eq $Lang::tr{'backup export key'}) {
    if (!defined($settings{'PASSWORD'})) {
        $errormessage = $Lang::tr{'password not set'};
    }
    elsif ($settings{'PASSWORD'} =~ m/[\s\"']/) {
        $errormessage = $Lang::tr{'password contains illegal characters'};
    }
    elsif (length($settings{'PASSWORD'}) < 6) {
        $errormessage = $Lang::tr{'passwords must be at least 6 characters in length'};
    }
    else {
        my $size     = 0;
        my $filename = 'backup.' . &hostname() . '.key';
        (my $fh, my $tmpfilename) = tempfile('/tmp/logfile.XXXXXX');
        $errormessage =
            &get_bk_error(system('/usr/local/bin/ofwbkcfg', '--keycat', "$settings{'PASSWORD'}", "$tmpfilename") >> 8);
        if (!$errormessage) {
            open FH, "< $tmpfilename" or die "Unable to open tmp key file !";
            my @lines = <FH>;
            close FH;
            if (scalar @lines != 2) {
                $errormessage = "Bad tmp key file : wrong lines number!";
            }
            else {
                $lines[0] = &Header::cleanhtml($lines[0]);
                $lines[1] = &Header::cleanhtml($lines[1]);
                use bytes;
                foreach (@lines) {
                    $size += length($_);
                }
                print "Content-Type: application/force-download\n";
                print "Content-Disposition: attachment; filename=" . $filename . "\n";
                print "Content-length: $size\n\n";    # twice \n as an empty line is necessary before the data
                print @lines;
            }
        }
        unlink $tmpfilename;
    }
}

my $cryptkeymissing = system('/usr/local/bin/ofwbkcfg', '--keyexist') >> 8;

# disable 'create key' or other buttons
if ($cryptkeymissing) {
    $disabled = "disabled='disabled'";
}
else {
    $disabled = '';
}

# Create new archive set
if ($settings{'ACTION'} eq $Lang::tr{'create new backup'}) {
    $settings{'DESCRIPTION'} =~ s/[^ \w'_-]//g;    # remove everything potentially bad
                                                   # just because of the page layout
    if (length($settings{'DESCRIPTION'}) > 80) {
        $errormessage = "$Lang::tr{'description'}" . $Lang::tr{'too long 80 char max'};
    }
    else {
        $errormessage = &get_bk_error(system('/usr/local/bin/ofwbkcfg', '--write', "$settings{'DESCRIPTION'}") >> 8);
    }
}

# Delete an archive set
if (defined($settings{$Lang::tr{'remove'} . '.y'})) {

    #check form input before erase files
    if ($settings{'KEY'} !~ m!^$setdir/$hostfilter\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.dat$!) {
        $errormessage = $Lang::tr{'bad characters in'} . 'KEY';
    }
    else {
        unlink $settings{'KEY'};
        unlink $settings{'KEY'} . '.time';
    }
}

# Import an archive set
if ($settings{'ACTION'} eq $Lang::tr{'import'}) {
    if (blessed($settings{'FH'}) ne 'CGI::File::Temp') {
        $errormessage = $Lang::tr{'no cfg upload'};
    }
    elsif (!copy($settings{'FH'}, "$setdir/$datafile")) {
        $errormessage = $Lang::tr{'save error'};
    }
    else {
        $errormessage = &get_rs_error(system('/usr/local/bin/ofwrestore', '--import') >> 8);
    }
}

# Restore an archive :special confirmation page
if (defined($settings{$Lang::tr{'restore'} . '.y'})
    || $settings{'ACTION'} eq $Lang::tr{'restore'})
{
    if ($settings{'ACTION'} eq $Lang::tr{'restore'}) {

        # if keyfile does not exist
        if ($cryptkeymissing) {
            $errormessage = $Lang::tr{'backup missing key'};
        }
        elsif (!-e "$settings{'KEY'}") {

            # encrypted dat is required
            $errormessage = $Lang::tr{'missing dat'};
        }
        elsif ($settings{'RESTOREHW'} eq 'on') {

            # can't use ? --hardware : '' because argc is wrong for the helper.
            $errormessage =
                get_rs_error(system('/usr/local/bin/ofwrestore', '--restore', "$settings{'KEY'}", '--hardware') >> 8);
        }
        else {
            $errormessage = get_rs_error(system('/usr/local/bin/ofwrestore', '--restore', "$settings{'KEY'}") >> 8);
        }
        if (!$errormessage) {

            # restored ok, recommend restarting system
            $warnmessage = $Lang::tr{'cfg restart'};
        }
    }
    else {
        &Header::showhttpheaders();
        &Header::openpage($Lang::tr{'backup'}, 1, '');
        &Header::openbigbox('100%', 'left');
        &Header::openbox('100%', 'left', $Lang::tr{'are you sure'});
        my $settime = read_timefile($settings{'KEY'});
        print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='KEY' value="$settings{'KEY'}" />
<table align='center' border='0'>
<tr>
    <td>$Lang::tr{'restore'}:</td>
    <td>$settime</td>
</tr>
<tr>
    <td>$Lang::tr{'restore hardware settings'}: <input type='checkbox' name='RESTOREHW' /></td>
</tr>
<tr>
    <td align='center'><input type='submit' name='ACTION' value='$Lang::tr{'restore'}' /></td>
    <td><input type='submit' name='ACTION' value='$Lang::tr{'cancel'}' /></td>
</tr>
</table>
</form>
END
            ;
        &Header::closebox();
        &Header::closebigbox();
        &Header::closepage();
        exit(0);
    }
}

# Build the list of removable device
# Read partitions sizes registered
my %partitions;
my %devcount;    # Count partitions to not make whole device mountable when partitioned
foreach my $li (`/bin/cat /proc/partitions | /bin/grep 'sd'`) {

    # partitions{'sda1'} = 128M        if         /major minor  blocks name/
    if ($li =~ /(\d+) +(\d+) +(\d+) +(.*)/) {
        $partitions{$4} = &kmgt($3 * 1024, 4);
        if (length($4) == 3) {
            $devcount{$4} = 0;
        }
        else {

            # count the partition on corresponding dev
            ++$devcount{substr($4, 0, 3)};
        }
    }
}

# Search usb-storage device(s)
my %medias;
foreach my $blockdev (`/bin/ls -d /sys/block/sd* 2>/dev/null`) {
    chop($blockdev);

    # we only want removable sd* devices
    next if (index(`/bin/cat $blockdev/removable`, '0') != -1);

    # strip the /sys/block part from device name
    $blockdev =~ s!/sys/block/(.*)!$1!;

    # add to our list of media
    $medias{$blockdev}{'Attached'} = 'Yes';
    $medias{$blockdev}{'Host'} = "$blockdev";
    $medias{$blockdev}{'Vendor'} = `/bin/cat /sys/block/$blockdev/device/vendor`;
    $medias{$blockdev}{'Product'} = `/bin/cat /sys/block/$blockdev/device/model`;
}

# Mount a media
if ($settings{'ACTION'} eq $Lang::tr{'mount'}) {
    if ($settings{'MEDIA'} !~ /^sd[a-z]\d{1,2}$/ && $settings{'DESCRIPTION'} ne '') {
        $errormessage = $Lang::tr{'bad characters in'} . 'MEDIA';
    }
    else {

        #umount previous, even if same device already mounted.
        system('/usr/local/bin/ofwbkcfg', '--umount');
        if ($settings{'MEDIA'} eq $Lang::tr{'local hard disk'}) {
            # TODO: make this an error ?
            # $errormessage = $Lang::tr{'cannot mount local hard disk'};
        }
        elsif (grep (/$settings{'MEDIA'}/, %partitions)) {
            $errormessage = `/usr/local/bin/ofwbkcfg --mount $settings{'MEDIA'}`;
        }
    }
}

# Umount a removable media
if ($settings{'ACTION'} eq $Lang::tr{'umount'}) {
    system('/usr/local/bin/ofwbkcfg', '--umount');
}

my $mounted = &findmounted();

# For current media, compute a full description of device
my $media_des = $mounted;    # Description
if ($mounted eq $Lang::tr{'local hard disk'}) {
    $umountdisabled = "disabled='disabled'";
}
else {
    $umountdisabled = '';
    $_              = $mounted;

    # sda1 => sda
    tr/0-9//d;

    # display Vendor and Product as where the usefull info vary
    $media_des = "$medias{$_}{'Vendor'} $medias{$_}{'Product'} ($mounted, $partitions{$mounted})";
}

sub readfreespace() {

    # df output can look like this:
    #   Filesystem           1M-blocks      Used Available Use% Mounted on
    #   /dev/disk/by-label/root
    #                             304M      206M       83M  72% /
    #
    # or this:
    #   Filesystem           1M-blocks      Used Available Use% Mounted on
    #   /dev/sda                  175M       11M      156M   7% /usr/local/apache/html/backup
    #
    # find the correct line & cut it to pieces. We want the Available column.
    my $space = 0;
    if ($mounted eq $Lang::tr{'local hard disk'}) {

        # not able to run awk from the GUI
        $space = `/bin/df -B M / | /bin/grep -v Filesystem | /bin/grep M | /usr/bin/cut -d M -f3`;
    }
    else {
        $space = `/bin/df -B M /dev/$mounted | /bin/grep -v Filesystem  | /bin/grep M | /usr/bin/cut -d M -f3`;
    }
    return $space;
}
my $freespace = &readfreespace();

&Header::showhttpheaders();
&Header::openpage($Lang::tr{'backup'}, 1, '');
&Header::openbigbox('100%', 'left', '');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();
}

# after a restore
if ($warnmessage) {
    &Header::openbox('100%', 'left', '', 'warning');
    $warnmessage = "<font class='ofw_StatusBigRed'>$Lang::tr{'capswarning'}</font>: $warnmessage";
    print "<b>$Lang::tr{'alt information'}</b><br />$warnmessage";
    &Header::closebox();
}
&Header::openbox('100%', 'left', "$Lang::tr{'backup'}:");

print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}' enctype='multipart/form-data'>
<table width='100%' border='0'>
<tr>
    <td class='comment1button'>$Lang::tr{'insert floppy'}</td>
    <td class='button1button'><input type='submit' name='ACTION' class='commonbuttons' value='$Lang::tr{'backup to floppy'}' /></td>
    <td class='onlinehelp'><a href='${General::adminmanualurl}/system-backup.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a></td>
</tr>
</table>
<table width='100%' border='0'>
<tr>
    <td colspan='3'><hr /></td>
</tr>
<tr>
    <td colspan='3'><table width='100%' border='0'>
        <tr>
            <td valign='top' colspan='2'><table width='100%' border='0'>
                <tr>
                    <th colspan='2' align='left'>$Lang::tr{'select media'}</th>
                </tr>
END
    ;

my $checked = '';
foreach my $media (keys %medias) {

    # Care only of device attached to USB bus
    if ($medias{$media}{'Attached'} eq 'Yes') {
        $checked = $medias{$media}{'Host'} eq $mounted ? "checked='checked'" : '';
        my $devname = "<b>$medias{$media}{'Vendor'} $medias{$media}{'Product'}</b>";
        $devname = $devname . "&nbsp;$medias{$media}{'Host'} ($partitions{$medias{$media}{'Host'}})";
        if ($devcount{$medias{$media}{'Host'}} > 0) {
            print "<tr><td>&nbsp;</td><td><input type='radio' name='MEDIA' ";
            print "value='$medias{$media}{'Host'}' disabled='disabled' />$devname</td></tr>\n";
        }
        else {
            if ($checked ne '') {
                print "<tr><td><img src='/blob.gif' alt='*' /></td>";
            }
            else {
                print "<tr><td>&nbsp;</td>";
            }
            print "<td><input type='radio' name='MEDIA' ";
            print "value='$medias{$media}{'Host'}' $checked />$devname</td></tr>\n";
        }

        # list attached partitions to this media
        foreach my $part (sort (keys(%partitions))) {
            if ($part =~ /$medias{$media}{'Host'}./) {
                $checked = $part eq $mounted ? "checked='checked'" : '';
                if ($checked ne '') {
                    print "<tr><td><img src='/blob.gif' alt='*' /></td>";
                }
                else {
                    print "<tr><td>&nbsp;</td>";
                }
                print "<td><input type='radio' name='MEDIA' ";
                print "value='$part' $checked />&nbsp;&nbsp;$part ($partitions{$part})</td></tr>\n";
            }
        }
    }
}

#Add an entry for the local disk, next is key interface management
$checked = $Lang::tr{'local hard disk'} eq $mounted ? "checked='checked'" : '';
print <<END
                <tr>
                    <td>&nbsp;</td>
                    <th align='left'><input type='radio' name='MEDIA' value='$Lang::tr{'local hard disk'}' $checked />
                        $Lang::tr{'local hard disk'}
                    </th>
                </tr>
END
    ;

# after a umount
if ($settings{'ACTION'} eq $Lang::tr{'umount'}) {
    print "<tr><td colspan='2'>$Lang::tr{'safe removal of umounted device'}</td></tr>";
}
elsif ($checked ne '') {
    print "<tr><td colspan='2'>$Lang::tr{'removable device advice'}</td></tr>";
}
else {
    print <<END
                <tr>
                    <td><img src='/blob.gif' alt='*' /></td>
                    <td nowrap='nowrap'>$Lang::tr{'umount removable media before to unplug'}</td>
                </tr>
END
        ;
}
print <<END
                <tr>
                    <td colspan='2' align='center'>
                        <input type='submit' name='ACTION' value='$Lang::tr{'refresh'}' />&nbsp;
                        <input type='submit' name='ACTION' value='$Lang::tr{'mount'}' />&nbsp;
                        <input type='submit' name='ACTION' value='$Lang::tr{'umount'}' $umountdisabled />&nbsp;
                    </td>
                </tr>
                </table>
            </td>
            <td valign='top'>
                <table border='0' align='center'>
                <tr>
                    <th align='left'>$Lang::tr{'backup key'}</th>
                </tr>
                <tr>
                    <td nowrap='nowrap'>$Lang::tr{'backup password'}:&nbsp;
                        <input type='password' name='PASSWORD' size='15' />
                    </td>
                </tr>
                <tr>
                    <td align='center'>
                        <input type='submit' name='ACTION' value='$Lang::tr{'backup export key'}' />
                    </td>
                </tr>
END
    ;
print <<END
                </table>
            </td>
        </tr>
        <tr>
            <td colspan='3'><hr /></td>
        </tr>
        <tr>
            <th colspan='3' align='left'>$Lang::tr{'current media'}:
                <font class='ofw_StatusBigRed'>$media_des &nbsp;</font>
                $Lang::tr{'free'}:$freespace M
            </th>
        </tr>
        <tr>
            <td colspan='3'>&nbsp;</td>
        </tr>
        <tr>
            <td colspan='3'><b>$Lang::tr{'create new backup'}</b></td>
        </tr>
        <tr>
            <td colspan='3' nowrap='nowrap'>$Lang::tr{'description'}:&nbsp;
                <input type='text' name='DESCRIPTION' size='30' $disabled />&nbsp;&nbsp;
                <input type='submit' name='ACTION' value='$Lang::tr{'create new backup'}' $disabled />
            </td>
        </tr>
        <tr>
            <td colspan='3'>&nbsp;</td>
        </tr>
        <tr>
            <td colspan='3'><b>$Lang::tr{'backup import dat file'}:</b></td>
        </tr>
        <tr>
            <td colspan='3'><input type='file' name='FH' size='40' />&nbsp;&nbsp;
                <input type='submit' name='ACTION' value='$Lang::tr{'import'}' />
            </td>
        </tr>
    </table></td></tr>
</table></form>
<table width='100%' border='0'>
        <tr>
            <td colspan='3'>&nbsp;</td>
        </tr>
        <tr>
            <td colspan='3'><b>$Lang::tr{'backup sets'}:</b>
                <table width='100%' border='0'>
                <tr>
                    <th width='90%' class='boldbase' align='center'>$Lang::tr{'description'}</th>
                    <th class='boldbase' align='center' colspan='3'>$Lang::tr{'action'}</th>
                </tr>
END
    ;

# get list of available sets by globbing directories under $setdir
# External device (usk key) are mounted in $setdir. -R permits finding sets in hierarchy.
my $i   = 0;
my $set = '';
foreach $set (`/bin/ls -t1 $setdir/*.dat 2>/dev/null`) {

    #remove newline from line
    chop($set);

    # filter files out of name format
    if ($set =~ m!^$setdir/$hostfilter\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.dat$!) {
        print "<tr class='table".int(($i % 2) + 1)."colour'>";

        # read time with comment and reformat time
        my $settime = read_timefile($set);
        my $name = substr($set, length($setdir) + 1);
        print <<END
                <td>$settime</td>
                <td align='center'><form method='post' action='$ENV{'SCRIPT_NAME'}'>
                    <input type='image' name='$Lang::tr{'restore'}' src='/images/reload.gif' alt='$Lang::tr{'restore'}' title='$Lang::tr{'restore'}' />
                    <input type='hidden' name='KEY' value='$set' /></form></td>
                <td align='center'><a href='/backup/$name'><img src='/images/floppy.gif' alt='$Lang::tr{'export'}' title='$Lang::tr{'export'}' /></a></td>
                <td align='center'><form method='post' action='$ENV{'SCRIPT_NAME'}'>
                    <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
                    <input type='hidden' name='KEY' value='$set' /></form></td>
            </tr>
END
        ;
        $i++;
    }
}
print "</table>\n</td></tr><tr><td colspan='3'>" . ($i ? "<br />" : "$Lang::tr{'empty'}!<br /><br />");

# after a floppy backup
if ($settings{'ACTION'} eq $Lang::tr{'backup to floppy'}) {
    print "<hr /><b>$Lang::tr{'alt information'}</b><pre>" . `/usr/local/bin/ofwbackup` . '&nbsp;</pre>';
}
print "</td></tr></table>";

&Header::closebox();
&Header::closebigbox();
&Header::closepage();

1;
