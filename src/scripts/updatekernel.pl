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
# (c) 2009-2012, the IPCop team
#
# $Id: updatekernel.pl 6815 2012-10-31 10:50:55Z owes $
#

use strict;
require '/usr/lib/ipcop/general-functions.pl';

my %bootconfig = (
    'i486'  => '/boot/extlinux.conf',
    'ppc'   => '/boot/yaboot.conf',
    'sparc' => '/boot/silo.conf',
);

my $newversion  = '';
my $keepversion = '';
my $oldversion  = '';


while (@ARGV) {
    my $argument = shift;

    if (($argument eq '--add') && ($#ARGV >= 0)) {
        $newversion = shift;
    }
    elsif (($argument eq '--keep') && ($#ARGV >= 0)) {
        $keepversion = shift;
    }
    elsif (($argument eq '--remove') && ($#ARGV >= 0)) {
        $oldversion = shift;
    }
}


# We need at least a new version and a current version (otherwise it is not an upgrade ;-))
# old version is optional and does not need to exist
#
# Usages:
#   IPCop installed with kernel .9. Update adds kernel .10, current is .9 and old (to be deleted) is .8
#   IPCop installed with kernel .9. Update adds kernel .11, current is .10 and old (to be deleted) is .9
#


# Do syntax check
if (($newversion eq '') || ($keepversion eq '')) {
    print "Usage is: updatekernel.pl --add <version> --keep <version> [--remove <version>]\n";
    exit 1;
}
if (system("/bin/grep $newversion $bootconfig{$General::machine} > /dev/null") == 0) {
    print "Boot configfile already has $newversion.\n";
    exit 0;
}

die "Kernel $newversion not found"  unless (-e "/lib/modules/$newversion" );
die "Kernel $keepversion not found" unless (-e "/lib/modules/$keepversion" );

# Flagfile to indicate reboot required in index.cgi
system('/usr/bin/touch /rebootrequired');
&General::log("installpackage", "New kernel $newversion, reboot required");

# Fetch some lines from the current boot configfile, architecture dependant
my %lines = ();
if ($General::machine eq 'i486') {
    $lines{'default'} = `/bin/grep -m 1 APPEND $bootconfig{$General::machine}`;
    chomp($lines{'default'});

    $lines{'noacpi'}  = `/bin/grep APPEND $bootconfig{$General::machine} | /bin/grep -m 1 acpi`;
    chomp($lines{'noacpi'});

    $lines{'verbose'} = `/bin/grep APPEND $bootconfig{$General::machine} | /bin/grep -m 1 -v quiet`;
    chomp($lines{'verbose'});
}
elsif ($General::machine eq 'ppc') {
    $lines{'root'} = `/bin/grep -m "root=" $bootconfig{$General::machine}`;
    chomp($lines{'root'});
}
elsif ($General::machine eq 'sparc') {
    $lines{'root'} = `/bin/grep -m "root=" $bootconfig{$General::machine}`;
    chomp($lines{'root'});
}


# Shift 'current' kernel to the new kernel in boot conf
&General::log("installpackage", "Shifting boot configfile from $keepversion to $newversion");
system("/bin/sed -i -e 's/$keepversion/$newversion/' $bootconfig{$General::machine}");


# Drop the old kernel if it exist
if (($oldversion ne '') && (-e "/lib/modules/$oldversion")) {
    &General::log("installpackage", "Removing kernel $oldversion");

    # Remove kernel modules
    system("rm -rf /lib/modules/$oldversion");
    # Remove files from /boot
    system("rm -rf /boot/ipcoprd-$oldversion.img");
    system("rm -rf /boot/System.map-$oldversion");
    system("rm -rf /boot/vmlinuz-$oldversion");
}

if (($oldversion ne '') && system("/bin/grep IPCop $bootconfig{$General::machine} | /bin/grep old > /dev/null") == 0) {
    # Shift the old (removed) kernel to the now previous one is easy
    &General::log("installpackage", "Shifting boot configfile from $oldversion to $keepversion");
    system("/bin/sed -i -e 's/$oldversion/$keepversion/' $bootconfig{$General::machine}");

    exit 0;
}

# Adding additional labels to boot configfile is more work
open(BOOTCONFIG, ">>", $bootconfig{$General::machine}) or die "Cannot open $bootconfig{$General::machine}";
&General::log("installpackage", "Adding labels to boot configfile for $keepversion");

if ($General::machine eq 'i486') {
    print BOOTCONFIG <<END

LABEL old-ipcop
  MENU LABEL IPCop old kernel ($keepversion)
  MENU SAVE
  KERNEL vmlinuz-$keepversion
$lines{'default'}

LABEL old-noacpi
  MENU LABEL IPCop old kernel ($keepversion ACPI disabled)
  MENU SAVE
  KERNEL vmlinuz-$keepversion
$lines{'noacpi'}

LABEL old-verbose
  MENU LABEL IPCop old kernel ($keepversion verbose booting)
  MENU SAVE
  KERNEL vmlinuz-$keepversion
$lines{'verbose'}
END
}
elsif ($General::machine eq 'ppc') {
    print BOOTCONFIG <<END

image=/vmlinuz
	label=IPCop old kernel 
$lines{'root'}
	initrd=/ipcoprd-$keepversion.img
	read-only
	append="mode=normal video=ofonly"
END
}
elsif ($General::machine eq 'sparc') {
    print BOOTCONFIG <<END

image[sun4u] = /boot/vmlinuz
	label=IPCop old kernel 
$lines{'root'}
	initrd=/boot/ipcoprd-$keepversion.img
	append="mode=normal"
	#append="mode=normal console=tty0 console=ttyS0,9600n8 video=atyfb:off"
END
}
