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
# Copyright (C) 2004-01-19 Mark Wormgoor <mark@wormgoor.com>.
# (c) 2007-2014, the Openfirewall Team
#
# $Id: makegraphs.pl 7496 2014-04-22 16:41:58Z owes $
#

use strict;

#use warnings;

use IO::Socket;
use RRDs;
require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my (%settings, $iface, $ERROR);
&General::readhash('/var/ofw/ethernet/settings', \%settings);

# Added for conversion of utf-8 characters
### TODO: check conversion still required
#use Encode 'from_to';

# Force language back to English (ugly hack!)
# These languages contain characters that our current RRD / Pango solution cannot display
if (${Lang::language} =~ /^(ar|bg|el|fa|gu|ja|ru|th|ur|vi|zh|zt)$/) {
    &Lang::reload(2);
}

# Settings
my $rrdlog = "/var/log/rrd";
my $graphs = "/usr/local/apache/html/graphs";
$ENV{PATH} = "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin";

# This from munin-graph which is: Copyright (C) 2002-2004 Jimmy Olsen, Audun Ytterdal
# Munin has some pretty cool RRD graphing.
sub RRDescape {
    my $text = shift;
    return undef if not defined $text;
    $text =~ s/\\/\\\\/g;
    $text =~ s/:/\\:/g;
    return $text;
}

sub rrd_header {
    my $name   = shift;
    my $period = shift;
    my $title  = shift;
    my $lower  = shift;
    my $upper  = shift;
    my $result = [];

    push @$result, "$graphs/$name-$period.png";
    push @$result, ("--title", "$title");
    push @$result, ("--start", "-1$period");
    push @$result, ("--width", 600);
    push @$result, ("--height", 100);
    if ($lower != -1) {
        push @$result, ("--lower-limit", $lower);
        push @$result, ("--upper-limit", $upper);
        push @$result, "--rigid";
    }
    push @$result, "--alt-y-grid";
    push @$result, "--lazy";
    push @$result, ("--imgformat", "PNG");
    # gets ignored in 1.3 for now
    push @$result, "--interlaced";
    push @$result, "--pango-markup";
    push @$result, ("--font", "TITLE:0:sans mono bold oblique");
    push @$result, ("--color", "SHADEA$Header::boxcolour");
    push @$result, ("--color", "SHADEB$Header::boxcolour");
    push @$result, ("--color", "BACK$Header::boxcolour");

    return $result;
}

sub rrd_lastupdate {
    my $result  = [];

    push @$result, "COMMENT:<span size='smaller'> </span>\\r";
    push @$result, "COMMENT:<span size='smaller'>Last update\\: ". RRDescape(scalar localtime()) ."</span>\\r";

    return $result;
}

sub gettraffic {
    my $device = $_[0];
    return "0:0" unless (-d  "/sys/class/net/$device");
    
    my $bytesin  = `cat /sys/class/net/$device/statistics/rx_bytes`;
    my $bytesout = `cat /sys/class/net/$device/statistics/tx_bytes`;

    chomp($bytesin);
    chomp($bytesout);

    return "$bytesin:$bytesout";
}

sub updatecpugraph {
    my $period = $_[0];
    my @rrd = ();

    my $col_width = length($Lang::tr{'user cpu usage'});
    $col_width = length($Lang::tr{'system cpu usage'}) if (length($Lang::tr{'system cpu usage'}) > $col_width);
    $col_width = length($Lang::tr{'idle cpu usage'})   if (length($Lang::tr{'idle cpu usage'}) > $col_width);
    $col_width += 2;

    push @rrd, @{&rrd_header("cpu", $period, "$Lang::tr{'cpu usage'} ($Lang::tr{$period})", 0, 100)};

    push @rrd, "DEF:user=$rrdlog/cpu.rrd:user:AVERAGE";
    push @rrd, "DEF:system=$rrdlog/cpu.rrd:system:AVERAGE";
    push @rrd, "DEF:idle=$rrdlog/cpu.rrd:idle:AVERAGE";
    push @rrd, "CDEF:total=user,system,idle,+,+";
    push @rrd, "CDEF:userpct=100,user,total,/,*";
    push @rrd, "CDEF:systempct=100,system,total,/,*";
    push @rrd, "CDEF:idlepct=100,idle,total,/,*";
    push @rrd, "AREA:userpct#0000FF:$Lang::tr{'user cpu usage'}" . (" " x ($col_width - length($Lang::tr{'user cpu usage'})));
    push @rrd, "GPRINT:userpct:MAX:$Lang::tr{'maximal'}\\:%6.2lf %%";
    push @rrd, "GPRINT:userpct:AVERAGE:$Lang::tr{'average'}\\:%6.2lf %%";
    push @rrd, "GPRINT:userpct:LAST:$Lang::tr{'current'}\\:%6.2lf %%\\j";
    push @rrd, "AREA:systempct#FF0000:$Lang::tr{'system cpu usage'}"
            . (" " x ($col_width - length($Lang::tr{'system cpu usage'})) . ":STACK");
    push @rrd, "GPRINT:systempct:MAX:$Lang::tr{'maximal'}\\:%6.2lf %%";
    push @rrd, "GPRINT:systempct:AVERAGE:$Lang::tr{'average'}\\:%6.2lf %%";
    push @rrd, "GPRINT:systempct:LAST:$Lang::tr{'current'}\\:%6.2lf %%\\j";
    push @rrd, "AREA:idlepct#00FF00:$Lang::tr{'idle cpu usage'}"
            . (" " x ($col_width - length($Lang::tr{'idle cpu usage'})) . ":STACK");
    push @rrd, "GPRINT:idlepct:MAX:$Lang::tr{'maximal'}\\:%6.2lf %%";
    push @rrd, "GPRINT:idlepct:AVERAGE:$Lang::tr{'average'}\\:%6.2lf %%";
    push @rrd, "GPRINT:idlepct:LAST:$Lang::tr{'current'}\\:%6.2lf %%\\j";

    push @rrd, @{&rrd_lastupdate()};
    RRDs::graph (@rrd);

    $ERROR = RRDs::error;
    print "Error in RRD::graph for cpu: $ERROR\n" if $ERROR;
}

sub updatecpudata {
    if (!-e "$rrdlog/cpu.rrd") {
        RRDs::create(
            "$rrdlog/cpu.rrd",                 "--step=300",
            "DS:user:COUNTER:600:0:500000000", "DS:system:COUNTER:600:0:500000000",
            "DS:idle:COUNTER:600:0:500000000", "RRA:AVERAGE:0.5:1:576",
            "RRA:AVERAGE:0.5:6:672",           "RRA:AVERAGE:0.5:24:732",
            "RRA:AVERAGE:0.5:144:1460"
        );
        $ERROR = RRDs::error;
        print "Error in RRD::create for cpu: $ERROR\n" if $ERROR;
    }

    my ($cpu, $user, $nice, $system, $idle);

    open STAT, "/proc/stat";
    while (<STAT>) {
        chomp;
        /^cpu\s/ or next;
        ($cpu, $user, $nice, $system, $idle) = split /\s+/;
        last;
    }
    close STAT;
    $user += $nice;

    RRDs::update("$rrdlog/cpu.rrd", "-t", "user:system:idle", "N:$user:$system:$idle");
    $ERROR = RRDs::error;
    print "Error in RRD::update for cpu: $ERROR\n" if $ERROR;
}

sub updatememgraph {
    my $period = $_[0];
    my @rrd = ();

    my $col_width = length($Lang::tr{'used memory'});
    $col_width = length($Lang::tr{'buffered memory'})   if (length($Lang::tr{'buffered memory'}) > $col_width);
    $col_width = length($Lang::tr{'cached memory'})     if (length($Lang::tr{'cached memory'}) > $col_width);
    $col_width = length($Lang::tr{'swapcached memory'}) if (length($Lang::tr{'swapcached memory'}) > $col_width);
    $col_width = length($Lang::tr{'free memory'})       if (length($Lang::tr{'free memory'}) > $col_width);
    $col_width += 2;

    push @rrd, @{&rrd_header("memory", $period, "$Lang::tr{'memory usage'} ($Lang::tr{$period})", 0, 100)};

    push @rrd, "DEF:used=$rrdlog/mem.rrd:memused:AVERAGE";
    push @rrd, "DEF:free=$rrdlog/mem.rrd:memfree:AVERAGE";
    push @rrd, "DEF:buffer=$rrdlog/mem.rrd:membuffers:AVERAGE";
    push @rrd, "DEF:cache=$rrdlog/mem.rrd:memcache:AVERAGE";
    push @rrd, "DEF:swapcached=$rrdlog/mem.rrd:memswapcached:AVERAGE";
    push @rrd, "CDEF:total=used,free,+";
    push @rrd, "CDEF:used2=used,buffer,cache,swapcached,+,+,-";
    push @rrd, "CDEF:usedpct=100,used2,total,/,*";
    push @rrd, "CDEF:bufferpct=100,buffer,total,/,*";
    push @rrd, "CDEF:cachepct=100,cache,total,/,*";
    push @rrd, "CDEF:swapcachedpct=100,swapcached,total,/,*";
    push @rrd, "CDEF:freepct=100,free,total,/,*";
    push @rrd, "AREA:usedpct#0000FF:$Lang::tr{'used memory'}" . (" " x ($col_width - length($Lang::tr{'used memory'})));
    push @rrd, "GPRINT:usedpct:MAX:$Lang::tr{'maximal'}\\:%6.2lf %%";
    push @rrd, "GPRINT:usedpct:AVERAGE:$Lang::tr{'average'}\\:%6.2lf %%";
    push @rrd, "GPRINT:usedpct:LAST:$Lang::tr{'current'}\\:%6.2lf %%\\j";
    push @rrd, "STACK:bufferpct#FF00FF:$Lang::tr{'buffered memory'}"
            . (" " x ($col_width - length($Lang::tr{'buffered memory'})));
    push @rrd, "GPRINT:bufferpct:MAX:$Lang::tr{'maximal'}\\:%6.2lf %%";
    push @rrd, "GPRINT:bufferpct:AVERAGE:$Lang::tr{'average'}\\:%6.2lf %%";
    push @rrd, "GPRINT:bufferpct:LAST:$Lang::tr{'current'}\\:%6.2lf %%\\j";
    push @rrd, "STACK:cachepct#FFFF00:$Lang::tr{'cached memory'}" . (" " x ($col_width - length($Lang::tr{'cached memory'})));
    push @rrd, "GPRINT:cachepct:MAX:$Lang::tr{'maximal'}\\:%6.2lf %%";
    push @rrd, "GPRINT:cachepct:AVERAGE:$Lang::tr{'average'}\\:%6.2lf %%";
    push @rrd, "GPRINT:cachepct:LAST:$Lang::tr{'current'}\\:%6.2lf %%\\j";
    push @rrd, "STACK:swapcachedpct#FF0000:$Lang::tr{'swapcached memory'}"
            . (" " x ($col_width - length($Lang::tr{'swapcached memory'})));
    push @rrd, "GPRINT:swapcachedpct:MAX:$Lang::tr{'maximal'}\\:%6.2lf %%";
    push @rrd, "GPRINT:swapcachedpct:AVERAGE:$Lang::tr{'average'}\\:%6.2lf %%";
    push @rrd, "GPRINT:swapcachedpct:LAST:$Lang::tr{'current'}\\:%6.2lf %%\\j";
    push @rrd, "STACK:freepct#00FF00:$Lang::tr{'free memory'}" . (" " x ($col_width - length($Lang::tr{'free memory'})));
    push @rrd, "GPRINT:freepct:MAX:$Lang::tr{'maximal'}\\:%6.2lf %%";
    push @rrd, "GPRINT:freepct:AVERAGE:$Lang::tr{'average'}\\:%6.2lf %%";
    push @rrd, "GPRINT:freepct:LAST:$Lang::tr{'current'}\\:%6.2lf %%\\j";

    push @rrd, @{&rrd_lastupdate()};
    RRDs::graph (@rrd);

    $ERROR = RRDs::error;
    print "Error in RRD::graph for mem: $ERROR\n" if $ERROR;
}

sub updatememdata {
    my ($memtotal, $memused, $memfree, $membuffers, $memcache, $memswapcached, $swaptotal, $swapused, $swapfree);
    if (!-e "$rrdlog/mem.rrd") {
        RRDs::create(
            "$rrdlog/mem.rrd",                            "--step=300",
            "DS:memused:ABSOLUTE:600:0:5000000000",       "DS:memfree:ABSOLUTE:600:0:5000000000",
            "DS:membuffers:ABSOLUTE:600:0:5000000000",    "DS:memcache:ABSOLUTE:600:0:5000000000",
            "DS:memswapcached:ABSOLUTE:600:0:5000000000", "DS:swapused:ABSOLUTE:600:0:5000000000",
            "DS:swapfree:ABSOLUTE:600:0:5000000000",      "RRA:AVERAGE:0.5:1:576",
            "RRA:AVERAGE:0.5:6:672",                      "RRA:AVERAGE:0.5:24:732",
            "RRA:AVERAGE:0.5:144:1460"
        );
        $ERROR = RRDs::error;
        print "Error in RRD::create for mem: $ERROR\n" if $ERROR;
    }

    # Achim TODO:
    # I initialize this here, because currently I don't know
    # which information I have to use from /proc/meminfo.

    # Olaf: here is some info http://www.redhat.com/advice/tips/meminfo.html
    # since memshared is always 0 -> replace with SwapCached

    open MEM, "/proc/meminfo";
    while (<MEM>) {
        chomp;
        if ($_ =~ /^MemTotal:/) {
            my @temp = split(/\s+/, $_);
            $memtotal = $temp[1];
        }
        elsif ($_ =~ /^MemFree:/) {
            my @temp = split(/\s+/, $_);
            $memfree = $temp[1];
        }
        elsif ($_ =~ /^Buffers:/) {
            my @temp = split(/\s+/, $_);
            $membuffers = $temp[1];
        }
        elsif ($_ =~ /^Cached:/) {
            my @temp = split(/\s+/, $_);
            $memcache = $temp[1];
        }
        elsif ($_ =~ /^SwapCached:/) {
            my @temp = split(/\s+/, $_);
            $memswapcached = $temp[1];
        }
        elsif ($_ =~ /^SwapTotal:/) {
            my @temp = split(/\s+/, $_);
            $swaptotal = $temp[1];
        }
        elsif ($_ =~ /^SwapFree:/) {
            my @temp = split(/\s+/, $_);
            $swapfree = $temp[1];
        }
    }
    close MEM;

    # Calc used values
    $memused  = $memtotal - $memfree;
    $swapused = $swaptotal - $swapfree;

    RRDs::update(
        "$rrdlog/mem.rrd", "-t",
        "memused:memfree:membuffers:memcache:memswapcached:swapused:swapfree",
        "N:$memused:$memfree:$membuffers:$memcache:$memswapcached:$swapused:$swapfree"
    );
    $ERROR = RRDs::error;
    print "Error in RRD::update for mem: $ERROR\n" if $ERROR;
}

sub updatediskusegraph {
    my $period = $_[0];
    my @rrd = ();

    my $col_width = length($Lang::tr{'used swap'});
    $col_width = length('/var/log')   if (length('/var/log') > $col_width);
    $col_width += 2;

    push @rrd, @{&rrd_header("diskuse", $period, "$Lang::tr{'disk usage'} ($Lang::tr{$period})", 0, 100)};

    push @rrd, "DEF:root=$rrdlog/diskuse.rrd:root:AVERAGE";
    push @rrd, "DEF:varlog=$rrdlog/diskuse.rrd:varlog:AVERAGE";
    push @rrd, "LINE2:root#0000FF:/" . (" " x ($col_width - length('/')));
    push @rrd, "GPRINT:root:MAX:$Lang::tr{'maximal'}\\:%3.0lf %%";
    push @rrd, "GPRINT:root:AVERAGE:$Lang::tr{'average'}\\:%3.0lf %%";
    push @rrd, "GPRINT:root:LAST:$Lang::tr{'current'}\\:%3.0lf %%\\j";
    push @rrd, "LINE2:varlog#00FF00:/var/log" . (" " x ($col_width - length('/var/log')));
    push @rrd, "GPRINT:varlog:MAX:$Lang::tr{'maximal'}\\:%3.0lf %%";
    push @rrd, "GPRINT:varlog:AVERAGE:$Lang::tr{'average'}\\:%3.0lf %%";
    push @rrd, "GPRINT:varlog:LAST:$Lang::tr{'current'}\\:%3.0lf %%\\j";
    unless (-e "/etc/FLASH") {
        push @rrd, "DEF:used=$rrdlog/mem.rrd:swapused:AVERAGE";
        push @rrd, "DEF:free=$rrdlog/mem.rrd:swapfree:AVERAGE";
        push @rrd, "CDEF:total=used,free,+";
        push @rrd, "CDEF:usedpct=100,used,total,/,*";
        push @rrd, "LINE2:usedpct#FF0000:$Lang::tr{'used swap'}" . (" " x ($col_width - length($Lang::tr{'used swap'})));
        push @rrd, "GPRINT:usedpct:MAX:$Lang::tr{'maximal'}\\:%3.0lf %%";
        push @rrd, "GPRINT:usedpct:AVERAGE:$Lang::tr{'average'}\\:%3.0lf %%";
        push @rrd, "GPRINT:usedpct:LAST:$Lang::tr{'current'}\\:%3.0lf %%\\j";
    }

    push @rrd, @{&rrd_lastupdate()};
    RRDs::graph (@rrd);

    $ERROR = RRDs::error;
    print "Error in RRD::graph for diskuse: $ERROR\n" if $ERROR;
}

sub updatediskusedata {
    my ($root, $varlog, $boot);
    if (!-e "$rrdlog/diskuse.rrd") {
        RRDs::create(
            "$rrdlog/diskuse.rrd",      "--step=300",
            "DS:root:GAUGE:600:0:1000", "DS:varlog:GAUGE:600:0:1000",
            "RRA:AVERAGE:0.5:1:576",	"RRA:AVERAGE:0.5:6:672",
            "RRA:AVERAGE:0.5:24:732",	"RRA:AVERAGE:0.5:144:1460"
        );
        $ERROR = RRDs::error;
        print "Error in RRD::create for diskuse: $ERROR\n" if $ERROR;
    }

    open(DF, '/bin/df -B M -x rootfs -x tmpfs|');
    my @df = <DF>;
    close DF;

    # skip first line:
    # Filesystem            Size  Used Avail Use% Mounted on
    shift(@df);
    chomp(@df);

    # merge all lines to one single line separated by spaces
    my $all_inOneLine = join(' ', @df);

    # now get all entries in an array
    my @all_entries = split(' ', $all_inOneLine);

    ($root)   = split('%', $all_entries[4]);
    ($varlog) = split('%', $all_entries[10]);

    RRDs::update("$rrdlog/diskuse.rrd", "-t", "root:varlog", "N:$root:$varlog");
    $ERROR = RRDs::error;
    print "Error in RRD::update for diskuse: $ERROR\n" if $ERROR;
}

sub updatediskgraph {
    my $period = $_[0];
    my @rrd = ();

    push @rrd, @{&rrd_header("disk", $period, "$Lang::tr{'disk access'} ($Lang::tr{$period})", -1, -1)};

    push @rrd, "DEF:read=$rrdlog/disk.rrd:readsect:AVERAGE";
    push @rrd, "DEF:write=$rrdlog/disk.rrd:writesect:AVERAGE";
    push @rrd, "CDEF:readneg=read,-1,*";
    push @rrd, "HRULE:0#000000";
    push @rrd, "AREA:readneg#0000FF:$Lang::tr{'sectors read from disk per second'}\\j";
    push @rrd, "GPRINT:read:MAX:$Lang::tr{'maximal'}\\:%8.0lf";
    push @rrd, "GPRINT:read:AVERAGE:$Lang::tr{'average'}\\:%8.0lf";
    push @rrd, "GPRINT:read:LAST:$Lang::tr{'current'}\\:%8.0lf\\j";
    push @rrd, "AREA:write#00FF00:$Lang::tr{'sectors written to disk per second'}\\j";
    push @rrd, "GPRINT:write:MAX:$Lang::tr{'maximal'}\\:%8.0lf";
    push @rrd, "GPRINT:write:AVERAGE:$Lang::tr{'average'}\\:%8.0lf";
    push @rrd, "GPRINT:write:LAST:$Lang::tr{'current'}\\:%8.0lf\\j";

    push @rrd, @{&rrd_lastupdate()};
    RRDs::graph (@rrd);

    $ERROR = RRDs::error;
    print "Error in RRD::graph for disk: $ERROR\n" if $ERROR;
}

sub updatediskdata {
    my ($readsect, $writesect);
    if (!-e "$rrdlog/disk.rrd") {
        RRDs::create(
            "$rrdlog/disk.rrd",                     "--step=300",
            "DS:readsect:COUNTER:600:0:5000000000", "DS:writesect:COUNTER:600:0:5000000000",
            "RRA:AVERAGE:0.5:1:576",                "RRA:AVERAGE:0.5:6:672",
            "RRA:AVERAGE:0.5:24:732",               "RRA:AVERAGE:0.5:144:1460"
        );
        $ERROR = RRDs::error;
        print "Error in RRD::create for disk: $ERROR\n" if $ERROR;
    }

    # see kernel Documentation/iostats.txt for format of /proc/diskstats

    my $diskstat = `cat /proc/diskstats | grep -m 1 -E '[h|s]d'`;
    chomp($diskstat);
    if ($diskstat ne '') {
        $diskstat =~ /[h|s]d.\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/;
        $readsect  = $3;
        $writesect = $7;

        RRDs::update("$rrdlog/disk.rrd", "-t", "readsect:writesect", "N:$readsect:$writesect");
        $ERROR = RRDs::error;
        print "Error in RRD::update for disk: $ERROR\n" if $ERROR;
    }
    else {
        print "Error in RRD::update for disk: no data available\n";
    }
}

sub updateifgraph {
    my $interface = $_[0];
    my $period    = $_[1];
    my @rrd = ();

    my ($title, $count) = split('_', lc($interface));
    $title = ($count >= 2) ? $Lang::tr{$title}." ".$count : $Lang::tr{$title};

    push @rrd, @{&rrd_header($interface, $period, "$Lang::tr{'traffic on'} $title ($Lang::tr{$period})", -1, -1)};

    push @rrd, "-v$Lang::tr{'bits per second'}";
    push @rrd, "DEF:incoming=$rrdlog/$interface.rrd:incoming:AVERAGE";
    push @rrd, "DEF:outgoing=$rrdlog/$interface.rrd:outgoing:AVERAGE";
    push @rrd, "CDEF:incomingbits=incoming,8,*";
    push @rrd, "CDEF:outgoingbits=outgoing,8,*";
    push @rrd, "CDEF:outgoingnegbits=outgoing,-8,*";
    push @rrd, "HRULE:0#000000";
    push @rrd, "AREA:incomingbits#00FF00:$Lang::tr{'incoming traffic in bits per second'}\\j";
    push @rrd, "GPRINT:incomingbits:MAX:$Lang::tr{'maximal'}\\:%8.3lf %sbps";
    push @rrd, "GPRINT:incomingbits:AVERAGE:$Lang::tr{'average'}\\:%8.3lf %sbps";
    push @rrd, "GPRINT:incomingbits:LAST:$Lang::tr{'current'}\\:%8.3lf %sbps\\j";
    push @rrd, "AREA:outgoingnegbits#0000FF:$Lang::tr{'outgoing traffic in bits per second'}\\j";
    push @rrd, "GPRINT:outgoingbits:MAX:$Lang::tr{'maximal'}\\:%8.3lf %sbps";
    push @rrd, "GPRINT:outgoingbits:AVERAGE:$Lang::tr{'average'}\\:%8.3lf %sbps";
    push @rrd, "GPRINT:outgoingbits:LAST:$Lang::tr{'current'}\\:%8.3lf %sbps\\j";

    push @rrd, @{&rrd_lastupdate()};
    RRDs::graph(@rrd);

    $ERROR = RRDs::error;
    print "Error in RRD::graph for $interface: $ERROR\n" if $ERROR;
}

sub updateifdata {
    my $interface = $_[0];
    my $device = $_[1];

    if (!-e "$rrdlog/$interface.rrd") {
        RRDs::create(
            "$rrdlog/$interface.rrd",              "--step=300",
            "DS:incoming:DERIVE:600:0:125000000",  "DS:outgoing:DERIVE:600:0:125000000",
            "RRA:AVERAGE:0.5:1:576",               "RRA:AVERAGE:0.5:6:672",
            "RRA:AVERAGE:0.5:24:732",              "RRA:AVERAGE:0.5:144:1460"
        );
        $ERROR = RRDs::error;
        print "Error in RRD::create for $interface: $ERROR\n" if $ERROR;
    }

    my $traffic = gettraffic($device);
    RRDs::update("$rrdlog/$interface.rrd", "-t", "incoming:outgoing", "N:$traffic");
    $ERROR = RRDs::error;
    print "Error in RRD::update for $interface: $ERROR\n" if $ERROR;
}

sub updatesquidgraph {
    my $period = $_[0];
    my @rrd = ();

    push @rrd, @{&rrd_header("squid-requests", $period, "$Lang::tr{'proxy requests'} ($Lang::tr{$period})", -1, -1)};

    push @rrd, "DEF:requests=$rrdlog/squid_requests.rrd:requests:AVERAGE";
    push @rrd, "LINE2:requests#00FF00:$Lang::tr{'proxy requests'}\\j";
    push @rrd, "GPRINT:requests:MAX:$Lang::tr{'maximal'}\\:%8.0lf";
    push @rrd, "GPRINT:requests:AVERAGE:$Lang::tr{'average'}\\:%8.0lf";
    push @rrd, "GPRINT:requests:LAST:$Lang::tr{'current'}\\:%8.0lf\\j";

    push @rrd, @{&rrd_lastupdate()};
    RRDs::graph (@rrd);

    $ERROR = RRDs::error;
    print "Error in RRD::graph for squid requests: $ERROR\n" if $ERROR;

    @rrd = ();

    push @rrd, @{&rrd_header("squid-hits", $period, "$Lang::tr{'proxy hits percentage'} ($Lang::tr{$period})", -1, -1)};

    push @rrd, "DEF:hits_per=$rrdlog/squid_requests.rrd:hits_per:AVERAGE";
    push @rrd, "LINE2:hits_per#00FF00:$Lang::tr{'proxy hits percentage'}\\j";
    push @rrd, "GPRINT:hits_per:MAX:$Lang::tr{'maximal'}\\:%8.0lf";
    push @rrd, "GPRINT:hits_per:AVERAGE:$Lang::tr{'average'}\\:%8.0lf";
    push @rrd, "GPRINT:hits_per:LAST:$Lang::tr{'current'}\\:%8.0lf\\j";

    push @rrd, @{&rrd_lastupdate()};
    RRDs::graph (@rrd);

    $ERROR = RRDs::error;
    print "Error in RRD::graph for squid hits: $ERROR\n" if $ERROR;
}

sub updatesquiddata {
    my $sock;
    my $host = "127.0.0.1";
    my $port = "82";

    if (!-e "$rrdlog/squid_requests.rrd") {
        RRDs::create(
            "$rrdlog/squid_requests.rrd",
            "--step=300",
            "DS:requests:DERIVE:600:0:U",
            "DS:hits_per:GAUGE:600:0:U",
            "RRA:AVERAGE:0.5:1:576",                "RRA:AVERAGE:0.5:6:672",
            "RRA:AVERAGE:0.5:24:732",               "RRA:AVERAGE:0.5:144:1460"
        );
        $ERROR = RRDs::error;
        print "Error in RRD::create for squid requests: $ERROR\n" if $ERROR;
    }

    if (!($sock = IO::Socket::INET->new(PeerAddr => scalar($host), PeerPort => $port, Proto => 'tcp'))) {
        print "Could not connect to proxy manager. Proxy probably disabled.\n";
        return;
    }
    $sock->autoflush(1);
    print $sock "GET cache_object://$host/info HTTP/1.0\n\n";
    my @result = <$sock>;
    close $sock;

    my %vals;
    open(FILE, ">/var/log/squid/info");
    foreach(@result) {
        print FILE $_;
        $vals{requests} = $1 if (/Number of HTTP requests received:\s+(\d+)/);
        $vals{hits_per} = $1 if (/Hits as % of all requests:\s+5min:\s+([^%]+)%,\s+60min:\s+([^%]+)%/);
    }
    close(FILE);

#    print "$vals{requests} $vals{hits_per}\n";

    RRDs::update("$rrdlog/squid_requests.rrd", "-t", "requests:hits_per", "N:$vals{requests}:$vals{hits_per}");
    $ERROR = RRDs::error;
    print "Error in RRD::update for squid: $ERROR\n" if $ERROR;
}


###
### utf8 conversion
###
### TODO: check conversion still required
#if (   (${Lang::language} eq 'cs')
#    || (${Lang::language} eq 'hu')
#    || (${Lang::language} eq 'pl')
#    || (${Lang::language} eq 'sk'))
#{
#
#    # Czech, Hungarian, Polish and Slovak character set
#    foreach my $key (keys %Lang::tr) {
#        from_to($Lang::tr{$key}, "utf-8", "iso-8859-2");
#    }
#}
#elsif (${Lang::language} eq 'tr') {
#
#    # Turkish
#    foreach my $key (keys %Lang::tr) {
#        from_to($Lang::tr{$key}, "utf-8", "iso-8859-9");
#    }
#}
#else {
#    foreach my $key (keys %Lang::tr) {
#        from_to($Lang::tr{$key}, "utf-8", "iso-8859-1");
#    }
#}

###
### System graphs
###
updatecpudata();
updatecpugraph("hour");
updatecpugraph("day");
updatecpugraph("week");
updatecpugraph("month");
updatecpugraph("year");

updatememdata();
updatememgraph("hour");
updatememgraph("day");
updatememgraph("week");
updatememgraph("month");
updatememgraph("year");

updatediskusedata();
updatediskusegraph("hour");
updatediskusegraph("day");
updatediskusegraph("week");
updatediskusegraph("month");
updatediskusegraph("year");

updatediskdata();
updatediskgraph("hour");
updatediskgraph("day");
updatediskgraph("week");
updatediskgraph("month");
updatediskgraph("year");

###
### Network Graphs
###
for my $color ('GREEN', 'RED', 'ORANGE', 'BLUE') {
    my $icount = $settings{"${color}_COUNT"};
    while ($icount > 0) {
        my $thisitf = "${color}_${icount}";
        my $thisdev = $settings{"${thisitf}_DEV"};
        updateifdata($thisitf, $thisdev);
        if (-e "$rrdlog/$thisitf.rrd") {
            updateifgraph($thisitf, "hour");
            updateifgraph($thisitf, "day");
            updateifgraph($thisitf, "week");
            updateifgraph($thisitf, "month");
            updateifgraph($thisitf, "year");
        }
        $icount--;
    }
}
###
### Special case Modem/ISDN
###
if ($settings{'RED_COUNT'} == 0) {
    my $thisitf = 'RED_1';
    my $thisdev = &General::getredinterface();
    
    # If RED interface does not exist, add 0:0 to traffic
    $thisdev = 'dummyinterface' if ($thisdev eq '');
    updateifdata($thisitf, "ppp0");
    if (-e "$rrdlog/$thisitf.rrd") {
        updateifgraph($thisitf, "hour");
        updateifgraph($thisitf, "day");
        updateifgraph($thisitf, "week");
        updateifgraph($thisitf, "month");
        updateifgraph($thisitf, "year");
    }
}

updatesquiddata();
updatesquidgraph("hour");
updatesquidgraph("day");
updatesquidgraph("week");
updatesquidgraph("month");
updatesquidgraph("year");
