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
# $Id: aggregatetraffic.pl 4953 2010-09-12 17:17:52Z owes $
#

use DBI;
use strict;
use XML::Simple;
#use warnings;

require '/usr/lib/ipcop/traffic-lib.pl';

# Debug level:
#	0 - aggregate traffic, no print
#	1 - aggregate traffic, print
#	2 - only print traffic data
my $debugLevel = 0;

while (@ARGV) {
    my $argument = shift;

    if ($argument eq '-d') {
        $debugLevel++;
    }
}


my $dbsum = DBI->connect("dbi:SQLite:dbname=/var/log/traffic/aggregate.db", "", "", {RaiseError => 1, AutoCommit => 0});
# Set temp directory to /tmp instead of /var/tmp
eval { $dbsum->do("PRAGMA temp_store_directory=\"/tmp\";") };

my $whereClause = q{
    WHERE (type = ? OR (type IS NULL AND ? IS NULL) )
    AND (date = ? OR (date IS NULL AND ? IS NULL) )
    AND (oob_prefix = ? OR (oob_prefix IS NULL AND ? IS NULL) )
    AND (ip_saddr = ? OR (ip_saddr IS NULL AND ? IS NULL) )
    AND (ip_protocol = ? OR (ip_protocol IS NULL AND ? IS NULL) )
    AND (tcp_dport = ? OR (tcp_dport IS NULL AND ? IS NULL) )
    AND (udp_dport = ? OR (udp_dport IS NULL AND ? IS NULL) )
};

# Detailed aggregation on/off
my $detailed = 'off';
if ($TRAFFIC::settings{'DETAIL_LEVEL'} eq 'High') {
    $detailed = 'on';
    &aggregate_ulogd();
}
else {
    &aggregate_vnstat();
}

$dbsum->disconnect() or warn $dbsum->errstr;


sub aggregate_ulogd()
{
# FIXME/TODO: as ulogd locks the database we have to stop it here and restart after aggregation
# As long as ulogd is not running the traffic flow is not logged, we lose some data!
system("/usr/bin/killall ulogd");
    my $cnt = 0;
    while (system('ps aux | grep ulogd | grep -v grep') == 0) {
        sleep(1);
        $cnt++;
    }
#    &General::log("aggregate", "cnt $cnt");
my $dbh = DBI->connect("dbi:SQLite:dbname=/var/log/traffic/ulogd.db", "", "", {RaiseError => 1, AutoCommit => 0});
my $groupDetailed = "";
my $selectColumns = "";

# Set temp directory to /tmp instead of /var/tmp
eval { $dbh->do("PRAGMA temp_store_directory=\"/tmp\";") };

if ($detailed eq 'on') {
    ### Aggregate detailed
    $selectColumns = " ip_saddr, ip_protocol, tcp_dport, udp_dport, ";
    $groupDetailed = " , ip_saddr, ip_protocol, tcp_dport, udp_dport ";
}
else {
    ### Aggregate simple
    $selectColumns = " NULL AS ip_saddr, NULL AS ip_protocol, NULL AS tcp_dport, NULL AS udp_dport, ";
    $groupDetailed = "";
}

#my $statementSelect = "select oob_prefix, count(*), sum(ip_totlen) from ulog group by oob_prefix;";
my $statementSelect = "SELECT strftime(\"%Y%m%d\", oob_time_sec, 'unixepoch') AS date, oob_prefix, ";
$statementSelect .= $selectColumns;
$statementSelect .= " SUM(ip_totlen) ";
$statementSelect .= " FROM ulog ";
$statementSelect .= " GROUP BY date, oob_prefix ";
$statementSelect .= $groupDetailed;
$statementSelect .= ";";

eval {
    my $sthSelect = $dbh->prepare($statementSelect);
    my $sthInsert = $dbsum->prepare(
        q{
          INSERT INTO daily (type, date, oob_prefix, ip_saddr, ip_protocol, tcp_dport, udp_dport, ip_totlen) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
      }
    );
    my $sthCheckDailyCount = $dbsum->prepare("SELECT count(*) FROM daily $whereClause;");
    my $sthCheckDaily      = $dbsum->prepare("SELECT ip_totlen FROM daily $whereClause;");
    my $sthUpdate          = $dbsum->prepare("UPDATE daily set ip_totlen = ? $whereClause;");
    my $sthDelete          = $dbh->prepare("DELETE FROM ulog;");

    $sthSelect->execute();

    # Bind Perl variables to columns:
    my ($date, $prefix, $srcAdr, $proto, $tcpPort, $udpPort, $bytes);

    $sthSelect->bind_columns(\$date, \$prefix, \$srcAdr, \$proto, \$tcpPort, \$udpPort, \$bytes);

    my $countDaily = 0;
    $sthCheckDailyCount->bind_columns(\$countDaily);
    my $bytesCheck;
    $sthCheckDaily->bind_columns(\$bytesCheck);

    while ($sthSelect->fetch()) {
        my @whereData =
            ('ulogd', 'ulogd', $date, $date, $prefix, $prefix, $srcAdr, $srcAdr, $proto, $proto, $tcpPort, $tcpPort, $udpPort, $udpPort);

        $sthCheckDailyCount->execute(@whereData);
        $sthCheckDailyCount->fetch();
        if ($countDaily > 0) {
            $sthCheckDaily->execute(@whereData);
            $sthCheckDaily->fetch();

            # There is already an traffic entry with this data
            $bytes = $bytesCheck + $bytes;
            if ($debugLevel < 2) {
                $sthUpdate->execute($bytes, @whereData);
            }
            print "Update: " if ($debugLevel > 0);
        }
        else {

            # New Entry
            if ($debugLevel < 2) {
                $sthInsert->execute('ulogd', $date, $prefix, $srcAdr, $proto, $tcpPort, $udpPort, $bytes);
            }
            print "Insert: " if ($debugLevel > 0);
        }

        print " $date|$prefix|$srcAdr|$proto|$tcpPort|$udpPort|$bytes \n" if ($debugLevel > 0);
    }

    if ($debugLevel < 2) {
        $sthDelete->execute();
    }

    $sthSelect->finish();
    $sthInsert->finish();
    $sthCheckDailyCount->finish();
    $sthCheckDaily->finish();
    $sthUpdate->finish();

    $dbsum->commit();       # commit the changes if we get this far
    $dbh->commit();         # commit the changes if we get this far
};
if ($@) {
    warn "Transaction aborted because $@";
    &General::log("aggregate", "Transaction aborted because $@");

    # now rollback to undo the incomplete changes
    # but do it in an eval{} as it may also fail
    eval { $dbh->rollback() };
    eval { $dbsum->rollback() };

    # add other application on-error-clean-up code here
}

$dbh->disconnect() or warn $dbh->errstr;

# reconnect for "VACUUM"
$dbh = DBI->connect("dbi:SQLite:dbname=/var/log/traffic/ulogd.db", "", "");

# shrink database file
eval { $dbh->do("VACUUM;") };
$dbh->disconnect() or warn $dbh->errstr;

# FIXME/TODO: Restart ulogd
system("/usr/sbin/ulogd -d") if($TRAFFIC::settings{'ENABLED'} eq 'on');
}


sub aggregate_vnstat()
{
    unlink('/tmp/vnstat.xml');
    system('/usr/bin/vnstat --xml > /tmp/vnstat.xml');

    my $vnstat = eval { XMLin('/tmp/vnstat.xml') };
    if ($@) {
        # TODO: report error?
        exit(1);
    }

    my $date;

    foreach my $data (@{$vnstat->{interface}}) {
        # $data->{id}[0] is lan-1, wan-1, etc.
        print "$data->{id}[0] $data->{nick}\n" if ($debugLevel > 1);
        if (exists($data->{traffic}->{days}->{day}->{id})) {
            # Only data for 1 day exists
            my $dataday = $data->{traffic}->{days}->{day};
            # We now have a date and Rx,Tx in KiB
            print "$dataday->{date}->{year}-$dataday->{date}->{month}-$dataday->{date}->{day} Rx: $dataday->{rx} KiB Tx: $dataday->{tx} KiB\n"  if ($debugLevel > 1);

            $date = "$dataday->{date}->{year}$dataday->{date}->{month}$dataday->{date}->{day}";
            &updatedb_daily('vnstat', $date, "$data->{nick}_INPUT", "", 0, 0, 0, $dataday->{rx} * 1024);
            &updatedb_daily('vnstat', $date, "$data->{nick}_OUTPUT", "", 0, 0, 0, $dataday->{tx} * 1024);
        }

        my $day = 0;
        while (exists($data->{traffic}->{days}->{day}->{$day})) {
            my $dataday = $data->{traffic}->{days}->{day}->{$day};
            # We now have a date and Rx,Tx in KiB
            print "$dataday->{date}->{year}-$dataday->{date}->{month}-$dataday->{date}->{day} Rx: $dataday->{rx} KiB Tx: $dataday->{tx} KiB\n"  if ($debugLevel > 1);
            
            $date = "$dataday->{date}->{year}$dataday->{date}->{month}$dataday->{date}->{day}";
            &updatedb_daily('vnstat', $date, "$data->{nick}_INPUT", "", 0, 0, 0, $dataday->{rx} * 1024);
            &updatedb_daily('vnstat', $date, "$data->{nick}_OUTPUT", "", 0, 0, 0, $dataday->{tx} * 1024);

            $day++;
        }
    }

    $dbsum->commit();    # commit the changes

    unlink('/tmp/vnstat.xml');
}


sub updatedb_daily()
{
    my $type = shift;
    my $date = shift;
    my $prefix = shift;
    my $srcAdr = shift;
    my $proto = shift;
    my $tcpPort = shift;
    my $udpPort = shift;
    my $bytes = shift;

    my $sthCheckDailyCount = $dbsum->prepare("SELECT count(*) FROM daily $whereClause;");
    my $sthCheckDaily      = $dbsum->prepare("SELECT ip_totlen FROM daily $whereClause;");
    my $countDaily = 0;
    $sthCheckDailyCount->bind_columns(\$countDaily);
    my $bytesCheck;
    $sthCheckDaily->bind_columns(\$bytesCheck);

    my @whereData =
        ($type, $type, $date, $date, $prefix, $prefix, $srcAdr, $srcAdr, $proto, $proto, $tcpPort, $tcpPort, $udpPort, $udpPort);

    $sthCheckDailyCount->execute(@whereData);
    $sthCheckDailyCount->fetch();
    if ($countDaily > 0) {
        # Update Entry
        my $sthUpdate = $dbsum->prepare("UPDATE daily set ip_totlen = $bytes $whereClause;");
        if ($debugLevel < 2) {
            $sthUpdate->execute(@whereData);
        }
        $sthUpdate->finish();
        print "Update: " if ($debugLevel > 0);
    }
    else {
        # New Entry
        my $sthInsert = $dbsum->prepare(
            q{
              INSERT INTO daily (type, date, oob_prefix, ip_saddr, ip_protocol, tcp_dport, udp_dport, ip_totlen) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
          }
        );

        if ($debugLevel < 2) {
            $sthInsert->execute($type, $date, $prefix, $srcAdr, $proto, $tcpPort, $udpPort, $bytes);
        }
        $sthInsert->finish();
        print "Insert: " if ($debugLevel > 0);
    }

    print " $type|$date|$prefix|$srcAdr|$proto|$tcpPort|$udpPort|$bytes \n" if ($debugLevel > 0);
}
