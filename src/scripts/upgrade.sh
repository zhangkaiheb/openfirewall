#!/bin/bash
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
# (c) Gilles Espinasse
#
# Universal upgrade script
# - called after every restore (from installation or backup)
# - place a call on update only if a new fix was added
# - every change on data include in backup need to be there
#   and not in update setup
#
# $Id: upgrade.sh 7975 2015-07-06 08:42:30Z owes $
#


# Tweak ntp.conf file if NTPd is running (modified in 1.9.11)
TMP=`grep "ENABLED_NTP=on" /var/ipcop/time/settings`
if [ "x$TMP" != "x" ]; then
    /bin/sed -i -e "s+^fudge\s*127\.127\.1\.0.*+fudge  127.127.1.0 stratum 7+" \
                -e "s+^driftfile.*+driftfile /var/log/ntp/drift+" /var/ipcop/time/ntp.conf

    # Modify server restrictions (1.9.18 and 2.1.8)
    /bin/sed -i -e "s+^restrict default.*+restrict default kod limited nomodify nopeer noquery notrap+" \
                -e "s+nomodify notrap+nomodify noquery notrap+" \
                -e "/^restrict.*mask 255\.255\.255\.255.*/ d" /var/ipcop/time/ntp.conf
fi

# OpenVPN config file, modified in 1.9.11 and 1.9.13
if [ -e /var/ipcop/openvpn/server.conf ]; then
    TMP=`grep "script-security" /var/ipcop/openvpn/server.conf`
    if [ "x$TMP" == "x" ]; then
        echo "script-security 2" >> /var/ipcop/openvpn/server.conf
    fi
    /bin/sed -i -e "s+^client-connect.*+client-connect /usr/local/bin/openvpn.sh+" \
                -e "s+^client-disconnect.*+client-disconnect /usr/local/bin/openvpn.sh+" \
                /var/ipcop/openvpn/server.conf
fi

# OpenVPN-Blue, OpenVPN-Orange and OpenVPN-Red no longer exist, modified in 1.9.12
if [ -e /var/ipcop/firewall/policy ]; then
    /bin/sed -i -e "/OpenVPN-Blue/ d" \
                -e "/OpenVPN-Orange/ d" \
                -e "/OpenVPN-Red/ d" /var/ipcop/firewall/policy
fi

# IPsec, change from KLIPS to NETKEY, modified in 1.9.15
if [ -e /var/ipcop/ipsec/ipsec.conf ]; then
    /bin/sed -i -e "/^interfaces=.*/ d" \
                -e "s/protostack=klips/protostack=netkey/" /var/ipcop/ipsec/ipsec.conf
fi

# Make sure we have IP when RED=PPPoE, modified in 1.9.15
TMP=`grep "RED_1_TYPE" /var/ipcop/ethernet/settings`
if [ "x$TMP" == "xPPPOE" ]; then
    TMP=`grep "RED_1_ADDRESS" /var/ipcop/ethernet/settings`
    if [ "x$TMP" == "x" ]; then
        echo "RED_1_ADDRESS=1.1.1.1" >> /var/ipcop/ethernet/settings
        echo "RED_1_NETADDRESS=1.1.1.0" >> /var/ipcop/ethernet/settings
        echo "RED_1_NETMASK=255.255.255.0" >> /var/ipcop/ethernet/settings
    fi
fi

# dnsmasq config file, modified in 1.9.15
TMP=`grep "listen-address" /var/ipcop/dhcp/dnsmasq.conf`
if [ "x$TMP" != "x" ]; then
    /bin/sed -i -e "/^listen-address.*/ d" /var/ipcop/dhcp/dnsmasq.conf
    echo "except-interface=wan-1" >> /var/ipcop/dhcp/dnsmasq.conf
    echo "except-interface=ppp0" >> /var/ipcop/dhcp/dnsmasq.conf
    echo "except-interface=dmz-1" >> /var/ipcop/dhcp/dnsmasq.conf
fi
# dnsmasq config file, modified in 1.9.18
TMP=`grep "domain-needed" /var/ipcop/dhcp/dnsmasq.conf`
if [ "x$TMP" == "x" ]; then
    echo "domain-needed" >> /var/ipcop/dhcp/dnsmasq.conf
fi

# External access rules no longer possible as INPUT rule, modified in 1.9.18
/bin/sed -i -e "/,INPUT,.*,defaultSrcNet,Red,/{s/,INPUT,/,EXTERNAL,/}" /var/ipcop/firewall/config

# Detail High for traffic accounting disabled in 2.0.3
/bin/sed -i -e "s/DETAIL_LEVEL=.*/DETAIL_LEVEL=Low/" /var/ipcop/traffic/settings

# Not used directory proxy/autoupdate removed in 2.0.3
rm -rf /var/ipcop/proxy/autoupdate

# 2.0.3 update changed the owner of /var/ipcop/proxy, fix that
chown nobody:nobody /var/ipcop/proxy

# Wrong directory openvpn/ca and file openvpn/caconfig removed in 2.1.1
rm -rf /var/ipcop/openvpn/ca
rm -rf /var/ipcop/openvpn/caconfig

# Fix permissions of urlfilter files if necessary
/usr/local/bin/blacklistupdate.pl --perm

# write new squid.conf (format changed with squid 3.3.x in 2.1.1
/usr/local/bin/makesquidconf.pl

# Move local ca-certificates
if [ -d /var/ipcop/ca/ca-certificates ]; then
    if [ -e /var/ipcop/ca/ca-certificates/* ]; then
        mv -f /var/ipcop/ca/ca-certificates/* /var/ipcop/ca-local
    fi
    rm -rf /var/ipcop/ca/ca-certificates
    chown -R nobody.nobody /var/ipcop/ca-local
fi

# CA certificate bundle
/usr/sbin/update-ca-certificates --fresh

TMP=`grep "squidGuard -f" /var/ipcop/proxy/redirector/urlfilter`
if [ "x$TMP" != "x" ]; then
    /bin/sed -i -e "s+CMD=.*+CMD=/usr/bin/squidGuard+" /var/ipcop/proxy/redirector/urlfilter
    echo "OPTION_CHAIN=-f" >> /var/ipcop/proxy/redirector/urlfilter
fi

# Blacklist URL changed
/bin/sed -i -e "s+Univ\. Toulouse.*+Univ\. Toulouse,ftp://ftp\.ut-capitole\.fr/blacklist/blacklists\.tar\.gz+" /var/ipcop/proxy/blacklistupdate/blacklistupdate.urls
