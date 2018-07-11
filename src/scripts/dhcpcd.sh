#!/bin/bash
#
# dhcpcd.sh is called by dhcpcd
#
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
# This script is based on the dhcpcd.sh sample script of the dhcpcd package, which has
# following copyright information:
#   dhcpcd-3 - DHCP client daemon
#   Copyright 2006-2008 Roy Marples <roy at marples dot name>
#
#
# (c) 2008-2016, the IPCop team
#
# $Id: dhcpcd.sh 8079 2016-01-19 10:13:13Z owes $
#


make_info_file() {
    cat /dev/null > $FILE_INFO
    echo "DHCLIENT_IPADDR=${new_ip_address}" >> $FILE_INFO
    echo "DHCLIENT_INTERFACE=${interface}" >> $FILE_INFO
    router=`echo ${new_routers} | /usr/bin/cut -d ' ' -f 1`
    echo "DHCLIENT_GATEWAY=$router" >> $FILE_INFO
    count=1
    for nameserver in ${new_domain_name_servers}; do
        echo "DHCLIENT_DNS$count=$nameserver" >> $FILE_INFO
        ((++count))
    done
    echo "DHCLIENT_HOSTNAME=$new_host_name" >> $FILE_INFO
    echo "DHCLIENT_DOMAIN=${new_domain_name}" >> $FILE_INFO
    echo "DHCLIENT_SIADDR=${new_dhcp_server_identifier}" >> $FILE_INFO
    echo "DHCLIENT_LEASETIME=${new_dhcp_lease_time}" >> $FILE_INFO
    EXPIRY=$(( `date +"%s"` + ${new_dhcp_lease_time} ))
    echo "DHCLIENT_EXPIRY=$EXPIRY" >> $FILE_INFO
}


FILE_INFO=/var/log/dhcpclient.info

# Write all variables to file for testing, code snippet from dhcpcd-hooks/01-test
#echo `set | grep "^\(new_\|old_\)" | sort` > /tmp/dhcpcd.env
#

case "${reason}" in
    REBIND|RENEW)
        if [ ! -z ${DEBUG} ]; then
            /usr/bin/logger -p local0.info -t dhcpcd[] \
            "interface ${interface} has been configured with old IP=${new_ip_address}"
        fi
        # Put your code here for when the interface has been brought up with an
        # old IP address here
        make_info_file
        state=renew
        ;;

    BOUND|REBOOT)
        if [ ! -z ${DEBUG} ]; then
            /usr/bin/logger -p local0.info -t dhcpcd[] \
            "interface ${interface} has been configured with new IP=${new_ip_address}"
        fi
        # Put your code here for when the interface has been brought up with a
        # new IP address
        make_info_file
        state=up
        ;;

    RELEASE|EXPIRE|STOP)
        if [ ! -z ${DEBUG} ]; then
            /usr/bin/logger -p local0.info -t dhcpcd[] \
            "interface ${interface} has been brought down"
        fi
        # Put your code here for the when the interface has been shut down
        state=down
        ;;

    PREINIT|CARRIER|NAK|STOPPED)
        exit 0
        ;;

    FAIL|NOCARRIER)
        if [ ! -z ${DEBUG} ]; then
            /usr/bin/logger -s -p local0.info -t dhcpcd[] \
            "interface ${interface} lease failed"
        fi
        # Put your code here for the when the interface failed
        state=down
        ;;

    *)
        logger -s -p local0.err -t dhcpcd[] "unknown usage ${reason}"
        exit 1
        ;;

esac

/etc/rc.d/rc.updatered dhcpcd ${state} $FILE_INFO

exit 0
