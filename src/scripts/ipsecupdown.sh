#!/bin/bash
#
# ipsecupdown.sh is called by ipsec
#
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
# along with Openfirewall; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
# 
# (c) 2010, the Openfirewall Team
#
# $Id: ipsecupdown.sh 4591 2010-05-18 15:57:44Z owes $
#

case "$PLUTO_VERB" in
    prepare-host|prepare-client)
        /usr/bin/logger -t ipsec "$PLUTO_VERB"
        # Delete possibly-existing route (preliminary to adding a route)
        # Not used for NETKEY
        ;;
    route-host|route-client)
        /usr/bin/logger -t ipsec "$PLUTO_VERB"
        # connection to me or my client subnet being routed
        ;;
    unroute-host|unroute-client)
        /usr/bin/logger -t ipsec "$PLUTO_VERB"
        # connection to me or my client subnet being unrouted
        ;;
    up-client)
        /usr/bin/logger -t ipsec "$PLUTO_VERB"
        # connection to my client subnet coming up
        # avoid NAT on tunneled traffic
        /sbin/iptables -t nat -I REDNAT -s ${PLUTO_MY_CLIENT} -d ${PLUTO_PEER_CLIENT} -j ACCEPT
        ;;
    down-client)
        /usr/bin/logger -t ipsec "$PLUTO_VERB"
        # connection to my client subnet going down
        /sbin/iptables -t nat -D REDNAT -s ${PLUTO_MY_CLIENT} -d ${PLUTO_PEER_CLIENT} -j ACCEPT
        ;;
    *)
        /usr/bin/logger -t ipsec "unknown verb $PLUTO_VERB"
        #echo `set | sort` > /tmp/ipsec.env
        ;;
        
esac
