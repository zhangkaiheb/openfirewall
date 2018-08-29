#!/bin/sh
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
# along with Openfirewall.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright (C) 2009-2015, the Openfirewall Team.
#
# $Id: openvpn.sh 7939 2015-03-14 14:52:12Z owes $
#


case "$script_type" in
    client-connect)
        /usr/bin/logger -t openvpn "CONNECT $common_name $ifconfig_pool_remote_ip $trusted_ip"
        ;;
    client-disconnect)
        /usr/bin/logger -t openvpn "DISCONNECT $common_name $ifconfig_pool_remote_ip $trusted_ip rx=$bytes_received tx=$bytes_sent connect=$time_duration"
        ;;
    *)
        /usr/bin/logger -t openvpn "openvpn.sh unexpected script type: $script_type"
        ;;
esac

exit 0
