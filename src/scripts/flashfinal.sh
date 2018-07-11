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
# $Id: flashfinal.sh 7626 2014-07-16 04:11:18Z owes $
#


if [ -f /etc/FLASH ]; then
    echo "This is already a FLASH'd IPCop."
    exit 1
fi


############################################################################
#                                                                          #
# Touching /etc/FLASH                                                      #
#                                                                          #
############################################################################
/usr/bin/touch /etc/FLASH


############################################################################
#                                                                          #
# Reconfiguring logrotate                                                  #
#                                                                          #
############################################################################
/bin/ln -sf /etc/logrotate.conf.FLASH /etc/logrotate.conf


############################################################################
#                                                                          #
# Rescue log, rrd, ulogd, /var/log will be in RAM disk                     #
# Normally this is not necessary since rc.flash.down will do this, but do  #
# this just in case of installation and/or abnormal shutdown               #
#                                                                          #
############################################################################
tar -czf /var/log_compressed/log.tgz --exclude=/var/log/cache/* /var/log/*


############################################################################
#                                                                          #
# Rescue fcrontab, /var/spool will be in RAM disk                          #
# Normally this is not necessary since rc.flash.down will do this, but do  #
# this just in case of installation and/or abnormal shutdown               #
#                                                                          #
############################################################################
tar -czf /var/log_compressed/spool.tgz -C /var/spool cron


############################################################################
#                                                                          #
# Configure apache to follow symlinks in /home/httpd/html                  #
#                                                                          #
############################################################################
if [ -z "`/bin/grep \"Options ExecCGI FollowSymlinks\" /etc/httpd/conf/httpd.conf`" ]; then
    sed -i -e s/"^\s*Options ExecCGI.*"/"    Options ExecCGI FollowSymlinks"/1 /etc/httpd/conf/httpd.conf
fi

