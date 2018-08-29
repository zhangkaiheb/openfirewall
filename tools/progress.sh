#!/bin/bash
#
############################################################################
#                                                                          #
# This file is part of the Openfirewall.                                 #
#                                                                          #
# Openfirewall is free software; you can redistribute it and/or modify            #
# it under the terms of the GNU General Public License as published by     #
# the Free Software Foundation; either version 2 of the License, or        #
# (at your option) any later version.                                      #
#                                                                          #
# Openfirewall is distributed in the hope that it will be useful,                 #
# but WITHOUT ANY WARRANTY; without even the implied warranty of           #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            #
# GNU General Public License for more details.                             #
#                                                                          #
# You should have received a copy of the GNU General Public License        #
# along with Openfirewall; if not, write to the Free Software                     #
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA #
#                                                                          #
############################################################################
#
# $Id: progress.sh 4101 2010-01-09 17:18:13Z owes $
#
#
# Started through make.sh to show progress indicator (second counter).
# Parameters:
#   filename        this file is created by make.sh and removed when build is 
#                   finished or aborted.
#
# Environment variables:
#   BOLD            magic to change to bold text
#   NORMAL          magic to change to normal text
#   SET_TIME_COL    column position for progress time
#   RESULT_COL      column position for build result
#

# Test for marker
BUILD_MARKER=$1
[[ -z ${BUILD_MARKER} ]] && exit
[[ ! -f ${BUILD_MARKER} ]] && exit

PKG_TIME_START=`date +%s`

# Wait a bit, if the marker is gone then there is nothing to be done
sleep 2.5
[[ ! -f ${BUILD_MARKER} ]] && exit


#
# Same as in make.sh
position_cursor()
{
    START=${1}
    STRING=${2}
    OFFSET=${3}

    STRING_LENGTH=${#STRING}

    if [ ${OFFSET} -lt 0 ]; then
    COL=$((${START} + ${OFFSET} - ${STRING_LENGTH}))
    else
    COL=$((${START} + ${OFFSET}))
    fi

    SET_COL="\\033[${COL}G"

    echo ${SET_COL}
} # End of position_cursor()


# Hide the cursor
echo -ne "\\033[?25l"

# Move the cursor to the results column
echo -ne "${SET_TIME_COL}[           ]"
echo -ne "\\033[11D"

while true ; do
    [ ! -f ${BUILD_MARKER} ] && echo -ne "\\033[?25h" && exit

    PKG_TIME_END=`date +%s`
    PKG_TIME=$[ ${PKG_TIME_END} - ${PKG_TIME_START} ]
    SET_TIME_COL_REAL=`position_cursor ${RESULT_COL} ${PKG_TIME} -3`
	echo -ne "${SET_TIME_COL}[ ${BOLD}${SET_TIME_COL_REAL}${PKG_TIME}${NORMAL} ]"
    echo -ne "\\033[11D" 2> /dev/null
    sleep 0.2
done

exit
