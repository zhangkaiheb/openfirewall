#!/bin/bash
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
# Copyright (c) 2009 The Openfirewall Team
#
# $Id: test-library.sh 3427 2009-08-13 09:31:32Z owes $
#


#
# Basic script to do some library.sh testing
#

. /usr/lib/ipcop/library.sh

# Test for library
if [ "x${LIBVERSION}" = "x" -o ${LIBVERSION} -lt 1 ]; then
    echo "Helper library not found or incorrect version (${LIBVERSION}), exiting."
    exit 1
fi


# Test for IPCop version
isversion 1.9.0 1.9.4 && echo "This is a pretty old, pre-test release stage version (${IPCOPVERSION})"
isversion 1.9.5 1.9.6 && echo "This is a test release stage version (${IPCOPVERSION})"


# Test for architecture
ismachine alpha && echo "Architecture Alpha"
ismachine i486  && echo "Architecture i486"
ismachine ppc   && echo "Architecture PowerPC"
ismachine sparc && echo "Architecture Sparc"


# Language files
#addtolanguage MyAddon en,de,es,fr,it subdir
#removefromlanguage MyAddon

# Add stuff to end of file
echo "######"  > test.full
echo "test 1" >> test.full
echo "test 2" >> test.full
echo "test tail" > test.tail
addtofiletail MyAddon test.tail test.full
cat test.full

removefromfile MyAddon test.full
cat test.full

# Add stuff in the middle of file
echo "test position" > test.position
addtofile MyAddon test.position test.full "test 1"
cat test.full

rm test.full test.tail test.position

# Test CGI addition
touch /tmp/test.cgi
addcgi /tmp/test.cgi
ls -l /home/httpd/cgi-bin/test.cgi

# And removal
removecgi test.cgi
ls -l /home/httpd/cgi-bin/test.cgi
rm /tmp/test.cgi
