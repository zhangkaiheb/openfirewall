#!/bin/sh
#
# Note: this usb_modeswitch.sh script is different.
# The 'standard' one would start a TCL script.
# We (for now anyway) run the usb_modeswitch binary directly and depend on the /etc/usb_modeswitch.conf file.
#
# $Id: usb_modeswitch.sh 4111 2010-01-12 18:44:57Z owes $
#

/usr/bin/logger -t usb_modeswitch "Device: ${1}"
/usr/sbin/usb_modeswitch
