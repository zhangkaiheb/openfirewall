#!/bin/bash
#
# Build a list of PCI and USB identification codes for inclusion on the ipcop.org wiki
# https://sourceforge.net/p/ipcop/wiki/IPCopIDMapPCI/
# https://sourceforge.net/p/ipcop/wiki/IPCopIDMapUSB/
#
# Use this script at top level after full build with ./tools/prepareIDmap.sh
#
# $Id: make.sh 180 2007-04-15 03:26:52Z chepati $
# 


KVER=`grep --max-count=1 VER lfs/linux | awk '{ print $3 }' | tr -d '\n'; grep --max-count=1 IPCOPKRELEASE lfs/linux | awk '{ print $3 }'`
if [ -z $KVER ]; then
  echo "I'm confused (Kernel version not found), please run me from top level with ./tools/prepareIDmap.sh"
  exit 0
fi
MACHINE=''
for i in i486 alpha ppc sparc
do
  if [ -d "build_$i" ]; then
    MACHINE=$i
  fi
done

if [ -z $MACHINE ]; then
  echo "No build directory found, build IPCop first using: make.sh"
  exit 0
fi
echo "Preparing $MACHINE pci and usb maps for publication on the wiki"
if [ ! -s build_$MACHINE/ipcop/lib/modules ]; then
  echo "Module info not found, try rebuilding IPCop using: make.sh clean && make.sh build"
  exit 1
fi
if [ ! -s build_$MACHINE/ipcop/lib/modules/$KVER/modules.pcimap ]; then
  echo "PCI map not found for kernel $KVER, try rebuilding IPCop using: make.sh clean && make.sh build"
  exit 1
fi
if [ ! -s build_$MACHINE/ipcop/lib/modules/$KVER/modules.usbmap ]; then
  echo "USB map not found for kernel $KVER, try rebuilding IPCop using: make.sh clean && make.sh build"
  exit 1
fi


# suppress first line temporary and sort by module name, only output module and vendor+device ID
sed -e '/module/d' build_$MACHINE/ipcop/lib/modules/$KVER/modules.pcimap | sort | awk '{ printf "%s|%s|%s\n",$1,$2,$3 }' > doc/tmpmap1.txt

# add comment
echo "PCI id from $KVER compilation `date +'%Y-%m-%d'`" > doc/PCIidmap.txt
echo " "  >>  doc/PCIidmap.txt

# add table header
echo "pci module | vendor | device" >> doc/PCIidmap.txt
echo "----- | ----- | -----" >> doc/PCIidmap.txt

# add the list of modules
cat doc/tmpmap1.txt >> doc/PCIidmap.txt

echo "PCI map stored as doc/PCIidmap.txt"


# suppress first line temporary and sort by module name, only output module, flags and vendor+product ID
sed -e '/module/d' build_$MACHINE/ipcop/lib/modules/$KVER/modules.usbmap | sort | awk '{ printf "%s|%s|%s|%s\n",$1,$2,$3,$4 }' > doc/tmpmap1.txt

# add comment
echo "USB id from $KVER compilation `date +'%Y-%m-%d'`" > doc/USBidmap.txt
echo " "  >>  doc/USBidmap.txt

# add table header
echo "usb module | match_flags | idVendor | idProduct" >>  doc/USBidmap.txt
echo "----- | ----- | ----- | -----" >> doc/USBidmap.txt

# add the list of modules
cat doc/tmpmap1.txt >> doc/USBidmap.txt

echo "USB map stored as doc/USBidmap.txt"

# clean up
rm doc/tmpmap1.txt

