#!/bin/sh

if [ -f /boot/quik-NOT_CONFIGURED.conf -a $# -lt 2 ]; then
	echo "Usage: install-quik.sh <boot device> <root device>"
	echo "Example: If /boot is on /dev/hda3 and / is /dev/hda4"
	echo "Run: install-quik.sh /dev/hda3 /dev/hda4"
	exit 1
elif [ -f /boot/quik.conf -a $# -lt 1 ]; then
	echo "Usage: install-quik.sh <boot device>"
	echo "Example: If /boot is on /dev/hda3"
	echo "Run: install-quik.sh /dev/hda3"
	exit 1
fi

# We need to pass the boot and root devices
BOOT_DEVICE=$1
ROOT_DEVICE=$2

# First, configure quik.conf for this particular machine
if [ -f /boot/quik-NOT_CONFIGURED.conf ]; then
	echo -ne "Configuring quik for the first time run... "
	/bin/sed -e "s,root=.*,root=$ROOT_DEVICE,g" \
		/boot/quik-NOT_CONFIGURED.conf > /boot/quik.conf
	rm -f /boot/quik-NOT_CONFIGURED.conf
	echo -ne "Done configuring quik.\n"
else
	echo -ne "quik already configured. "
	if [ $ROOT_DEVICE ]; then
		echo "Changing root device in /boot/quik.conf"
		/bin/sed -i "s,root=.*,root=$ROOT_DEVICE,g" /boot/quik.conf
	else
		echo "Leaving /boot/quik.conf alone."	
	fi
fi

# Now run quik
echo "Now running quik..."
/sbin/quik -v -C /boot/quik.conf
echo "Done."

# Set the boot-device on oldworld macs
echo -ne "Configuring Open Firmware for booting... "
/usr/sbin/nvsetenv boot-device `/usr/sbin/ofpath $BOOT_DEVICE`
/usr/sbin/nvsetenv boot-command "begin ['] boot catch 1000 ms cr again boot"
echo "Open Firmware configured."
echo -n "boot-device set to: "
/usr/sbin/nvsetenv boot-device
echo -n "boot-command set to: "
/usr/sbin/nvsetenv boot-command
echo "This machine should now be able to boot on its own."
