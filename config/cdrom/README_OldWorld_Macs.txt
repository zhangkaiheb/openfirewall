In the images directory of the cdrom there are a files you need to
copy to floppies in order to boot OldWorld macs. Do this:

dd if=boot.img of=/dev/fd0                  (this is the boot disk)
dd if=fdinitrd.gz of=/dev/fd0               (this is the root disk)
dd if=drivers1.img of=/dev/fd0              (this is the scsi disk)
dd if=drivers2.img of=/dev/fd0              (this is the net disk)

Note: if the boot.img floppy can't boot your machine, you'll need to
boot from Open Firmware.  There's a different boot image for that and
you prepare it like this:

dd if=bootofw.img of=/dev/fd0               (this is the OFW boot disk)

Then boot with the boot disk in the floppy drive.  You should see a
little penguin icon overlapping a mac.  After the kernel has been
loaded successfully, you'll be prompted to insert the root disk.
Linux kernels v2.6.x have a bug in the SWIM3 driver (the OldWorld floppy
controller) that prevents software eject of floppies.  Therefore the
floppy will not be automatically ejected for you and you'll need to
insert a paper clip in the manual eject hole to do it manually.  After
that insert the root floppy and press Enter.

If for some reason loading the boot disk fails (the computer freezes
or you get a red X over the penguin icon) you'll need to boot with the
alternative boot disk, bootofw.img.  Enter OpenFirmware
(press Command+Option+O+F when you hear the mac chime) and type:

boot fd:zImage
