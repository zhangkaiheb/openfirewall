#!/bin/bash
# vim: set columns=120 noexpandtab:
#
#########################################################################################################
#
# This file is part of the OpenFirewall.
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
# Copyright (C) 2001 Mark Wormgoor <mark@wormgoor.com>.
#
# (c) 2001 Eric S. Johansson <esj@harvee.billerica.ma.us> Check for Bash
# (c) 2002 Thorsten Fischer <frosch@cs.tu-berlin.de> MD5Sum checking
#
#########################################################################################################
#
# $Id: make.sh 8084 2016-01-22 08:05:55Z owes $
#
#########################################################################################################




#########################################################################################################
#########################################################################################################
# BLOCK 1 -- Variables											#
#########################################################################################################
#########################################################################################################


#########################################################################################################
# Some important variables -- these are not customizable						#
#########################################################################################################

# The official project name
NAME="Openfirewall"

# Just a short name for Openfirewall
SNAME="openfirewall"

# This is the Openfirewall version number for the release.
VERSION=2.2.0

# VERSIONSTEP is only used when the update is split into 2 versions/packages.
#VERSIONSTEP=2.1.0

# This is the last official Openfirewall version number. Needed for ./make.sh newupdate.
PREVIOUSVERSION=2.1.9
# This is the SVN revision number for the last Openfirewall version. Needed for ChangeLog.
PREVIOUSSVNREV=7814

# Just an arbitrary name for the downloadable, prebuilt toolchain (if you want to save time compiling).
TOOLCHAINVERSION=2.1.4

# A collection of all the external software needed to build, install, and run openfirewall.  This is for GPL compliance.
OTHERSRC=${SNAME}-${VERSION}-othersrc.tar.bz2

# The official Openfireall slogan
SLOGAN="The Bad Packets Stop Here"

# Where the openfireall specific config files will be installed (this is the path on a running openfirewall system)
CONFIG_ROOT=/var/ofw

# What's the kernel version we're building (this is not the host kernel)
KVER=`grep --max-count=1 VER lfs/linux | awk '{ print $3 }' | tr -d '\n'; grep --max-count=1 OFW_KRELEASE lfs/linux | awk '{ print $3 }'`

# Get Perl version
PERLVER=`grep --max-count=1 VER lfs/perl | awk '{ print $3 }'  | tr -d '\n'`

# Let's see what's our host architecture
MACHINE=`uname -m`

# Debian specific settings
if [ ! -e /etc/debian_version ]; then
	FULLPATH=`which ${0}`
else
	if [ -x /usr/bin/realpath ]; then
		FULLPATH=`/usr/bin/realpath ${0}`
	else
		echo "ERROR: Need to do apt-get install realpath"
		exit 1
	fi
fi

# This is just a temporary variable to help us decide what our current working directory is
BASENAME=`basename ${0}`

# The directory where make.sh is.  Needed by every script
BASEDIR=`echo ${FULLPATH} | sed "s/\/${BASENAME}//g"`
export BASEDIR

# This is used to test source file download on the web with ./make.sh check (erase tags with ./make.sh checkclean)
DIR_CHK=${BASEDIR}/cache/check

# This is an optional .config file with variables overriding the default values
OFW_CONFIG=${BASEDIR}/.config

# Set up INSTALLER_DIR
INSTALLER_DIR=installer

# Not running tests suite after each package compilation by default
RUNNING_TEST='no'

# To compile a package more than once in the same stage
# and send PASS value to both the log file and lfs makefile
# Has to be reset after usage or next log will have a wrong name
PASS=""

# This is the LFS branch we're following for check_versions.
# Can be either stable or development
#LFS_BRANCH=stable
LFS_BRANCH=development

# This is the URL that lists the versions of packages for the LFS branch we are using as the basis for Openfirewall
LFS_PACKAGES_URL=http://www.linuxfromscratch.org/lfs/view/${LFS_BRANCH}/chapter03/packages.html

# HOST SYSTEM REQUIREMENTS
# Openfirewall-2.0 is based on LFS-8.0.
# Check http://www.linuxfromscratch.org/lfs/view/stable/prologue/hostreqs.html for a list of
# host system requirements.  The values below are based on LFS-6.3

# If you absolutely know what you're doing and want to ignore the prerequisites, set this variable to "yes"
# OVERRIDING THIS IS STRONGLY DISCOURAGED
IGNORE_PREREQUISITES=no

# NOTE!!!
# When building toolchain and base we require at least kernel 2.6.5.
# Nobody should be using a really really old kernel: http://lkml.org/lkml/2007/11/14/6
# The benefit (size and compile time) of increasing kernel compatiblity is small.
# A glibc compiled with --enable-kernel=2.6.5 is very unlikely to run on a system with kernel < 2.6.5
# If you have a kernel that is older than REQUIRED_KERNEL below, upgrade now!
##REQUIRED_BASH=2.05a
REQUIRED_BASH=3.2
##REQUIRED_BINUTILS=2.12
REQUIRED_BINUTILS=2.17
##REQUIRED_BISON=1.875
REQUIRED_BISON=2.3
##REQUIRED_BZIP2=1.0.2
REQUIRED_BZIP2=1.0.4
##REQUIRED_COREUTILS=5.0
REQUIRED_COREUTILS=6.9
##REQUIRED_DIFFUTILS=2.8
REQUIRED_DIFFUTILS=2.8.1
##REQUIRED_FINDUTILS=4.1.20
REQUIRED_FINDUTILS=4.2.31
##REQUIRED_GAWK=3.1.5
REQUIRED_GAWK=4.0.1
##REQUIRED_GCC=3.0.1
REQUIRED_GCC=4.7
##REQUIRED_GLIBC=2.2.5
REQUIRED_GLIBC=2.11
##REQUIRED_GREP=2.5
REQUIRED_GREP=2.5.1a
##REQUIRED_GZIP=1.2.4
REQUIRED_GZIP=1.3.12
#REQUIRED_KERNEL=2.6.5
REQUIRED_KERNEL=3.2
##REQUIRED_MAKE=3.79.1
REQUIRED_MAKE=3.81
REQUIRED_PATCH=2.5.4
##REQUIRED_SED=3.0.2
REQUIRED_SED=4.1.5
##REQUIRED_TAR=1.14
REQUIRED_TAR=1.22
REQUIRED_TEXINFO=4.8
# END OF HOST SYSTEM REQUIREMENTS

# This array holds the names of all customizable variables
declare -a CUSTOMIZABLE_VARIABLES

# Store 'now' in YYYYMMDD-HHMMSS and in seconds since 1970 format
BUILDDATE=`date +"%Y%m%d-%H%M%S"`
BUILDSTART=`date +"%s"`

#########################################################################################################
# End of important non-customizable variables								#
#########################################################################################################


#########################################################################################################
# The following variables can be customized on .config to fit your preferences				#
#########################################################################################################
END=no
COUNTER=0
until [ x"${END}" == x"yes" ];
do
	# How nice should we be?
	NICE=10 && CUSTOMIZABLE_VARIABLES[${COUNTER}]="NICE" && COUNTER=$[ ${COUNTER} + 1 ]

	# How many concurrent jobs to run (NOTE: Don't use too high a value, or packages may have timing issues.
	# At least openssh fails if this is too high.  It's safe to set this to number of CPUs + 1)
	PARALLELISM=3 && CUSTOMIZABLE_VARIABLES[${COUNTER}]="PARALLELISM" && COUNTER=$[ ${COUNTER} + 1 ]

	# How many times should prefetch try to download a package. Don't set to too high a value and hammer sites
	MAX_RETRIES=3 && CUSTOMIZABLE_VARIABLES[${COUNTER}]="MAX_RETRIES" && COUNTER=$[ ${COUNTER} + 1 ]

	# Make distcc optional, by default don't use it.  Override this in .config
	USE_DISTCC=no && CUSTOMIZABLE_VARIABLES[${COUNTER}]="USE_DISTCC" && COUNTER=$[ ${COUNTER} + 1 ]

	# To what servers should distcc distribute the load
	DISTCC_HOSTS=localhost && CUSTOMIZABLE_VARIABLES[${COUNTER}]="DISTCC_HOSTS" && COUNTER=$[ ${COUNTER} + 1 ]

	# Should we skip creation of USB images
	SKIP_USB_IMAGES=yes && CUSTOMIZABLE_VARIABLES[${COUNTER}]="SKIP_USB_IMAGES" && COUNTER=$[ ${COUNTER} + 1 ]

	# Should we skip creation of floppy images
	SKIP_FLOPPY_IMAGES=yes && CUSTOMIZABLE_VARIABLES[${COUNTER}]="SKIP_FLOPPY_IMAGES" && COUNTER=$[ ${COUNTER} + 1 ]

	# Should we skip creation of package with avm drivers
	SKIP_AVM_DRIVERS=yes && CUSTOMIZABLE_VARIABLES[${COUNTER}]="SKIP_AVM_DRIVERS" && COUNTER=$[ ${COUNTER} + 1 ]

	# If you *absolutely* want to build openfirewall as root, override this in .config. STRONGLY DISCOURAGED
	ALLOW_ROOT_TO_BUILD=no && CUSTOMIZABLE_VARIABLES[${COUNTER}]="ALLOW_ROOT_TO_BUILD" && COUNTER=$[ ${COUNTER} +1 ]

	# A timeout variable (in seconds) for when we need user input within a specified amount of time
	TIMEOUT=5 && CUSTOMIZABLE_VARIABLES[${COUNTER}]="TIMEOUT" && COUNTER=$[ ${COUNTER} +1 ]

	# Should make.sh show you a nice progress meter
	SHOW_PROGRESS=no && CUSTOMIZABLE_VARIABLES[${COUNTER}]="SHOW_PROGRESS" && COUNTER=$[ ${COUNTER} +1 ]

	# Some brave soul might want to skip the test for available diskspace
	SKIP_CHECK_DISKSPACE=no && CUSTOMIZABLE_VARIABLES[${COUNTER}]="SKIP_CHECK_DISKSPACE" && COUNTER=$[ ${COUNTER} +1 ]

	# Build for debugging, includes gdb
	DEBUGGING=no && CUSTOMIZABLE_VARIABLES[${COUNTER}]="DEBUGGING" && COUNTER=$[ ${COUNTER} +1 ]

	# Add new variables before this line
	END=yes
done
unset COUNTER
unset END

#########################################################################################################
# End of customizable variables										#
#########################################################################################################


#########################################################################################################
# Beautifying variables & presentation & input/output interface						#
#########################################################################################################

## Screen dimensions
# Find current screen size
if [ -z "${COLUMNS}" ]; then
	COLUMNS=$(stty size)
	COLUMNS=${COLUMNS##* }
fi

# When using remote connections, such as a serial port, stty size returns 0
if [ "${COLUMNS}" = "0" ]; then
	COLUMNS=80
fi

## Measurements for positioning result messages
RESULT_WIDTH=4
WGET_WIDTH=4
ARCH_WIDTH=5
FOUND_WIDTH=9
REQUIRED_WIDTH=10
TIME_WIDTH=9
OPT_WIDTH=11 # to display 1.9.18 on update
VER_WIDTH=10

RESULT_COL=$((${COLUMNS} - ${RESULT_WIDTH} - 4))
WGET_COL=$((${RESULT_COL} - ${WGET_WIDTH} - 5))
ARCH_COL=$((${WGET_COL} - ${ARCH_WIDTH} - 5))
FOUND_COL=$((${RESULT_COL} - ${FOUND_WIDTH} - 5))
REQUIRED_COL=$((${FOUND_COL} - ${REQUIRED_WIDTH} - 5))
TIME_COL=$((${RESULT_COL} - ${TIME_WIDTH} - 5))
VER_COL=$((${TIME_COL} - ${VER_WIDTH} - 5))
OPT_COL=$((${VER_COL} - ${OPT_WIDTH} - 5))

## Set Cursor Position Commands, used via echo -e
SET_RESULT_COL="\\033[${RESULT_COL}G"
SET_WGET_COL="\\033[${WGET_COL}G"
SET_ARCH_COL="\\033[${ARCH_COL}G"
SET_FOUND_COL="\\033[${FOUND_COL}G"
SET_REQUIRED_COL="\\033[${REQUIRED_COL}G"
SET_TIME_COL="\\033[${TIME_COL}G"
SET_OPT_COL="\\033[${OPT_COL}G"
SET_VER_COL="\\033[${VER_COL}G"

# Define color for messages
BOLD="\\033[1;39m"
DONE="\\033[0;32m"
SKIP="\\033[0;34m"
WARN="\\033[0;35m"
FAIL="\\033[0;31m"
NORMAL="\\033[0;39m"
STOP="\\033[0;33m"
INFO="\\033[0;36m"

#########################################################################################################
# End of beautifying variables & presentation & input/output interface					#
#########################################################################################################


#########################################################################################################
# Now that .config is optional, set the toolchain variables here so they				#
# are available globally										#
# THESE ARE EXTREMELY IMPORTANT VARIABLES.								#
#########################################################################################################

# MACHINE is the target for userspace, so 32b (except alpha wich know only 64b world)
# MACHINE_REAL is the target for kernel compilation
# If MACHINE != MACHINE_REAL, gcc-x-cross-compile is build.
# Currently sparc64 and ppc64 use gcc -m64 to compile the kernel

###LDFLAGS="-Wl,--hash-style=gnu" # may try later adding -Wl,-O1 but that may make the code larger

# Toolchain is different on 32 vs 64-bits build

case ${MACHINE} in
	i?86)
#		MACHINE=i486
		MACHINE=x86
		MACHINE_REAL=${MACHINE}
		# lfs is just something different than (pc|unknow) to force cross-compilation on the first pass
		# i486 is different from i586,i686
		LFS_TGT=${MACHINE}-lfs-linux-gnu	# for pass 1 cross-compilation
		TARGET_2=${MACHINE}-linux-gnu		# for pass 2
		LINKER=/lib/ld-linux.so.2
		CFLAGS="-Os -march=${MACHINE} -mtune=pentium -pipe -fomit-frame-pointer"
		;;
	x86_64)
		MACHINE_REAL=${MACHINE}
##		MACHINE=x86_64
		LFS_TGT=${MACHINE}-lfs-linux-gnu
		TARGET_2=${MACHINE}-ofw-linux-gnu
#		WRAPPER_32BIT=linux32
#		LINKER=/lib/ld-linux.so.2
		LINKER=/lib64/ld-linux-x86-64.so.2
#		CFLAGS="-Os -march=${MACHINE} -mtune=pentium -pipe -fomit-frame-pointer"
#		CFLAGS="-Os -march=x86-64 -pipe -fomit-frame-pointer"
		;;
	alpha)
		MACHINE_REAL=${MACHINE}
		LFS_TGT=${MACHINE}-lfs-linux-gnu
		TARGET_2=${MACHINE}-linux-gnu
		LINKER=/lib/ld-linux.so.2
		CFLAGS="-O2 -march=ev4 -mtune=ev56 -mieee -pipe"
		;;
	sparc|sparc64)
		MACHINE_REAL=${MACHINE}
		MACHINE=sparc
		# force a 32-bits build
		LFS_TGT=${MACHINE}-lfs-linux-gnu
		TARGET_2=${MACHINE}-linux-gnu
		WRAPPER_32BIT=linux32
		LINKER=/lib/ld-linux.so.2
		CFLAGS="-O2 -pipe -mcpu=ultrasparc -mtune=ultrasparc"
		;;
	ppc|ppc64)
		MACHINE_REAL=${MACHINE}
		MACHINE=ppc
		# ppc is different from powerpc
		LFS_TGT=powerpc-lfs-linux-gnu
		TARGET_2=powerpc-linux-gnu
		WRAPPER_32BIT=linux32
		LINKER=/lib/ld.so.1
		CFLAGS="-O2 -pipe"
		;;
	*)
		echo -ne "${FAIL}Can't determine your architecture - ${MACHINE}${NORMAL}\n"
		exit 1
		;;
esac

# Preliminary logs are send there
PREPLOGFILE=${BASEDIR}/log_${MACHINE}/_build_00_preparation.log

# find last failing log always at the same place
LATEST=log_${MACHINE}/_latest_interrupt.log

# Set up what is /tools on LFS
TOOLS_DIR=tools_${MACHINE}

##CCACHE=${BASEDIR}/build_${MACHINE}/${TOOLS_DIR}/usr/bin/ccache
##export CCACHE_DIR=${BASEDIR}/ccache
##export CCACHE_HASHDIR=1

##if [ x"${USE_DISTCC}" == x"yes" -a ! -z "${DISTCC_HOSTS}" ]; then
##	export CCACHE_PREFIX="distcc"
##	export DISTCC_DIR=${BASEDIR}/distcc
##fi

# This is the directory that holds the newly built openfirewall system
LFS=${BASEDIR}/build_${MACHINE}/ofw

# For toolchain LFS chap5
# /${TOOLS_DIR}/usr/bin is for ccache symlink
##PATH_CH5=/${TOOLS_DIR}/usr/bin:/${TOOLS_DIR}/bin:${PATH}
PATH_CH5=/${TOOLS_DIR}/bin:/bin:/usr/bin
# For LFS chap 6 and later
##PATH_CH6=/${TOOLS_DIR}/usr/bin:/bin:/usr/bin:/sbin:/usr/sbin:/${TOOLS_DIR}/bin
PATH_CH6=/bin:/usr/bin:/sbin:/usr/sbin:/${TOOLS_DIR}/bin

# Save the original PATH to a temporary variable.  We reset the PATH for the next few commands, just in case
ORG_PATH=${PATH}

# On some systems /sbin and /usr/sbin are not in non-root users' PATH.  Use a temporary PATH to include them
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

# Give the right error if /dev/null is broken instead of failing many test later.
echo dummy > /dev/null || exiterror "/dev/null is broken"

# Find out the location of some programs. /etc/sudoers needs an absolute path to the executable for which
# users are granted access (ie you can't type mount, you have to type /bin/mount)
# We use bash's type as which may not be available
# Don't allow bash to use hashing for the commands, or this might not work
CHMOD=`bash +h -c "type -p chmod"`
CHROOT=`bash +h -c "type -p chroot"`
DU=`bash +h -c "type -p du"`
LN="`bash +h -c "type -p ln"` -sf"
LOSETUP=`bash +h -c "type -p losetup"`
MKDIR="`bash +h -c "type -p mkdir"` -p"
MKNOD=`bash +h -c "type -p mknod"`
MOUNT=`bash +h -c "type -p mount"`
BIND="${MOUNT} --bind"
MV=`bash +h -c "type -p mv"`
NICECMD=`bash +h -c "type -p nice"`
RM="`bash +h -c "type -p rm"` -fr"
UMOUNT=`bash +h -c "type -p umount"`

# Just to warn on SElinux enabled host
GETENFORCE=`bash +h -c "type -p getenforce"`

# Who's running this script?
CURRENT_USER=`id -un`
CURRENT_USER_GROUP=`id -gn`

# Find where sudo is if we're doing a non-root build
if [ x"${CURRENT_USER}" != x"root" ]; then
	# Do we have sudo?
	SUDO=`bash +h -c "type -p sudo"`
else
	SUDO=
fi

# Reset PATH to the original
export PATH=${ORG_PATH}

# include machine in TOOLCHAINNAME
TOOLCHAINNAME=${SNAME}-${TOOLCHAINVERSION}-toolchain-${MACHINE_REAL}.tar.gz

#################################################################################
# Make sure the log directory exists						#
#################################################################################
${MKDIR} $BASEDIR/log_${MACHINE}

# Remove previous log before writing into again
# Those are totaly remade at each build, so don't accumulate
# (files are user-owned, so no need to wait directories are mounted to be able to use SUDO RM)
rm -f ${PREPLOGFILE} ${BASEDIR}/${LATEST}
rm -f ${BASEDIR}/log_${MACHINE}/0*/fix-up-svn-*
rm -f ${BASEDIR}/log_${MACHINE}/05_packages/*
rm -f ${BASEDIR}/log_${MACHINE}/_build_06_othersrc-list.log

#########################################################################################################
# Ok, now's your chance to override any of the "customizable" variables					#
#													#
# NO MORE VARIABLE OVERRIDING BELOW THIS LINE								#
#########################################################################################################
if [ -e ${OFW_CONFIG} ]; then
	echo -ne "${BOLD}*** Openfirewall build .config found. Parsing ...${NORMAL}\n"

	# Now write the list of overwritten variables
	echo "=== LIST OF OVERWRITTEN VARIABLES ===" >> ${PREPLOGFILE}

	ORG_IFS=${IFS}
	IFS=$'\n'

	# Take care of garbage
	sed -i "s@^ .*@#& ## DISABLED by make.sh@g" ${OFW_CONFIG}

	for LINE in `grep -v '^#' ${OFW_CONFIG}`
	do
		VARIABLE=`echo "${LINE}" | cut -d= -f 1`
		VALUE=`echo "${LINE}" | cut -d= -f 2-`

		if [ -z $(eval echo "\${${VARIABLE}}") ]; then
			echo -ne "*** ${WARN}Ignoring invalid variable ${VARIABLE} and disabling in .config\n"
			sed -i "s@^.*${VARIABLE}.*@#& ## DISABLED by make.sh@g" ${OFW_CONFIG}
		elif echo ${CUSTOMIZABLE_VARIABLES[*]} | grep -qEi "${VARIABLE}"; then
			echo -ne "*** Setting ${BOLD}${VARIABLE}${NORMAL} to '${BOLD}${VALUE}${NORMAL}'\n"

			if [ x"${VARIABLE}" == x"PARALLELISM" ]; then
				if [ ${VALUE} -gt ${PARALLELISM} ]; then
					echo -ne "*** ${WARN}Setting PARALLELISM too high "
					echo -ne "may break the build${NORMAL}\n"
				fi
			fi

			export `eval echo ${VARIABLE}`=${VALUE}

			echo -ne "Variable ${VARIABLE} was overwritten and is now ${VALUE}\n" >> ${PREPLOGFILE}

		else
			echo -ne "*** ${WARN}Skipping non-customizable variable ${VARIABLE} and disabling in .config\n"
			sed -i "s@^.*${VARIABLE}.*@#& ## DISABLED by make.sh@g" ${OFW_CONFIG}
		fi
	done
	IFS=${ORG_IFS}
	echo "=== END OF LIST OF OVERWRITTEN VARIABLES ===" >> ${PREPLOGFILE}

	echo -ne "${BOLD}*** Done parsing .config${NORMAL}\n"
else
	echo -ne "${BOLD}*** Openfirewall build .config not found. Using defaults${NORMAL}\n"
fi

#########################################################################################################
# NO MORE VARIABLE OVERRIDING BELOW THIS LINE								#
#########################################################################################################

#########################################################################################################
#########################################################################################################
# End of BLOCK 1 -- Variables										#
#########################################################################################################
#########################################################################################################




#########################################################################################################
#########################################################################################################
# BLOCK 2 -- Functions											#
#########################################################################################################
#########################################################################################################

#########################################################################################################
# This is the function that helps beautify() do its job							#
#########################################################################################################
position_cursor()
{
	# ARG1=starting position on screen
	# ARG2=string to be printed
	# ARG3=offset, negative for left movement, positive for right movement, relative to ARG1
	# For example if your starting position is column 50 and you want to print Hello three columns to the right
	# of your starting position, your call will look like this:
	# position_cursor 50 "Hello" 3 (you'll get the string Hello at position 53 (= 50 + 3)
	# If on the other hand you want your string "Hello" to end three columns to the left of position 50,
	# your call will look like this:
	# position_cursor 50 "Hello" -3 (you'll get the string Hello at position 42 (= 50 - 5 -3)
	# If you want to start printing at the exact starting location, use offset 0

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



#########################################################################################################
# This is the function that makes the build process output pretty					#
#########################################################################################################
beautify()
{
	# Commands: build_stage, make_pkg, message, result
	case "${1}" in
		message)
			local SET_COL
			local MESSAGE
			if [ "${3}" -a x"${3}" == x"wget" ]; then
				local SET_COL=${SET_WGET_COL}
				MESSAGE=
			else
				local SET_COL=${SET_RESULT_COL}
				MESSAGE="${3}"
			fi

			case "${2}" in
				DONE)
					echo -ne "${BOLD}${MESSAGE}${NORMAL}${SET_COL}[${DONE} DONE ${NORMAL}]"
					;;
				WARN)
					echo -ne "${WARN}${MESSAGE}${NORMAL}${SET_COL}[${WARN} WARN ${NORMAL}]"
					;;
				FAIL)
					echo -ne "${BOLD}${MESSAGE}${NORMAL}${SET_COL}[${FAIL} FAIL ${NORMAL}]"
					;;
				SKIP)
					echo -ne "${BOLD}${MESSAGE}${NORMAL}${SET_COL}[${SKIP} SKIP ${NORMAL}]"
					;;
				STOP)
					echo -ne "${BOLD}${MESSAGE}${NORMAL}${SET_COL}[${STOP} STOP ${NORMAL}]"
					;;
				INFO)
					echo -ne "${INFO}${MESSAGE}${NORMAL}${SET_COL}[${INFO} INFO ${NORMAL}]"
					;;
				ARCH)
					SET_ARCH_COL_REAL=`position_cursor ${WGET_COL} ${3} -3`
					echo -ne "${SET_ARCH_COL}[ ${BOLD}${SET_ARCH_COL_REAL}${3}${NORMAL} ]"
					;;
			esac

			if [ x"${3}" != x"wget" -a x"${2}" != x"ARCH" ]; then
				echo -ne "\n"
			fi
			;;
		build_stage)
			MESSAGE=${2}
			echo -ne "${BOLD}*** ${MESSAGE}${SET_OPT_COL} options${SET_VER_COL}    version"
			echo -ne "${SET_TIME_COL} time (sec)${SET_RESULT_COL} status${NORMAL}\n"
			;;
		make_pkg)
			echo "${2}" | while read PKG_VER_SHORT PROGRAM
			do
				OPTIONS=""
				[ -n "${PASS}" ] && OPTIONS="PASS=${PASS}"
				SET_VER_COL_REAL=`position_cursor ${TIME_COL} ${PKG_VER_SHORT} -3`

				if [ x"${OPTIONS}" == x"" ]; then
					echo -ne "${PROGRAM}${SET_VER_COL}[ ${BOLD}${SET_VER_COL_REAL}${PKG_VER_SHORT}"
					echo -ne "${NORMAL} ]"
				else
					echo -ne "${PROGRAM}${SET_OPT_COL}[ ${BOLD}${OPTIONS}${NORMAL} ]"
					echo -ne "${SET_VER_COL}[ ${BOLD}${SET_VER_COL_REAL}${PKG_VER_SHORT}"
					echo -ne "${NORMAL} ]${SET_RESULT_COL}"
				fi
			done
			;;
		result)
			RESULT=${2}

			if [ ! ${3} ]; then
				PKG_TIME=0
			else
				PKG_TIME=${3}
			fi

			local PROGRAM=${4}
			local VERSION=${5}
			local STAGE_ORDER=${6}
			local STAGE=${7}

			SET_TIME_COL_REAL=`position_cursor ${RESULT_COL} ${PKG_TIME} -3`
			case "${RESULT}" in
				DONE)
					echo -ne "${SET_TIME_COL}[ ${BOLD}${SET_TIME_COL_REAL}$PKG_TIME${NORMAL} ]"
					echo -ne "${SET_RESULT_COL}[${DONE} DONE ${NORMAL}]\n"
					;;
				FAIL)
					echo -ne "${SET_TIME_COL}[ ${BOLD}${SET_TIME_COL_REAL}$PKG_TIME${NORMAL} ]"
					echo -ne "${SET_RESULT_COL}[${FAIL} FAIL ${NORMAL}]\n"
					;;
				SKIP)
					echo -ne "${SET_TIME_COL}[ ${BOLD}${SET_TIME_COL_REAL}$PKG_TIME${NORMAL} ]"
					echo -ne "${SET_RESULT_COL}[${SKIP} SKIP ${NORMAL}]\n"
					;;
				PENDING)
					echo -ne "${SET_TIME_COL}[ ${BOLD}${SET_TIME_COL_REAL}$PKG_TIME${NORMAL} ]"
					;;
			esac
			;;
	esac
} # End of beautify()



#########################################################################################################
# This is the function that checks for required version of a prerequisite				#
#########################################################################################################
check_version()
{
	local PKG_NAME="${1}"
	local REAL_REQUIRED="${2}"
	local REAL_FOUND="${3}"
	local REQUIRED=`echo "${REAL_REQUIRED}" | sed "s,\.,DOT,g" | tr '[:punct:]' '-' | sed "s,DOT,.,g" | tr -d '[:alpha:]' | cut -d"-" -f1`
	local FOUND=`echo "${REAL_FOUND}" | sed "s,\.,DOT,g" | tr '[:punct:]' '-' | sed "s,DOT,.,g" | tr -d '[:alpha:]' | cut -d"-" -f1`
	local FAILURE=0
	local i

	echo -ne "Checking for ${PKG_NAME}" | tee -a ${PREPLOGFILE}

	for i in `seq 1 4`; do
		if [ 0`echo ${FOUND} | cut -d"." -f ${i}` -gt 0`echo ${REQUIRED} | cut -d"." -f ${i}` ]; then
			FAILURE=0
			break
		elif [ 0`echo ${FOUND} | cut -d"." -f ${i}` -eq 0`echo ${REQUIRED} | cut -d"." -f ${i}` ]; then
			FAILURE=0
		else
			FAILURE=1
			break
		fi
	done

	SET_REQUIRED_COL_REAL=`position_cursor ${FOUND_COL} ${REAL_REQUIRED} -3`
	SET_FOUND_COL_REAL=`position_cursor ${RESULT_COL} ${REAL_FOUND} -3`

	echo -ne "${SET_REQUIRED_COL}[ ${BOLD}${SET_REQUIRED_COL_REAL}${REAL_REQUIRED}${NORMAL} ]"
	echo -ne "${SET_FOUND_COL}[ ${BOLD}${SET_FOUND_COL_REAL}${REAL_FOUND}${NORMAL} ]"

	if [ ${FAILURE} -eq 0 ]; then
		beautify message DONE
	else
		beautify message FAIL
	fi

	return ${FAILURE}
} # End of check_version()



#########################################################################################################
# Return the version number of a package inside PKG_VER, PKG_VER_SHORT variables			#
#########################################################################################################
get_pkg_ver()
{
	if grep -q "^PATCHLEVEL" ${1} ; then
		PKG_VER=`grep ^PATCHLEVEL ${1} | awk '{print $3}'`
	else
		PKG_VER=`grep ^VER ${1} | awk '{print $3}'`
	fi

	if [ -z ${PKG_VER} ]; then
		PKG_VER="svn-$(grep "# \$Id:" ${1} | awk '{print $4}')"
	fi

	# PKG_VER is full lenght string when PKG_VER_SHORT is VER_WIDTH limited
	PKG_VER_SHORT=$PKG_VER
	if [ ${#PKG_VER_SHORT} -gt ${VER_WIDTH} ]; then
		# If a package version number is greater than ${VER_WIDTH}, we keep the first 4 characters
		# and replace enough characters to fit the resulting string on the screen.  We'll replace
		# the extra character with .. (two dots).  That's why the "+ 2" in the formula below.
		# Example: if we have a 21-long version number that we want to fit into a 10-long space,
		# we have to remove 11 characters.  But if we replace 11 characters with 2 characters, we'll
		# end up with a 12-character long string.  That's why we replace 12 characters with ..
		REMOVE=`expr substr "${PKG_VER_SHORT}" 4 $[ ${#PKG_VER_SHORT} - ${VER_WIDTH} + 2 ]`
		PKG_VER_SHORT=`echo ${PKG_VER_SHORT/${REMOVE}/..}`
	fi
} # End of get_pkg_ver()



#########################################################################################################
# This is the function that unmounts all directories needed for the build				#
#########################################################################################################
stdumount()
{
	# First find and unmount any loop-mounted filesystems
	${MOUNT} | grep ".*${BASEDIR}.*loop.*" | sed 's/^.* on \(.[^ ]*\).*loop=\(.*\))/\1 \2/' \
	| while read MOUNT_POINT DEVICE
	do
		${SUDO} ${UMOUNT} ${MOUNT_POINT} > /dev/null 2>&1
		${SUDO} ${LOSETUP} -d ${DEVICE} > /dev/null 2>&1
	done

	# Umount /dev/pts and /dev/shm before /dev, test if mounted as ./make.sh clean doesn't mount.
	${MOUNT} | grep -q ${LFS}/dev/pts && ${SUDO} ${UMOUNT} ${LFS}/dev/pts
	# Find nothing mounted if /dev/shm is a symlink to /run/shm
	${MOUNT} | grep -q ${LFS}/dev/shm && ${SUDO} ${UMOUNT} ${LFS}/dev/shm
	# Debian v7 symlink /dev/shm to /run/shm, assume another mounted shm than the first was by us.
	[ $(${MOUNT} | grep /run/shm | wc -l) -gt 1 ] && ${SUDO} ${UMOUNT} /run/shm

	# Now find and unmount any of the bound filesystems we need for the build
	for i in `${MOUNT} | grep ${BASEDIR} | sed 's/^.* on \(.[^ ]*\).*$/\1/'`
	do
		${SUDO} ${UMOUNT} ${i} > /dev/null 2>&1

		# If the unmount command failed, give it 3 more chances, 5 seconds apart
		# This is necessary if a child process is keeping a bound filesystem busy
		if [ ${?} -ne 0 ]; then

			# Print the next warning message on a new line
			echo -ne "\n"
			beautify message WARN "Retrying to unmount ${i}"

			for SEQ in `seq 1 3`
			do
				sleep 5
				echo -ne "[ Attempt ${SEQ} ]"
				${SUDO} ${UMOUNT} ${i} > /dev/null 2>&1

				if [ ${?} -eq 0 ]; then
					beautify message DONE
					break
				else
					beautify message FAIL
				fi
			done
		fi
	done

	# If after all our attempts to unmount we still fail, quit, but show a failure message
	if ${MOUNT} | grep ${BASEDIR} > /dev/null 2>&1; then
		beautify message FAIL "Some bound filesystems could not be unmounted. Unmount them manually"
		${MOUNT} | grep ${BASEDIR} | sed 's/^.* on \(.[^ ]*\).*$/\1/' | sort | uniq
		return 1
	fi
} # End of stdumount()



#########################################################################################################
# This is the function that gracefully ends the build process						#
#########################################################################################################
exiterror()
{
	#
	${RM} ${BASEDIR}/log_${MACHINE}/_marker_*

	if echo "$*" | grep -qi interrupted; then
		beautify message STOP
	fi
	beautify message FAIL "\n${FAIL}ERROR${NORMAL}: ${BOLD}$*${NORMAL}"

	[ "${RUNNING_TEST}" == 'yes' ] && parse_tests

	# we may recompiling and don't know when LOGFILE exist if we are writing there
	if [ -z ${LOGFILE} ]; then
		# stop before compilation : prequisite, download, md5
		echo -ne "Check ${PREPLOGFILE} for errors if applicable"
	else
		# stop during compilation
		cp ${LOGFILE} ${BASEDIR}/${LATEST}
		echo -ne "Check ${LATEST} for errors if applicable"
	fi

	# In case of an abnormal ending, make sure the cursor is visible
	echo -ne "\\033[?25h\n"

	# Then unmount everything
	stdumount

	exit 1
} # End of exiterror()



###############################################################################################################
# This is the function that makes sure our build environment meets the requirements for building openfirewall #
###############################################################################################################
check_build_env()
{
	echo -ne "${BOLD}*** Checking for host prerequisites${NORMAL}\n"

	#################################################################################
	# Are we running the right shell?						#
	#################################################################################
	echo -ne "Checking if we're using bash"
	if [ ! "${BASH}" ]; then
		exiterror "BASH environment variable is not set.  You're probably running the wrong shell."
	fi

	if [ -z "${BASH_VERSION}" ]; then
		exiterror "Not running BASH shell."
	fi

	beautify message DONE

	#################################################################################
	# Checking if running as non-root user						#
	#################################################################################
	echo -ne "Checking if we're running as non-root user"
	if [ `id -u` -eq 0 -a x"${ALLOW_ROOT_TO_BUILD}" != x"yes" ]; then
		exiterror "Building as root is no longer supported.\n Please use another account or set ALLOW_ROOT_TO_BUILD=yes in .config"
	elif [ `id -u` -eq 0 -a x"${ALLOW_ROOT_TO_BUILD}" == x"yes" ]; then
		beautify message WARN " You're on your own, Mr. root"
	else
		beautify message DONE

		#################################################################################
		# Checking if sudo was found							#
		#################################################################################
		echo -ne "Checking if we have sudo"
		if [ ! ${SUDO} -o -z ${SUDO} -a x"${ALLOW_ROOT_TO_BUILD}" != x"yes" ]; then
			exiterror "sudo not found but is required!"
		else
			beautify message DONE
		fi

		#################################################################################
		# Checking if sudo is configured						#
		#################################################################################
		echo -ne "Checking if sudo is configured ${BOLD}"
		SUDO_ERROR=0
		# Check if the user is configured in sudoers
		# Ask the configuration with password send from closed standard input (0>&-)
		# so no password is asked for an unconfigured user
		if (! ${SUDO} -l -U ${CURRENT_USER} -S 0>&- &>/dev/null); then
			SUDO_ERROR=1
		else
			# Check every command is registered
			for cmd in "$BIND" "$CHMOD" "$DU" "$LN" "$LOSETUP" "$MKDIR" "$MKNOD" "$MV" "$NICECMD" "$RM" "$UMOUNT"; do
				if ( ! ${SUDO} -ll -U ${CURRENT_USER} | grep -q "${cmd}" ); then
					[ $SUDO_ERROR -eq 0 ] && beautify message FAIL
					beautify message FAIL "sudo fail for ${cmd}"
					SUDO_ERROR=1
				fi
			done
			# If /dev/shm is a symlink to /run/shm like debian v7, it is required to umount /run/shm and not ${LFS}/dev/shm
			[ -h /dev/shm ] && if ( ! ${SUDO} -ll -U ${CURRENT_USER} | grep -q 'umount /run/shm'); then
				[ $SUDO_ERROR -eq 0 ] && beautify message FAIL
				beautify message FAIL "sudo not configured to umount /run/shm"
				SUDO_ERROR=1
			fi
		fi
		echo -ne "${NORMAL}"
		if [ ${SUDO_ERROR} -eq 0 ]; then
			beautify message DONE
		else
			echo -ne "${BOLD}"
			echo -ne "\nAs root, use visudo to add these lines to /etc/sudoers\n"
			echo -ne "Make sure you don't break the lines!\n\n"
			echo -ne "# *** Openfirewall configuration ***\n"
			echo -ne "User_Alias OFW_BUILDER = ${CURRENT_USER}\n\n"
			echo -ne "Cmnd_Alias BIND = ${BIND} /dev* ${LFS}/dev*, \\ \n"
			echo -ne "\t\t${BIND} /proc ${LFS}/proc, \\ \n"
			echo -ne "\t\t${BIND} /sys ${LFS}/sys, \\ \n"
			echo -ne "\t\t${BIND} ${BASEDIR}/* ${LFS}/*\n"
			echo -ne "Cmnd_Alias CHMOD = ${CHMOD} [0-9]* ${LFS}/*\n"
			echo -ne "Cmnd_Alias DU = ${DU} -skx ${BASEDIR}\n"
			echo -ne "Cmnd_Alias LN = ${LN} * ${LFS}/*, \\ \n"
			echo -ne "\t\t${LN} ${BASEDIR}/build_${MACHINE}/${TOOLS_DIR} /\n"
			echo -ne "Cmnd_Alias LOSETUP = ${LOSETUP} -d /dev/loop*\n"
			echo -ne "Cmnd_Alias MKDIR = ${MKDIR} ${LFS}/*, \\ \n"
			echo -ne "\t\t${MKDIR} ${BASEDIR}/build_${MACHINE}/${INSTALLER_DIR}\n"
			echo -ne "Cmnd_Alias MKNOD = ${MKNOD} ${LFS}/dev/*\n"
			echo -ne "Cmnd_Alias MV = ${MV} ${LFS}/tmp/* \\ \n"
			echo -ne "\t\t\t\t${LFS}/tmp/*, \\ \n"
			echo -ne "\t\t${MV} ${BASEDIR}/build_${MACHINE}/${INSTALLER_DIR}/images/openfirewall-* \\ \n"
			echo -ne "\t\t\t\t${BASEDIR}/\n"
			echo -ne "Cmnd_Alias NICECMD = ${NICECMD} * ${CHROOT} ${LFS} *\n"
			echo -ne "Cmnd_Alias RM = ${RM} ${BASEDIR}/*, \\ \n"
			echo -ne "\t\t${RM} /${TOOLS_DIR}\n"
			echo -ne "Cmnd_Alias UMOUNT = ${UMOUNT} ${LFS}/*, \\ \n"
			echo -ne "\t\t${UMOUNT} /dev/loop*, \\ \n"
			echo -ne "\t\t${UMOUNT} /run/shm\n\n"
			echo -ne "OFW_BUILDER	ALL = NOPASSWD: BIND,CHMOD,DU,LN,LOSETUP,MKDIR,MKNOD,MV,NICECMD,RM,UMOUNT\n"
			echo -ne "# *** End of Openfirewall configuration ***\n"
			echo -ne "${NORMAL}"

			exiterror "sudo is not fully configured for user \"${CURRENT_USER}\"."
		fi
	fi

	#################################################################################
	# Checking for necessary temporary space					#
	#################################################################################
	if [[ (x"${SKIP_CHECK_DISKSPACE}" == x"no") && (x"${ACTION}" = x'build' || x"${ACTION}" = x'prefetch' || x"${ACTION}" = x'toolchain') ]]; then
		BASE_DEV=`df -P -k ${BASEDIR} | tail -n 1 | awk '{ print $1 }'`
		echo -ne "Checking for necessary space on disk ${BASE_DEV}"
		BASE_ASPACE=`df -P -k ${BASEDIR} | tail -n 1 | awk '{ print $4 }'`
		if (( 5242880 > ${BASE_ASPACE} )); then
			BASE_USPACE=`${SUDO} ${DU} -skx ${BASEDIR} | awk '{print $1}'`
			if (( 5242880 - ${BASE_USPACE} > ${BASE_ASPACE} )); then
				exiterror "Not enough temporary space available, need at least 5 GiB on ${BASE_DEV}"
			else
				beautify message DONE
			fi
		else
			beautify message DONE
		fi
	fi
} # End of check_build_env()



#########################################################################################################
# Function to prepare the build environment								#
#########################################################################################################
prepareenv()
{
	echo -ne "${BOLD}*** Setting up our build environment${NORMAL}\n"

	# System configuration
	echo "System configuration" >> ${PREPLOGFILE}

	# Set umask
	umask 022

	# Trap on emergency exit
	trap "exiterror 'Build process interrupted'" SIGINT SIGTERM SIGKILL SIGSTOP SIGQUIT

	# Setting our nice level
	if [ x`nice` != x"${NICE}" ]; then
		echo -e "Using nice level ${SET_OPT_COL}: ${INFO}${NICE}${NORMAL}"
		echo "Using nice level ${NICE}" >> ${PREPLOGFILE}
		NICEPARAM="-n ${NICE}"
	else
		NICECMD=
		NICEPARAM=
	fi

	# Set SCHED_BATCH
	if [ -x /usr/bin/schedtool ]; then
		echo -ne "Setting kernel schedular to ${SET_OPT_COL}: ${INFO}SCHED_BATCH${NORMAL}"
		/usr/bin/schedtool -B $$

		if [ ${?} -eq 0 ]; then
			beautify message DONE
		else
			beautify message FAIL
		fi
	fi

	# Check TOOLS_DIR symlink
	if [ -h /${TOOLS_DIR} ]; then
		${SUDO} ${RM} /${TOOLS_DIR}
	fi
	
	if [ ! -a /${TOOLS_DIR} ]; then
		${SUDO} ${LN} ${BASEDIR}/build_${MACHINE}/${TOOLS_DIR} /
	fi

	if [ ! -h /${TOOLS_DIR} ]; then
		exiterror "Could not create /${TOOLS_DIR} symbolic link."
	fi


	# Setup environment
	set +h
	LC_ALL=POSIX
	export LC_ALL
	unset CC CXX CPP LD_LIBRARY_PATH LD_PRELOAD
#	export LFS LC_ALL LFS_TGT PATH

	# Make some extra directories
	${MKDIR} ${BASEDIR}/{cache,ccache,cache/tmp}
	${MKDIR} ${BASEDIR}/build_${MACHINE}/${TOOLS_DIR}/usr
	${MKDIR} ${BASEDIR}/files_${MACHINE}
	${MKDIR} ${BASEDIR}/test_${MACHINE}

	# let src user owned, so we don't need to grant everyone a write access
	# that make some coreutils tests to fail because /usr/src/<package> is added to PATH during test
	# and perl complain about 'Insecure directory in $ENV{PATH} while running with -T switch'
	${MKDIR} ${LFS}/usr/src

##	if [ x"${USE_DISTCC}" == x"yes" -a ! -z "${DISTCC_HOSTS}" ]; then
##		${MKDIR} ${DISTCC_DIR}
##		${SUDO} ${MKDIR} ${LFS}/usr/src/distcc
##	fi

	# needed to create them now before to 'mount bind' them
	${SUDO} ${MKDIR} ${BASEDIR}/build_${MACHINE}/${INSTALLER_DIR}
	${SUDO} ${MKDIR} ${LFS}/${TOOLS_DIR}
##	${SUDO} ${MKDIR} ${LFS}/dev/pts
##	${SUDO} ${MKDIR} ${LFS}/dev/shm
	${SUDO} ${MKDIR} ${LFS}/dev
	${SUDO} ${MKDIR} ${LFS}/proc
	${SUDO} ${MKDIR} ${LFS}/sys
	${SUDO} ${MKDIR} ${LFS}/run
	${SUDO} ${MKDIR} ${LFS}/usr/src/{cache,ccache,config,doc,files_${MACHINE},html,langs,lfs,log_${MACHINE},src,test_${MACHINE},updates}
	${SUDO} ${MKDIR} ${LFS}/${INSTALLER_DIR}

	# use chroot tmp even for toolchain in case real /tmp is not writable by everyone
	${SUDO} ${MKDIR} ${LFS}/tmp
	${SUDO} ${CHMOD} 1777 ${LFS}/tmp

	#################################################################################
	# Make sure ${LFS}/bin/bash exists.  We used to do this check in lfs/bash, but	#
	# it's better to do it here so that the toolchain becomes completely		#
	# self-sufficient (ie you can start with no build_MACHINE/ofw and lfs/stage2)	#
	#################################################################################
	${SUDO} ${MKDIR} ${LFS}/bin
	if [ ! -f ${LFS}/bin/bash ]; then
		${SUDO} ${LN} /${TOOLS_DIR}/bin/bash ${LFS}/bin/bash
		${SUDO} ${LN} bash ${LFS}/bin/sh
	fi

	#################################################################################
	# Make all sources and proc available under lfs build				#
	#################################################################################
	${SUDO} ${RM} ${LFS}/dev/console
	${SUDO} ${RM} ${LFS}/dev/null
	${SUDO} ${MKNOD} ${LFS}/dev/console -m 0600 c 5 1
	${SUDO} ${MKNOD} ${LFS}/dev/null -m 0666 c 1 3


	${SUDO} ${BIND} /dev							${LFS}/dev
##	${SUDO} ${BIND} /dev/pts						${LFS}/dev/pts
##	${SUDO} ${BIND} /proc							${LFS}/proc
##	${SUDO} ${BIND} /sys							${LFS}/sys

	${SUDO} ${MOUNT} -vt devpts	devpts				${LFS}/dev/pts -o gid=5,mode=620  > /dev/null
	${SUDO} ${MOUNT} -vt proc proc					${LFS}/proc  > /dev/null
	${SUDO} ${MOUNT} -vt sysfs sysfs				${LFS}/sys   > /dev/null
##	${SUDO} ${MOUNT} -vt tmpfs tmpfs				${LFS}/run   > /dev/null
##	${SUDO} ${BIND} /dev/shm						${LFS}/dev/shm
	if [ -h $LFS/dev/shm ]; then
		${SUDO} ${MKDIR} -pv ${LFS}/$(readlink ${LFS}/dev/shm)
	fi
	${SUDO} ${BIND} ${BASEDIR}/cache					${LFS}/usr/src/cache
##	${SUDO} ${BIND} ${BASEDIR}/ccache					${LFS}/usr/src/ccache
	${SUDO} ${BIND} ${BASEDIR}/config					${LFS}/usr/src/config
	${SUDO} ${BIND} ${BASEDIR}/doc						${LFS}/usr/src/doc
	${SUDO} ${BIND} ${BASEDIR}/files_${MACHINE}				${LFS}/usr/src/files_${MACHINE}
	${SUDO} ${BIND} ${BASEDIR}/html						${LFS}/usr/src/html
	${SUDO} ${BIND} ${BASEDIR}/langs					${LFS}/usr/src/langs
	${SUDO} ${BIND} ${BASEDIR}/lfs						${LFS}/usr/src/lfs
	${SUDO} ${BIND} ${BASEDIR}/log_${MACHINE}				${LFS}/usr/src/log_${MACHINE}
	${SUDO} ${BIND} ${BASEDIR}/src						${LFS}/usr/src/src
	${SUDO} ${BIND} ${BASEDIR}/test_${MACHINE}				${LFS}/usr/src/test_${MACHINE}
	${SUDO} ${BIND} ${BASEDIR}/updates					${LFS}/usr/src/updates
	${SUDO} ${BIND} ${BASEDIR}/build_${MACHINE}/${TOOLS_DIR}		${LFS}/${TOOLS_DIR}
	${SUDO} ${BIND} ${BASEDIR}/build_${MACHINE}/${INSTALLER_DIR}		${LFS}/${INSTALLER_DIR}


	#################################################################################
	# Write the distcc hosts only if we're using distcc and we've specified the hosts
	#################################################################################
##	if [ x"${USE_DISTCC}" == x"yes" -a ! -z "${DISTCC_HOSTS}" ]; then
##		echo "${DISTCC_HOSTS}" > ${DISTCC_DIR}/hosts
##		${SUDO} ${BIND} ${DISTCC_DIR}					${LFS}/usr/src/distcc
##	fi

	# Set same timezone in the chroot as the build machine, so time is consistant
	# or once glibc is installed, system has a different time
	# Save etc/localtime to cache as user-owned, ${LFS}/usr/src is set owned by root in stage2
	cp /etc/localtime ${BASEDIR}/cache/localtime

	# svn info does not grow on commit but on update
	if [ -d ${BASEDIR}/.svn ]; then
		SVNREV=$(svn info | grep Revision | awk '{ print $2}')
		echo -e "Last svn up ${SET_OPT_COL}: ${INFO} Revision ${SVNREV}${NORMAL}"
	else
		SVNREV=0
		echo -e "Last svn up ${SET_OPT_COL}: ${INFO}no svn history found${NORMAL}"
	fi

	# Remove pre-install list of installed files in case user erase some files before to build again
	${SUDO} ${RM} ${LFS}/usr/src/lsalr 2>/dev/null

	# Warn that compilation of gnupg may fail in enforcing mode
	if ([ -n "${GETENFORCE}" ] && [ x"$(${GETENFORCE})" == xEnforcing ]); then
		beautify message WARN "gnupg compilation fail in SElinux Enforcing mode, at least on Centos-5.9."
		beautify message WARN "You may retry, disabling SElinux temporary by running 'setenforce 0'."
		# or say us how to really fix that
	fi
	
	# If not running test, do not warn for running kernel modules used during tests
	[ "${RUNNING_TEST}" == 'yes' ] || return 0

	# Copy host kernel modules required to run some tests in util-linux, mdadm, parted
	# Less tests could run if running kernel version name is exactly the same as compiled kernel version
	# as nobody would bet on compatibility between host and build kernel config
	[ ${KVER} == $(uname -r) ] && [ "${RUNNING_TEST}" == 'yes' ] \
		&& beautify message INFO "Skip copying running modules for testing, to avoid conflict with compiled kernel (same version name)" \
		&& return 0
	for flavor in lib/modules/$(uname -r) lib64/modules/$(uname -r); do
		[ -d /${flavor} ] || continue
		${SUDO} ${MKDIR} ${LFS}/${flavor}
		${SUDO} ${CHMOD} 0777 ${LFS}/${flavor}
		NOT_FOUND=
		for module in scsi_debug crc-t10dif scsi_mod md-mod; do
			M_FOUND=$(find /${flavor} -name "${module}.ko*" )
			if [ -z ${M_FOUND} ]; then
				NOT_FOUND="${NOT_FOUND} ${module}.ko"
			else
				cp ${M_FOUND} ${LFS}/${flavor}
			fi
		done
		# Uncompress modules if needed, names are hardcoded in .dep because that easier
		find ${LFS}/${flavor} -name '*.ko.gz' -exec gzip -fd {} \;

		if [ -n "${NOT_FOUND}" ]; then
			beautify message WARN "Less tests will run in util-linux, mdadm, parted"
			beautify message WARN "Those kernel modules, needed for the tests have not been found:${NOT_FOUND}"
		fi
		echo -e 'alias block-major-9-* md_mod\nalias md md_mod' >${LFS}/${flavor}/modules.alias
		echo -e 'crc-t10dif.ko:\nscsi_mod.ko:\nmd-mod.ko:\nscsi_debug.ko: scsi_mod.ko crc-t10dif.ko' >${LFS}/${flavor}/modules.dep
		${SUDO} ${CHMOD} 0666 ${LFS}/${flavor}
	done

} # End of prepareenv()


#########################################################################################################
# Check if we run build test and report									#
# firt arg is ./make.sh second arg									#
#########################################################################################################
check_running_test()
{
	if [ "${1}" -a x"${1}" == x"test" ]; then
		RUNNING_TEST='yes'
		${MKDIR} ${BASEDIR}/test_${MACHINE}/${BUILDDATE}
		[ ! -e /dev/pts ] && [ ! -e /dev/ptyp0 ] && exiterror "Missing /dev/pts or /dev/ptyp0 for reliable tests"
	fi
	echo -en "Running compilation tests ${SET_OPT_COL}: ${INFO}"
	beautify message INFO "$RUNNING_TEST"
} # End of check_running_test()


#########################################################################################################
# Print result of a toolchain prerequisites test to log							#
#########################################################################################################
report_result()
{
	if [ $1 -eq 0 ]; then
		echo ": DONE" >> ${PREPLOGFILE}
	else
		echo ": FAIL" >> ${PREPLOGFILE}
	fi
} # End of report_result()

#########################################################################################################
# update compiler signature for ccache with installed gcc						#
#########################################################################################################
# arg is the path to gcc
update-gcc-hash()
{
	#[ -f $1 ] || exiterror "Bad path: $1 for gcc"
	local hash=$(md5sum $1)
	#[ $? -eq 0 ] || exiterror "md5sum error for $1"
	export CCACHE_COMPILERCHECK="echo ${hash}"
	echo "Update CCACHE_COMPILERCHECK to ${CCACHE_COMPILERCHECK}" >>${PREPLOGFILE}
}

#########################################################################################################
# Function that checks for toolchain prerequisites							#
#########################################################################################################
toolchain_check_prerequisites()
{
	local SUCCESS=1
	local RESULT

	echo -ne "${BOLD}*** Checking for toolchain prerequisites${SET_REQUIRED_COL}   required${SET_FOUND_COL}    found"
	echo -ne "${SET_RESULT_COL} status${NORMAL}\n"

	check_version "GNU bash" ${REQUIRED_BASH} `bash --version | head -n1 | cut -d" " -f4 | cut -d"(" -f1`
	RESULT=${?}
	SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
	report_result ${RESULT}

	if bash +h -c "type ld" > /dev/null 2>&1; then
		check_version "GNU binutils" ${REQUIRED_BINUTILS} \
			`ld --version | head -n1 | sed "s,.* \([0-9]*\.[0-9][^ ]*\).*$,\1,g"`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU binutils not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type bison" > /dev/null 2>&1; then
		check_version "GNU bison" ${REQUIRED_BISON} `bison --version | head -n1 | cut -d" " -f4`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU bison not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type bzip2" > /dev/null 2>&1; then
		check_version "GNU bzip2" ${REQUIRED_BZIP2} \
			`bzip2 --version 2>&1 < /dev/null | head -n1 | cut -d" " -f8 | cut -d, -f1`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU bzip2 not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type chown" > /dev/null 2>&1; then
		check_version "GNU coreutils" ${REQUIRED_COREUTILS} `chown --version | head -n1 | cut -d")" -f2 | cut -d" " -f2`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU coreutils not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type diff" > /dev/null 2>&1; then
		check_version "GNU diffutils" ${REQUIRED_DIFFUTILS} `diff --version | head -n1 | cut -d" " -f4`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU diffutils not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type find" > /dev/null 2>&1; then
		check_version "GNU findutils" ${REQUIRED_FINDUTILS} `find --version | head -n1 | cut -d" " -f4`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU findutils not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type gawk" > /dev/null 2>&1; then
		check_version "GNU awk" ${REQUIRED_GAWK} `gawk --version | head -n1 | cut -d" " -f3`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU awk not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type gcc" > /dev/null 2>&1; then
		check_version "GNU CC" ${REQUIRED_GCC} `gcc -dumpversion`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU CC not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	# run first libc found, another match if any, is given as parameter to the first and ignored
	# 2>/dev/null hide empty path that may happen (at least on 32-bits host)
	# also look in /usr/lib as /lib may not exist or contain a symlink
	check_version "GNU libc" ${REQUIRED_GLIBC} $($(find /lib{,64} /usr/lib{,64} -name libc.so.6* 2>/dev/null) | head -n1 | sed "s,.*version \([0-9]*\.[0-9]*\).*$,\1,g")
	RESULT=${?}
	SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
	report_result ${RESULT}
	# Contrary to LFS, a static libc is needed to compile a portable toolchain (with a static ccache)
	echo -n "Checking static libc.a"
	# On Centos-5.9, find /usr/lib report 'Permission denied' with /usr/lib/audit
	# Instead of checking for a find error, look if at least a libc.a file has been found.
	local LIBC_STATIC=$(find /usr/lib{,64} -name libc.a 2>/dev/null | head -n1)
	if [ -n "${LIBC_STATIC}" ]; then
		echo -n " :  found ${LIBC_STATIC}"
		beautify message DONE
	else
		beautify message FAIL
		SUCCESS=$[ ${SUCCESS} - 1 ]
		echo " missing libc.a, install a glibc-static package" | tee -a ${LOGFILE}
	fi

	if bash +h -c "type grep" > /dev/null 2>&1; then
		check_version "GNU grep" ${REQUIRED_GREP} \
			`grep --version | head -n1 | sed "s,.* \([0-9]*\.[0-9][^ ]*\).*$,\1,g"`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU grep not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type gzip" > /dev/null 2>&1; then
		check_version "GNU gzip" ${REQUIRED_GZIP} `gzip --version | head -n1 | cut -d" " -f2`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU gzip not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	check_version "Linux Kernel" ${REQUIRED_KERNEL} `uname -r`
	RESULT=${?}
	SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
	report_result ${RESULT}

	if bash +h -c "type make" > /dev/null 2>&1; then
		check_version "GNU make" ${REQUIRED_MAKE} `make --version | head -n1 | cut -d" " -f3`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU make not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type patch" > /dev/null 2>&1; then
		check_version "GNU patch" ${REQUIRED_PATCH} `patch --version | head -n1 | sed "s,.* \([0-9]*\.[0-9][^ ]*\).*$,\1,g"`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU patch not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type sed" > /dev/null 2>&1; then
		check_version "GNU sed" ${REQUIRED_SED} `sed --version | head -n1 | cut -d" " -f4`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU sed not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type tar" > /dev/null 2>&1; then
		check_version "GNU tar" ${REQUIRED_TAR} `tar --version | head -n1 | cut -d" " -f4`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU tar not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if bash +h -c "type makeinfo" > /dev/null 2>&1; then
		check_version "GNU texinfo" ${REQUIRED_TEXINFO} `makeinfo --version | head -n1 | cut -d" " -f4`
		RESULT=${?}
		SUCCESS=$[ ${SUCCESS} - ${RESULT} ]
		report_result ${RESULT}
	else
		beautify message FAIL "GNU texinfo not found but it's required"
		SUCCESS=$[ ${SUCCESS} - 1 ]
	fi

	if [ ${SUCCESS} -lt 1 ]; then
		if [ x${IGNORE_PREREQUISITES} == x"yes" ]; then
			beautify message WARN "You've ignored failed host requirements!  You're on your own."
		else
			exiterror "Some host system requirements not met!  See the output above and rectify."
		fi
	fi
} # End of check_toolchain_prerequisites()



#########################################################################################################
# This is the function that sets the environment of a chroot and enters it				#
#########################################################################################################
entershell()
{
	if [ ! -e ${LFS}/usr/src/lfs/ ]; then
		exiterror "No such file or directory: ${LFS}/usr/src/lfs/"
	fi

	echo -ne "Entering ${BOLD}${MACHINE_REAL}${NORMAL} LFS chroot, type exit to return to host environment\n"

	# By default, needed to log stage2 and fix-up
	STAGE_ORDER=02; STAGE=base

	# Set CCACHE_COMPILERCHECK
	###for GCC_AVAILABLE in ${BASEDIR}/build_${MACHINE}/ofw/usr/bin/gcc /${TOOLS_DIR}/bin/${TARGET_2}-gcc; do
	for GCC_AVAILABLE in ${BASEDIR}/build_${MACHINE}/ofw/usr/bin/gcc /${TOOLS_DIR}/bin/${TARGET_2}-gcc; do
		[ -f ${GCC_AVAILABLE} ] && update-gcc-hash "$GCC_AVAILABLE" && break
	done

	chroot_make stage2
	chroot_make fix-up

	echo "zhk 1"
	${SUDO} ${NICECMD} ${NICEPARAM} ${CHROOT} ${LFS} /${TOOLS_DIR}/bin/env -i \
		HOME=/root \
		TERM=${TERM} \
		PS1="\[${BOLD}\][chroot-${MACHINE_REAL}]\[${NORMAL}\] \u:\w\$ " \
		PATH=${PATH_CH6} \
		CONFIG_ROOT=${CONFIG_ROOT} \
		VERSION=${VERSION} \
		NAME=${NAME} \
		SNAME=${SNAME} \
		SLOGAN="${SLOGAN}" \
		CCACHE_COMPILERCHECK="${CCACHE_COMPILERCHECK}" \
		CCACHE_DIR=/usr/src/ccache \
		CCACHE_HASHDIR=${CCACHE_HASHDIR} \
		DISTCC_DIR=/usr/src/distcc \
		PARALLELISM=${PARALLELISM} \
		LINKER=${LINKER} \
		TOOLS_DIR=${TOOLS_DIR} \
		INSTALLER_DIR=${INSTALLER_DIR} \
		MACHINE="${MACHINE}" \
		MACHINE_REAL="${MACHINE_REAL}" \
		CFLAGS="${CFLAGS}" \
		CXXFLAGS="${CFLAGS}" \
		LDFLAGS="${LDFLAGS}" \
		KVER=${KVER} \
		STAGE=${STAGE} \
		STAGE_ORDER=${STAGE_ORDER} \
		LOGFILE=`echo ${PREPLOGFILE} | sed "s,${BASEDIR},/usr/src,g"` \
		${WRAPPER_32BIT} bash

	STAGE_ORDER=05; STAGE=packages
	chroot_make fix-up
	stdumount
} # End of entershell()



#########################################################################################################
# This is the function that downloads and checks md5sum of every package				#
# Return:0 caller can continue										#
#	:1 skip (nothing to do)										#
#	or fail if no script file found									#
#########################################################################################################
lfsmakecommoncheck()
{
	${MKDIR} ${BASEDIR}/files_${MACHINE}/${STAGE_ORDER}_${STAGE}
	${MKDIR} ${BASEDIR}/log_${MACHINE}/${STAGE_ORDER}_${STAGE}

	# so we catch for sure error in PREPLOGFILE
	unset LOGFILE

	# Warn if somehow an accident happen inside our own source tree
	[ -f ${BASEDIR}/lfs/${1} ] || exiterror "Script: ${BASEDIR}/lfs/${1} missing"
	[ -r ${BASEDIR}/lfs/${1} ] || exiterror "Script: ${BASEDIR}/lfs/${1} not readable"
	# If the file is found empty, you should check if an implicit make rule did not broke the lfs file.
	# Look for make -p | grep SUFFIXES, if one of the suffix added to lfs name did not match DL_FILE or another object
	[ -s ${BASEDIR}/lfs/${1} ] || exiterror "Script: ${BASEDIR}/lfs/${1} empty"
	# If we replace by mistake lfs by config/rootfiles, avoid silently doing nothing
	cd ${BASEDIR}/lfs && (grep -q '^check' ${1} && grep -q '^download' ${1}) || exiterror "Script: ${BASEDIR}/lfs/${1} doesn't look our Makefile"

	if grep -q -E "^HOST_ARCH.*${MACHINE}|^HOST_ARCH.*all" ${BASEDIR}/lfs/${1}; then
		get_pkg_ver ${BASEDIR}/lfs/${1}

		beautify make_pkg "${PKG_VER_SHORT} $*"

		# Send download and checksum to preparation.log,
		# so splitted log have minimal more text on rebuild
		# make: Nothing to be done for `install'
		echo -e "`date -u '+%b %e %T'`: Building $*" >> ${PREPLOGFILE}

		# -r as implicit make rules are never used for download and md5, that should be faster, -s is less verbose for rebuild
		cd ${BASEDIR}/lfs && make -srf $* MACHINE=${MACHINE} LFS_BASEDIR=${BASEDIR} MESSAGE="${1}\t " download >> ${PREPLOGFILE} 2>&1
		[ ${?} -ne 0 ] && exiterror "Download error in ${1}"

		cd ${BASEDIR}/lfs && make -srf $* MACHINE=${MACHINE} LFS_BASEDIR=${BASEDIR} MESSAGE="${1}\t md5sum" md5 >> ${PREPLOGFILE} 2>&1
		[ ${?} -ne 0 ] && exiterror "md5sum error in ${1}, check file in cache or signature"

		# Split log per package
		LOGFILE="${BASEDIR}/log_${MACHINE}/${STAGE_ORDER}_${STAGE}/${1}-${PKG_VER}"
		# Add a separator and PASS if PASS is not empty
		[ -n "${PASS}" ] && LOGFILE="${LOGFILE}_${PASS}"

		return 0	# pass all!
	else
		return 1	# skip, not for this arch
	fi
} # End of lfsmakecommoncheck()



#########################################################################################################
# This is the function that builds every package in stage "toolchain"					#
#########################################################################################################
toolchain_make()
{
	lfsmakecommoncheck $*
	[ ${?} -eq 1 ] && return 0	# package is not for this arch, goto next

	local PKG_TIME_START=`date +%s`

	local WRAPPER_32BIT=${WRAPPER_32BIT}
	# On x86_64, we use host linux32 until util-linux is compiled
	# on alpha, WRAPPER_32BIT is not set

	# Create build marker and start progress indicator tool (if activated)
	BUILD_MARKER="${BASEDIR}/log_${MACHINE}/_marker_${STAGE_ORDER}_${1}"
	touch ${BUILD_MARKER}
	[ x"${SHOW_PROGRESS}" == x"yes" ] && RESULT_COL=${RESULT_COL} \
		SET_TIME_COL=${SET_TIME_COL} \
		BOLD=${BOLD} \
		NORMAL=${NORMAL} \
		${BASEDIR}/tools/progress.sh ${BUILD_MARKER} &

	# CFLAGS and CXXFLAGS are not set on purpose (recommended to be empty by lfs)
	# Not all machines have /tmp writable by non-root, so use ${LFS}/tmp made for the chroot
	bash -x -c "cd ${BASEDIR}/lfs && ${WRAPPER_32BIT} make -f $* install \
		CONFIG_ROOT=${CONFIG_ROOT} \
		LFS_TGT=${LFS_TGT} \
		TARGET_2=${TARGET_2} \
		LINKER=${LINKER} \
		TOOLS_DIR=${TOOLS_DIR} \
		REQUIRED_KERNEL=${REQUIRED_KERNEL} \
		MACHINE="${MACHINE}" \
		BUILDDATE="${BUILDDATE}" \
		LFS_BASEDIR=${BASEDIR} \
		LFS=${LFS} \
		PARALLELISM=${PARALLELISM} \
		PASS=${PASS} \
		RUNNING_TEST=${RUNNING_TEST} \
		STAGE=${STAGE} \
		STAGE_ORDER=${STAGE_ORDER} \
		SHELL='/bin/bash' \
		TMPDIR=${LFS}/tmp \
		" >> ${LOGFILE} 2>&1
	# the >> is needed to keep log on rebuild or log is replaced by
	# make: Nothing to be done for `install'.

	local COMPILE_RESULT=${?}
	local PKG_TIME_END=`date +%s`
	${RM} ${BUILD_MARKER}

	if [ ${COMPILE_RESULT} -ne 0 ]; then
		beautify result FAIL $[ ${PKG_TIME_END} - ${PKG_TIME_START} ] ${1} ${PKG_VER_SHORT} ${STAGE_ORDER} ${STAGE}
		exiterror "Building $*";
	else
		beautify result DONE $[ ${PKG_TIME_END} - ${PKG_TIME_START} ] ${1} ${PKG_VER_SHORT} ${STAGE_ORDER} ${STAGE}
	fi

	return 0
} # End of toolchain_make()



#########################################################################################################
# This is the function that builds every package in stage "base"					#
#########################################################################################################
chroot_make()
{
	lfsmakecommoncheck $*
	[ ${?} -eq 1 ] && return 0	# package is not for this arch, goto next

	local PKG_TIME_START=`date +%s`

#	local WRAPPER_32BIT=${WRAPPER_32BIT}
	# When cross-compiling, make sure the kernel is compiled for the target
	[ x"${MACHINE_REAL}" == x"sparc64" -a x"${1}" == x"linux" ] && unset WRAPPER_32BIT
	# don't play 32bit on alpha
	[ x${MACHINE} == x"alpha" ] && unset WRAPPER_32BIT

	# Also, make sure external kernel modules are compiled 64bit
	if grep -qEi 'KERNEL_MOD = yes' ${1} ; then
		[ x"${MACHINE_REAL}" == x"sparc64" ] && unset WRAPPER_32BIT
	fi

	# Create build marker and start progress indicator tool (if activated)
	BUILD_MARKER="${BASEDIR}/log_${MACHINE}/_marker_${STAGE_ORDER}_${1}"
	touch ${BUILD_MARKER}
	[ x"${SHOW_PROGRESS}" == x"yes" ] && RESULT_COL=${RESULT_COL} \
		SET_TIME_COL=${SET_TIME_COL} \
		BOLD=${BOLD} \
		NORMAL=${NORMAL} \
		${BASEDIR}/tools/progress.sh ${BUILD_MARKER} &

	
	${SUDO} ${NICECMD} ${NICEPARAM} ${CHROOT} ${LFS} /${TOOLS_DIR}/bin/env -i \
		HOME=/root \
		TERM=${TERM} \
		PS1='\u:\w\$ ' \
		PATH=${PATH_CH6} \
		CONFIG_ROOT=${CONFIG_ROOT} \
		VERSION=${VERSION} \
		NAME=${NAME} \
		SNAME=${SNAME} \
		SLOGAN="${SLOGAN}" \
		PARALLELISM=${PARALLELISM} \
		PASS=${PASS} \
		TARGET_2=${TARGET_2} \
		LINKER=${LINKER} \
		TOOLS_DIR=${TOOLS_DIR} \
		INSTALLER_DIR=${INSTALLER_DIR} \
		REQUIRED_KERNEL=${REQUIRED_KERNEL} \
		MACHINE="${MACHINE}" \
		MACHINE_REAL="${MACHINE_REAL}" \
		SKIP_FLOPPY_IMAGES="${SKIP_FLOPPY_IMAGES}" \
		BUILDDATE="${BUILDDATE}" \
		RUNNING_TEST=${RUNNING_TEST} \
		KVER=${KVER} \
		PERLVER=${PERLVER} \
		STAGE=${STAGE} \
		STAGE_ORDER=${STAGE_ORDER} \
		LOGFILE=`echo ${LOGFILE} | sed "s,${BASEDIR},/usr/src,g"` \
		bash --login -x +h -c "cd /usr/src/lfs && make -f $* LFS_BASEDIR=/usr/src install" >> ${LOGFILE} 2>&1

###		bash --login -x +h -c "cd /usr/src/lfs && make -f $* LFS_BASEDIR=/usr/src install" >> ${LOGFILE} 2>&1
###		bash -x -c "cd /usr/src/lfs && make -f $* LFS_BASEDIR=/usr/src install" >> ${LOGFILE} 2>&1
###		${WRAPPER_32BIT} make -f $* LFS_BASEDIR=/usr/src install" >> ${LOGFILE} 2>&1

###		CCACHE_COMPILERCHECK="${CCACHE_COMPILERCHECK}" \
###		CCACHE_DIR=/usr/src/ccache \
###		CCACHE_HASHDIR=${CCACHE_HASHDIR} \
###		DISTCC_DIR=/usr/src/distcc \

###		CFLAGS="${CFLAGS}" \
###		CXXFLAGS="${CFLAGS}" \
###		LDFLAGS="${LDFLAGS}" \


	local COMPILE_RESULT=${?}
	local PKG_TIME_END=`date +%s`
	${RM} ${BUILD_MARKER}

	if [ ${COMPILE_RESULT} -ne 0 ]; then
		beautify result FAIL $[ ${PKG_TIME_END} - ${PKG_TIME_START} ] ${1} ${PKG_VER_SHORT} ${STAGE_ORDER} ${STAGE}
		exiterror "Building $*";
	else
		beautify result DONE $[ ${PKG_TIME_END} - ${PKG_TIME_START} ] ${1} ${PKG_VER_SHORT} ${STAGE_ORDER} ${STAGE}
	fi

	return 0
} # End of chroot_make()



#########################################################################################################
# This builds the entire stage "toolchain"								#
#########################################################################################################
toolchain_build()
{
	beautify build_stage "Building ${TOOLCHAINVERSION} toolchain"
	ORG_PATH=${PATH}
	export PATH=${PATH_CH5}
	STAGE_ORDER=01
	STAGE=toolchain

	if [ -f $BASEDIR/log_${MACHINE}/01_toolchain/ccache-* ]; then
		beautify message INFO "You can't partially rebuild some parts of the toolchain cleanly."
		beautify message INFO "Preferably before each toolchain build, use:\n./make.sh clean"
	fi

	# Let's adjust removed files possible, so remade strip each time
	${RM} ${LFS}/usr/src/{log,files}_${MACHINE}/01_toolchain/strip

	# make distcc first so that CCACHE_PREFIX works immediately
##	if [ x"${USE_DISTCC}" == x"yes" -a ! -z "${DISTCC_HOSTS}" ]; then
##		toolchain_make distcc
##	fi

	# search gcc host path before ccache is made, as ccache installed gcc symlink is found earlier in PATH chain
##	local HOSTGCC=$(bash +h -c "type -p gcc")

#	toolchain_make ccache
#	update-gcc-hash ${HOSTGCC}		# preset the compiler hash with the value of the host compiler
	PASS="1"
	toolchain_make xz			# Early, to be sure, even in old host we could open .lzma or .xz package like glibc
	toolchain_make binutils
	toolchain_make gmp
	toolchain_make mpfr
	toolchain_make mpc
	toolchain_make gcc
	# gcc pass1 is removed on lfs/strip. If absent that mean we don't need this signature
#	[ -f /${TOOLS_DIR}/bin/${LFS_TGT}-gcc ] && update-gcc-hash "/${TOOLS_DIR}/bin/${LFS_TGT}-gcc"
	PASS=""
	toolchain_make linux-headers
	toolchain_make glibc
	toolchain_make libstdc++
	toolchain_make adjust-toolchain
	PASS="2"
	toolchain_make binutils
	toolchain_make gcc
#	update-gcc-hash "/${TOOLS_DIR}/bin/${TARGET_2}-gcc"
	PASS=""
	toolchain_make ncurses
	toolchain_make bash
	toolchain_make bzip2
	PASS="2"
	toolchain_make xz			# rebuild with our compiled libc
	PASS=""
	toolchain_make tar			# build just after xz to avoid using pipe with .xz package (if host tar is old)
	toolchain_make coreutils
	toolchain_make diffutils
	toolchain_make file
	toolchain_make util-linux		# contrary to LFS, we need mount and linux32 for stage2 and chroot_make
	toolchain_make findutils
	toolchain_make gawk
	toolchain_make gettext
	toolchain_make grep
	toolchain_make gzip
	toolchain_make m4
	toolchain_make make
	toolchain_make patch
	toolchain_make pax-utils		# for compilation QA
	toolchain_make perl
	toolchain_make sed
	toolchain_make strace
	toolchain_make texinfo
	toolchain_make bison
	toolchain_make tcl			# tcl,expect,dejagnu only needed to run gcc tests
	toolchain_make expect
	toolchain_make dejagnu
	toolchain_make strip
	export PATH=${ORG_PATH}
} # End of toolchain_build()



#########################################################################################################
# This builds the entire stage "base"									#
#########################################################################################################
base_build()
{
	beautify build_stage "Building base"
	STAGE_ORDER=02
	STAGE=base

##	update-gcc-hash "/${TOOLS_DIR}/bin/${TARGET_2}-gcc"

	
	PASS="${SVNREV}"
	chroot_make stage2
	PASS=""
	chroot_make fix-up
	chroot_make linux-headers
	chroot_make glibc
	chroot_make tzdata
	chroot_make adjust-toolchain
	chroot_make zlib
	chroot_make file       ##zhk
	chroot_make readline   ##zhk
	chroot_make m4         ##zhk
##	chroot_make bc         # zhk move here
	chroot_make binutils
	chroot_make gmp
	chroot_make mpfr
	chroot_make mpc
	chroot_make gcc
##	update-gcc-hash "${BASEDIR}/build_${MACHINE}/ofw/usr/bin/gcc"
##	chroot_make sed
	chroot_make bzip2
	chroot_make pkg-config
	chroot_make ncurses
	chroot_make attr   # add by zk
	chroot_make acl   # add by zk
	chroot_make libcap # move by zk
	chroot_make sed
	chroot_make shadow		# provide su for util-linux and coreutils tests
	chroot_make psmisc
#	chroot_make util-linux
	chroot_make bison
	chroot_make flex
	chroot_make grep
	chroot_make bash
	chroot_make libtool		# libtoolize contain hardcoded grep path
	chroot_make perl
	chroot_make autoconf
	chroot_make automake
	chroot_make xz          # required by kmod/compressed modules
	chroot_make kmod
	chroot_make gettext
	chroot_make procps		# ps for an e2fsprogs test
	chroot_make e2fsprogs
	chroot_make coreutils
	chroot_make iana-etc
##	chroot_make m4
#	chroot_make bison
##	chroot_make readline
#	chroot_make bash
	chroot_make pcre		# grep search pcre, glib use system pcre, pcre use readline
#	chroot_make grep
#	chroot_make libtool		# libtoolize contain hardcoded grep path
#	chroot_make perl
#	chroot_make autoconf
#	chroot_make automake
##	chroot_make bzip2
	chroot_make diffutils
	chroot_make gawk		# file is not recompiled on base as not include in iso
	chroot_make findutils
#	chroot_make flex
	chroot_make aboot
	chroot_make sparc-utils
	chroot_make silo
	chroot_make powerpc-utils
	chroot_make hfsutils
	chroot_make yaboot
	chroot_make quik
##	chroot_make gettext
	chroot_make groff
	chroot_make less
	chroot_make gzip		# gzip zless tests require less 
	chroot_make iproute2
	chroot_make kbd
#	chroot_make xz          # required by kmod/compressed modules
#	chroot_make kmod
	chroot_make make
	chroot_make patch
	chroot_make openssl
	chroot_make json-c      # required by rsyslog
	chroot_make curl      # required by rsyslog
	chroot_make rsyslog
	chroot_make strace		# compile early for debug purpose
	chroot_make sysvinit
	chroot_make util-linux  ##zhk
	chroot_make tar
	chroot_make texinfo
	chroot_make gperf
##	chroot_make udev
	chroot_make eudev
	chroot_make vim
} # End of base_build()



#########################################################################################################
# This builds the entire stage "ofw"	                                 								#
#########################################################################################################
openfirewall_build()
{
	beautify build_stage "Building openfirewall"
	STAGE_ORDER=03
	STAGE=openfirewall

	# Build these first as some of the kernel packages below rely on
	# these for some of their client program functionality
	chroot_make libffi		# for Python, glib
#####	chroot_make openssl
	chroot_make Python		# glib require Python
	chroot_make glib		# for cairo
	chroot_make tcl			# for krb5 and db tests
	chroot_make openfirewall
	chroot_make which
	chroot_make net-tools
	chroot_make libusb
	chroot_make libpcap
	chroot_make libtirpc
	chroot_make rpcsvc-proto
	chroot_make libxml2
	chroot_make linux-atm
	chroot_make ppp
	chroot_make rp-pppoe
	chroot_make unzip           # only needed to unpack rawwrite in lfs/cdrom
	chroot_make bc              # needed to run some openssl tests and compile kernel >= 3.10
	chroot_make linux
	#chroot_make CnxADSL        # compilation broken with 3.10 kernel
	chroot_make e1000e          # supply newer kernel driver
	if [ x"${SKIP_AVM_DRIVERS}" != x"yes" ]; then
		chroot_make fcdsl       # DEBUG -- compiles, but functionality is uncertain
		chroot_make fcdsl2      # DEBUG -- compiles, but functionality is uncertain
		chroot_make fcdslsl     # DEBUG -- compiles, but functionality is uncertain
	fi
	chroot_make firmware-extractor
##	chroot_make igb             # supply newer kernel driver
	#chroot_make pulsar         # compilation broken with 3.10 kernel
	chroot_make solos-pci
	#chroot_make wanpipe        # compilation broken with 3.4 kernel
##	chroot_make pcmciautils
##	chroot_make eciadsl-usermode
	# end of linux kernel and drivers
	chroot_make linux-firmware
	chroot_make cpio
	chroot_make expat
##	chroot_make openssl
	chroot_make ca-certificates
	chroot_make libgpg-error	# radiusplugin for OpenVPN
	chroot_make libgcrypt		# radiusplugin for OpenVPN
	chroot_make libnet
	chroot_make libpng
	chroot_make dejavu
	chroot_make freetype
	chroot_make harfbuzz
##	chroot_make gperf
	chroot_make fontconfig
	chroot_make pixman
	chroot_make cairo
	chroot_make pango
	chroot_make popt		# logrotate
##	chroot_make libcap
	chroot_make pciutils
	chroot_make usbutils
	chroot_make acpid
	chroot_make apache
	chroot_make beep
##	chroot_make bind
##	chroot_make capi4k-utils
	chroot_make db			# squidGuard
	chroot_make dnsmasq
	chroot_make ethtool
	chroot_make ez-ipupdate
	chroot_make fcron
	chroot_make gnupg
	chroot_make hdparm
	chroot_make ibod
	chroot_make libmnl                  # iptables/conntrack
	chroot_make libnfnetlink            # iptables/conntrack
	chroot_make libnetfilter_acct       # iptables/conntrack
	chroot_make libnetfilter_log        # iptables/conntrack
	chroot_make libnetfilter_conntrack  # iptables/conntrack
	chroot_make libnetfilter_cthelper   # iptables/conntrack
	chroot_make libnetfilter_cttimeout  # iptables/conntrack
	chroot_make libnetfilter_queue      # iptables/conntrack
	chroot_make iptables
	chroot_make conntrack-tools   ###############################
	chroot_make iptstate
	chroot_make iftop
	chroot_make openfirewall-gui
	chroot_make openfirewall-progs
	chroot_make iperf
	chroot_make iputils
##	chroot_make isdn4k-utils
	chroot_make krb5
	chroot_make logrotate
	chroot_make logwatch
	chroot_make lsof
	chroot_make lzo			# OpenVPN
	chroot_make mdadm
	chroot_make nano
	chroot_make nasm		# only used in case we patch and fully compile syslinux
	chroot_make sqlite		# before DBD-SQLite and ulogd that depend on it
	# PERL CPAN packages
	chroot_make perl-archive-zip        # OpenVPN
	chroot_make perl-apache-htpasswd
	chroot_make perl-crypt-passwdmd5
	chroot_make perl-cgi
	chroot_make perl-uri
	chroot_make perl-html-tagset
	chroot_make perl-html-parser
	chroot_make perl-dbi
	chroot_make perl-dbd-sqlite
	chroot_make perl-digest-sha1
	chroot_make perl-digest-hmac
	chroot_make perl-encode-locale
	chroot_make perl-http-message
	chroot_make perl-http-date
	chroot_make perl-net-http
	chroot_make perl-libwww
	chroot_make perl-locale-maketext-gettext
	chroot_make perl-netaddr-ip
	chroot_make perl-net-dns
	chroot_make perl-net-ssleay  #####################
	chroot_make perl-io-socket-ssl  #######################
	chroot_make perl-xml-parser
	chroot_make perl-xml-simple
	# end of CPAN
	chroot_make ntp
	chroot_make dhcpcd		# After ntp to detect ntpd and /etc/rc.d
	chroot_make openldap
	chroot_make openssh   #######################################
	chroot_make openswan
	chroot_make openvpn
	chroot_make pptp
	chroot_make radiusplugin	# OpenVPN
	chroot_make rrdtool
	chroot_make sendEmail
	chroot_make setserial
	chroot_make smartmontools
	chroot_make cppunit		# for squid tests
	chroot_make squid
	chroot_make squid-langpack
	chroot_make squidGuard
	chroot_make tcpdump
	chroot_make traceroute
	chroot_make ulogd
	chroot_make usb-modeswitch
	chroot_make usb-modeswitch-data
	chroot_make vnstat
	chroot_make wget
	chroot_make wireless_tools
	chroot_make libnl
	chroot_make iw
	chroot_make 3c5x9setup
} # End of openfirewall_build()



#########################################################################################################
# This builds the entire stage "misc"									#
#########################################################################################################
misc_build()
{
	beautify build_stage "Building miscellaneous"
	STAGE_ORDER=04
	STAGE=misc

	chroot_make xorriso
	chroot_make memtest
	chroot_make syslinux
	chroot_make macutils
	chroot_make rsrce
	chroot_make miboot
	chroot_make mtools
	chroot_make parted
	chroot_make slang
	chroot_make newt
	chroot_make busybox
	chroot_make openfirewall-lang
	chroot_make mklibs
	chroot_make dosfstools
	if [ x"${SKIP_FLOPPY_IMAGES}" != x"yes" ]; then
		chroot_make klibc
		chroot_make xz-embedded
	else
		echo "Skip floppy images"
	fi
	if [ x"${DEBUGGING}" == x"yes" ]; then
		chroot_make gdb
	fi
} # End of misc_build()



#########################################################################################################
# This builds the entire stage "packages"								#
#########################################################################################################
packages_build()
{
	beautify build_stage "Building packages"
	STAGE_ORDER=05
	STAGE=packages

	chroot_make fix-up
	chroot_make openfirewall-installer
	chroot_make openfirewall-initramfs
	if [ x"${SKIP_FLOPPY_IMAGES}" != x"yes" ]; then
		chroot_make openfirewall-boot-floppy
	else
		echo "Skip floppy images"
	fi
	if [ x"${SKIP_AVM_DRIVERS}" != x"yes" ]; then
		chroot_make avmdrv
	else
		echo "Skip avm drivers"
	fi

###	if [ "${VERSIONSTEP}" ]; then
###		PASS="${VERSIONSTEP}"
###		chroot_make openfirewall-update
###	fi
###	PASS="${VERSION}"
###	chroot_make openfirewall-update
###	PASS=""
	chroot_make openfirewall-boot-cd
	chroot_make openfirewall-boot-net
	chroot_make check_files

	if [ x"${SKIP_USB_IMAGES}" != x"yes" ]; then
		chroot_make openfirewall-boot-usb
	else
		echo "Skip usb images to save time"
	fi

	# Our tools directory is not mounted inside chroot, so done outside
	if [ ! -f ${BASEDIR}/doc/${NAME}-${PREVIOUSVERSION}-all-files-list.${MACHINE}.txt.md5 ]; then
		beautify message INFO "No MD5 all-files-list for ${PREVIOUSVERSION} found, no comparison."
	else
		echo -ne "Running MD5 compare"
		${BASEDIR}/tools/comp_md5.pl ${BASEDIR} ${VERSION} ${PREVIOUSVERSION} ${MACHINE} ${KVER} ${PERLVER} ${VERSIONSTEP}
		if [ $? -ne 0 ]; then
			beautify message FAIL
		else
			beautify message DONE
			echo "See ${BASEDIR}/doc/${NAME}-${VERSION}-diff-list.${MACHINE}.txt for result"
		fi
	fi

} # End of packages_build()



#########################################################################################################
# This downloads all the external sources								#
#########################################################################################################
loadsrc()
{
	${MKDIR} ${BASEDIR}/log_${MACHINE}
	${MKDIR} ${BASEDIR}/cache
	local COUNTER=0
	local ALL_PACKAGES=0
	local ARCHES=${1}
	local FINISHED=0
	local WGET_FAIL_COUNTER=0
	local MD5SUM_FAIL_COUNTER=0
	declare -a FAILED
	cd ${BASEDIR}/lfs

	if [ x"${ARCHES}" == x"all" ]; then
		echo -ne "${BOLD}*** Prefetching files for all supported architectures"
		echo -ne "${SET_ARCH_COL}   arch${SET_WGET_COL}  wget${SET_RESULT_COL} md5sum${NORMAL}\n"
	else
		echo -ne "${BOLD}*** Prefetching files for ${MACHINE} only"
		echo -ne "${SET_ARCH_COL}   arch${SET_WGET_COL}  wget${SET_RESULT_COL} md5sum${NORMAL}\n"
	fi

	ALL_PACKAGES=`grep -l -E "^objects.*=" * | wc -l`

	for i in `grep -l -E "^objects.*=" *`
	do
		grep -E "^HOST_ARCH.*${MACHINE}|^HOST_ARCH.*all" ${i} >/dev/null

		if [ $? -eq 0 -o x"${ARCHES}" == x"all" ]; then
			COUNTER=$[ ${COUNTER} + 1 ]
			echo -ne "${i}"
			local HOST_ARCH=`grep "^HOST_ARCH" ${i} | sed "s,^HOST_ARCH.*= ,,"`

			if echo "${HOST_ARCH}" | grep -E "," > /dev/null 2>&1; then
				HOST_ARCH="some"
			fi

			beautify message ARCH ${HOST_ARCH}

			make -s -f ${i} MACHINE=${MACHINE} LFS_BASEDIR=${BASEDIR} MESSAGE="${i}\t" download >> ${PREPLOGFILE} 2>&1
			if [ ${?} -ne 0 ]; then
				beautify message FAIL wget
				echo "${1} : wget error in '${i}'" >> ${PREPLOGFILE} 2>&1
				FINISHED=0
				FAILED[${WGET_FAIL_COUNTER}]=${i}
				WGET_FAIL_COUNTER=$[ ${WGET_FAIL_COUNTER} + 1]
			else
				beautify message DONE wget
			fi

			make -s -f ${i} MACHINE=${MACHINE} LFS_BASEDIR=${BASEDIR} MESSAGE="${i}\t " md5 >> ${PREPLOGFILE} 2>&1
			if [ ${?} -ne 0 ]; then
				beautify message FAIL
				MD5SUM_FAIL_COUNTER=$[ ${MD5SUM_FAIL_COUNTER} + 1]
			else
				beautify message DONE
			fi
		else
			echo "${i} : skipping '${i}' on ${MACHINE}" >> ${PREPLOGFILE} 2>&1
		fi
	done

	if [ ${#FAILED[*]} -gt 0 ]; then
		echo -ne "${BOLD}*** Retrying failed files${SET_WGET_COL}  wget${SET_RESULT_COL} md5sum${NORMAL}\n"

		for c in `seq 2 ${MAX_RETRIES}`
		do
			for i in ${FAILED[@]}
			do
				if [ ${FINISHED} -eq 1 ]; then
					break
				fi

				FINISHED=1

				echo -ne "${BOLD}${i} (Attempt: ${c})${NORMAL}"
				make -s -f ${i} MACHINE=${MACHINE} LFS_BASEDIR=${BASEDIR} MESSAGE="${i}\t (${c}/${MAX_RETRIES})" download >> ${PREPLOGFILE} 2>&1
				if [ ${?} -ne 0 ]; then
					beautify message FAIL wget
					echo "${1} : wget error in '${i}'" >> ${PREPLOGFILE} 2>&1
					FINISHED=0
				else
					beautify message DONE wget
					WGET_FAIL_COUNTER=$[ ${WGET_FAIL_COUNTER} - 1]
				fi

				make -s -f ${i} MACHINE=${MACHINE} LFS_BASEDIR=${BASEDIR} MESSAGE="${i}\t " md5 >> ${PREPLOGFILE} 2>&1
				if [ ${?} -ne 0 ]; then
					beautify message FAIL
				else
					beautify message DONE
					MD5SUM_FAIL_COUNTER=$[ ${MD5SUM_FAIL_COUNTER} - 1]
				fi
			done
		done
	fi

	beautify message INFO "Attempted to download ${COUNTER} of ${ALL_PACKAGES} packages"

	if [ ${WGET_FAIL_COUNTER} -gt 0 -o ${MD5SUM_FAIL_COUNTER} -gt 0 ]; then
		echo -ne "${BOLD}*** ${WGET_FAIL_COUNTER} package(s) could not be downloaded${NORMAL}\n"
		echo -ne "${BOLD}*** ${MD5SUM_FAIL_COUNTER} package(s) had incorrect md5sum${NORMAL}\n"
		echo -ne "*** google for files no more found in original URL, that's safe when md5 remain the ${BOLD}same${NORMAL}\n"
		return 1
	else
		echo -ne "${BOLD}*** All packages successfully downloaded with correct md5 sums${NORMAL}\n"
		return 0
	fi

	unset FAILED
	cd - > /dev/null
} # End of loadsrc()



#########################################################################################################
# This is the function that will create the toolchain tar archive					#
#########################################################################################################
package_toolchain()
{
	# if base adjust-toolchain has run, we can't package
	if [ -f ${TOOLS_DIR}/bin/ld-old ]; then
		exiterror "Too late, toolchain has been altered"
	fi
	TOOLCHAINFILES="01_toolchain.lst"
	echo "*** Packaging the ${MACHINE} toolchain" >> ${PREPLOGFILE}
	echo -ne "${BOLD}*** Packaging the ${MACHINE_REAL} toolchain${NORMAL}\n"

	# tag toolchain
	echo "${SVNREV}" >${BASEDIR}/log_${MACHINE}/toolchain-svn-rev

 	echo "Creating the ${MACHINE_REAL} toolchain tar archive" >> ${PREPLOGFILE}
 	echo  -ne "Creating the ${MACHINE_REAL} toolchain tar archive"
 	cd ${BASEDIR} && tar --create --gzip --verbose \
				--exclude="log_${MACHINE}/_build_0[0-6]_*.log" \
 				--exclude="log_${MACHINE}/_build_${TOOLCHAINFILES}" \
				--exclude="log_${MACHINE}/0[0-6]_*" \
 				--file=cache/${TOOLCHAINNAME} \
 				build_${MACHINE}/${TOOLS_DIR} \
 				log_${MACHINE} \
				files_${MACHINE}/01_toolchain \
				> log_${MACHINE}/_build_${TOOLCHAINFILES}

	if [ $? -eq 0 ]; then
		beautify message DONE
	else
		beautify message FAIL
	fi

	echo "Calculating the ${MACHINE_REAL} toolchain tar archive md5sum" >> ${PREPLOGFILE}
	echo -ne "Calculating the ${MACHINE_REAL} toolchain tar archive md5sum"
	md5sum cache/${TOOLCHAINNAME} > cache/${TOOLCHAINNAME}.md5

	if [ $? -eq 0 ]; then
		beautify message DONE
	else
		beautify message FAIL
	fi

} # End of package_toolchain()

#########################################################################################################
# Read build test result when we run them								#
#########################################################################################################
parse_tests()
{
	beautify build_stage "Parsing build test"
	${BASEDIR}/tools/error-parser ${BASEDIR}/test_${MACHINE}/${BUILDDATE}
} # End of parse_tests

#########################################################################################################
#########################################################################################################
# End of BLOCK 2 -- Functions										#
#########################################################################################################
#########################################################################################################




#########################################################################################################
#########################################################################################################
# BLOCK 3 -- THIS IS WHERE EXECUTION STARTS								#
#########################################################################################################
#########################################################################################################

# First check if we meet the build environment requirements
check_build_env

# See  what we're supposed to do
ACTION=${1}
case "${ACTION}" in
build)
	# On first build attempt, better prefetch everything first.
	# This will allow to find packages URL that may have moved as soon as possible.
	if [ ! -d ${BASEDIR}/cache ]; then
		beautify message WARN "You should use './make.sh prefetch' to load all files before building"
		loadsrc
	fi

	echo -ne "Building ${BOLD}${NAME}-${VERSION}${NORMAL} for ${BOLD}${MACHINE} on ${MACHINE_REAL}${NORMAL}\n"

	if [ -f ${BASEDIR}/files_${MACHINE}/01_toolchain/strip ]; then
		beautify message DONE "Stage toolchain already built (found files_${MACHINE}/01_toolchain/strip)"
		check_running_test ${2}
		prepareenv
	elif [ -f ${BASEDIR}/cache/${TOOLCHAINNAME} -a -f ${BASEDIR}/cache/${TOOLCHAINNAME}.md5 ]; then
		echo -ne "${BOLD}*** Restore from ${TOOLCHAINNAME}${NORMAL}\n"
		echo -ne "Checking md5sum"
		TOOLCHAIN_MD5_FOUND=`md5sum ${BASEDIR}/cache/${TOOLCHAINNAME} | awk '{print $1}'`
		TOOLCHAIN_MD5_NEEDED=`cat ${BASEDIR}/cache/${TOOLCHAINNAME}.md5 | awk '{print $1}'`

		if [ x"${TOOLCHAIN_MD5_FOUND}" != x"${TOOLCHAIN_MD5_NEEDED}" ]; then
			exiterror "${TOOLCHAINNAME} md5 did not match. Check downloaded package"
		fi
		# toolchain look good, use it
		beautify message DONE

		echo -ne "md5sum matches : "
		beautify message INFO "${TOOLCHAIN_MD5_FOUND}"

		echo -ne "Unpacking toolchain ${TOOLCHAINNAME}"
		tar --no-same-owner --group=${CURRENT_USER_GROUP} -zxf ${BASEDIR}/cache/${TOOLCHAINNAME} -C ${BASEDIR}
		[ ${?} -ne 0 ] && exiterror "${TOOLCHAINNAME} could not be unpacked. Check downloaded package"

		beautify message DONE

		# Now prepare the environment
		check_running_test ${2}
		prepareenv
	else
		echo -ne "${BOLD}*** Full toolchain compilation${NORMAL}\n"
		check_running_test ${2}
		prepareenv

		# Check if host can build the toolchain
		toolchain_check_prerequisites

		# Now build the toolchain
		toolchain_build

		# Now create the toolchain tar archive
		package_toolchain
	fi

	base_build

	openfirewall_build

	misc_build

	packages_build

	# Cleanup
	stdumount
	${SUDO} ${RM} ${LFS}/tmp/*
	${SUDO} ${MV} ${BASEDIR}/build_${MACHINE}/${INSTALLER_DIR}/images/${SNAME}-${VERSION}-install-* ${BASEDIR}/
	${SUDO} ${MV} ${BASEDIR}/build_${MACHINE}/${INSTALLER_DIR}/images/${SNAME}-${VERSION}-update* ${BASEDIR}/
	[ "${VERSIONSTEP}" ] && ${SUDO} ${MV} ${BASEDIR}/build_${MACHINE}/${INSTALLER_DIR}/images/${SNAME}-${VERSIONSTEP}-update* ${BASEDIR}/

	[ "${RUNNING_TEST}" == 'yes' ] && parse_tests

	echo ""
	echo "... and all this hard work for:"
	${DU} -bsh ${BASEDIR}/${SNAME}-${VERSION}-install-cd.${MACHINE}.iso
	if [ x"${SKIP_USB_IMAGES}" != x"yes" ]; then
		${DU} -bsh ${BASEDIR}/${SNAME}-${VERSION}-install-usb-*.${MACHINE}.img.gz
	fi
	if [ "${VERSIONSTEP}" ]; then
		${DU} -bsh ${BASEDIR}/${SNAME}-${VERSIONSTEP}-update.${MACHINE}.tgz
	fi
	${DU} -bsh ${BASEDIR}/${SNAME}-${VERSION}-update.${MACHINE}.tgz
	BUILDTIME=$[`date +"%s"` - ${BUILDSTART}]
	BUILDMINUTES=$[${BUILDTIME} / 60]
	BUILDSECONDS=$[${BUILDTIME} - ${BUILDMINUTES}*60]
	echo "... which took: ${BUILDMINUTES} minutes and ${BUILDSECONDS} seconds"
	;;
buildsingle)
	if [ -z ${2} ]; then
		exiterror "Stage parameter missing, use 02 03 04"
	elif [ -z ${3} ]; then
		exiterror "Packagename parameter missing"
	fi

	if [ ! -f lfs/${3} ]; then
		exiterror "Packagename lfs/${3} does not exist"
	fi
	STAGE_ORDER=${2}
	if [ ${STAGE_ORDER} == '02' ]; then
		STAGE=base
	elif [ ${STAGE_ORDER} == '03' ]; then
		STAGE=openfirewall
	elif [ ${STAGE_ORDER} == '04' ]; then
		STAGE=misc
	else
		exiterror "Incorrect stage parameter, use 02 03 04"
	fi
	# force rebuild
	rm -f ${BASEDIR}/files_${MACHINE}/${STAGE_ORDER}_${STAGE}/${3}*
	check_running_test ${4}
	prepareenv
	beautify build_stage "Building single package in stage ${STAGE}"
	chroot_make ${3}
	stdumount
	[ "${RUNNING_TEST}" == 'yes' ] && parse_tests
	;;
shell)
	# Enter a shell inside LFS chroot
	prepareenv
	# on sparc64 and ppc64, we don't want to set WRAPPER_32BIT to configure the kernel
	[ x"${MACHINE_REAL}" == x"sparc64" ] && unset WRAPPER_32BIT
	[ x"${MACHINE_REAL}" == x"ppc64" ] && unset WRAPPER_32BIT
	entershell
	;;
changelog)
	echo "Building new doc/ChangeLog from SVN"
	# svn2cl script come from http://ch.tudelft.nl/~arthur/svn2cl/

	${BASEDIR}/tools/svn2cl/svn2cl.sh -r "COMMITTED:$[${PREVIOUSSVNREV} + 1]" -o ${BASEDIR}/doc/ChangeLog-${VERSION}
	cp ${BASEDIR}/doc/ChangeLog ${BASEDIR}/doc/ChangeLog.tmp
	cat > ${BASEDIR}/doc/ChangeLog <<END
###
#
# ${VERSION} release
#
###

END
	cat ${BASEDIR}/doc/ChangeLog-${VERSION} >> ${BASEDIR}/doc/ChangeLog
	cat ${BASEDIR}/doc/ChangeLog.tmp >> ${BASEDIR}/doc/ChangeLog
	rm ${BASEDIR}/doc/ChangeLog.tmp ${BASEDIR}/doc/ChangeLog-${VERSION}
	echo
	echo "Verify the release 'marker' in doc/ChangeLog and commit doc/ChangeLog to update SVN"
	;;
check_url)
	echo "Checking sources files availability on the web"
	if [ ! -d ${DIR_CHK} ]; then
		${MKDIR} ${DIR_CHK}
	fi

	FINISHED=0
	cd ${BASEDIR}/lfs
	for c in `seq ${MAX_RETRIES}`
	do
		if [ ${FINISHED} -eq 1 ]; then
			break
		fi

		FINISHED=1
		cd ${BASEDIR}/lfs
		for i in *
		do
			if [ -f "${i}" -a x"${i}" != x"Config" ]; then
				make -s -f ${i} MACHINE=${MACHINE} LFS_BASEDIR=${BASEDIR} LFS=${LFS} \
				MESSAGE="${i}\t (${c}/${MAX_RETRIES})" check
				if [ ${?} -ne 0 ]; then
					echo "Check : wget error in lfs/${i}"
					FINISHED=0
				fi
			fi
		done
	done

	cd - > /dev/null
	;;
check_url_clean)
	echo "Erasing sources files availability tags"
	${RM} ${DIR_CHK}/*
	;;
check_versions)
		echo -ne "${BOLD}*** Comparing LFS-${LFS_BRANCH} & ${NAME}-${VERSION}"
		echo -ne "${SET_REQUIRED_COL}      LFS${SET_FOUND_COL}    OPENFIREWALL"
		echo -ne "${SET_RESULT_COL} status${NORMAL}\n"

		wget -q ${LFS_PACKAGES_URL} -O - \
			| grep 'span class="term"' \
			| tr 'A-Z' 'a-z' \
			| sed	-e 's,berkeley ,,g' \
				-e 's,^.*span class="term">\(.*\) (\([0-9]*[^ ]*\)).*$,\1 \2,g' \
			| grep -v -E "documentation|add-on|lfs-bootscripts|man-|configuration|optional" \
			| while IFS= read -r LINE
			do
				PKG_NAME=`echo ${LINE} | awk '{print $1}'`

				if [ ! -f "${BASEDIR}/lfs/${PKG_NAME}" ]; then
					beautify message INFO "${PKG_NAME} not used in ${SNAME}-${VERSION}"
				else
					PKG_LFS=`echo ${LINE} | cut -d" " -f2`
					if [ x"${PKG_NAME}" == x"xz" ]; then
						# Listed as Xz Utils in LFS
						PKG_LFS=`echo ${LINE} | cut -d" " -f3`
					fi
					get_pkg_ver ${BASEDIR}/lfs/${PKG_NAME}

					check_version "${PKG_NAME}" ${PKG_LFS} ${PKG_VER}
					unset PKG_NAME PKG_LFS PKG_VER
				fi
			done

		beautify message INFO "Failures are not necessarily bad."
	;;
check_distrowatch)
        echo -ne "${BOLD}*** Comparing DistroWatch & ${NAME}-${VERSION}"
        echo -ne "${SET_REQUIRED_COL}  Distrowatch${SET_FOUND_COL}    OPENFIREWALL"
        echo -ne "${SET_RESULT_COL} status${NORMAL}\n"

        wget -q --user-agent=Lynx http://distrowatch.com/packages.php -O - \
            | while IFS= read -r LINE
            do
                if echo ${LINE} | grep -q "<th><a href=" ; then
                    PKG_NAME=`echo ${LINE} | sed -e 's#.*">\(.*\)<\/a.*#\1#g'`
                    if [ x"${PKG_NAME}" == x"httpd" ]; then
                        PKG_NAME=apache
                    fi
                    if [ -f "${BASEDIR}/lfs/${PKG_NAME}" ]; then
                        IFS= read -r LINE
                        PKG_DISTRO=`echo ${LINE} | sed -e 's#.*">\(.*\)<\/a.*#\1#g'`
                        get_pkg_ver ${BASEDIR}/lfs/${PKG_NAME}

                        check_version "${PKG_NAME}" ${PKG_DISTRO} ${PKG_VER}
                    fi
                    unset PKG_NAME PKG_DISTRO PKG_VER
                fi
            done

        beautify message INFO "Failures are not necessarily bad."
    ;;
clean)
	echo -ne "Cleaning ${BOLD}${MACHINE}${NORMAL} buildtree${SET_RESULT_COL}"

	stdumount
	[ ${?} -ne 0 ] && exiterror "Not safe to clean the tree with some mountpoint still there, retry when compilation has finished"

	${SUDO} ${RM} ${BASEDIR}/build_${MACHINE}
	${SUDO} ${RM} ${BASEDIR}/files_${MACHINE}
	${SUDO} ${RM} ${BASEDIR}/log_${MACHINE}
	${SUDO} ${RM} ${BASEDIR}/updates/${VERSION}/patch.tar.gz

	if [ -h /${TOOLS_DIR} ]; then
		${SUDO} ${RM} /${TOOLS_DIR}
	fi

	rm -rf ${BASEDIR}/cache/tmp/*

	beautify message DONE
	;;
ccache_clean)
	echo -ne "Cleaning ${BOLD}ccache cache${NORMAL} (patience) ... ${SET_RESULT_COL}"
	[ -f ${CCACHE} ] && ${CCACHE} --clear > /dev/null
	beautify message DONE
	;;
dist)
	# TODO: How to do ./make.sh dist for multiple architectures ?
	echo "Building list of changed files"
	# TODO: build list of changed files

	echo "Calculating MD5 of release files"
	MD5INSTALL=`md5sum openfirewall-${VERSION}-install*`
	if [ "${VERSIONSTEP}" ]; then
		MD5UPDATE=`md5sum openfirewall-${VERSIONSTEP}-update*.gpg openfirewall-${VERSION}-update*.gpg`
	else
		MD5UPDATE=`md5sum openfirewall-${VERSION}-update*.gpg`
	fi

	# Create release-notes-<VERSION>.txt, the file will need some manual modification
	# but can be uploaded directly to SF and attached to the release file(s)
	echo "Creating release notes file for ${VERSION}"
	NOTESFILE=${BASEDIR}/doc/release-notes-${VERSION}.txt
	cat > ${NOTESFILE} <<END
Openfirewall ${VERSION} is released

### Modification summary here

You need to reboot to use the new kernel after upgrading to ${VERSION}.

Updates
${MD5UPDATE}

Installation
${MD5INSTALL}

### Modification details here
### or better to link to a ChangeLog that we put somewhere online ?

END

	;;
newupdate)
	# create structure for $VERSION update
	if [ ! -e "updates/${VERSION}" ]; then
		if [ "${VERSIONSTEP}" ]; then
			# Tweak previous version if upgrade requires 2 packages
			PREVIOUSVERSION=${VERSIONSTEP}
		fi
		echo -ne "Preparing structure for update ${BOLD}${VERSION}${NORMAL}, previous ${BOLD}${PREVIOUSVERSION}${NORMAL}\n"
		echo -ne "Create directory for ${VERSION} and populate with files"
		mkdir -p updates/${VERSION}
		for i in updates/template/ROOTFILES.*
		do
			cp ${i} updates/${VERSION}/`basename ${i}`-${VERSION}
		done
		sed -e "s+^UPGRADEVERSION.*$+UPGRADEVERSION=${VERSION}+" \
			-e "s+^PREVIOUSVERSION.*$+PREVIOUSVERSION=${PREVIOUSVERSION}+" \
				updates/template/setup > updates/${VERSION}/setup
		sed -e "s+UPGRADEVERSION+${VERSION}+" \
			-e "s+PREVIOUSVERSION+${PREVIOUSVERSION}+" \
				updates/template/information.xml > updates/${VERSION}/information.xml
		beautify message DONE
		echo -ne "Adding directory $VERSION to svn\n"
		svn add updates/${VERSION}
		beautify message DONE
	else
		beautify message FAIL "updates/$VERSION already exists"
		exit 1
	fi
	;;
prefetch)
	# Create cache and cache/tmp
	prepareenv
	# Download all the packages marked as OTHER_SRC=yes
	if [ "${2}" -a x"${2}" == x"all" ]; then
		loadsrc all
	else
		loadsrc
	fi

	if [ $? -eq 1 ]; then
		beautify message WARN "Some files in ${BASEDIR}/cache failed to download or have incorrect md5 sums"
	fi
	stdumount
	;;
othersrc)
	loadsrc all

	if [ $? -eq 1 ]; then
		beautify message WARN "Some files in ${BASEDIR}/cache failed to download or have incorrect md5 sums"
	else

		echo -ne "${BOLD}*** Creating othersrc tarball. This may take some time${NORMAL}\n"
		echo -ne "${OTHERSRC}"

		# Create build marker and start progress indicator tool (if activated)
		BUILD_MARKER="${BASEDIR}/log_${MACHINE}/_marker_06_othersrc-list"
		touch ${BUILD_MARKER}
		[ x"${SHOW_PROGRESS}" == x"yes" ] && RESULT_COL=${RESULT_COL} \
			SET_TIME_COL=${SET_TIME_COL} \
			BOLD=${BOLD} \
			NORMAL=${NORMAL} \
			${BASEDIR}/tools/progress.sh ${BUILD_MARKER} &

		cd ${BASEDIR}/cache && tar -c --files-from=${BASEDIR}/log_${MACHINE}/_build_06_othersrc-list.log \
			-jf ${BASEDIR}/${OTHERSRC} && md5sum ${BASEDIR}/${OTHERSRC} > ${BASEDIR}/${OTHERSRC}.md5

		COMPILE_RESULT=${?}
		${RM} ${BUILD_MARKER}

		if [ ${COMPILE_RESULT} -ne 0 ]; then
			beautify message FAIL
		else
			beautify message DONE
		fi

	cd - > /dev/null
	fi
	;;
toolchain)
	# Prepare the environment
	check_running_test ${2}
	prepareenv

	# Check if host can build the toolchain
	toolchain_check_prerequisites

	# Now build the toolchain
	toolchain_build

	# Since we're stopping here, run stdumount
	stdumount

	# Now create the toolchain tar archive
	package_toolchain
	[ "${RUNNING_TEST}" == 'yes' ] && parse_tests

	BUILDTIME=$[`date +"%s"` - ${BUILDSTART}]
	BUILDMINUTES=$[${BUILDTIME} / 60]
	BUILDSECONDS=$[${BUILDTIME} - ${BUILDMINUTES}*60]
	echo "took: ${BUILDMINUTES} minutes and ${BUILDSECONDS} seconds"
	;;
gettoolchain)
	# Create cache and cache/tmp
	prepareenv
	URL_OFPKGS=`grep URL_OFPKGS lfs/Config | awk '{ print $3 }'`
	echo "Loading ${TOOLCHAINNAME}"

	# load to temp directory and move only if md5 match
	# that's the only way to support wget -c and load same toolchain name
	# wich may or may not have a different size when locally build
	cd ${BASEDIR}/cache/tmp
	wget -c ${URL_OFPKGS}/o/${TOOLCHAINNAME} ${URL_OFPKGS}/o/${TOOLCHAINNAME}.md5 -P ${BASEDIR}/cache/tmp

	if [ ${?} -ne 0 ]; then
		echo -ne "Error downloading toolchain for ${MACHINE} machine"
		beautify message FAIL
		echo "Precompiled toolchain not always available for every MACHINE"
	else
		if [ "`md5sum ${TOOLCHAINNAME} | awk '{print $1}'`" = "`cat ${TOOLCHAINNAME}.md5 | awk '{print $1}'`" ]; then
			beautify message DONE
			echo "Toolchain md5 ok"
			mv -f ${TOOLCHAINNAME}.md5 ${TOOLCHAINNAME} ${BASEDIR}/cache
		else
			exiterror "${TOOLCHAINNAME}.md5 did not match, check downloaded package"
		fi
	fi
	stdumount
	;;
language)
	${BASEDIR}/tools/gen_strings.pl ${BASEDIR} langs/
	;;
*)
	echo "Usage: ${0} {prefetch|build|clean|gettoolchain|check_files|language|shell}"
	cat doc/make.sh-usage
	exit 1
	;;
esac

#########################################################################################################
#########################################################################################################
# End of BLOCK 3 -- THIS IS WHERE EXECUTION ENDS							#
#########################################################################################################
#########################################################################################################
