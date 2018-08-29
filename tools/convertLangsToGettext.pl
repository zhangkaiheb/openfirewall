#!/usr/bin/perl
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
# Copyright (C) 2004-03-12 Mark Wormgoor <mark@wormgoor.com>               #
#                                                                          #
############################################################################
#
# $Id: convertLangsToGettext.pl 2 2007-04-07 18:46:27Z mark $
#
# Achim Weber 16 June 2006:
#	Adapted 'check_strings.pl' to convert old code with $Lang::tr{}
#	to use gettext.
#

use strict;
use warnings;
use Cwd;
use File::Find;

my $basedir = cwd();
print "-> $0\n";

sub convertFile
{
	if ( -f $File::Find::name && open(FILE, $File::Find::name))
	{
		# do not convert this script
		return if ($File::Find::name =~ /convertLangsToGettext.pl|lang.pl/);

		my @current = <FILE>;
		close(FILE);

		# Do we have to convert this file?
		return unless (grep (/\$Lang::tr{'([A-Za-z0-9,:_\s\/\.-]+)'}/, @current));

		print "Convert File: $File::Find::name\n";

		open(WRITE_FILE, ">$File::Find::name");
		flock WRITE_FILE, 2;

		foreach my $line (@current)
		{
			# we have to remove the line endings, otherwith the convert function
			# will remove them and two lines will be one line later.
			chomp($line);
			my $newLine = &convertLine($line);
			print WRITE_FILE "$newLine\n";
		}
		close(WRITE_FILE);
	}
}

sub convertLine
{
	my $line = shift;

	while($line =~ /(.*)\$Lang::tr{'([A-Za-z0-9,:_\s\/\.-]+)'}(.*)$/)
	{
		$line = $1."\$Lang::gt->gettext('$2')".$3;
	}
	return $line;
}

## Main
find (\&convertFile, $basedir );
