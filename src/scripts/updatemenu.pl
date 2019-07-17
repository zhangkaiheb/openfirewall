#!/usr/bin/perl
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

#
# Lines in menu.lst match this for top-level menus:
# MENUTOP 010 system "alt system"
#
# Using 010, 020, 030 etc. the left -> right order is assigned, a symbolic name (in this case system)
# and the text to use.
# Custom menus can be inserted anywhere.
#
#
# grep the CGI files for specific lines:
# # MENUENTRY system 010 "alt home" "alt home" haveBlue haveProxy
#
# Use symbolic name to place in wanted menu, use 010, 020, 030 etc. to assign up/down position.
# haveBlue and haveProxy are optional flags, so menus can be selectively displayed.
#
#
# After making modifications, like adding a new CGI file, run updatemenu.pl and the menu will be
# regenerated.
#


use strict;

require '/usr/lib/ofw/lang.pl';

# Where we store our CGIs
my $path = "/usr/local/apache/cgi-bin/";

my @lines;
my @sublines = ();
my $line;
my %menunumbers = ();

my @l3lines = ();
##my @sub12lines = ();
##my @sub23lines = ();
#my %menul2numbers = ();
my %menul3numbers = ();

@lines = `cat /var/ofw/main/menu.lst`;
@sublines = `grep "# MENUENTRY" ${path}*.cgi`;
@l3lines = `grep "# MENUTHRDLVL" ${path}*.cgi`;

##@sub12lines = `grep "# MENUENTRY" ${path}*.cgi`;
##@sub23lines = `grep "# MENUTHRDLVL" ${path}*.cgi`;
# TODO: die if no content

open(MENUFILE, ">/usr/lib/ofw/menu.pl") or die "Unable to write menu";
print MENUFILE <<END
#!/usr/bin/perl
#
# This file is part of the Openfirewall.
#
# DO NOT MODIFY ANY CONTENT HERE.
# Use updatemenu.pl to (re)generate this file from the information contained in
# the CGI files.
#

package Menu;
\%Menu::menu = ();
\%Menu::l3menu = ();

sub buildmenu()
{
    my \$menuconfig = shift;

END
;


#
# Fetch top-level entries first, no need to sort as header.pl will take care of that.
#

foreach $line (@lines) {
    chomp $line;
    next unless ($line =~ /^MENUTOP\s+(\d{3})\s+(\w+)\s+"(.*)"/);
    my $head = $1;
    my $name = $2;
    my $contents = "\$Lang::tr{'$3'}";
    # Revert to the 'real text' if translation is missing
    $contents = "'$3'" unless(defined($Lang::tr{"$3"}));

    if (defined($menunumbers{$name})) {
        # protect against duplicates
        system("/usr/bin/logger -t openfirewall Duplicate MENUTOP: $name");
        next;
    }

    # TODO: skip top-level if there are no matching sub-level entries
    #  If a sub-level is missing, menu creation will fail in header.pl

    $menunumbers{$name} = $head;

    # And print to menu.pl
    print MENUFILE <<END
    \%{\$Menu::menu{"$head"}} = (
        'contents'   => $contents,
        'uri'        => '',
        'statusText' => '',
        'subMenu'    => []
    );
END
    ;
}

print MENUFILE "\n";


#
# Write out sub-level entries, sort on numbers.
#
@lines = ();
foreach $line (sort @sublines) {
    chomp $line;
    next unless ($line =~ /${path}(.*):# MENUENTRY\s+(\w+)\s+(\d{3})\s+(.*)/);
    my $cginame = "/cgi-bin/$1";
    my $name = $2;
    my $sub = $3;
    $line = $4;

#    next unless ($line =~ /"(.+?)"\s*(.*)/);
#    my $submenu = "'$1'";

    if (!defined($menunumbers{$name})) {
        # protect against non existing top-level
        system("/usr/bin/logger -t openfirewall Missing MENUTOP ($name) for $cginame");
        next;
    }

#    if (defined($menul2numbers{$submenu})) {
#        system("/usr/bin/logger -t openfirewall Duplicate MENUENTRY: $submenu");
#        open(STDERR, '>&', STDOUT) or die "Can't redirect stderr: $!";
#        print "p1 $1, name $name, sub $sub, line $line\n";
#        next;
#    }
#    $menul2numbers{$submenu} = "1";

    push(@lines, "$menunumbers{$name} $sub $cginame $line\n");
}


#
# We now have a sortable list
#

foreach $line (sort @lines) {
    chomp $line;
    next unless ($line =~ /(\d+)\s+(\d{3})\s+(.*?)\s+(.*)/);
    my $head = $1;
    my $sub = $2;
    my $cginame = "$3";
    my $menuname = '';
    $line = $4;

    # We need at least 1 text
    next unless ($line =~ /"(.+?)"\s*(.*)/);
    my $contents = "\$Lang::tr{'$1'}";
    $contents = "'$1'" unless(defined($Lang::tr{"$1"}));
    $menuname = $1;
    $line = $2;

    # A 2nd text is optional
    my $status = "''";
    if ($line =~ /"(.*?)"\s*(.*)/) {
        $status = "\$Lang::tr{'$1'}";
        $status = "'$1'" unless(defined($Lang::tr{"$1"}));
        $line = $2;
    }

    # A 3rd text is also optional
    my $uri = "";
    if ($line =~ /"(.*?)"\s*(.*)/) {
        $cginame = "${cginame}$1";
        $line = $2;
    }

    if (index($line, 'haveProxy') != -1) {
        print MENUFILE "    if (\$menuconfig->{'haveProxy'}) {\n";
    }
    if (index($line, 'haveBlue') != -1) {
        print MENUFILE "    if (\$menuconfig->{'haveBlue'}) {\n";
    }

    # If third submenu exist, disable the second level menu URI
    my @thirdmenu = `grep '# MENUTHRDLVL \"$menuname\"' ${path}*.cgi`;
    if ($#thirdmenu >= 0) {
        $cginame = '';
    }

    # And print to menu.pl
    print MENUFILE <<END
    push(\@{\$Menu::menu{"$head"}{'subMenu'}}, [ $contents, '$cginame', $status ]);
END
    ;

    if (index($line, 'haveBlue') != -1) {
        print MENUFILE "    }\n";
    }
    if (index($line, 'haveProxy') != -1) {
        print MENUFILE "    }\n";
    }

    print MENUFILE "\n";
}


##########################################################################################
#                                                                                        #
# Fetch third-level entries first.                                                       #
#                                                                                        #
##########################################################################################

foreach $line (@l3lines) {
    chomp $line;
    next unless ($line =~ /${path}(.*):# MENUTHRDLVL\s+"(.+?)"\s+(\d{3})\s+(.*)/);
    my $head = $1;
    my $name = $2;
    my $contents = "\$Lang::tr{'$1'}";
#print "content: $contents .. 1: $1\n";
    # Revert to the 'real text' if translation is missing
    $contents = "'$1'" unless(defined($Lang::tr{"$1"}));
#print "content2: $contents \n";

#    if (!defined($menul2numbers{$name})) {
#        # protect against duplicates
#        system("/usr/bin/logger -t openfirewall Missing MENUENTRY: $name");
#        next;
#    }


    if (defined($menul3numbers{$name})) {
        system("/usr/bin/logger -t openfirewall Duplicate MENUENTRY: $name");
        next;
    }
    # TODO: skip top-level if there are no matching sub-level entries
    #  If a sub-level is missing, menu creation will fail in header.pl

    $menul3numbers{$name} = "1";

    # And print to menu.pl
    print MENUFILE <<END
    \%{\$Menu::l3menu{"$name"}} = (
        'subMenu'    => []
    );
END
    ;
}

print MENUFILE "\n";


#
# Write out third-level entries, sort on numbers.
#
@lines = ();
foreach $line (sort @l3lines) {
    chomp $line;
    next unless ($line =~ /${path}(.*):# MENUTHRDLVL\s+"(.+?)"\s+(\d{3})\s+(.*)/);
    my $cginame = "/cgi-bin/$1";
    my $name = $2;
    my $sub = $3;
    $line = $4;

#    if (!defined($menul2numbers{$name})) {
#        # protect against non existing top-level
#        system("/usr/bin/logger -t openfirewall Missing MENUENTRY ($name) for $cginame");
#        next;
#    }
    push(@lines, "$name $sub $cginame $line\n");
}

#
# We now have a sortable list
#

foreach $line (sort @lines) {
    chomp $line;
    next unless ($line =~ /(.+?)\s+(\d{3})\s+(.*?)\s+(.*)/);
    my $sub = $2;
    my $cginame = "$3";
    $line = $4;

    # find the sub-level menu
    my $head = "\$Lang::tr{'$1'}";
    $head = "'$1'" unless(defined($Lang::tr{"$1"}));

    # We need at least 1 text
    next unless ($line =~ /"(.+?)"\s*(.*)/);
    my $contents = "\$Lang::tr{'$1'}";
    $contents = "'$1'" unless(defined($Lang::tr{"$1"}));
    $line = $2;

    # A 2nd text is optional
    my $status = "''";
    if ($line =~ /"(.*?)"\s*(.*)/) {
        $status = "\$Lang::tr{'$1'}";
        $status = "'$1'" unless(defined($Lang::tr{"$1"}));
        $line = $2;
    }

    # A 3rd text is also optional
    my $uri = "";
    if ($line =~ /"(.*?)"\s*(.*)/) {
        $cginame = "${cginame}$1";
        $line = $2;
    }

    # And print to menu.pl
    print MENUFILE <<END
    push(\@{\$Menu::l3menu{"$head"}{'subMenu'}}, [ $contents, '$cginame', $status ]);
END
    ;

    print MENUFILE "\n";
}



print MENUFILE <<END
}

1;
END
;
close MENUFILE;



#####################################################################
#                                                                   #
# Write out menu layout.                                            #
#                                                                   #
#####################################################################

my @sub12lines = ();
my @sub23lines = ();

@sub12lines = `grep "# MENUENTRY" ${path}*.cgi`;
@sub23lines = `grep "# MENUTHRDLVL" ${path}*.cgi`;


open(LAYOUTFILE, ">/usr/lib/ofw/menu-layout.pl") or die "Unable to write menu layout";

print LAYOUTFILE <<END
#!/usr/bin/perl
#
# This file is part of the Openfirewall.
#

package MLayout;
\%MLayout::layout = ();

sub buildlayout()
{

END
;


foreach $line (sort @sub23lines) {
    chomp $line;
    next unless ($line =~ /${path}(.*):# MENUTHRDLVL\s+"(.+?)"\s+(\d{3})\s+"(.+?)"\s+(.*)/);
    my $l1;
    my $cginame = "/cgi-bin/$1";

    my $l3 = "\$Lang::tr{'$4'}";
    $l3 = "'$4'" unless(defined($Lang::tr{"$4"}));

    my $l2 = "\$Lang::tr{'$2'}";
    $l2 = "'$2'" unless(defined($Lang::tr{"$2"}));



    foreach my $subline (sort @sub12lines) {
        chomp $subline;
        next unless ($subline =~ /${path}(.*):# MENUENTRY\s+(\w+)\s+(\d{3})\s+"(.+?)"\s+(.*)/);

        my $l2sub = "\$Lang::tr{'$4'}";
        $l2sub = "'$4'" unless(defined($Lang::tr{"$4"}));

        if ($l2sub eq $l2) {
            $l1 = "\$Lang::tr{'$2'}";
            $l1 = "'$2'" unless(defined($Lang::tr{"$2"}));
            last;
        }
    }


    print LAYOUTFILE <<END
    \%{\$MLayout::layout{"$cginame"}} = (
        'l1'    => $l1,
        'l2'    => $l2,
        'l3'    => $l3
    );
END
;
}

foreach my $subline (sort @sub12lines) {
    chomp $subline;
    next unless ($subline =~ /${path}(.*):# MENUENTRY\s+(\w+)\s+(\d{3})\s+"(.+?)"\s+(.*)/);

    my $cginame = "/cgi-bin/$1";

    my $l1 = "\$Lang::tr{'$2'}";
    $l1 = "'$2'" unless(defined($Lang::tr{"$2"}));

    my $l2 = "\$Lang::tr{'$4'}";
    $l2 = "'$4'" unless(defined($Lang::tr{"$4"}));

    my $l3;

    print LAYOUTFILE <<END
    \%{\$MLayout::layout{"$cginame"}} = (
        'l1'    => $l1,
        'l2'    => $l2,
        'l3'    => $l3
    );
END
;

}


print LAYOUTFILE <<END
}

1;
END
;
close LAYOUTFILE;

