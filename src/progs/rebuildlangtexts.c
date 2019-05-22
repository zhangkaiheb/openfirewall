/* Openfirewall helper program - rebuildhosts
 *
 * This file is part of the Openfirewall.
 *
 * Openfirewall is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Openfirewall is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Openfirewall; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * (c) 2018-2019, the Openfirewall Team
 *
 */


#include <stdlib.h>
#include "setuid.h"


int main(int argc, char *argv[])
{
    if (!(initsetuid()))
        exit(1);

    safe_system("perl -e \"require '/usr/lib/ofw/lang.pl'; &Lang::BuildAddonLang\"");

    return 0;
}
