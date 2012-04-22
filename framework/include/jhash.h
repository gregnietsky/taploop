/*
Copyright (C) 2012  Gregory Nietsky <gregory@distrotetch.co.za>
        http://www.distrotech.co.za

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>

/*easter egg copied from <linux/jhash.h>*/
#define JHASH_INITVAL		0xdeadbeef

uint32_t hashlittle(const void *key, size_t length, uint32_t initval);

#define jenhash(key, length, initval)	hashlittle(key, length, (initval) ? initval : JHASH_INITVAL);
