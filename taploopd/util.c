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

#include <sys/socket.h>
#include <linux/if_arp.h>
#include <unistd.h>
#include <fcntl.h>

#include "refobj.h"

/*
 * read from /dev/random
 */
void linrand(void *buf, int len) {
	int fd = open("/dev/random", O_RDONLY);

	read(fd, buf, len);
	close(fd);
}

/*
 * create random MAC address
 */
void randhwaddr(unsigned char *addr) {
	linrand(addr, ETH_ALEN);
	addr [0] &= 0xfe;       /* clear multicast bit */
	addr [0] |= 0x02;       /* set local assignment bit (IEEE802) */
}
