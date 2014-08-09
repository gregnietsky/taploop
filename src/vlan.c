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

#include <sys/ioctl.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/if.h>

#include <dtsapp.h>

#include "include/taploop.h"
#include "include/tlsock.h"

/*
 * Create a VLAN on the device
 */
extern int add_kernvlan(char *iface, int vid) {
	struct taploop *tap = NULL;
	struct tl_socket *tlsock;
	struct bucket_loop *bloop;
	char ifname[IFNAMSIZ];
	int fd;

	/*check VID*/
	if ((vid <= 1 ) || (vid > 0xFFF)) {
		printf("Requested VID %i is out of range\n", vid);
		return (-1);
	}

	/* check for existing loop*/
	bloop = init_bucket_loop(taplist);
	while (bloop && (tap = next_bucket_loop(bloop))) {
		if (tap && !strncmp(tap->pdev, iface, IFNAMSIZ)) {
			break;
		}
		objunref(tap);
		tap = NULL;
	}
	remove_bucket_loop(bloop);

	if ((create_kernvlan(iface, vid))) {
		objunref(tap);
		return (-1);
	}

	snprintf(ifname, IFNAMSIZ, "%s.%i", iface, vid);

	if (!tap) {
		ifup(ifname, 0);
		return (0);
	}

	/*set the network dev up*/
	if ((fd = interface_bind(ifname, ETH_P_ALL, IFF_BROADCAST | IFF_MULTICAST)) < 0) {
		objunref(tap);
		return (-1);
	}

	/* add the socket to tap socks list we will not add this
	 * to select FD_SET as its a kernel vlan i may want to mangle
	 * traffic to it so will keep it on the list.
	 * when writing to this socket i need not append 802.1Q header
	 */
	if ((tlsock = objalloc(sizeof(*tlsock), NULL))) {
		tlsock->sock = fd;
		tlsock->vid = vid;
		tlsock->flags = TL_SOCKET_8021Q;
		objlock(tap);
		addtobucket(tap->socks, tlsock);
		objunlock(tap);
		objunref(tap);
	} else {
		printf("Memmory error\n");
		delete_kernvlan(iface, vid);
		close(fd);
		objunref(tap);
		return (-1);
	}

	return (0);
}
