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


#include "taploop.h"
#include "tlsock.h"
#include "refobj.h"
#include "util.h"
#include "thread.h"

/*
 * instruct the kernel to remove a VLAN
 */
int delete_kernvlan(int fd, char *ifname, int vid) {
	struct vlan_ioctl_args vifr;

	memset(&vifr, 0, sizeof(vifr));
	snprintf(vifr.device1, IFNAMSIZ, "%s.%i", ifname, vid);
	vifr.u.VID = vid;
	vifr.cmd = DEL_VLAN_CMD;

	/*Delete the vlan*/
	if (ioctl(fd , SIOCSIFVLAN, &vifr) < 0) {
		perror("VLAN ioctl(SIOCSIFVLAN) Failed");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/*
 * instruct the kernel to create a VLAN
 */
int create_kernvlan(char *ifname, int vid) {
	struct vlan_ioctl_args vifr;
	int proto = htons(ETH_P_ALL);
	int fd;

	memset(&vifr, 0, sizeof(vifr));
	strncpy(vifr.device1, ifname, IFNAMSIZ);
	vifr.u.VID = vid;
	vifr.cmd = ADD_VLAN_CMD;

	/* open network raw socket */
	if ((fd = socket(PF_PACKET, SOCK_RAW, proto)) < 0) {
		return -1;
	}

	/*Create the vlan*/
	if (ioctl(fd , SIOCSIFVLAN, &vifr) < 0) {
		perror("VLAN ioctl(SIOCSIFVLAN) Failed");
		close(fd);
		return -1;
	}
	return fd;
}

/*
 * Create a VLAN on the device
 */
void add_kernvlan(char *iface, int vid) {
	struct taploop *tap = NULL;
	struct ifreq ifr;
	struct sockaddr_ll sll;
	struct tl_socket *tlsock;
	int proto = htons(ETH_P_ALL);
	int fd;

	/*check VID*/
	if ((vid <= 1 ) || (vid > 0xFFF)) {
		printf("Requested VID %i is out of range\n", vid);
		return;
	}

	/* check for existing loop*/
	BLIST_FOREACH_START(taplist, tap) {
		if (tap && !strncmp(tap->pdev, iface, IFNAMSIZ)) {
			objref(tap);
			break;
		}
		tap = NULL;
	}
	BLIST_FOREACH_END;

	if (!tap) {
		return;
	}

	if ((fd = create_kernvlan(iface, vid)) < 0) {
		objunref(tap);
		return;
	}

	/*set the network dev up*/
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s.%i", iface, vid);
	ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr ) < 0 ) {
       		perror("ioctl(SIOCSIFFLAGS) failed\n");
		delete_kernvlan(fd, iface, vid);
		objunref(tap);
	        return;
	}

	/* set the interface index for bind*/
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl(SIOCGIFINDEX) failed\n");
		delete_kernvlan(fd, iface, vid);
		objunref(tap);
		return;
	}

	/*bind to the interface*/
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = proto;
	sll.sll_ifindex = ifr.ifr_ifindex;
	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
		perror("bind(ETH_P_ALL) failed");
		delete_kernvlan(fd, iface, vid);
		objunref(tap);
		return;
	}

	/* add the socket to tap socks list we will not add this
	 * to select FD_SET as its a kernel vlan i may want to mangle
	 * traffic to it so will keep it on the list.
	 * when writing to this socket i need not append 802.1Q header
	 */
	if ((tlsock = objalloc(sizeof(*tlsock)))) {
		tlsock->sock = fd;
		tlsock->vid = vid;
		tlsock->flags = TL_SOCKET_8021Q;
		objlock(tap);
		BLIST_ADD(tap->socks, tlsock);
		objunlock(tap);
	} else {
		printf("Memmory error\n");
		delete_kernvlan(fd, iface, vid);
	}
	objunref(tap);
};
