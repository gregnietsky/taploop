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

#include <netinet/in.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "framework.h"

/*#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>*/

/*
 * instruct the kernel to remove a VLAN
 */
int delete_kernvlan(char *ifname, int vid) {
	struct vlan_ioctl_args vifr;
	int proto = htons(ETH_P_ALL);
	int fd;

	/* open network raw socket */
	if ((fd = socket(PF_PACKET, SOCK_RAW, proto)) < 0) {
		return (-1);
	}

	memset(&vifr, 0, sizeof(vifr));
	snprintf(vifr.device1, IFNAMSIZ, "%s.%i", ifname, vid);
	vifr.u.VID = vid;
	vifr.cmd = DEL_VLAN_CMD;

	/*Delete the vlan*/
	if (ioctl(fd , SIOCSIFVLAN, &vifr) < 0) {
		perror("VLAN ioctl(SIOCSIFVLAN) Failed");
		close(fd);
		return (-1);
	}
	close(fd);
	return (0);
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
		return (-1);
	}

	/*Create the vlan*/
	if (ioctl(fd , SIOCSIFVLAN, &vifr) < 0) {
		perror("VLAN ioctl(SIOCSIFVLAN) Failed");
		close(fd);
		return (-1);
	}
	close(fd);
	return (0);
}

/*
 * instruct the kernel to remove a VLAN
 */
int delete_kernmac(char *ifname) {
	struct vlan_ioctl_args vifr;
	int proto = htons(ETH_P_ALL);
	int fd;

	/* open network raw socket */
	if ((fd = socket(PF_PACKET, SOCK_RAW, proto)) < 0) {
		return (-1);
	}

	memset(&vifr, 0, sizeof(vifr));
/*	snprintf(vifr.device1, IFNAMSIZ, "%s.%i", ifname, vid);
	vifr.u.VID = vid;*/
	vifr.cmd = DEL_VLAN_CMD;

	/*Delete the vlan*/
	if (ioctl(fd , SIOCSIFVLAN, &vifr) < 0) {
		perror("VLAN ioctl(SIOCSIFVLAN) Failed");
		close(fd);
		return (-1);
	}
	close(fd);
	return (0);
}

/*
 * instruct the kernel to create a VLAN
 */
int create_kernmac(char *ifname, char *macdev) {
	struct vlan_ioctl_args vifr;
	int proto = htons(ETH_P_ALL);
	int fd;

	memset(&vifr, 0, sizeof(vifr));
	strncpy(vifr.device1, ifname, IFNAMSIZ);
/*	vifr.u.VID = vid;*/
	vifr.cmd = ADD_VLAN_CMD;

	/* open network raw socket */
	if ((fd = socket(PF_PACKET, SOCK_RAW, proto)) < 0) {
		return (-1);
	}

	/*Create the vlan*/
	if (ioctl(fd , SIOCSIFVLAN, &vifr) < 0) {
		perror("VLAN ioctl(SIOCSIFVLAN) Failed");
		close(fd);
		return (-1);
	}
	close(fd);
	return (0);
}

/*
 * bind to device fd may be a existing socket
 */
int interface_bind(char *iface, int protocol, int flags) {
	struct ifreq ifr;
	struct sockaddr_ll sll;
	int proto = htons(protocol);
	int fd;


	/* open network raw socket */
	if ((fd = socket(PF_PACKET, SOCK_RAW,  proto)) < 0) {
		return (-1);
	}

	/*set the network dev up*/
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING | flags;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr ) < 0 ) {
       		perror("ioctl(SIOCSIFFLAGS) failed\n");
		close(fd);
	        return (-1);
	}

	/* set the interface index for bind*/
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl(SIOCGIFINDEX) failed\n");
		close(fd);
		return (-1);
	}

	/*bind to the interface*/
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = proto;
	sll.sll_ifindex = ifr.ifr_ifindex;
	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
		perror("bind failed");
		close(fd);
		return (-1);
	}

	return (fd);
}

/*
 * create random MAC address
 */
void randhwaddr(unsigned char *addr) {
	genrand(addr, ETH_ALEN);
	addr [0] &= 0xfe;       /* clear multicast bit */
	addr [0] |= 0x02;       /* set local assignment bit (IEEE802) */
}

int create_tun(const char *ifname, const unsigned char *hwaddr, int flags) {
	struct ifreq ifr;
	int fd, rfd;
	unsigned char rndhwaddr[ETH_ALEN];
	char *tundev = "/dev/net/tun";

	/* open the tun/tap clone dev*/
 	if ((fd = open(tundev, O_RDWR)) < 0) {
		return (-1);
 	}

 	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;

	/* configure the device*/
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0 ) {
		perror("ioctl(TUNSETIFF) failed\n");
		close(fd);
		return (-1);
	}

	/* set the MAC address*/
	if (!hwaddr) {
		randhwaddr(rndhwaddr);
	}

	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	memcpy(&ifr.ifr_hwaddr.sa_data, (hwaddr) ? hwaddr : rndhwaddr, ETH_ALEN);
	if (ioctl(fd, SIOCSIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCSIFHWADDR) failed\n");
		close(fd);
		return (-1);
	}

	/* open network raw socket */
	if ((rfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		close(fd);
		return (-1);
	}

	/*set the network dev up*/
	ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
	if (ioctl(rfd, SIOCSIFFLAGS, &ifr ) < 0 ) {
		perror("ioctl(SIOCSIFFLAGS) failed");
		close(rfd);
		close(fd);
		return (-1);
	}
	close(rfd);

	return (fd);
}

int ifdown(const char *ifname) {
	int proto = htons(ETH_P_ALL);
	struct ifreq ifr;
	int fd;

	/* open network raw socket */
	if ((fd = socket(PF_PACKET, SOCK_RAW, proto)) < 0) {
		return (-1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

	/*down the device*/
	ifr.ifr_flags &= ~IFF_UP & ~IFF_RUNNING;
	if (ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 ) {
		perror("ioctl(SIOCSIFFLAGS) failed");
		close(fd);
		return (-1);
	}

	close(fd);
	return (0);
}

int ifrename(const char *oldname, const char *newname) {
	int proto = htons(ETH_P_ALL);
	struct ifreq ifr;
	int fd;

	/* open network raw socket */
	if ((fd = socket(PF_PACKET, SOCK_RAW, proto)) < 0) {
		return (-1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, oldname, sizeof(ifr.ifr_name) - 1);

	/*down the device before renameing*/
	ifr.ifr_flags &= ~IFF_UP & ~IFF_RUNNING;
	if (ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 ) {
		perror("ioctl(SIOCSIFFLAGS) failed");
		close(fd);
		return (-1);
	}
	/* rename the device*/
	strncpy(ifr.ifr_newname, newname, IFNAMSIZ);
	if (ioctl(fd, SIOCSIFNAME, &ifr) <0 ) {
		perror("ioctl(SIOCSIFNAME) failed\n");
		close(fd);
		return (-1);
	} else {
		strncpy(ifr.ifr_name, newname, sizeof(ifr.ifr_name) - 1);
	}

	close(fd);
	return (0);
}

int ifhwaddr(const char *ifname, unsigned char *hwaddr) {
	int proto = htons(ETH_P_ALL);
	struct ifreq ifr;
	int fd;

	/* open network raw socket */
	if ((fd = socket(PF_PACKET, SOCK_RAW, proto)) < 0) {
		return (-1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

	/*get the MAC address*/
	if ((ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) ||
	    (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)) {
		perror("ioctl(SIOCGIFHWADDR) failed\n");
		close(fd);
		return (-1);
	}
	memcpy(hwaddr, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	close(fd);
	return (0);
}
