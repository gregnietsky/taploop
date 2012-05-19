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
#include <linux/if_tun.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

/* use ring buffer af_packet*/
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>

#include <framework.h>

#include "include/taploop.h"
#include "include/tlsock.h"
#include "include/packet.h"

static int hash_tapdata(const void *data, int key) {
	int ret;
	const struct taploop *tap = data;
	const char* hashkey = (key) ? data : tap->pdev;

	ret = jenhash(hashkey, strlen(hashkey), 0);

	return(ret);
}

static void *inittaplist(void) {
	return (create_bucketlist(2, hash_tapdata));
}

/* tap the taploop struct
 * hwaddr used to set the tap device MAC adddress
 */
static struct tl_socket *virtopen(struct taploop *tap) {
	struct tl_socket *tlsock;
	int fd;

	objlock(tap);
	if ((fd = create_tun(tap->pdev, tap->hwaddr, IFF_TAP | IFF_NO_PI)) < 0) {
		objunlock(tap);
		return (NULL);
	}

	if ((tlsock = objalloc(sizeof(*tlsock), NULL))) {
		/*passing ref back*/
		objref(tlsock);
		tlsock->sock = fd;
		tlsock->vid = 0;
		tlsock->flags = TL_SOCKET_VIRT;
		addtobucket(tap->socks, tlsock);
	}
	objunlock(tap);

	return (tlsock);
}

/*
 * Initialise the physical device
 */
static struct tl_socket *phyopen(struct taploop *tap) {
	struct tl_socket *tlsock;
	struct tpacket_req reqr;
	int fd, mapsiz = 0;
	void *rxmmbuf = NULL;
	struct iovec *ring = NULL;

	if (ifrename(tap->pdev, tap->pname)) {
		return NULL;
	}

	objlock(tap);
	ifhwaddr(tap->pname, tap->hwaddr);
	objunlock(tap);

	/*set the device up*/
	if ((fd = interface_bind(tap->pname, ETH_P_ALL, IFF_BROADCAST | IFF_MULTICAST | IFF_PROMISC | IFF_NOARP | IFF_ALLMULTI)) < 0) {
		return NULL;
	}

#ifdef PACKET_MMAP_RX
	/* Setup the fd for mmap() ring buffer RX*/
	reqr.tp_block_size=8192; /*multiple of pagesize and power of 2 8192 seems best*/
	reqr.tp_block_nr=64;
	reqr.tp_frame_size=2048; /*must be a multiple of TPACKET_ALIGNMENT */
	reqr.tp_frame_nr= (reqr.tp_block_size / reqr.tp_frame_size) * reqr.tp_block_nr; /*must be exactly frames_per_block*tp_block_nr*/
	mapsiz = reqr.tp_block_size * reqr.tp_block_nr;

	/*enable RX Ring Buff*/
	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (char *)&reqr, sizeof(reqr))) {
		perror("setsockopt(PACKET_RX_RING)");
		close(fd);
		return NULL;
	};

	/*mmap the memory*/
	if ((rxmmbuf = mmap(NULL, mapsiz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		perror("mmap()");
		close(fd);
		return NULL;
	}

	/* configure ring buff*/
	if (ring = objalloc(reqr.tp_frame_nr * sizeof(struct iovec), NULL)) {
		int i;
		for(i=0; i<reqr.tp_frame_nr; i++) {
			ring[i].iov_base=(void *)((long)rxmmbuf)+(i*reqr.tp_frame_size);
			ring[i].iov_len=reqr.tp_frame_size;
		}
	} else {
		munmap(rxmmbuf, mapsiz);
		close(fd);
	}
#endif

	if ((tlsock = objalloc(sizeof(*tlsock), NULL))) {
		/*passing ref back*/
		objref(tlsock);
		tlsock->sock = fd;
		tlsock->vid = 0;
		tlsock->flags = TL_SOCKET_PHY;
		objlock(tap);
		tap->mmap_blks = reqr.tp_frame_nr;
		tap->mmap_size = reqr.tp_block_size;
		tap->mmap = rxmmbuf;
		tap->ring = ring;
		addtobucket(tap->socks, tlsock);
		objunlock(tap);
	} else {
		if (rxmmbuf) {
			munmap(rxmmbuf, mapsiz);
		}
		close(fd);
		if (ring) {
			objunref(ring);
		}
	}

	return (tlsock);
}

/*
 * close and free a tap loop
 */
static void *stoptap(void *data) {
	struct taploop	 *tap = data;
	struct tl_socket *phy = NULL, *virt = NULL, *socket;
	struct bucket_loop *bloop;
	int ifindex;

	if (!tap) {
		return NULL;
	}

	/* get physical socket to reconfigure it and drop it*/
	bloop = init_bucket_loop(tap->socks);
	while (bloop && (socket = next_bucket_loop(bloop))) {
		remove_bucket_loop(bloop);
		if (socket->flags & TL_SOCKET_PHY) {
			phy = socket;
		} else if (socket->flags & TL_SOCKET_VIRT) {
			virt = socket;
		} else {
			if (socket->flags & TL_SOCKET_8021Q) {
				delete_kernvlan(tap->pdev, socket->vid);
			}
			close(socket->sock);
			objunref(socket);
		}
		objunref(socket);
	}
	stop_bucket_loop(bloop);

	/*close the tap*/
	if (virt) {
		close(virt->sock);
		objunref(virt);
	}

	/*down the device and restore name*/
	if (phy) {
		ifindex = get_iface_index(tap->pname);
		set_interface_flags(ifindex, 0, IFF_UP | IFF_RUNNING | IFF_PROMISC | IFF_MULTICAST | IFF_ALLMULTI | IFF_NOARP);
		ifrename(tap->pname, tap->pdev);
		close(phy->sock);
		objunref(phy);
	}

	/* release mmap*/
	if (tap->mmap) {
		munmap(tap->mmap, tap->mmap_blks * tap->mmap_size);
	}

	if (tap->ring) {
		objunref(tap->ring);
	}

	objunref(data);
	return NULL;
}

/*
 * return a socklist entry and add sock to fd_set
 */
static void *addsocket(struct taploop *tap, struct tl_socket *tsock, int *maxfd, fd_set *rd_set) {
	if (tsock->sock > *maxfd) {
		*maxfd = tsock->sock;
	}
	FD_SET(tsock->sock, rd_set);

	return NULL;
}

/*
static void rbuffread(struct taploop *tap) {
	int i=0;

	while(*(unsigned long*)tap->ring[i].iov_base) {
		struct tpacket_hdr *h=tap->ring[i].iov_base;
		struct sockaddr_ll *sll=(void *)h + TPACKET_ALIGN(sizeof(*h));
		unsigned char *bp=(unsigned char *)h + h->tp_mac;

		printf("%u.%.6u: if%u %i %u bytes\n",
			h->tp_sec, h->tp_usec,
			sll->sll_ifindex,
			sll->sll_pkttype,
			h->tp_len);

		h->tp_status=0;
		i= (i == tap->mmap_blks-1) ? 0 : i+1;
	}
}
*/

/*
 * pass data between physical and tap
 */
static void *mainloop(void **data) {
	struct taploop	*tap = *data;
	/* accomodate 802.1Q [4]*/
	fd_set	rd_set, act_set;
	char	buffer[ETH_FRAME_LEN+4];
	int	maxfd, selfd, rlen;
	struct	timeval	tv;
	struct	tl_socket *tlsock, *osock, *phy, *virt;
	struct	bucket_loop *bloop;

	if (!tap) {
		return NULL;
	}

	FD_ZERO(&rd_set);

	/* initialise physical device*/
	if (!(phy = phyopen(tap))) {
		printf("Could not configure pysical device %s\n", tap->pdev);
		return NULL;
	}

	/* initialise virtual device*/
	if (!(virt = virtopen(tap))) {
		printf("Could not create TAP clone\n");
		close(phy->sock);
		objunref(phy);
		return NULL;
	}

	maxfd = 0;
	addsocket(tap, phy, &maxfd, &rd_set);
	addsocket(tap, virt, &maxfd, &rd_set);

	/* initialise tap device*/
	maxfd++;
	while (framework_threadok(data) && !tap->stop) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 2000;

		selfd = select(maxfd, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			continue;
		} else if (selfd < 0) {
			break;
		}

		bloop = init_bucket_loop(tap->socks);
		while (bloop && (tlsock = next_bucket_loop(bloop))) {
			if (FD_ISSET(tlsock->sock, &act_set)) {
				/*set the default output socket can be changed in handler*/
				/*make sure the socks dont disapear grab a ref as i my use them in a thread elsewhere*/

/*XXXXX optomise i have the ref handle it in packet*/

				if ((tlsock->flags & TL_SOCKET_PHY) || (tlsock->flags & TL_SOCKET_8021Q)) {
					rlen = recv(tlsock->sock, buffer, ETH_FRAME_LEN+4, 0);
				} else {
					rlen = read(tlsock->sock, buffer, ETH_FRAME_LEN+4);
				}
				if (rlen > 0) {
					if (tlsock->flags & TL_SOCKET_PHY) {
						osock = virt;
					} else {
						osock = phy;
					}
					process_packet(buffer, rlen, tap, tlsock, osock, 0);

				}
				break;
			}
			objunref(tlsock);
		}
		stop_bucket_loop(bloop);
	}

	/*remove ref's*/
	objunref(virt);
	objunref(phy);

	return NULL;
}

/*
 * allocate and start a phy <-> tap thread
 */
extern int add_taploop(char *dev, char *name) {
	struct taploop		*tap = NULL;

	if (!taplist && !(taplist = inittaplist())) {
		return (-1);
	}

	/* do not continue on zero length options*/
	if (!dev || !name || (dev[1] == '\0') || (name[1] == '\0')) {
		return (-1);
	}

	if ((tap = bucket_list_find_key(taplist, dev)) || !(tap = objalloc(sizeof(*tap), NULL))) {
		objunref(tap);
		return (-1);
	}

	strncpy(tap->pdev, dev, IFNAMSIZ);
	strncpy(tap->pname, name, IFNAMSIZ);
	tap->socks = create_bucketlist(5, NULL);
	tap->ring = NULL;
	tap->mmap = NULL;
	tap->mmap_size = 0;
	addtobucket(taplist, tap);

	/* Start thread*/
	return ((framework_mkthread(mainloop, stoptap, NULL, tap)) ? 0 : -1);
}

/*
 * stop a phy <-> tap thread
 */
extern int del_taploop(char *dev, char *name) {
	struct taploop		*tap = NULL;

	/* do not continue on zero length options*/
	if (!dev || !name || (dev[1] == '\0') || (name[1] == '\0')) {
		return (-1);
	}

	if (!taplist && !(taplist = inittaplist())) {
		return (-1);
	}

	if (!(tap = bucket_list_find_key(taplist, dev))) {
		return (-1);
	}

	/* Stop tap*/
	objlock(tap);
	tap->stop = 1;
	objunlock(tap);
	objunref(tap);

	return (0);
}
