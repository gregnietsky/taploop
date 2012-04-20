#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>

#include "refobj.h"

/* Use uthash lists
 * Copyright (c) 2007-2011, Troy D. Hanson   http://uthash.sourceforge.net All rights reserved.
 */
#include "utlist.h"

/*socket flags*/
enum sockopt {
	TL_SOCKET_NONE	= 0,
	/*this is the tap socket */
	TL_SOCKET_VIRT	= 1 << 0,
	/*this is the physical socket */
	TL_SOCKET_PHY	= 1 << 1,
	/*when writing to this socket do so as 802.1q if vid set*/
	TL_SOCKET_8021Q	= 1 << 2,
};

enum threadopt {
	TL_THREAD_NONE	= 0,
	/* thread is marked as running*/
	TL_THREAD_RUN	= 1 << 1,
	/* thread is marked as complete*/
	TL_THREAD_DONE	= 1 << 2,
	/* This is a taploop*/
	TL_THREAD_TAP	= 1 << 3,
};

/* socket entry*/
struct tl_socket {
	int	sock;
	int	vid;		/* VLAN ID*/
	enum sockopt flags;
	struct	tl_socket	*next;
};

/* taploop structure defining sockets dev names*/
struct taploop {
	char	pname[IFNAMSIZ+1];
	char	pdev[IFNAMSIZ+1];
	unsigned char	hwaddr[ETH_ALEN];
	int	mmap_size;	/*for mmap ring buffer phy sock*/
	int	mmap_blks;	/*for mmap ring buffer phy sock*/
	void	*mmap;		/*mmaap buffer phy sock*/
	struct iovec *ring;	/*ring buffer phy*/
	struct	tl_socket *socks;
};

/* thread struct used to create threads*/
struct tl_thread {
	void	*data;
	enum threadopt flags;
	void	*(*cleanup)(void *data);
	pthread_t		thr;
	struct tl_thread	*next;
};

/* thread list*/
struct threadlist {
	struct	tl_thread	*list;
};

struct threadlist *threads;

/* tun/tap clone device and client socket*/
char	*tundev = "/dev/net/tun";
char	*clsock = "/tmp/tlsock";

void setflag(void *obj, void *flag, int flags) {
	int *flg = flag;
	objlock(obj);
	*flg |= flags;
	objunlock(obj);
}

void clearflag(void *obj, void *flag, int flags) {
	int *flg = flag;
	objlock(obj);
	*flg &= ~flags;
	objunlock(obj);
}

int testflag(void *obj, void *flag, int flags) {
	int *flg = flag;
	int ret = 0;
	objlock(obj);
	ret = (*flg & flags) ? 1 : 0;
	objunlock(obj);
	return ret;
}

/*
 * read from /dev/random
 */
void linrand(void *buf, int len) {
	int fd = open("/dev/random", O_RDONLY);

	read(fd, buf, len);
	close(fd);
}

void randhwaddr(unsigned char *addr) {
	linrand(addr, ETH_ALEN);
	addr [0] &= 0xfe;       /* clear multicast bit */
	addr [0] |= 0x02;       /* set local assignment bit (IEEE802) */
}


/* tap the taploop struct
 * hwaddr used to set the tap device MAC adddress
 */
struct tl_socket *virtopen(struct taploop *tap, struct tl_socket *phy) {
	struct ifreq ifr;
	struct tl_socket *tlsock;
	int fd;

	/* open the tun/tap clone dev*/
 	if ((fd = open(tundev, O_RDWR)) < 0) {
		return NULL;
 	}

 	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	/* configure the device as a tap with no PI*/
	strncpy(ifr.ifr_name, tap->pdev, IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0 ) {
		perror("ioctl(TUNSETIFF) failed\n");
		close(fd);
		return NULL;
	}

	/* set the MAC address*/
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	objlock(tap);
	memcpy(&ifr.ifr_hwaddr.sa_data, tap->hwaddr, ETH_ALEN);
	objunlock(tap);
	if (ioctl(fd, SIOCSIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCSIFHWADDR) failed\n");
		close(fd);
		return NULL;
	}

	/*set the network dev up*/
	ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
	if (ioctl(phy->sock, SIOCSIFFLAGS, &ifr ) < 0 ) {
       		perror("ioctl(SIOCSIFFLAGS) failed\n");
		close(fd);
	        return NULL;
	}

	if ((tlsock = objalloc(sizeof(*tlsock)))) {
		/*passing ref back*/
		objref(tlsock);
		tlsock->sock = fd;
		tlsock->vid = 0;
		tlsock->flags = TL_SOCKET_VIRT;
		objlock(tap);
		LL_APPEND(tap->socks, tlsock);
		objunlock(tap);
	}
	return tlsock;
}

/*
 * Initialise the physical device
 */
struct tl_socket *phyopen(struct taploop *tap) {
	struct ifreq ifr;
	struct sockaddr_ll sll;
	struct tl_socket *tlsock;
	struct tpacket_req reqr;
	int proto = htons(ETH_P_ALL);
	int fd, mapsiz = 0;
	void *rxmmbuf = NULL;
	struct iovec *ring = NULL;

	/* open network raw socket */
	if ((fd = socket(PF_PACKET, SOCK_RAW, proto)) < 0) {
		return NULL;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, tap->pdev, sizeof(ifr.ifr_name) - 1);

	/*down the device before renameing*/
	ifr.ifr_flags &= ~IFF_UP & ~IFF_RUNNING;
	if (ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 ) {
       		perror("ioctl(SIOCSIFFLAGS) failed\n");
		close(fd);
	        return NULL;
	}

	/* rename the device*/
	strncpy(ifr.ifr_newname, tap->pname, IFNAMSIZ);
	if (ioctl(fd, SIOCSIFNAME, &ifr) <0 ) {
		perror("ioctl(SIOCSIFNAME) failed\n");
		close(fd);
		return NULL;
	} else {
		strncpy(ifr.ifr_name, tap->pname, sizeof(ifr.ifr_name) - 1);
	}

	/*get the MAC address to be returned to allow tap to clone it*/
	if ((ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) ||
	    (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)) {
		perror("ioctl(SIOCGIFHWADDR) failed\n");
		close(fd);
		return NULL;
	}
	objlock(tap);
	memcpy(tap->hwaddr, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	objunlock(tap);

	/*set the device up*/
	ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST | IFF_PROMISC | IFF_NOARP | IFF_ALLMULTI;
	if (ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 ) {
       		perror("ioctl(SIOCSIFFLAGS) failed\n");
		close(fd);
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
	if (ring = objalloc(reqr.tp_frame_nr * sizeof(struct iovec))) {
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

	/* set the interface index for bind*/
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl(SIOCGIFINDEX) failed\n");
		if (rxmmbuf) {
			munmap(rxmmbuf, mapsiz);
		}
		close(fd);
		if (ring) {
			objunref(ring);
		}
		return NULL;
	}


	/*bind to the interface*/
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = proto;
	sll.sll_ifindex = ifr.ifr_ifindex;
	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
		perror("bind(ETH_P_ALL) failed");
		if (rxmmbuf) {
			munmap(rxmmbuf, mapsiz);
		}
		close(fd);
		if (ring) {
			objunref(ring);
		}
		return NULL;
	}

	if ((tlsock = objalloc(sizeof(*tlsock)))) {
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
		LL_APPEND(tap->socks, tlsock);
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

	return tlsock;
}

int delete_kernvlan(int fd, char *ifname, int vid) {
	struct vlan_ioctl_args vifr;

	memset(&vifr, 0, sizeof(vifr));
	snprintf(vifr.device1, IFNAMSIZ, "%s.%i", ifname, vid);
	vifr.u.VID = vid;
	vifr.cmd = DEL_VLAN_CMD;

	/*Create the vlan*/
	if (ioctl(fd , SIOCSIFVLAN, &vifr) < 0) {
		perror("VLAN ioctl(SIOCSIFVLAN) Failed");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

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
	struct tl_thread *thread;
	struct ifreq ifr;
	struct sockaddr_ll sll;
	struct tl_socket *tlsock;
	int proto = htons(ETH_P_ALL);
	int fd;

	/*check VID*/
	if ((vid <= 0 ) || (vid > 0xFFF)) {
		printf("Requested VID %i is out of range\n", vid);
		return;
	}

	/* check for existing loop*/
	objlock(threads);
	LL_FOREACH(threads->list, thread) {
		if (testflag(thread, &thread->flags, TL_THREAD_TAP)) {
			tap = thread->data;
			if (tap && !strncmp(tap->pdev, iface, IFNAMSIZ)) {
				objref(tap);
				break;
			}
			tap = NULL;
		}
	}
	objunlock(threads);

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
		LL_APPEND(tap->socks, tlsock);
		objunlock(tap);
	} else {
		printf("Memmory error\n");
		delete_kernvlan(fd, iface, vid);
	}
	objunref(tap);
};

/*
 * close and free a tap loop
 */
void *stoptap(void *data) {
	struct taploop	 *tap = data;
	struct ifreq ifr;
	struct tl_socket *phy = NULL, *virt = NULL;
	struct tl_socket *sl_ent, *sl_tmp;

	if (!tap) {
		return NULL;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, tap->pname, sizeof(ifr.ifr_name) - 1);

	/* get physical socket to reconfigure it and drop it*/
	objlock(tap);
	LL_FOREACH_SAFE(tap->socks, sl_ent, sl_tmp) {
		LL_DELETE(tap->socks, sl_ent);
		if (sl_ent->flags & TL_SOCKET_PHY) {
			phy = sl_ent;
		} else if (sl_ent->flags & TL_SOCKET_VIRT) {
			virt = sl_ent;
		} else {
			if (sl_ent->flags & TL_SOCKET_8021Q) {
				delete_kernvlan(sl_ent->sock, tap->pdev, sl_ent->vid);
			} else {
				close(sl_ent->sock);
			}
			objunref(sl_ent);
		}
	}
	objunlock(tap);

	/*close the tap*/
	if (virt) {
		close(virt->sock);
		objunref(virt);
	}

	/*down the device*/
	if (phy) {
		ifr.ifr_flags &= ~IFF_UP & ~IFF_RUNNING & ~IFF_PROMISC & ~IFF_MULTICAST & ~IFF_ALLMULTI & ~IFF_NOARP;
		ioctl(phy->sock, SIOCSIFFLAGS, &ifr);

		/*restore name*/
		strncpy(ifr.ifr_newname, tap->pdev, IFNAMSIZ);
		ioctl(phy->sock, SIOCSIFNAME, &ifr);

		/*close phy*/
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

void frame_handler_ipv4(struct ethhdr *fr, void *packet, int *plen) {
	struct iphdr *ip;
	unsigned char	*src,*dest;

	ip=(struct iphdr*)packet;
	src=(unsigned char *)&ip->saddr;
	dest=(unsigned char *)&ip->daddr;

	printf("\tS: %03i.%03i.%03i.%03i D: %03i.%03i.%03i.%03i P:%i\n",src[0], src[1], src[2], src[3], dest[0], dest[1], dest[2], dest[3], ip->protocol);
};

/*
 * Handle the packet for now we looking at the following
 * IPv4+6 to enable / disable them based on session info and snoop dhcp to link ip to mac
 * Vlans to put traffic onto a vlan either soft or kernel based
 * PPPoE for pppoe relay to a specified dsl port
 * 802.1x pass this on to a authenticator maybe talk to radius ??
 */
void process_packet(void *buffer, int len, struct taploop *tap, struct tl_socket *sock, struct tl_socket *osock, int offset) {
	struct ethhdr	*fr = buffer+offset;
	void		*packet;
	unsigned short	etype, vhdr, vid = 0, cfi = 0, pcp =0;
	int plen;

	/* i cannot be smaller than a ether header*/
	if (len < sizeof(*fr)) {
		return;
	}
	etype = ntohs(fr->h_proto);

	printf("Frame Of %i Bytes From %02x:%02x:%02x:%02x:%02x:%02x  To %02x:%02x:%02x:%02x:%02x:%02x type 0x%x\n", len, fr->h_source[0],
		fr->h_source[1], fr->h_source[2],fr->h_source[3], fr->h_source[4], fr->h_source[5],
		fr->h_dest[0], fr->h_dest[1], fr->h_dest[2], fr->h_dest[3], fr->h_dest[4], fr->h_dest[5], etype);

	/*get the packet length and payload
	 * 8021Q is handled here so the protocol handlers get the packet
	 */
	if (etype == ETH_P_8021Q) {
		plen = len - (sizeof(*fr));
		packet = buffer + offset + (len - plen);
		/* 2 byte VLAN Header*/
		vhdr = ntohs(*(unsigned short *)packet);
		/* 2 byte Real Protocol type*/
		etype = ntohs(*(unsigned short*)(packet+2));
		packet = packet + 4;
		plen = plen - 4;

		/* vid is 12 bits*/
		vid = vhdr & 0xFFF;
		cfi = (vhdr >> 12) & 0x1;
		pcp = (vhdr >> 13);

		printf("\tVID %i PCP %i CFI %i type 0x%x\n", vid, pcp, cfi, etype);
	} else {
		plen = len - (sizeof(*fr));
		packet = buffer + offset + (len - plen);
	}

	/* frame handlers can mangle the packet and header
	 * osock can be set to a alternate socket as a placehoder i set obuff to buffer
	 */
	switch (fr->h_proto) {
		/* ARP*/
		case ETH_P_ARP:
			break;
		/* RARP*/
		case ETH_P_RARP:
			break;
		/* IPv4*/
		case ETH_P_IP : frame_handler_ipv4(fr, packet, &plen);
			break;
		/* IPv6*/
		case ETH_P_IPV6:
			break;
		/* PPPoE [DSL]*/
		case ETH_P_PPP_DISC:
		case ETH_P_PPP_SES:
			break;
		/*802.1x*/
		case ETH_P_PAE:
			break;
		/* all other traffic ill pass on*/
		default:
			break;
	}

	/* XXX
	 * need routines and triggers to strip 802.1Q to phy
	 */

	/*Dispatch the packet if its not nulled [plen = 0] and the socket is valid*/
	if (plen && osock && osock->sock) {
		objlock(tap);
		if ((osock->flags & TL_SOCKET_PHY) || (osock->flags & TL_SOCKET_8021Q)) {
			send(osock->sock, buffer, len, 0);
		} else {
			write(osock->sock, buffer, len);
		}
		objunlock(tap);
	}
}

/*
 * return a socklist entry and add sock to fd_set
 */
struct socketlist *addsocket(struct taploop *tap, struct  tl_socket *tsock, int *maxfd, fd_set *rd_set) {
	if (tsock->sock > *maxfd) {
		*maxfd = tsock->sock;
	}
	FD_SET(tsock->sock, rd_set);

	return NULL;
};

/*
void rbuffread(struct taploop *tap) {
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
void *mainloop(void *data) {
	struct tl_thread *thread = data;
	struct taploop	*tap;
	/* accomodate 802.1Q [4]*/
	int buffsize = ETH_FRAME_LEN +4;
	fd_set	rd_set, act_set;
	char	buffer[buffsize];
	int	maxfd, selfd, rlen;
	struct	timeval	tv;
	struct  tl_socket *tlsock, *osock, *phy, *virt, *sl_tmp;

	if (thread && thread->data) {
		tap = thread->data;
	} else {
		return NULL;
	}

	setflag(thread, &thread->flags, TL_THREAD_RUN);
	FD_ZERO(&rd_set);

	/* initialise physical device*/
	if (!(phy = phyopen(tap))) {
		printf("Could not configure pysical device %s\n", tap->pdev);
		return NULL;
	}

	/* initialise virtual device*/
	if (!(virt = virtopen(tap, phy))) {
		printf("Could not create TAP clone\n");
		close(phy->sock);
		objunref(phy);
		return NULL;
	}

	addsocket(tap, phy, &maxfd, &rd_set);
	addsocket(tap, virt, &maxfd, &rd_set);

	/* initialise tap device*/
	maxfd++;
	while (testflag(thread, &thread->flags, TL_THREAD_RUN)) {
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

		objlock(tap);
		LL_FOREACH_SAFE(tap->socks, tlsock, sl_tmp) {
			if (FD_ISSET(tlsock->sock, &act_set)) {
				/*set the default output socket can be changed in handler*/
				/*make sure the socks dont disapear grab a ref as i my use them in a thread elsewhere*/
				objref(tlsock);
				objunlock(tap);

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
				objunref(tlsock);
				break;
			} else {
				tlsock = NULL;
			}
		}
		/* i was not nulled above was i not found ??*/
		if (!tlsock) {
			objunlock(tap);
		}
	}

	/*remove ref's*/
	objunref(virt);
	objunref(phy);

	setflag(thread, &thread->flags, TL_THREAD_DONE);
	return NULL;
}

/*
 * this is run to flag running threads to stop and clean up dead threads
 */
void checkthread(struct tl_thread *thread, int stop) {
	objlock(thread);

	if (stop && (thread->flags & TL_THREAD_RUN) && !(thread->flags & TL_THREAD_DONE)) {
		thread->flags &= ~TL_THREAD_RUN;
		objunlock(thread);
		return;
	}

	if ((thread->flags & TL_THREAD_DONE) || pthread_kill(thread->thr, 0)){
		LL_DELETE(threads->list, thread);
		if  (thread->cleanup) {
			thread->cleanup(thread->data);
		}
		objunlock(thread);
		objunref(thread->data);
		objunref(thread);
		return;
	}
	objunlock(thread);
}

/*
 * loop through all threads till they stoped
 * setting stop will flag threads to stop
 */
void verifythreads(int sl, int stop) {
	struct tl_thread	*thread, *tmp;
	pthread_t	me;

	me =  pthread_self();
	for(;;) {
		objlock(threads);
		if (!threads->list) {
			objunlock(threads);
			break;
		}

		LL_FOREACH_SAFE(threads->list , thread, tmp) {
			checkthread(thread, stop);
			/*this is my call im done*/
			if ((pthread_equal(thread->thr, me)) &&
			    (!(testflag(thread, &thread->flags, TL_THREAD_RUN)))) {
				setflag(thread, &thread->flags, TL_THREAD_DONE);
				pthread_cancel(me);
				pthread_detach(me);
				break;
			}
		}
		objunlock(threads);

		usleep(sl);
	}
}

/*
 * handle signals to cleanup gracefully on exit
 */
static void sig_handler(int sig, siginfo_t *si, void *unused) {
	/* flag and clean all threads*/
	verifythreads(10000, 1);
	exit(0);
}

/*
 * create a taploop thread
 */
struct tl_thread *mkthread(void *func, void *cleanup, void *data, enum threadopt flags) {
	struct tl_thread *thread;

	if (!(thread = objalloc(sizeof(*thread)))) {
		return NULL;
	}

	thread->data = data;
	thread->cleanup = cleanup;
	thread->flags = 0;
	thread->flags = flags;
	/* set this and check this in thread*/
	thread->flags &= ~TL_THREAD_RUN & ~TL_THREAD_DONE;

	/* grab a ref to data for thread to make sure it does not go away*/
	objref(thread->data);
	if (pthread_create(&thread->thr, NULL, func, thread)) {
		objunref(thread);
		objunref(thread->data);
		return NULL;
	}

	/* am i up and running move ref to list*/
	if (!pthread_kill(thread->thr, 0)) {
		objlock(threads);
		LL_APPEND(threads->list, thread);
		objunlock(threads);
		return thread;
	} else {
		objunref(thread);
	}

	return NULL;
}

void *managethread(void *data) {
	struct tl_thread *thread = data;

	setflag(thread, &thread->flags, TL_THREAD_RUN);
	verifythreads(100000, 0);
	setflag(thread, &thread->flags, TL_THREAD_DONE);

	return NULL;
}

/*
 * allocate and start a phy <-> tap thread
 */
int add_taploop(char *dev, char *name) {
	struct taploop		*tap = NULL;
	struct tl_thread	*thread;

	/* do not continue on zero  length options*/
	if (!dev || !name || (dev[1] == '\0') || (name[1] == '\0')) {
		return -1;
	}

	/* check for existing loop*/
	objlock(threads);
	LL_FOREACH(threads->list, thread) {
		if (testflag(thread, &thread->flags, TL_THREAD_TAP)) {
			tap = thread->data;
			if (tap && !strncmp(tap->pdev, dev, IFNAMSIZ)) {
				objunlock(threads);
				return -1;
			}
		}
	};
	objunlock(threads);

	if (!(tap = objalloc(sizeof(*tap)))) {
		return -1;
	}

	strncpy(tap->pdev, dev, IFNAMSIZ);
	strncpy(tap->pname, name, IFNAMSIZ);
	tap->socks = NULL;
	tap->ring = NULL;
	tap->mmap = NULL;
	tap->mmap_size = 0;

	/* Start thread*/
	return (mkthread(mainloop, stoptap, tap, TL_THREAD_TAP)) ? 0 : -1;
}

void *clientsock_client(void *data) {
	struct tl_thread *thread = data;
	int fd = *(int*)thread->data;

	setflag(thread, &thread->flags, TL_THREAD_RUN);

	int len = 256;
	char buff[256];
	len = read(fd, buff, len);
	printf("Connected %s %i\n", buff, len);
	*(int *)thread->data = -1;
	close(fd);

	setflag(thread, &thread->flags, TL_THREAD_DONE);

	return NULL;
}

/*
 * cleanup routine for client sock
 */
void delclientsock_client(void *data) {
	int fd = *(int *)data;

	if (fd >= 0) {
		close(fd);
	}
	objunref(data);

	return;
}

/*
 * client sock server
 */
void *clientsock_serv(void *data) {
	struct tl_thread *thread = data;
	char *sock = thread->data;
	struct sockaddr_un	adr;
	int fd;
	unsigned int salen;
	fd_set	rd_set, act_set;
	int selfd;
	struct	timeval	tv;
	int *clfd;

	setflag(thread, &thread->flags, TL_THREAD_RUN);

	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		return NULL;
	}

	fcntl(fd, F_SETFD, O_NONBLOCK);
	memset(&adr, 0, sizeof(adr));
	adr.sun_family = PF_UNIX;
	salen = sizeof(adr);
	strncpy((char *)&adr.sun_path, sock, sizeof(adr.sun_path) -1);

	if (bind(fd, (struct sockaddr *)&adr, salen)) {
		if (errno == EADDRINUSE) {
			/* delete old file*/
			unlink(sock);
			if (bind(fd, (struct sockaddr *)&adr, sizeof(struct sockaddr_un))) {
				perror("clientsock_serv (bind)");
				close(fd);
				return NULL;
			}
		} else {
			perror("clientsock_serv (bind)");
			close(fd);
			return NULL;
		}
	}

	if (listen(fd, 10)) {
		perror("client sock_serv (listen)");
		close(fd);
		return NULL;
	}

	FD_ZERO(&rd_set);
	FD_SET(fd, &rd_set);

	while (testflag(thread, &thread->flags, TL_THREAD_RUN)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 2000;

		selfd = select(fd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
     			continue;
		} else if (selfd < 0) {
			break;
		}

		if (FD_ISSET(fd, &act_set)) {
			clfd = objalloc(sizeof(int));
			if ((*clfd = accept(fd, (struct sockaddr *)&adr, &salen))) {
				mkthread(clientsock_client, delclientsock_client, clfd, TL_THREAD_NONE);
			} else {
				objunref(clfd);
			}
		}
	}

	setflag(thread, &thread->flags, TL_THREAD_DONE);
	return NULL;
};

/*
 * cleanup routine for client sock
 */
void delclientsock_serv(void *data) {
	char *sock = data;

	/* delete sock*/
	unlink(sock);

	return;
}

void *clientcon(void *data) {
	struct tl_thread *thread = data;
	char *sock = thread->data;
	struct sockaddr_un	adr;
	int fd, salen;

	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("client connect (socket)");
		return NULL;
	}

	salen = sizeof(adr);
	memset(&adr, 0, salen);
	adr.sun_family = PF_UNIX;
	strncpy((char *)&adr.sun_path, sock, sizeof(adr.sun_path) -1);

	if (connect(fd, (struct sockaddr *)&adr, salen)) {
		perror("clientcon (connect)");
		return NULL;
	}
	write(fd, sock, strlen(sock)+1);
	close(fd);
	return NULL;
}

/*
 * daemonise and start socket
 */
int main(int argc, char *argv[]) {
	pid_t	daemon;
	struct sigaction sa;
	struct tl_thread	*manage;

	/* fork and die daemonize*/
	daemon=fork();
	if (daemon > 0) {
		/* im all grown up and can pass onto child*/
		exit(0);
	} else if (daemon < 0) {
		/* could not fork*/
		exit(-1);
	}
	/*set pid for consistancy i was 0 when born*/
	daemon = getpid();

	/* Dont want these */
	signal(SIGTSTP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	/* interupt handler close clean on term so physical is reset*/
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sig_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGKILL, &sa, NULL);

	/*init the threadlist start thread manager*/
	threads = objalloc(sizeof(*threads));
	threads->list = NULL;
	manage = mkthread(managethread, NULL, NULL, TL_THREAD_NONE);

	/*client socket to allow client to connect*/
	mkthread(clientsock_serv, delclientsock_serv, clsock, TL_THREAD_NONE);

	/* the bellow should be controlled by client not daemon*/
	if (argc >= 3) {
		if (add_taploop(argv[1], argv[2])) {
			printf("Failed to add taploop %s -> %s\n", argv[1], argv[2]);
		} else {
			/*XXX this is for testing add static vlans 100/150/200*/
			sleep(3);
			int i;
			for (i = 3;i < argc;i++ ) {
				add_kernvlan(argv[1], atoi(argv[i]));
			}
		}
	} else {
		printf("%s <DEV> <PHY NAME> [<VLAN> .....]\n", argv[0]);
	}

	/* send some data to client socet for testing*/
	sleep(2);
	mkthread(clientcon, NULL, clsock, TL_THREAD_NONE);
	sleep(2);
	mkthread(clientcon, NULL, clsock, TL_THREAD_NONE);
	sleep(2);
	mkthread(clientcon, NULL, clsock, TL_THREAD_NONE);

	/*join the manager thread its the last to go*/
	pthread_join(manage->thr, NULL);

	/* turn off the lights*/
	return 0;
}
