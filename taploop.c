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
#include <sys/ioctl.h>
#include <sys/un.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>

#include "taploop.h"
#include "tlsock.h"
#include "refobj.h"
#include "util.h"
#include "thread.h"
#include "vlan.h"

/* Use uthash lists
 * Copyright (c) 2007-2011, Troy D. Hanson   http://uthash.sourceforge.net All rights reserved.
 */
#include "utlist.h"

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
 * handle signals to cleanup gracefully on exit
 */
static void sig_handler(int sig, siginfo_t *si, void *unused) {
	/* flag and clean all threads*/
	verifythreads(10000, 1);
	exit(0);
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

	printf("Copyright (C) 2012  Gregory Nietsky <gregory@distrotetch.co.za>\n"
"        http://www.distrotech.co.za\n\n"
"    This program comes with ABSOLUTELY NO WARRANTY\n"
"    This is free software, and you are welcome to redistribute it\n"
"    under certain condition\n");

	tundev = "/dev/net/tun";
	clsock = "/tmp/tlsock";

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
