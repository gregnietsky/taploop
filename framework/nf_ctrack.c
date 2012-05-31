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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include <framework.h>

enum NF_CTRACK_FLAGS {
	NFCTRACK_DONE    = 1 << 0
};

union l4hdr {
	struct tcphdr tcp;
	struct udphdr udp;
	struct icmphdr icmp;
};

struct nfct_struct {
	struct nfct_handle* nfct;
	int fd;
	int flags;
} *ctrack = NULL;

static void close_nfct(void *data) {
	struct nfct_struct* nfct = data;

	nfct_close(nfct->nfct);
}

static int nfct_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
	char buf[1024];

	nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3 | NFCT_OF_TIME | NFCT_OF_TIMESTAMP);
	printf("%s\n", buf);

	return NFCT_CB_CONTINUE;
}

static struct nfct_struct *nf_ctrack_alloc(uint8_t subsys_id, unsigned subscriptions) {
	struct nfct_struct *nfct;

	if (!(nfct = objalloc((sizeof *ctrack), close_nfct))) {
		return (NULL);
	}

	/* expectations and conntrack*/
	if (!(nfct->nfct = nfct_open(subsys_id, subscriptions))) {
		objunref(nfct);
		return (NULL);
	}

	if ((nfct->fd = nfct_fd(nfct->nfct)) < 0) {
		objunref(nfct);
		return (NULL);
	}

	return (nfct);
}

extern uint8_t nf_ctrack_init(void) {
	if (!(ctrack = nf_ctrack_alloc(0, 0))) {
		return (-1);
	}
	return (0);
}

static struct nf_conntrack *build_ct(uint8_t *pkt) {
	struct nf_conntrack *ct;
	struct iphdr *ip = (struct iphdr*)pkt;
	union l4hdr *l4 = (union l4hdr*)(ip + ip->ihl*4);

	if (!(ct = nfct_new())) {
		return (NULL);
	}

	nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, PF_INET);
	nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO, ip->protocol);
	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, ip->saddr);
	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, ip->daddr);

	switch(ip->protocol) {
		case IPPROTO_TCP:
			nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, l4->tcp.source);
			nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, l4->tcp.dest);
			break;
		case IPPROTO_UDP:
			nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, l4->udp.source);
			nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, l4->udp.dest);
			break;
		default:
			break;
	};

	nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);
/*	nfct_set_attr_u32(ct, ATTR_REPL_IPV4_SRC, ip->saddr);
	nfct_set_attr_u16(ct, ATTR_REPL_PORT_SRC, ip->daddr);*/

	if (ip->protocol == IPPROTO_TCP) {
		nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_SYN_SENT);
	}
	nfct_set_attr_u32(ct, ATTR_TIMEOUT, 120);

	return (ct);
}

extern uint8_t nf_ctrack_nat(uint8_t *pkt, uint32_t addr, uint16_t port, uint8_t dnat) {
	struct nf_conntrack *ct;
	uint8_t unref = 0;
	uint8_t ret = 0;

	if (!ctrack) {
		if (nf_ctrack_init()) {
			return (-1);
		}
		unref = 1;
	}

	ct = build_ct(pkt);

	nfct_set_attr_u32(ct, (dnat) ? ATTR_DNAT_IPV4 : ATTR_SNAT_IPV4, addr);
	if (port) {
		nfct_set_attr_u16(ct, (dnat) ? ATTR_DNAT_PORT : ATTR_SNAT_PORT, port);
	}

	objlock(ctrack);
	if (nfct_query(ctrack->nfct, NFCT_Q_CREATE_UPDATE, ct) < 0) {
		ret = -1;
	}
	objunlock(ctrack);
	nfct_destroy(ct);

	if (unref) {
		nf_ctrack_close();
	}

	return (ret);
}

extern void nf_ctrack_dump(void) {
	uint32_t family = PF_INET;
	uint8_t unref = 0;

	if (!ctrack) {
		if (nf_ctrack_init()) {
			return;
		}
		unref = 1;
	}

	objlock(ctrack);
	nfct_callback_register(ctrack->nfct, NFCT_T_ALL, nfct_cb, NULL);
	nfct_query(ctrack->nfct, NFCT_Q_DUMP, &family);
	nfct_callback_unregister(ctrack->nfct);
	objunlock(ctrack);

	if (unref) {
		nf_ctrack_close();
	}
}

static void *nf_ctrack_trace_th(void **data) {
	struct nfct_struct *nfct = *data;
	fd_set  rd_set, act_set;
	struct timeval tv;
	int selfd;
	int opt = 1;

	nfct_callback_register(nfct->nfct, NFCT_T_ALL, nfct_cb, NULL);

	FD_ZERO(&rd_set);
	FD_SET(nfct->fd, &rd_set);
	fcntl(nfct->fd, F_SETFD, O_NONBLOCK);
	ioctl(nfct->fd, FIONBIO, &opt);

	while (!testflag(nfct, NFCTRACK_DONE) && framework_threadok(data)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;
		selfd = select(nfct->fd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			continue;
		} else if (selfd < 0) {
			break;
		}

		if (FD_ISSET(nfct->fd, &act_set)) {
			nfct_catch(nfct->nfct);
		}
	}
	return (NULL);
}

struct nfct_struct *nf_ctrack_trace(void) {
	struct nfct_struct *nfct;

	if (!(nfct = nf_ctrack_alloc(CONNTRACK, NFCT_ALL_CT_GROUPS))) {
		return (NULL);
	}

	if (!framework_mkthread(nf_ctrack_trace_th, NULL, NULL, nfct)) {
		objunref(nfct);
		return (NULL);
	}
	return (nfct);
}

extern void nf_ctrack_endtrace(struct nfct_struct *nfct) {
	if (nfct) {
		setflag(nfct, NFCTRACK_DONE);
	}
	objunref(nfct);
}

extern void nf_ctrack_close(void) {
	if (ctrack) {
		objunref(ctrack);
	}
	ctrack = NULL;
}
