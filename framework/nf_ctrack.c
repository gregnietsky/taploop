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

struct nfct_struct {
	struct nfct_handle* nfct;
	int fd;
};

static void close_nfct(void *data) {
	struct nfct_struct* nfct = data;

	nfct_close(nfct->nfct);
}

static struct nfct_struct *nfctrack_init(uint8_t subsys_id, unsigned subscriptions) {
	struct nfct_struct* nfct;

	if (!(nfct = objalloc((sizeof *nfct), close_nfct))) {
		return (NULL);
	}

	if (!(nfct->nfct = nfct_open(subsys_id, subscriptions))) {
		objunref(nfct);
		return (NULL);
	}

	nfct->fd = nfct_fd(nfct->nfct);

	return (nfct);
}

void nf_ctrack_dnat(struct nfct_struct* nfct, uint8_t *pkt, uint32_t daddr, uint16_t dport) {
	struct iphdr *ip = (struct iphdr*)pkt;
	struct tcphdr *tcp = (struct tcphdr*)(ip + ip->ihl*4);
	struct nf_conntrack *ct;

	if (!(ct = nfct_new())) {
		perror("nfct_new");
		return;
	}

	nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, AF_INET);
	nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, ip->saddr);
	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, ip->daddr);
	nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, tcp->source);
	nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, tcp->dest);
	nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);
	nfct_set_attr_u32(ct, ATTR_REPL_IPV4_SRC, ip->saddr);
	nfct_set_attr_u16(ct, ATTR_REPL_PORT_SRC, ip->daddr);
	nfct_set_attr_u32(ct, ATTR_DNAT_IPV4, daddr);
	nfct_set_attr_u16(ct, ATTR_DNAT_PORT, dport);
	nfct_set_attr_u32(ct, ATTR_TIMEOUT, 120);
	nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_SYN_SENT2);

	if (nfct_query(nfct->nfct, NFCT_Q_CREATE, ct) < 0) {
		perror("nfct_query");
		return;
	}
	nfct_destroy(ct);
}

extern void add_ctrack(void) {
	nfctrack_init(NFNL_SUBSYS_CTNETLINK, NFNL_SUBSYS_CTNETLINK);
}
