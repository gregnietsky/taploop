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

#include <linux/ip.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>

#include <framework.h>

#include "taploop.h"
#include "tlsock.h"

void frame_handler_ipv4(struct ethhdr *fr, void *packet, int *plen) {
	struct iphdr *ip;
	unsigned char	*src,*dest;

	ip=(struct iphdr*)packet;
	src=(unsigned char *)&ip->saddr;
	dest=(unsigned char *)&ip->daddr;

	printf("\tS: %03i.%03i.%03i.%03i D: %03i.%03i.%03i.%03i P:%i\n",src[0], src[1], src[2], src[3], dest[0], dest[1], dest[2], dest[3], ip->protocol);
}

/*
 * Handle the packet for now we looking at the following
 * IPv4+6 to enable / disable them based on session info and snoop dhcp to link ip to mac
 * Vlans to put traffic onto a vlan either soft or kernel based
 * PPPoE for pppoe relay to a specified dsl port
 * 802.1x pass this on to a authenticator maybe talk to radius ??
 */
void process_packet(void *buffer, int len, struct taploop *tap, struct tl_socket *sock, struct tl_socket *osock, int offset) {
	char	*ptr = buffer;
	struct ethhdr	*fr;
	char		*packet;
	unsigned short	etype, vhdr, vid = 0, cfi = 0, pcp =0;
	int plen;

	ptr = ptr + offset;
	fr = (struct ethhdr*)ptr;


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
		packet = (char *)buffer + offset + (len - plen);
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
		packet = (char *)buffer + offset + (len - plen);
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
		} else if (write(osock->sock, buffer, len)) {
		}
		objunlock(tap);
	}
}
