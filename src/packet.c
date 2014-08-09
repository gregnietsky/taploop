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
#include <linux/if_arp.h>
#include <stdio.h>
#include <unistd.h>

#include <dtsapp.h>

#include "include/taploop.h"
#include "include/tlsock.h"

/*
 * EAP Protocol Specification
 *
 * http://www.javvin.com/protocol8021X.html
 * ftp://ftp.iplcommunication.com.au/Alcatel%20Downloads/Documentation/OXE%20Release%208.0%20Expert%20manual/09011b02809a8934-1191670860784/cdrom/content/1_1_9_6_3.html
 * http://www.ietf.org/rfc/rfc3748.txt
 *	Extensible Authentication Protocol (EAP)
 *
 * http://www.ietf.org/rfc/rfc3580.txt
 *	IEEE 802.1X Remote Authentication Dial In User Service (RADIUS)
 *	Usage Guidelines
 *
 * http://www.ietf.org/rfc/rfc3579.txt
 *	RADIUS (Remote Authentication Dial In User Service)
 *	Support For Extensible Authentication Protocol (EAP)
 *
 * EAP does not support PMTU and requires setting Framed-MTU
 * MIN MTU 1020
 * Unknown eap code types mmust be ignored / logged
 * if multiple requests were sent multiple responses are possible and can be ignored
 * modify ID field for NEW packets
 * Request packets should be reliably relayed to radius
 *
 *	The Type field of a Response MUST either match that of the
 *	Request, or correspond to a legacy or Expanded Nak (see Section
 *	5.3) indicating that a Request Type is unacceptable to the peer.
 *	A peer MUST NOT send a Nak (legacy or expanded) in response to a
 *	Request, after an initial non-Nak Response has been sent.  An EAP
 *	server receiving a Response not meeting these requirements MUST
 *	silently discard it.
 *
 * Sucess / failure packets are not acked/nacked/retransmited
 *
 * Unauthenticated traffic arrives that should be authenticated
 * 1) Send PAE_TYPE_PACKET EAP_CODE_REQUEST EAP_TYPE_IDENTITY no data to new connections reliably
 * 2) Handshake Bellow
 *
 * Authentification Request Arrives PAE_TYPE_START
 * 1) Send identity to peer reliably
 *	PAE_TYPE_PACKET EAP_CODE_REQUEST EAP_TYPE_IDENTITY no data to new connections
 * 2) Handshake Bellow
 *
 * Handshake
 * 1) Wait for response and pass onto radius [What about NAK 3/254]
 *	PAE_TYPE_PACKET EAP_CODE_RESPONSE EAP_TYPE_IDENTITY
 * 2) Pass auth challenge from radius to peer [NB NAK]
 *	PAE_TYPE_PACKET EAP_CODE_REQUEST EAP_TYPE_* [>2 NB NAK 3/254]
 * 3) Auth response passed from peer to radius
 *	PAE_TYPE_PACKET EAP_CODE_RESPONSE EAP_TYPE_* [see 3 above]
 * 4) Radius will pass Success/Fail
 *	PAE_TYPE_PACKET EAP_CODE_[SUCCESS|FAILURE] NULL
 *
 * RADIUS
 * Copy eap_data response to identity into User-Name attr and do so for all access requests to radius
 * if this is not possible use Calling-Station-Id as User-Name [MAC ADDR] ie we did not send identify
 * Radius message 202 (decimal), "Invalid EAP Packet (Ignored)" is not fatal
 *	NAS identification attributes include NAS-Identifier,
 *	NAS-IPv6-Address and NAS-IPv4-Address.  Session identification
 *	attributes include User-Name, NAS-Port, NAS-Port-Type, NAS-Port-Id,
 *	Called-Station-Id, Calling-Station-Id and Originating-Line-Info.
 * CHECK RADIUS ACCEPT/FAIL MATCHES EAP_CODE 3/4
 * ACCESS Challenge MUST NOT BE code 3/4
 * Reply-Message can be sent in notification packet EAP_TYPE 2 but should rather ignore it
 *
 * The NAS-Port or NAS-Port-Id attributes SHOULD be included by the NAS
 * in Access-Request packets, and either NAS-Identifier, NAS-IP-Address
 * or NAS-IPv6-Address attributes MUST be included.
 *
 * EAP-Message must be accompanied by Message-Authenticator
 *
 *	Implementation Note: Because the authentication process will
 *	often involve user input, some care must be taken when deciding
 *	upon retransmission strategies and authentication timeouts.  It
 *	is suggested a retransmission timer of 6 seconds with a maximum
 *	of 10 retransmissions be used as default.  One may wish to make
 *	these timeouts longer in certain cases (e.g. where Token Cards
 *	are involved).  Additionally, the peer must be prepared to
 *	silently discard received retransmissions while waiting for
 *	user input.
 *
 *	Because the authentication process will often involve user input,
 *	some care must be taken when deciding upon retransmission strategies
 *	and authentication timeouts.  By default, where EAP is run over an
 *	unreliable lower layer, the EAP retransmission timer SHOULD be
 *	dynamically estimated.  A maximum of 3-5 retransmissions is
 *	suggested.
 *
 * http://www.ietf.org/rfc/rfc1321.txt The MD5 Message-Digest Algorithm
 * http://www.ietf.org/rfc/rfc2104.txt HMAC: Keyed-Hashing for Message Authentication
 */

enum EAP_CODE {
	EAP_CODE_REQUEST	= 1,
	EAP_CODE_RESPONSE	= 2,
	EAP_CODE_SUCCESS	= 3,
	EAP_CODE_ERROR		= 4
};

enum EAP_TYPE {
	EAP_TYPE_IDENTITY	= 1,
	EAP_TYPE_NOTIFICATION	= 2,
	EAP_TYPE_NAK		= 3,
	EAP_TYPE_MD5		= 4,
	EAP_TYPE_OTP		= 5,
	EAP_TYPE_GTC		= 6,
	EAP_TYPE_EXPANDED	= 254,
	EAP_TYPE_EXPERIMENTAL	= 255
};

enum PAE_TYPE {
	PAE_TYPE_PACKET		= 0,
	PAE_TYPE_START		= 1,	/*authentification requested explicitly*/
	PAE_TYPE_LOGOFF		= 2,
	PAE_TYPE_KEY		= 3,
	PAE_TYPE_ASFALERT	= 4
};

struct eap_data {
	char	type;
	char	*data;
};

struct eap_info {
	char	code;
	char	id;		/*session id*/
	short	len;		/*this will be same as pae len whole eap len >= 5 <= 253*/
	char	*eap_data;	/*depends on code NULL for success/failure*/
};

struct pae_hdr {
	short	etype;
	char	ver;
	char	ptype;
	short	len;		/* len of eap_info*/
	char	*eap_info;
};


static void frame_handler_pae(struct ethhdr *fr, void *packet, int *plen) {
	struct pae_hdr *pae;

	pae = (struct pae_hdr*)packet;

	/*check dst against MAC/BCAST/PAE*/
	/*check pae len and eap len*/

	/*on phy only PAE_START PAE_PACK PAE_LOGOFF EAP_RESPONSE are valid*/
	/*on virt PAE_PACK and not EAP_RESOPNSE*/

	printf("\tEth Type: %i Pae V: %i Packet: %i Len %i\n", pae->etype, pae->ver, pae->ptype, pae->len);
}

static void frame_handler_arp(struct ethhdr *fr, void *packet, int *plen) {
	struct arphdr *arp;

	arp = (struct arphdr*)packet;
	printf("\tHw: %i Proto: %i HW Len %i P Len %i OP %i\n", arp->ar_hrd, arp->ar_pro, arp->ar_hln, arp->ar_pln, arp->ar_op);
}

static void frame_handler_ipv4(struct ethhdr *fr, void *packet, int *plen) {
	struct iphdr *ip;
	unsigned char	*src,*dest;

	ip = (struct iphdr*)packet;
	src = (unsigned char *)&ip->saddr;
	dest = (unsigned char *)&ip->daddr;

	printf("\tS: %03i.%03i.%03i.%03i D: %03i.%03i.%03i.%03i P:%i\n",src[0], src[1], src[2], src[3], dest[0], dest[1], dest[2], dest[3], ip->protocol);
}

/*
 * Handle the packet for now we looking at the following
 * IPv4+6 to enable / disable them based on session info and snoop dhcp to link ip to mac
 * Vlans to put traffic onto a vlan either soft or kernel based
 * PPPoE for pppoe relay to a specified dsl port
 * 802.1x pass this on to a authenticator maybe talk to radius ??
 */
extern void process_packet(void *buffer, int len, struct taploop *tap, struct tl_socket *sock, struct tl_socket *osock, int offset) {
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

	plen = len - (sizeof(*fr));
	packet = (char *)buffer + offset + (len - plen);

	/*get the packet length and payload
	 * 8021Q is handled here so the protocol handlers get the packet
	 */
	if (etype == ETH_P_8021Q) {

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
	}

	/* frame handlers can mangle the packet and header
	 * osock can be set to a alternate socket as a placehoder i set obuff to buffer
	 */
	switch (fr->h_proto) {
		/* ARP*/
		case ETH_P_ARP: frame_handler_arp(fr, packet, &plen);
			break;
		/* IPv4*/
		case ETH_P_IP : frame_handler_ipv4(fr, packet, &plen);
			break;
		/*802.1x*/
		case ETH_P_PAE: frame_handler_pae(fr, packet, &plen);
			break;
		/* IPv6*/
		case ETH_P_IPV6:
			break;
		/* PPPoE [DSL]*/
		case ETH_P_PPP_DISC:
		case ETH_P_PPP_SES:
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
