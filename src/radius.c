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

/*
 * User password crypt function from the freeradius project (addattrpasswd)
 * Copyright (C) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 The FreeRADIUS Server Project
 */

#include <string.h>
#include <uuid/uuid.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include <framework.h>
#include <openssl/md5.h>

#include "radius.h"

struct eap_info {
        char    code;
        char    id;             /*session id*/
        short   len;            /*this will be same as pae len whole eap len*/
	char	type;
};

int udpconnect(char *ipaddr, int port) {
	struct sockaddr_in addr;
	int sockfd;

	addr.sin_family = PF_INET;
	addr.sin_port = htons(port);
	inet_aton(ipaddr, &addr.sin_addr);
	if ((sockfd = socket(addr.sin_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		return (-1);
	}
	connect(sockfd, (const struct sockaddr *)&addr, sizeof(addr));

	return sockfd;
}

int send_radpacket(struct radius_packet *packet, int sockfd, char *userpass, char *secret) {
	unsigned char* vector;
	short len;
	int scnt;

	if (userpass) {
		addattrpasswd(packet, userpass,  secret);
	}

	vector = addattr(packet, RAD_ATTR_MESSAGE, NULL, RAD_AUTH_TOKEN_LEN);
	len = packet->len;
	packet->len = htons(len);
	md5hmac(vector + 2, packet, len, secret, strlen(secret));

	scnt = send(sockfd, packet, len, 0);
	if (len != scnt) {
		return (-1);
	}
	return (0);
}

int rad_recv(struct radius_packet *request, int sockfd, char *secret) {
	struct radius_packet *packet;
	unsigned char buff[4096];
	unsigned char rtok[RAD_AUTH_TOKEN_LEN];
	unsigned char rtok2[RAD_AUTH_TOKEN_LEN];
	int chk, plen;

	chk = recv(sockfd, buff, 4096, 0);

	packet = (struct radius_packet*)&buff;
	plen = ntohs(packet->len);

	if ((chk < plen) || (chk <= RAD_AUTH_HDR_LEN)) {
		printf("OOps Did not get proper packet\n");
		return -1;
	}

	memcpy(rtok, packet->token, RAD_AUTH_TOKEN_LEN);
	memcpy(packet->token, request->token, RAD_AUTH_TOKEN_LEN);
	md5sum2(rtok2, packet, plen, secret, strlen(secret));

	if (md5cmp(rtok, rtok2, RAD_AUTH_TOKEN_LEN)) {
		printf("Invalid Signature");
	}

	return 0;
}

int radmain (void) {
	unsigned char uuid[16];
	struct eap_info eap;
	int cnt, cnt2, sockfd;
	char *user = "gregory";
	char *secret = "RadSecret";
	unsigned char *data;
	struct radius_packet *lrp;
	unsigned char *ebuff;

	sockfd = udpconnect("127.0.0.1", 1812);

	lrp = new_radpacket(RAD_CODE_AUTHREQUEST, 1);
	addattrstr(lrp, RAD_ATTR_USER_NAME, user);
	addattrip(lrp, RAD_ATTR_NAS_IP_ADDR, "127.0.0.1");
	addattrint(lrp, RAD_ATTR_NAS_PORT, 0);
	addattrint(lrp, RAD_ATTR_SERVICE_TYPE, 1);
	addattrint(lrp, RAD_ATTR_PORT_TYPE, 15);

	eap.type = 1;
	eap.code = 2;
	eap.id = 1;
	cnt = 5 + strlen(user);
	eap.len = htons(cnt);
	ebuff = addattr(lrp, RAD_ATTR_EAP, (unsigned char*)&eap, cnt);
	memcpy(ebuff + 7, user, strlen(user));

	uuid_generate(uuid);
	addattr(lrp, RAD_ATTR_ACCTID, uuid, 16);

	if (send_radpacket(lrp, sockfd, "testpass", secret)) {
		printf("Sending Failed\n");
		return -1;
	}

	cnt = ntohs(lrp->len) - RAD_AUTH_HDR_LEN;
	data = lrp->attrs;
	while(cnt > 0) {
		printf("Type %i Len %i / %i 0x", data[0], data[1], cnt);
		for (cnt2 = 2;cnt2 < data[1]; cnt2++) {
			printf("%02x", data[cnt2]);
		}
		printf("\n");
		cnt -= data[1];
		data += data[1];
	}


	rad_recv(lrp, sockfd, secret);
	return 0;
}
