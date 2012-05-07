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

#define RAD_AUTH_HDR_LEN	20
#define RAD_AUTH_PACKET_LEN	4096
#define RAD_AUTH_TOKEN_LEN	16
#define RAD_MAX_PASS_LEN	128

#define RAD_ATTR_USER_NAME	1	/*string*/
#define RAD_ATTR_USER_PASSWORD	2	/*passwd*/
#define RAD_ATTR_NAS_IP_ADDR	4	/*ip*/
#define RAD_ATTR_NAS_PORT	5	/*int*/
#define RAD_ATTR_SERVICE_TYPE	6	/*int*/
#define RAD_ATTR_ACCTID		44
#define RAD_ATTR_PORT_TYPE	61	/*int*/
#define RAD_ATTR_EAP		79	/*oct*/
#define RAD_ATTR_MESSAGE	80	/*oct*/

enum RADIUS_CODE {
	RAD_CODE_AUTHREQUEST	=	1,
	RAD_CODE_AUTHACCEPT	=	2,
	RAD_CODE_AUTHREJECT	=	3,
	RAD_CODE_ACCTREQUEST	=	4,
	RAD_CODE_ACCTRESPONSE	=	5,
	RAD_CODE_AUTHCHALLENGE	=	11
};

struct eap_info {
        char    code;
        char    id;             /*session id*/
        short   len;            /*this will be same as pae len whole eap len*/
	char	type;
};

struct rad_head {
	char	code;
	char	id;
	short	len;
	unsigned char	token[16];
};

struct radattr {
	unsigned char	type;
	unsigned char	len;
	unsigned char	*value;
};

struct rad_packet {
	struct	rad_head head;
	unsigned char	attrs[RAD_AUTH_PACKET_LEN - RAD_AUTH_HDR_LEN];
};

struct rad_info {
	struct rad_packet *packet;
	int	len;
	int	sockfd;
	struct sockaddr_in addr;
};

unsigned char *addattr(struct rad_info *lrp, char type, unsigned char *val, char len) {
	unsigned char *data = lrp->packet->attrs + lrp->len - 20;

	if (!len) {
		return NULL;
	}

	data[0] = type;
	data[1] = len + 2;
	if (val) {
		memcpy(data + 2, val, len);
	}

	lrp->len += data[1];
	return data;
}

void addattrint(struct rad_info *lrp, char type, unsigned int val) {
	unsigned int tval;

	tval = htonl(val);
	addattr(lrp, type, (unsigned char*)&tval, sizeof(tval));
}

void addattrip(struct rad_info *lrp, char type, char *ipaddr) {
	unsigned int tval;

	tval = inet_addr(ipaddr);
	addattr(lrp, type, (unsigned char*)&tval, sizeof(tval));
}

void addattrstr(struct rad_info *lrp, char type, char *str) {
	addattr(lrp, type, (unsigned char*)str, strlen(str));
}

void addattrpasswd(struct rad_info *lrp, char *pw, char *secret) {
	unsigned char pwbuff[RAD_MAX_PASS_LEN];
	unsigned char digest[RAD_AUTH_TOKEN_LEN];
	MD5_CTX c, old;
	int len, n, i;

	len = strlen(pw);
	if (len > RAD_MAX_PASS_LEN) {
		len = RAD_MAX_PASS_LEN;
	}

	memcpy(pwbuff, pw, len);
	memset(pwbuff+len, 0, RAD_MAX_PASS_LEN -len);

	/* pad len to RAD_AUTH_TOKEN_LEN (16)*/
	if (!len) {
		len = RAD_AUTH_TOKEN_LEN;
	}  else if (!(len & 0xf)) {
		len += 0xf;
		len &= ~0xf;
	}

	MD5_Init(&c);
	MD5_Update(&c, secret, strlen(secret));
	old = c;

	MD5_Update(&c, lrp->packet->head.token, RAD_AUTH_TOKEN_LEN);
	for (n = 0; n < len; n += RAD_AUTH_TOKEN_LEN) {
		if (n > 0) {
			c = old;
			MD5_Update(&c, pwbuff + n - RAD_AUTH_TOKEN_LEN, RAD_AUTH_TOKEN_LEN);
                }
		MD5_Final(digest, &c);
		for (i = 0; i < RAD_AUTH_TOKEN_LEN; i++) {
			pwbuff[i + n] ^= digest[i];
		}
	}
	addattr(lrp, RAD_ATTR_USER_PASSWORD, pwbuff, len);
}

struct rad_info *new_radpacket(unsigned char code, unsigned char id) {
	struct rad_info *lrp;

	if ((lrp = malloc(sizeof(*lrp)))) {
		memset(lrp, 0, sizeof(*lrp));
		if ((lrp->packet = malloc(sizeof(struct rad_packet)))) {
			memset(lrp->packet, 0, sizeof(*lrp->packet));
			lrp->len = RAD_AUTH_HDR_LEN;
			lrp->packet->head.id = id;
			lrp->packet->head.code = code;
			genrand(&lrp->packet->head.token, RAD_AUTH_TOKEN_LEN);
		} else {
			free(lrp);
			lrp = NULL;
		}
	}
	return lrp;
}

int send_radpacket(struct rad_info *lrp, char *ipaddr, int port, char *secret) {
	unsigned char* vector;
	int scnt;

	lrp->addr.sin_family = PF_INET;
	lrp->addr.sin_port = htons(port);
	inet_aton(ipaddr, &lrp->addr.sin_addr);
	if ((lrp->sockfd = socket(lrp->addr.sin_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		return (-1);
	}

	vector = addattr(lrp, RAD_ATTR_MESSAGE, NULL, 16);
	lrp->packet->head.len = htons(lrp->len);
	md5hmac(vector + 2, lrp->packet, lrp->len, secret, strlen(secret));

	scnt = sendto(lrp->sockfd, lrp->packet, lrp->len, 0, (const struct sockaddr *)&lrp->addr, sizeof(lrp->addr));
	if (lrp->len != scnt) {
		return (-1);
	}
	return (0);
}

int rad_recv(struct rad_info *request, char *secret) {
	struct rad_packet *lrpr;
	unsigned char buff[4096];
	unsigned char rtok[RAD_AUTH_TOKEN_LEN];
	unsigned char rtok2[RAD_AUTH_TOKEN_LEN];
	socklen_t alen;
	int chk, plen;

	alen  = sizeof(request->addr);

	chk = recvfrom(request->sockfd, buff, 4096, 0, (struct sockaddr*)&request->addr, &alen);

	lrpr = (struct rad_packet*)&buff;
	plen = ntohs(lrpr->head.len);

	if ((chk < plen) || (chk <= RAD_AUTH_HDR_LEN)) {
		printf("OOps Did not get proper packet\n");
		return -1;
	}

	memcpy(rtok, lrpr->head.token, RAD_AUTH_TOKEN_LEN);
	memcpy(lrpr->head.token, request->packet->head.token, RAD_AUTH_TOKEN_LEN);
	md5sum2(rtok2, lrpr, plen, secret, strlen(secret));

	if (md5cmp(rtok, rtok2, RAD_AUTH_TOKEN_LEN)) {
		printf("Invalid Signature");
	}

	return 0;
}

int radmain (int argc, char **argv) {
	unsigned char uuid[16];
	struct eap_info eap;
	int cnt, cnt2;
	char *user = "gregory";
	char *secret = "RadSecret";
	unsigned char *data;
	struct rad_info *lrp;
	unsigned char *ebuff;

	seedrand();

	lrp = new_radpacket(RAD_CODE_AUTHREQUEST, 1);
	addattrstr(lrp, RAD_ATTR_USER_NAME, user);
	addattrpasswd(lrp, "testpw",  secret);
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

	if (send_radpacket(lrp, "127.0.0.1", 1812, secret)) {
		printf("Sending Failed\n");
		return -1;
	}

	cnt = lrp->len - RAD_AUTH_HDR_LEN;
	data = lrp->packet->attrs;
	while(cnt > 0) {
		printf("Type %i Len %i / %i 0x", data[0], data[1], cnt);
		for (cnt2 = 2;cnt2 < data[1]; cnt2++) {
			printf("%02x", data[cnt2]);
		}
		printf("\n");
		cnt -= data[1];
		data += data[1];
	}


	rad_recv(lrp, secret);
	return 0;
}
