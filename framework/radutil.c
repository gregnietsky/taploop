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
#include <arpa/inet.h>
#include <openssl/md5.h>

#include "framework.h"

unsigned char *addattr(struct radius_packet *packet, char type, unsigned char *val, char len) {
	unsigned char *data = packet->attrs + packet->len - RAD_AUTH_HDR_LEN;

	if (!len) {
		return NULL;
	}

	data[0] = type;
	data[1] = len + 2;
	if (val) {
		memcpy(data + 2, val, len);
	}

	packet->len += data[1];
	return (data);
}

void addattrint(struct radius_packet *packet, char type, unsigned int val) {
	unsigned int tval;

	tval = htonl(val);
	addattr(packet, type, (unsigned char*)&tval, sizeof(tval));
}

void addattrip(struct radius_packet *packet, char type, char *ipaddr) {
	unsigned int tval;

	tval = inet_addr(ipaddr);
	addattr(packet, type, (unsigned char*)&tval, sizeof(tval));
}

void addattrstr(struct radius_packet *packet, char type, char *str) {
	addattr(packet, type, (unsigned char*)str, strlen(str));
}

void addattrpasswd(struct radius_packet *packet, char *pw, char *secret) {
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

	/* pad len to RAD_AUTH_TOKEN_LEN*/
	if (!len) {
		len = RAD_AUTH_TOKEN_LEN;
	}  else if (!(len & 0xf)) {
		len += 0xf;
		len &= ~0xf;
	}

	MD5_Init(&c);
	MD5_Update(&c, secret, strlen(secret));
	old = c;

	MD5_Update(&c, packet->token, RAD_AUTH_TOKEN_LEN);
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
	addattr(packet, RAD_ATTR_USER_PASSWORD, pwbuff, len);
}

struct radius_packet *new_radpacket(unsigned char code, unsigned char id) {
	struct radius_packet *packet;

	if ((packet = malloc(sizeof(*packet)))) {
		memset(packet, 0, sizeof(*packet));
		packet->len = RAD_AUTH_HDR_LEN;
		packet->code = code;
		genrand(&packet->token, RAD_AUTH_TOKEN_LEN);
	}
	return (packet);
}
