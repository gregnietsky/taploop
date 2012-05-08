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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <uuid/uuid.h>
#include <openssl/md5.h>
#include <framework.h>

#include "radius.h"

struct eap_info {
        char    code;
        char    id;             /*session id*/
        short   len;            /*this will be same as pae len whole eap len*/
	char	type;
};


/*
 * a radius session is based on a ID packets for
 * session are kept ?? the request token is also stored
 */
struct radius_session {
	unsigned short id;
	unsigned char request[RAD_AUTH_TOKEN_LEN];
	struct radius_connection *connex;
	struct radius_packet **packet;
};

/*
 * connect to the server one connex holds 256 sessions
 */
struct radius_connection {
	int socket;
	unsigned char id;
	int flags;
	struct radius_server *server;
	struct bucket_list *sessions;
};

/*
 * define a server with host auth/acct port and secret
 * create "connextions" on demand each with upto 256 sessions
 */
struct radius_server {
	const char	*name;
	const char	*authport;
	const char	*acctport;
	const char	*secret;
	struct bucket_lists *connex;
};

struct bucket_list *servers = NULL;

int hash_connex(void *data, int key) {
	int ret;
	struct radius_connection *connex = data;
	int *hashkey = (key) ? data : &connex->socket;

	ret = *hashkey;

	return (ret);
}

void radconnect(struct radius_server *server) {
	struct radius_connection *connex;

	if ((connex = objalloc(sizeof(*connex), NULL))) {
		if ((connex->socket = udpconnect(server->name, server->authport)) >= 0) {
			if (!server->connex) {
				server->connex = create_bucketlist(2, hash_connex);
			}
			genrand(&connex->id, sizeof(connex->id));
			connex->server = server;
			addtobucket(server->connex, connex);
		}
	}
	objunref(connex);
}

struct radius_session *radius_session(struct radius_packet *packet, struct radius_connection *connex) {
	struct radius_session *session = NULL;

	if ((session = objalloc(sizeof(*session), NULL))) {
		if (!connex->sessions) {
			connex->sessions = create_bucketlist(5, NULL);
		}
		memcpy(session->request, packet->token, RAD_AUTH_TOKEN_LEN);
		session->id = packet->id;
		session->connex = connex;
		addtobucket(connex->sessions, session);
	}
	return (session);
}

int send_radpacket(struct radius_packet *packet, const char *userpass) {
	int scnt;
	unsigned char* vector;
	short len, olen;
	struct radius_server *server;
	struct radius_session *session;
	struct radius_connection *connex;
	struct bucket_loop *sloop, *cloop;

	sloop = init_bucket_loop(servers);
	while (sloop && (server = next_bucket_loop(sloop))) {
		if (!server->connex) {
			radconnect(server);
		}
		cloop = init_bucket_loop(server->connex);
		while (cloop && (connex = next_bucket_loop(cloop))) {
			objlock(connex);
			if (connex->sessions) {
				if (bucket_list_cnt(connex->sessions) > 254) {
					objunlock(connex);
					objunref(connex);
					continue;
				}
			} else {
				create_bucketlist(5, NULL);
			}
			connex->id++;
			packet->id = connex->id;
			session = radius_session(packet, connex);
			objunlock(connex);

			olen = packet->len;
			if (userpass) {
				addattrpasswd(packet, userpass,  server->secret);
			}

			vector = addattr(packet, RAD_ATTR_MESSAGE, NULL, RAD_AUTH_TOKEN_LEN);
			len = packet->len;
			packet->len = htons(len);
			md5hmac(vector + 2, packet, len, server->secret, strlen(server->secret));

			scnt = send(connex->socket, packet, len, 0);
			objunref(connex);
			objunref(session);
			if (len == scnt) {
				remove_bucket_item(connex->sessions, session);
				objunref(server);
				stop_bucket_loop(cloop);
				stop_bucket_loop(sloop);
				return (0);
			} else {
				packet->len = olen;
				memset(packet->attrs + olen - RAD_AUTH_HDR_LEN, 0, len - olen);
			}
		}
		objunref(server);
		stop_bucket_loop(cloop);
	}
	stop_bucket_loop(sloop);

	return (-1);
}

int rad_recv(struct radius_packet *request) {
	struct radius_packet *packet;
	unsigned char buff[4096];
	unsigned char rtok[RAD_AUTH_TOKEN_LEN];
	unsigned char rtok2[RAD_AUTH_TOKEN_LEN];
	int chk, plen;
	char *secret = "RadSecret";
	int sockfd = -1;

	chk = recv(sockfd, buff, 4096, 0);

	packet = (struct radius_packet*)&buff;
	plen = ntohs(packet->len);

	if ((chk < plen) || (chk <= RAD_AUTH_HDR_LEN)) {
		printf("OOps Did not get proper packet\n");
		return (-1);
	}

	memcpy(rtok, packet->token, RAD_AUTH_TOKEN_LEN);
	memcpy(packet->token, request->token, RAD_AUTH_TOKEN_LEN);
	md5sum2(rtok2, packet, plen, secret, strlen(secret));

	if (md5cmp(rtok, rtok2, RAD_AUTH_TOKEN_LEN)) {
		printf("Invalid Signature");
	}

	return (0);
}

int hash_server(void *data, int key) {
	int ret;
	struct radius_server *server = data;
	const char* hashkey = (key) ? data : server->name;

	ret = jenhash(hashkey, strlen(hashkey), 0);

	return(ret);
}

void del_radserver(void *data) {
	struct radius_server *server = data;

	if (server->name) {
		free((char *)server->name);
	}
	if (server->authport) {
		free((char *)server->authport);
	}
	if (server->acctport) {
		free((char *)server->acctport);
	}
	if (server->secret) {
		free((char *)server->secret);
	}
}

void add_radserver(const char *ipaddr, const char *auth, const char *acct, const char *secret) {
	struct radius_server *server;

	if ((server = objalloc(sizeof(*server), del_radserver))) {
		 ALLOC_CONST(server->name, ipaddr);
		 ALLOC_CONST(server->authport, auth);
		 ALLOC_CONST(server->acctport, acct);
		 ALLOC_CONST(server->secret, secret);
		if (!servers) {
			servers = create_bucketlist(2, hash_server);
		}
		addtobucket(servers, server);
	}

	objunref(server);
}

void removeservers(void) {
	struct radius_server *server;
	struct bucket_loop *bloop;

	bloop = init_bucket_loop(servers);
	while (bloop && (server = next_bucket_loop(bloop))) {
		remove_bucket_loop(bloop);
		objunref(server);
	}
	stop_bucket_loop(bloop);
}

int radmain (void) {
	unsigned char *data, *ebuff, uuid[16];
	struct eap_info eap;
	int cnt, cnt2;
	char *user = "gregory";
	struct radius_packet *lrp;

	add_radserver("127.0.0.1", "1812", NULL, "RadSecret");

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

	if (send_radpacket(lrp, "testpass")) {
		printf("Sending Failed\n");
		return (-1);
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


/*
	rad_recv(lrp);
*/

	return (0);
}
