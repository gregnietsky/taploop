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

#include <stdio.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>
#include <string.h>
#include <framework.h>

struct eap_info {
        char    code;
        char    id;             /*session id*/
        short   len;            /*this will be same as pae len whole eap len*/
	char	type;
};

unsigned char *radius_attr_first(struct radius_packet *packet) {
	return (packet->attrs);
}

unsigned char *radius_attr_next(struct radius_packet *packet, unsigned char *attr) {
	printf("diff %i", attr - packet->attrs);

	return NULL;
}

void radius_read(struct radius_packet *packet, void *pvt_data) {
	int cnt, cnt2;
	unsigned char *data;

	printf("\nREAD PACKET\n");
	cnt = packet->len - RAD_AUTH_HDR_LEN;
	data = radius_attr_first(packet);
	while(cnt > 0) {
		printf("Type %i Len %i / %i 0x", data[0], data[1], cnt);
		for (cnt2 = 2;cnt2 < data[1]; cnt2++) {
			printf("%02x", data[cnt2]);
		}
		printf("\n");
		radius_attr_next(packet, data);
		cnt -= data[1];
		data += data[1];
	}
}

int rad_dispatch(struct radius_packet *lrp, const char *userpass, radius_cb read_cb, void *cb_data) {
	unsigned char *data;
	int cnt, cnt2;

	if (send_radpacket(lrp, userpass, read_cb, NULL)) {
		printf("Sending Failed\n");
		return (-1);
	}

	printf("\nSENT PACKET\n");
	cnt = lrp->len - RAD_AUTH_HDR_LEN;
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
	return (0);
}

int radmain (void) {
	unsigned char *ebuff, uuid[16];
	struct eap_info eap;
	int cnt;
	char *user = "gregory";
	struct radius_packet *lrp;

	add_radserver("192.168.245.124", "1812", NULL, "RadSecret", 10);
	add_radserver("127.0.0.1", "1812", NULL, "RadSecret", 10);

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

	rad_dispatch(lrp, "testpass", radius_read, NULL);

/*	objunref(servers);*/

	return (0);
}
