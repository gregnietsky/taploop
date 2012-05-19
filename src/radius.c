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

static void packet_dump(struct radius_packet *packet) {
	unsigned char *data;
	int cnt;

	for(data = radius_attr_first(packet); data; data = radius_attr_next(packet, data)) {
		printf("Type %i Len %i 0x", data[0], data[1]);
		for (cnt = 2;cnt < data[1]; cnt++) {
			printf("%02x", data[cnt]);
		}
		printf("\n");
	}
}

static void radius_read(struct radius_packet *packet, void *pvt_data) {
	printf("\nREAD PACKET\n");
	packet_dump(packet);
}

extern int radmain (void) {
	unsigned char *ebuff, uuid[16];
	struct eap_info eap;
	int cnt;
	char *user = "gregory";
	struct radius_packet *lrp;

	add_radserver("192.168.245.124", "1812", NULL, "RadSecret", 10);
	add_radserver("127.0.0.1", "1812", NULL, "RadSecret", 10);

	lrp = new_radpacket(RAD_CODE_AUTHREQUEST, 1);
	addradattrstr(lrp, RAD_ATTR_USER_NAME, user);
	addradattrip(lrp, RAD_ATTR_NAS_IP_ADDR, "127.0.0.1");
	addradattrint(lrp, RAD_ATTR_NAS_PORT, 0);
	addradattrint(lrp, RAD_ATTR_SERVICE_TYPE, 1);
	addradattrint(lrp, RAD_ATTR_PORT_TYPE, 15);

	eap.type = 1;
	eap.code = 2;
	eap.id = 1;
	cnt = 5 + strlen(user);
	eap.len = htons(cnt);
	ebuff = addradattr(lrp, RAD_ATTR_EAP, (unsigned char*)&eap, cnt);
	memcpy(ebuff + 7, user, strlen(user));

	uuid_generate(uuid);
	addradattr(lrp, RAD_ATTR_ACCTID, uuid, 16);

	if (send_radpacket(lrp, "testpass", radius_read, NULL)) {
		printf("Sending Failed\n");
		return (-1);
	}

	printf("\nSENT PACKET\n");
	packet_dump(lrp);

	return (0);
}
