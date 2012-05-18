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

#include <sys/un.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "include/client.h"

static int connect_socket(char *sock) {
	struct sockaddr_un	adr;
	int fd, salen;

	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("Unable to connect (socket)");
		return (-1);
	}

	salen = sizeof(adr);
	memset(&adr, 0, salen);
	adr.sun_family = PF_UNIX;
	strncpy((char *)&adr.sun_path, sock, sizeof(adr.sun_path) -1);

	if (connect(fd, (struct sockaddr *)&adr, salen)) {
		perror("Unable to connect (connect)");
		return (-1);
	}
	return (fd);
}

int main(int argc, char *argv[]) {
	struct client_command cmd;
	struct client_response res;
	int ret = -1;
	int sock, len = 0;

	if (argc < 4) {
		printf("Invalid command\n");
		return (-1);
	}

	if ((sock = connect_socket("/tmp/tlsock")) < 0) {
		return (-1);
	}

	/* set action*/
	if (!strcmp(argv[1], "add")) {
		cmd.action = CA_ADD;
	} else if (!strcmp(argv[1], "rem")) {
		cmd.action = CA_REM;
	} else {
		printf("Invalid command\n");
		goto out;
	}

	/* set data type/opts*/
	if (!strcmp(argv[2], "tap") && (argc == 5)) {
		cmd.datatype = CD_TAP;
		strncpy(cmd.payload.tap.device, argv[3], IFNAMSIZ);
		strncpy(cmd.payload.tap.name, argv[4], IFNAMSIZ);
	} else if (!strcmp(argv[2], "vlan") && (argc == 5)) {
		cmd.datatype = CD_VLAN;
		strncpy(cmd.payload.vlan.device, argv[3], IFNAMSIZ);
		cmd.payload.vlan.vid = atoi(argv[4]);
	} else if (!strcmp(argv[2], "mac") && (cmd.action == CA_ADD) && (argc >= 5)) {
		cmd.datatype = CD_MACVLAN;
		strncpy(cmd.payload.macvlan.device, argv[3], IFNAMSIZ);
		strncpy(cmd.payload.macvlan.name, argv[4], IFNAMSIZ);
	} else if (!strcmp(argv[2], "mac") && (cmd.action == CA_REM) && (argc == 4)) {
		cmd.datatype = CD_MACVLAN;
		strncpy(cmd.payload.macvlan.device, argv[3], IFNAMSIZ);
	} else {
		printf("Invalid command\n");
		goto out;
	}

	if (write(sock, &cmd, sizeof(cmd))) {
		if ((len = read(sock, &res, sizeof(res)) == sizeof(res))) {
			printf("%s : %s\n", res.message, (res.error) ? "Failed" : "OK");
			ret = res.error;
		}
	}
out:
	close(sock);
	return (ret);
}
