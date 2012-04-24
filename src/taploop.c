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

#include <sys/stat.h>
#include <stdio.h>

#include <framework.h>

#include "taploop.h"
#include "tlsock.h"
#include "vlan.h"
#include "config.h"

void *clientsock_client(void **data);
void delclientsock_client(void *data);

FRAMEWORK_MAIN("Taploop Network Stack",
		"Gregory Hinton Nietsky",
		PACKAGE_BUGREPORT,
		"http://www.distrotech.co.za",
		2012,
		"/var/run/taploopd") {

	/*client socket to allow client to connect*/
	tundev = "/dev/net/tun";
        int mask;

        mask = S_IXUSR | S_IWGRP | S_IRGRP | S_IXGRP | S_IWOTH | S_IROTH | S_IXOTH;
        framework_unixsocket("/tmp/tlsock", mask, clientsock_client, delclientsock_client);

	/* the bellow should be controlled by client not daemon*/
	if (argc >= 3) {
		if (add_taploop(argv[1], argv[2])) {
			printf("Failed to add taploop %s -> %s\n", argv[1], argv[2]);
		} else {
			/*XXX this is for testing add static vlans 100/150/200*/
			sleep(3);
			int i;
			for (i = 3;i < argc;i++ ) {
				add_kernvlan(argv[1], atoi(argv[i]));
			}
		}
	} else {
		printf("%s <DEV> <PHY NAME> [<VLAN> .....]\n", argv[0]);
	}
	return (0);
}
