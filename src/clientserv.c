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

#include <unistd.h>
#include <stdio.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>

#include <framework.h>

#include "include/taploop.h"
#include "include/client.h"
#include "include/tlsock.h"
#include "include/clientserv.h"

static void client_tap(enum client_action act, struct client_tap *ctap, struct client_response *res) {
	switch (act) {
		case CA_ADD:
			res->error = add_taploop(ctap->device, ctap->name);
			snprintf(res->message, sizeof(res->message) - 1, "Adding TAP %s %s", ctap->device, ctap->name);
			break;
		case CA_REM:
			res->error = del_taploop(ctap->device, ctap->name);
			snprintf(res->message, sizeof(res->message) - 1, "Removing TAP %s", ctap->device);
			break;
	}

}

static void client_vlan(enum client_action act, struct client_vlan *cvlan, struct client_response *res) {
	switch (act) {
		case CA_ADD:
			res->error = add_kernvlan(cvlan->device, cvlan->vid);
			snprintf(res->message, sizeof(res->message) - 1, "Adding VLAN %s.%i", cvlan->device, cvlan->vid);
			break;
		case CA_REM:
			res->error = delete_kernvlan(cvlan->device, cvlan->vid);
			snprintf(res->message, sizeof(res->message) - 1, "Removing VLAN %s.%i", cvlan->device, cvlan->vid);
			break;
	}

}

static void client_macvlan(enum client_action act, struct client_mac *cmvlan, struct client_response *res) {
	switch (act) {
		case CA_ADD:
			res->error = create_kernmac(cmvlan->device, cmvlan->name, NULL);
			snprintf(res->message, sizeof(res->message) - 1, "Adding MAC %s to %s", cmvlan->name, cmvlan->device);
			if (!res->error) {
				ifup(cmvlan->name, 0);
			}
			break;
		case CA_REM:
			res->error = delete_kernmac(cmvlan->device);
			snprintf(res->message, sizeof(res->message) - 1, "Removing MAC %s", cmvlan->device);
			break;
	}

}

void *clientsock_client(void **data) {
	struct client_command cmd;
	struct client_response res;
	int *fdptr = *data;
	int fd = *fdptr;
	int len = 256;

	len = read(fd, &cmd, sizeof(cmd));

	if (len != sizeof(cmd)) {
		printf("Invalid Command\n");
		goto out;
	}

	switch (cmd.datatype) {
		case CD_TAP: client_tap(cmd.action, &cmd.payload.tap, &res);
			break;
		case CD_VLAN: client_vlan(cmd.action, &cmd.payload.vlan, &res);
			break;
		case CD_MACVLAN: client_macvlan(cmd.action, &cmd.payload.macvlan, &res);
			break;
	}

	len = write(fd, &res, sizeof(res));
out:
	*fdptr = -1;
	close(fd);

	return NULL;
}

/*
 * cleanup routine for client sock
 */
void *delclientsock_client(void *data) {
	int fd = *(int *)data;

	if (fd >= 0) {
		close(fd);
	}
	objunref(data);

	return NULL;
}
