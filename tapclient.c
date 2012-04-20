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

#include "taploop.h"
#include "refobj.h"

int main(int argc, char *argv[]) {
	struct sockaddr_un	adr;
	int fd, salen;
	char *sock;

	sock = "/tmp/tlsock";

	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("client connect (socket)");
		return -1;
	}

	salen = sizeof(adr);
	memset(&adr, 0, salen);
	adr.sun_family = PF_UNIX;
	strncpy((char *)&adr.sun_path, sock, sizeof(adr.sun_path) -1);

	if (connect(fd, (struct sockaddr *)&adr, salen)) {
		perror("clientcon (connect)");
		return -1;
	}
	write(fd, sock, strlen(sock)+1);
	close(fd);
	return 0;
}
