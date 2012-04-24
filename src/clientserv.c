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

#include "taploop.h"

void *clientsock_client(void **data) {
	int *fdptr = *data;
	int fd = *fdptr;
	int len = 256;
	char buff[256];

	len = read(fd, buff, len);
	printf("Connected %s %i\n", buff, len);
	*fdptr = -1;
	close(fd);

	return NULL;
}

/*
 * cleanup routine for client sock
 */
void delclientsock_client(void *data) {
	int fd = *(int *)data;

	if (fd >= 0) {
		close(fd);
	}
	objunref(data);

	return;
}
