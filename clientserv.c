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

#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/if_arp.h>

#include "taploop.h"
#include "util.h"
#include "refobj.h"
#include "thread.h"

void *clientsock_client(void *data) {
	struct tl_thread *thread = data;
	int fd = *(int*)thread->data;

	setflag(thread, &thread->flags, TL_THREAD_RUN);

	int len = 256;
	char buff[256];
	len = read(fd, buff, len);
	printf("Connected %s %i\n", buff, len);
	*(int *)thread->data = -1;
	close(fd);

	setflag(thread, &thread->flags, TL_THREAD_DONE);

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

/*
 * client sock server
 */
void *clientsock_serv(void *data) {
	struct tl_thread *thread = data;
	char *sock = thread->data;
	struct sockaddr_un	adr;
	int fd;
	unsigned int salen;
	fd_set	rd_set, act_set;
	int selfd;
	struct	timeval	tv;
	int *clfd;

	setflag(thread, &thread->flags, TL_THREAD_RUN);

	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		return NULL;
	}

	fcntl(fd, F_SETFD, O_NONBLOCK);
	memset(&adr, 0, sizeof(adr));
	adr.sun_family = PF_UNIX;
	salen = sizeof(adr);
	strncpy((char *)&adr.sun_path, sock, sizeof(adr.sun_path) -1);

	if (bind(fd, (struct sockaddr *)&adr, salen)) {
		if (errno == EADDRINUSE) {
			/* delete old file*/
			unlink(sock);
			if (bind(fd, (struct sockaddr *)&adr, sizeof(struct sockaddr_un))) {
				perror("clientsock_serv (bind)");
				close(fd);
				return NULL;
			}
		} else {
			perror("clientsock_serv (bind)");
			close(fd);
			return NULL;
		}
	}

	if (listen(fd, 10)) {
		perror("client sock_serv (listen)");
		close(fd);
		return NULL;
	}

	FD_ZERO(&rd_set);
	FD_SET(fd, &rd_set);

	while (testflag(thread, &thread->flags, TL_THREAD_RUN)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 2000;

		selfd = select(fd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
     			continue;
		} else if (selfd < 0) {
			break;
		}

		if (FD_ISSET(fd, &act_set)) {
			clfd = objalloc(sizeof(int));
			if ((*clfd = accept(fd, (struct sockaddr *)&adr, &salen))) {
				mkthread(clientsock_client, delclientsock_client, clfd, TL_THREAD_NONE);
			} else {
				objunref(clfd);
			}
		}
	}

	setflag(thread, &thread->flags, TL_THREAD_DONE);
	return NULL;
};

/*
 * cleanup routine for client sock
 */
void delclientsock_serv(void *data) {
	char *sock = data;

	/* delete sock*/
	unlink(sock);

	return;
}

/*
 * start client socket to allow client to connect
 */
void clientserv_run(void) {
        mkthread(clientsock_serv, delclientsock_serv, clsock, TL_THREAD_NONE);
}
