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
#include <linux/if_arp.h>
#include <sys/un.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

#include "taploop.h"
#include "tlsock.h"
#include "refobj.h"
#include "thread.h"
#include "vlan.h"

void clientserv_run(void);

/*
 * handle signals to cleanup gracefully on exit
 */
static void sig_handler(int sig, siginfo_t *si, void *unused) {
	/* flag and clean all threads*/
	verifythreads(10000, 1);
	exit(0);
}

void *clientcon(void *data) {
	struct tl_thread *thread = data;
	char *sock = thread->data;
	struct sockaddr_un	adr;
	int fd, salen;

	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("client connect (socket)");
		return NULL;
	}

	salen = sizeof(adr);
	memset(&adr, 0, salen);
	adr.sun_family = PF_UNIX;
	strncpy((char *)&adr.sun_path, sock, sizeof(adr.sun_path) -1);

	if (connect(fd, (struct sockaddr *)&adr, salen)) {
		perror("clientcon (connect)");
		return NULL;
	}
	write(fd, sock, strlen(sock)+1);
	close(fd);
	return NULL;
}

/*
 * daemonise and start socket
 */
int main(int argc, char *argv[]) {
	pid_t	daemon;
	struct sigaction sa;
	struct tl_thread	*manage;

	printf("Copyright (C) 2012  Gregory Nietsky <gregory@distrotetch.co.za>\n"
"        http://www.distrotech.co.za\n\n"
"    This program comes with ABSOLUTELY NO WARRANTY\n"
"    This is free software, and you are welcome to redistribute it\n"
"    under certain condition\n");

	tundev = "/dev/net/tun";
	clsock = "/tmp/tlsock";

	/* fork and die daemonize*/
	daemon=fork();
	if (daemon > 0) {
		/* im all grown up and can pass onto child*/
		exit(0);
	} else if (daemon < 0) {
		/* could not fork*/
		exit(-1);
	}
	/*set pid for consistancy i was 0 when born*/
	daemon = getpid();

	/* Dont want these */
	signal(SIGTSTP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	/* interupt handler close clean on term so physical is reset*/
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sig_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGKILL, &sa, NULL);

	/*init the threadlist start thread manager*/
	threads = objalloc(sizeof(*threads));
	threads->list = NULL;
	manage = mkthread(managethread, NULL, NULL, TL_THREAD_NONE);

	/*client socket to allow client to connect*/
	clientserv_run();

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

	/* send some data to client socet for testing*/
	sleep(2);
	mkthread(clientcon, NULL, clsock, TL_THREAD_NONE);
	sleep(2);
	mkthread(clientcon, NULL, clsock, TL_THREAD_NONE);
	sleep(2);
	mkthread(clientcon, NULL, clsock, TL_THREAD_NONE);

	/*join the manager thread its the last to go*/
	pthread_join(manage->thr, NULL);

	/* turn off the lights*/
	return 0;
}
