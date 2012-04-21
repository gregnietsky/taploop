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
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
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
	switch (sig) {
		case SIGTERM:
		case SIGINT:
			stopthreads();
			break;
		case SIGUSR1:
		case SIGUSR2:
		case SIGHUP:
		case SIGALRM:
			thread_signal(sig);
			break;
	}
}

/*
 * daemonise and start socket
 */
int main(int argc, char *argv[]) {
	pid_t	daemon;
	struct sigaction sa;

	printf("Copyright (C) 2012  Gregory Nietsky <gregory@distrotetch.co.za>\n"
"        http://www.distrotech.co.za\n\n"
"    This program comes with ABSOLUTELY NO WARRANTY\n"
"    This is free software, and you are welcome to redistribute it\n"
"    under certain condition\n\n");

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

	/* Dont want these as a daemon*/
	signal(SIGTSTP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	/* interupt handler close clean on term so physical is reset*/
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sig_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/*internal interupts*/
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);

	/*init the threadlist start thread manager*/
	startthreads();

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

	/*join the manager thread its the last to go*/
	jointhreads();

	/* turn off the lights*/
	return 0;
}
