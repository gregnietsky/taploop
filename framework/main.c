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
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "framework.h"


void startthreads(void);
void stopthreads(void);
void jointhreads(void);
int thread_signal(int sig);

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
 * Print gnu snippet at program run
 */
void printgnu(struct framework_core *ci) {
	printf("Copyright (C) %i %s <%s>\n"
"        %s\n\n"
"    This program comes with ABSOLUTELY NO WARRANTY\n"
"    This is free software, and you are welcome to redistribute it\n"
"    under certain condition\n\n", ci->year, ci->developer, ci->email, ci->www);
}

pid_t daemonize() {
	pid_t	forkpid;

	/* fork and die daemonize*/
	forkpid = fork();
	if (forkpid > 0) {
		/* im all grown up and can pass onto child*/
		exit(0);
	} else if (forkpid < 0) {
		/* could not fork*/
		exit(-1);
	}

	/* Dont want these as a daemon*/
	signal(SIGTSTP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	/*set pid for consistancy i was 0 when born*/
	forkpid = getpid();
	return (forkpid);
}

void configure_sigact(struct sigaction *sa) {
	sa->sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&sa->sa_mask);
	sa->sa_sigaction = sig_handler;
	sigaction(SIGINT, sa, NULL);
	sigaction(SIGTERM, sa, NULL);

	/*internal interupts*/
	sigaction(SIGUSR1, sa, NULL);
	sigaction(SIGUSR2, sa, NULL);
	sigaction(SIGHUP, sa, NULL);
	sigaction(SIGALRM, sa, NULL);
}

/*
 * initialise core
 */
struct framework_core *framework_mkcore(char *name, char *email, char *web, int year) {
	struct framework_core *core_info = NULL;

	if (!(core_info = malloc(sizeof(*core_info)))) {
		return NULL;
	}

	if (core_info && !(core_info->sa = malloc(sizeof(*core_info->sa)))) {
		free(core_info);
		return NULL;
	}

	ALLOC_CONST(core_info->developer, name);
	ALLOC_CONST(core_info->email, email);
	ALLOC_CONST(core_info->www, web);

	return (core_info);
}


/*
 * free core
 */
void framework_free(struct framework_core *ci) {
	if (ci) {
		if (ci->developer) {
			free((char *)ci->developer);
		}
		if (ci->email) {
			free((char *)ci->email);
		}
		if (ci->www) {
			free((char *)ci->www);
		}
		if (ci->sa) {
			free((char *)ci->sa);
		}
	}
}

/*
 * daemonise and start socket
 */
int framework_init(int argc, char *argv[], void *callback, struct framework_core *core_info) {
	int (*startup)(int, char **);
	int ret = 0;

	/*prinit out a GNU licence summary*/
	printgnu(core_info);
	core_info->my_pid = daemonize();

	/* interupt handler close clean on term so physical is reset*/
	configure_sigact(core_info->sa);

	/*init the threadlist start thread manager*/
	startthreads();

	/*run the code from the application*/
	if (callback) {
		startup = callback;
		ret = startup(argc, argv);
	}

	/*join the manager thread its the last to go*/
	if (!ret) {
		jointhreads();
	} else {
		stopthreads();
	}

	/* turn off the lights*/
	return (ret);
}
