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

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "thread.h"
#include "list.h"
#include "refobj.h"
#include "util.h"

/*
 * create a taploop thread
 */
struct tl_thread *mkthread(void *func, void *cleanup, void *sig_handler, void *data, enum threadopt flags) {
	struct tl_thread *thread;

	if (!(thread = objalloc(sizeof(*thread)))) {
		return NULL;
	}

	thread->data = data;
	thread->cleanup = cleanup;
	thread->sighandler = sig_handler;
	thread->flags = 0;
	thread->flags = flags;
	/* set this and check this in thread*/
	thread->flags &= ~TL_THREAD_RUN & ~TL_THREAD_DONE;

	/* grab a ref to data for thread to make sure it does not go away*/
	objref(thread->data);
	if (pthread_create(&thread->thr, NULL, func, thread)) {
		objunref(thread);
		objunref(thread->data);
		return NULL;
	}

	/* am i up and running move ref to list*/
	if (!pthread_kill(thread->thr, 0)) {
		objlock(threads);
		LIST_ADD(threads->list, thread);
		objunlock(threads);
		return thread;
	} else {
		objunref(thread);
	}

	return NULL;
}


/*
 * close all threads when we get SIGHUP
 */
int manager_sig(int sig, struct tl_thread *thread) {
	switch(sig) {
		case SIGHUP:
			clearflag(thread, TL_THREAD_RUN);
			break;
	}
	return 1;
}

/*
 * loop through all threads till they stoped
 * setting stop will flag threads to stop
 */
void *managethread(void *data) {
	struct tl_thread *thread = data;
	int stop = 0;
	pthread_t       me;

	setflag(thread, TL_THREAD_RUN);

	me =  pthread_self();
	for(;;) {
		objlock(threads);
		if (!threads->list) {
			objunlock(threads);
			break;
		}

		LIST_FOREACH_START_SAFE(threads->list , thread) {
			/*this is my call im done*/
			if (pthread_equal(thread->thr, me)) {
				/* im going to leave the list and try close down all others*/
				if (!(testflag(thread, TL_THREAD_RUN))) {
					LIST_REMOVE_CURRENT(threads->list);
					stop = 1;
				}
				continue;
			}

			objlock(thread);
			if (stop && (thread->flags & TL_THREAD_RUN) && !(thread->flags & TL_THREAD_DONE)) {
				thread->flags &= ~TL_THREAD_RUN;
				objunlock(thread);
			} else if ((thread->flags & TL_THREAD_DONE) || pthread_kill(thread->thr, 0)){
				LIST_REMOVE_CURRENT(threads->list);
				if  (thread->cleanup) {
					thread->cleanup(thread->data);
				}
				objunlock(thread);
				objunref(thread->data);
				objunref(thread);
			} else {
				objunlock(thread);
			}
		}
		LIST_FOREACH_END;
		objunlock(threads);
		usleep(1000000);
	}
	setflag(thread, TL_THREAD_DONE);

	return NULL;
}

/*
 * initialise the threadlist
 * start manager thread
 */
void startthreads(void) {
	threads = objalloc(sizeof(*threads));
        LIST_INIT(threads->list, NULL);
	threads->manager = mkthread(managethread, NULL, manager_sig, NULL, TL_THREAD_NONE);
}

/*
 * find the thread the signal was delivered to
 * if the signal was handled returns 1
 * if the thread could not be handled returns -1
 * returns 0 if not for thread
 * NB sending a signal to the current thread while threads is locked
 * will cause a deadlock.
 */
int thread_signal(int sig) {
	int ret = 0;
	pthread_t       me;
	struct tl_thread        *thread;

	me =  pthread_self();
	objlock(threads);
	LIST_FOREACH_START(threads->list , thread) {
		if (pthread_equal(thread->thr, me)) {
			objunlock(threads);
			if (thread->sighandler) {
				thread->sighandler(sig, thread);
				ret = 1;
			} else {
				ret = -1;
			}
			break;
		}
	}
	LIST_FOREACH_END;
	if (!ret) {
		objunlock(threads);
	}
	return ret;
}
