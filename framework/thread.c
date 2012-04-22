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
#include <stdlib.h>

#include "thread.h"
#include "refobj.h"

/* thread struct used to create threads*/
struct thread_pvt {
	pthread_t		thr;
	void			*(*cleanup)(void *data);
	void			(*sighandler)(int sig, struct thread_pvt *thread);
	struct			thread_info *appinfo;
};

struct threadcontainer {
	struct bucket_list	*list;
	struct thread_pvt	*manager;
};

/*
 * Global threads list
 */
struct threadcontainer *threads;

/*
 * create a thread
 */
struct thread_pvt *mkthread(void *func, void *cleanup, void *sig_handler, void *data) {
	struct thread_pvt *thread;
	struct thread_info *thread_info;

	if (!(thread = objalloc(sizeof(*thread), NULL))) {
		return NULL;
	}

	if (!(thread_info = objalloc(sizeof(*thread_info), NULL))) {
		objunref(thread);
		return (NULL);
	}

	thread_info->data = data;
	thread_info->flags = 0;
	thread->cleanup = cleanup;
	thread->sighandler = sig_handler;
	thread->appinfo = thread_info;

	/* grab a ref to data for thread to make sure it does not go away*/
	objref(thread_info->data);
	if (pthread_create(&thread->thr, NULL, func, thread->appinfo)) {
		objunref(thread);
		objunref(thread_info->data);
		objunref(thread_info);
		return NULL;
	}

	/* am i up and running move ref to list*/
	if (!pthread_kill(thread->thr, 0)) {
		objlock(threads);
		BLIST_ADD(threads->list, thread);
		objunlock(threads);
		return (thread);
	} else {
		objunref(thread_info->data);
		objunref(thread_info);
		objunref(thread);
	}

	return NULL;
}


/*
 * close all threads when we get SIGHUP
 */
int manager_sig(int sig, struct thread_pvt *thread) {
	switch(sig) {
		case SIGHUP:
			clearflag(thread->appinfo, TL_THREAD_RUN);
			break;
	}
	return (1);
}

/*
 * loop through all threads till they stoped
 * setting stop will flag threads to stop
 */
void *managethread(void *data) {
	struct thread_info *mythread = data;
	struct thread_pvt *thread;
	pthread_t me;
	int stop = 0;

	setflag(mythread, TL_THREAD_RUN);

	me = pthread_self();
	while(bucket_list_cnt(threads->list)) {
		BLIST_FOREACH_START(threads->list , thread) {
			/*this is my call im done*/
			if (pthread_equal(thread->thr, me)) {
				/* im going to leave the list and try close down all others*/
				if (!(testflag(mythread, TL_THREAD_RUN))) {
					BLIST_REMOVE_CURRENT;
					stop = 1;
				}
				continue;
			}

			objlock(thread);
			if (stop && (thread->appinfo->flags & TL_THREAD_RUN) && !(thread->appinfo->flags & TL_THREAD_DONE)) {
				thread->appinfo->flags &= ~TL_THREAD_RUN;
				objunlock(thread);
			} else if ((thread->appinfo->flags & TL_THREAD_DONE) || pthread_kill(thread->thr, 0)){
				objunlock(thread);
				BLIST_REMOVE_CURRENT;
				if (thread->cleanup) {
					thread->cleanup(thread->appinfo->data);
				}
				objunref(thread->appinfo->data);
				objunref(thread->appinfo);
				objunref(thread);
			} else {
				objunlock(thread);
			}
		}
		BLIST_FOREACH_END;
		sleep(1);
	}
	setflag(mythread, TL_THREAD_DONE);

	return NULL;
}

/*
 * initialise the threadlist
 * start manager thread
 */
void startthreads(void) {
	threads = objalloc(sizeof(*threads), NULL);
	threads->list = create_bucketlist(5, NULL);
	threads->manager = mkthread(managethread, NULL, manager_sig, NULL);
}

/*
 * Stop all running threads
 * sending hup signal to manager
 */
void stopthreads(void) {
	pthread_kill(threads->manager->thr, SIGHUP);
}

/*
 * Join threads
 */
void jointhreads(void) {
	pthread_join(threads->manager->thr, NULL);
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
	struct thread_pvt *thread;
	pthread_t me;
	int ret = 0;

	me = pthread_self();
	BLIST_FOREACH_START(threads->list , thread) {
		if (pthread_equal(thread->thr, me)) {
			if (thread->sighandler) {
				thread->sighandler(sig, thread);
				ret = 1;
			} else {
				ret = -1;
			}
			break;
		}
	}
	BLIST_FOREACH_END;
	return (ret);
}
