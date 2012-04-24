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

#include "framework.h"

#define THREAD_MAGIC 0xfeedf158

enum threadopt {
        TL_THREAD_NONE  = 0,
        /* thread is marked as running*/
        TL_THREAD_RUN   = 1 << 1,
        /* thread is marked as complete*/
        TL_THREAD_DONE  = 1 << 2,
};

/*
 * thread struct used to create threads
 * data needs to be first element
 */
struct thread_pvt {
	void			*data;
	int			magic;
	pthread_t		thr;
	void			*(*cleanup)(void *data);
	void			*(*func)(void **data);
	void			(*sighandler)(int sig, struct thread_pvt *thread);
	enum                    threadopt flags;
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
 * let threads check there status by passing in a pointer to
 * there data
 */
int framework_threadok(void *data) {
	struct thread_pvt *thr = data;

	if (thr && (thr->magic == THREAD_MAGIC)) {
		return testflag(thr, TL_THREAD_RUN);
	}
	return 0;
}

void *threadwrap(void *data) {
	struct thread_pvt *thread = data;
	void *ret = NULL;

	if (thread && thread->func) {
		setflag(thread, TL_THREAD_RUN);
		ret = thread->func(&thread->data);
		setflag(thread, TL_THREAD_DONE);
	}

	return ret;
}

/*
 * create a thread
 */
struct thread_pvt *framework_mkthread(void *func, void *cleanup, void *sig_handler, void *data) {
	struct thread_pvt *thread;

	if (!(thread = objalloc(sizeof(*thread), NULL))) {
		return NULL;
	}

	thread->data = data;
	thread->flags = 0;
	thread->cleanup = cleanup;
	thread->sighandler = sig_handler;
	thread->func = func;
	thread->magic = THREAD_MAGIC;

	/* grab a ref to data for thread to make sure it does not go away*/
	objref(thread->data);
	if (pthread_create(&thread->thr, NULL, threadwrap, thread)) {
		objunref(thread);
		objunref(thread->data);
		return NULL;
	}

	/* am i up and running move ref to list*/
	if (!pthread_kill(thread->thr, 0)) {
		objlock(threads);
		BLIST_ADD(threads->list, thread);
		objunlock(threads);
		return (thread);
	} else {
		objunref(thread->data);
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
			clearflag(thread, TL_THREAD_RUN);
			break;
	}
	return (1);
}

/*
 * loop through all threads till they stoped
 * setting stop will flag threads to stop
 */
void *managethread(void **data) {
	struct thread_pvt *mythread = threads->manager;
	struct thread_pvt *thread;
	pthread_t me;
	int stop = 0;

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
			if (stop && (thread->flags & TL_THREAD_RUN) && !(thread->flags & TL_THREAD_DONE)) {
				thread->flags &= ~TL_THREAD_RUN;
				objunlock(thread);
			} else if ((thread->flags & TL_THREAD_DONE) || pthread_kill(thread->thr, 0)){
				objunlock(thread);
				BLIST_REMOVE_CURRENT;
				if (thread->cleanup) {
					thread->cleanup(thread->data);
				}
				objunref(thread->data);
				objunref(thread);
			} else {
				objunlock(thread);
			}
		}
		BLIST_FOREACH_END;
		sleep(1);
	}

	return NULL;
}

/*
 * initialise the threadlist
 * start manager thread
 */
int startthreads(void) {
	threads = objalloc(sizeof(*threads), NULL);
	threads->list = create_bucketlist(5, NULL);
	threads->manager = framework_mkthread(managethread, NULL, manager_sig, NULL);
	return (threads && threads->list && threads->manager);
}

/*
 * Stop all running threads
 * sending hup signal to manager
 */
void framework_shutdown(void) {
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
