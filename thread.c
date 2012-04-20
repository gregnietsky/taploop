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
#include "utlist.h"
#include "refobj.h"
#include "util.h"

/*
 * create a taploop thread
 */
struct tl_thread *mkthread(void *func, void *cleanup, void *data, enum threadopt flags) {
	struct tl_thread *thread;

	if (!(thread = objalloc(sizeof(*thread)))) {
		return NULL;
	}

	thread->data = data;
	thread->cleanup = cleanup;
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
		LL_APPEND(threads->list, thread);
		objunlock(threads);
		return thread;
	} else {
		objunref(thread);
	}

	return NULL;
}

/*
 * this is run to flag running threads to stop and clean up dead threads
 */
void checkthread(struct tl_thread *thread, int stop) {
	objlock(thread);

	if (stop && (thread->flags & TL_THREAD_RUN) && !(thread->flags & TL_THREAD_DONE)) {
		thread->flags &= ~TL_THREAD_RUN;
		objunlock(thread);
		return;
	}

	if ((thread->flags & TL_THREAD_DONE) || pthread_kill(thread->thr, 0)){
		LL_DELETE(threads->list, thread);
		if  (thread->cleanup) {
			thread->cleanup(thread->data);
		}
		objunlock(thread);
		objunref(thread->data);
		objunref(thread);
		return;
	}
	objunlock(thread);
}

/*
 * loop through all threads till they stoped
 * setting stop will flag threads to stop
 */
void verifythreads(int sl, int stop) {
	struct tl_thread        *thread, *tmp;
	pthread_t       me;

	me =  pthread_self();
	for(;;) {
		objlock(threads);
		if (!threads->list) {
			objunlock(threads);
			break;
		}

		LL_FOREACH_SAFE(threads->list , thread, tmp) {
			checkthread(thread, stop);
			/*this is my call im done*/
			if ((pthread_equal(thread->thr, me)) &&
			    (!(testflag(thread, &thread->flags, TL_THREAD_RUN)))) {
				setflag(thread, &thread->flags, TL_THREAD_DONE);
				pthread_cancel(me);
				pthread_detach(me);
				break;
			}
		}
		objunlock(threads);

		usleep(sl);
	}
}

void *managethread(void *data) {
	struct tl_thread *thread = data;

	setflag(thread, &thread->flags, TL_THREAD_RUN);
	verifythreads(100000, 0);
	setflag(thread, &thread->flags, TL_THREAD_DONE);

	return NULL;
}

