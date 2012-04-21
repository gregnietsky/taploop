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

enum threadopt {
	TL_THREAD_NONE	= 0,
	/* thread is marked as running*/
	TL_THREAD_RUN	= 1 << 1,
	/* thread is marked as complete*/
	TL_THREAD_DONE	= 1 << 2,
	/* This is a taploop*/
	TL_THREAD_TAP	= 1 << 3,
};

/* thread struct used to create threads*/
struct tl_thread {
	pthread_t		thr;
	enum			threadopt flags;
	void			*(*cleanup)(void *data);
	void			(*sighandler)(int sig, struct tl_thread *thread);
	void			*data;
};

typedef struct threadlist threadlist;

/* thread list*/
struct threadlist {
	struct tl_thread	*data;
	struct threadlist	*next;
	struct threadlist	*prev;
};

struct threadcontainer {
	struct threadlist	*list;
	struct tl_thread	*manager;
};

struct threadcontainer *threads;

struct tl_thread *mkthread(void *func, void *cleanup, void *sig_handler, void *data, enum threadopt flags);
int thread_signal(int sig);
void startthreads(void);
