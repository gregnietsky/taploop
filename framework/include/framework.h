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
};

/* thread struct*/
struct thread_info {
	void			*data;
	enum			threadopt flags;
};

typedef struct bucket_list bucket_list;
typedef struct bucket_loop bucket_loop;

struct thread_pvt *framework_mkthread(void *func, void *cleanup, void *sig_handler, void *data);

int objlock(void *data);
int objtrylock(void *data);
int objunlock(void *data);
int objcnt(void *data);
int objunref(void *data);
int objref(void *data);
void *objalloc(int size, void *destructor);

struct bucket_list *create_bucketlist(int bitmask, void *hash_function);

int addtobucket(struct bucket_list *blist, void *data);
int bucket_list_cnt(struct bucket_list *blist);

struct bucket_loop *init_bucket_loop(struct bucket_list *blist);
void stop_bucket_loop(struct bucket_loop *bloop);

void *next_bucket_loop(struct bucket_loop *bloop);
void remove_bucket_loop(struct bucket_loop *bloop);
int framework_init(int argc, char *argv[], void *startup);

/*
 * the program meat starts here predeclaring it
 * programner needs to write a startup func to run
 * and set this variable to point to it the framework
 * will initialise and run this function
 *
 * THERE MUST BE NO MAIN FUNCTION MAIN IS IN THE FRAMEWORK
 */
int *(*startup)(int, char **);

#define clearflag(obj, flag) objlock(obj); \
	obj->flags &= ~flag; \
	objunlock(obj)

#define setflag(obj, flag) objlock(obj); \
	obj->flags |= flag; \
	objunlock(obj)

#define testflag(obj, flag) (objlock(obj) | (obj->flags & flag) | objunlock(obj))


#define BLIST_FOREACH_START(blist, entry) { \
	{ \
		struct bucket_loop *_fea_bloop; \
        	_fea_bloop = init_bucket_loop(blist); \
        	while (_fea_bloop && (entry = next_bucket_loop(_fea_bloop)))

#define BLIST_FOREACH_END stop_bucket_loop(_fea_bloop); \
		} \
	}

#define BLIST_REMOVE_CURRENT remove_bucket_loop(_fea_bloop);

#define BLIST_ADD(blist, entry) addtobucket(blist, entry);
