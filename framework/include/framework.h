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

/*these can be set int the application */
struct framework_core {
	const char *developer;
	const char *email;
	const char *www;
	int  year;
	long	my_pid;
	struct sigaction *sa;
};

typedef struct bucket_list bucket_list;
typedef struct bucket_loop bucket_loop;

/*
 * Initialise the framework
 */
int framework_init(int argc, char *argv[], void *startup, struct framework_core *core_info);
/*
 * Setup the run enviroment
 */
struct framework_core *framework_mkcore(char *name, char *email, char *web, int year);
/*
 * Free run enviroment
 */
void framework_free(struct framework_core *core_info);

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

#define FRAMEWORK_MAIN(name, email, www, year, startup) \
	int  main(int argc, char *argv[]) { \
		struct framework_core *core_info; \
		int res; \
		core_info = framework_mkcore(name, email, www, year); \
		res = framework_init(argc, argv, startup, core_info); \
		framework_free(core_info); \
		return (res); \
	}

#define ALLOC_CONST(const_var, val) { \
		char *tmp_char; \
		tmp_char = malloc(strlen(val) + 1); \
		strcpy(tmp_char, val); \
		const_var = tmp_char; \
	}
