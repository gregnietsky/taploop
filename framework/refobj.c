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
#include <string.h>
#include "jhash.h"
#include "list.h"

#define REFOBJ_MAGIC		0xdeadc0de

/* ref counted objects*/
struct ref_obj {
	int	magic;
	int	cnt;
	int	size;
	pthread_mutex_t	lock;
	void *data;
};

/* bucket list obj*/
struct blist_obj {
	int	hash;
	struct	blist_obj *next;
	struct	blist_obj *prev;
	struct	ref_obj *data;
};

/*bucket list to hold hashed objects in buckets*/
struct bucket_list {
	unsigned short  bitmask;
	unsigned short	buckets;		/* number of buckets to create 2 ^ n masks hash*/
	unsigned int	count;
	int		(*hash_func)(void *data);
	struct		blist_obj **list;		/* array of blist_obj[buckets]*/
};

/*
 * buckets are more complex than linked lists
 * to loop through them we will use a structure
 * that holds the bucket and head it needs to
 * be initialised and destroyed it will lock
 * the bucketlist for the duration
 */
struct bucket_loop {
	struct bucket_list *blist;
	int bucket;
	struct blist_obj *head;
	/* this is for deletion purposes*/
	struct blist_obj *cur;
};

#define refobj_offset	sizeof(struct ref_obj);

void *objalloc(int size,void *destructor) {
	struct ref_obj *ref;
	int asize = size + refobj_offset;
	void *robj;

	if ((robj = malloc(asize))) {
		memset(robj, 0, asize);
		ref = (struct ref_obj*)robj;
		pthread_mutex_init(&ref->lock, NULL);
		ref->magic = REFOBJ_MAGIC;
		ref->cnt++;
		ref->data = robj + refobj_offset;
		ref->size = size;
		return (ref->data);
	}
	return NULL;
}

int objref(void *data) {
	int ret = 0;

	if (!data) {
		return (ret);
	}

	struct ref_obj *ref = data - refobj_offset;
	if ((ref->magic == REFOBJ_MAGIC) && (ref->cnt)) {
		pthread_mutex_lock(&ref->lock);
		ref->cnt++;
		ret = ref->cnt;
		pthread_mutex_unlock(&ref->lock);
	}
	return (ret);
}

int objunref(void *data) {
	int ret = -1;

	if (!data) {
		return (ret);
	}

	struct ref_obj *ref = data - refobj_offset;
	if ((ref->magic == REFOBJ_MAGIC) && (ref->cnt)) {
		pthread_mutex_lock(&ref->lock);
		ref->cnt--;
		ret = ref->cnt;
		pthread_mutex_unlock(&ref->lock);
		if (!ret) {
			pthread_mutex_destroy(&ref->lock);
			free(ref);
		}
	}
	return (ret);
}

int objcnt(void *data) {
	int ret = -1;
	struct ref_obj *ref = data - refobj_offset;
	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_lock(&ref->lock);
		ret = ref->cnt;
		pthread_mutex_unlock(&ref->lock);
	}
	return (ret);
}

int objlock(void *data) {
	struct ref_obj *ref = data - refobj_offset;

	if (data && ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_lock(&ref->lock);
	}
	return (0);
}

int objtrylock(void *data) {
	struct ref_obj *ref = data - refobj_offset;

	if (ref->magic == REFOBJ_MAGIC) {
		return ((pthread_mutex_trylock(&ref->lock)) ? -1 : 0);
	}
	return (-1);
}

int objunlock(void *data) {
	struct ref_obj *ref = data - refobj_offset;

	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_unlock(&ref->lock);
	}
	return (0);
}

/*
 * a bucket list is a ref obj the "list" element is a
 * array of "bucket" entries each has a hash
 * the default is to hash the memory when there is no call back
 */
struct bucket_list *create_bucketlist(int bitmask, void *hash_function) {
	struct bucket_list *new;
	short int buckets, cnt;

	buckets = (1 << bitmask);

	/* allocate session bucket list memory*/
	if (!(new = objalloc(sizeof(*new) + (sizeof(void*) * buckets),NULL))) {
		return NULL;
	}

	/*initialise each bucket*/
	new->buckets = buckets;
	new->bitmask = bitmask;
	new->list = (void *)new + sizeof(*new);
	for (cnt = 0; cnt < buckets; cnt++) {
		LIST_INIT(new->list[cnt], NULL);
	}
	return (new);
}

/*
 * add a ref to the object for the bucket list
 */
int addtobucket(struct bucket_list *blist, void *data) {
	struct ref_obj *ref = data - refobj_offset;
	struct blist_obj *lhead;
	unsigned int hash, bucket;

	if (blist && (ref->magic == REFOBJ_MAGIC)) {
		if (!blist->hash_func) {
			hash = jenhash(data, ref->size, 0);
		} else {
			hash = 0;
		}
		bucket = ((hash >> (32 - blist->bitmask)) & ((1 << blist->bitmask) - 1));
		lhead = blist->list[bucket];
		LIST_ADD_HASH(lhead, ref, hash);
		if (lhead->prev->data == ref) {
			blist->count++;
			objref(data);
		}
		return (1);
	}
	return (0);

}

/*
 * create a bucket loop and lock the list
 */
struct bucket_loop *init_bucket_loop(struct bucket_list *blist) {
	struct bucket_loop *bloop = NULL;

	if ((bloop = objalloc(sizeof(*bloop),NULL)) && objref(blist)) {
		bloop->blist = blist;
		bloop->bucket = -1;
		bloop->head = NULL;
	} else if (bloop) {
		objunref(bloop);
	}
	objlock(blist);

	return (bloop);
}

/*
 * release the bucket loop and unref list
 */
void stop_bucket_loop(struct bucket_loop *bloop) {
	if (bloop) {
		objunlock(bloop->blist);
		objunref(bloop->blist);
		objunref(bloop);
	}
};

/*
 * return the next object in the lists
 */
void *next_bucket_loop(struct bucket_loop *bloop) {
	struct ref_obj *entry = NULL;
	void *data = NULL;

	if (bloop->bucket < 0) {
		bloop->bucket = 0;
		bloop->head = bloop->blist->list[0];
	}

	while (!bloop->head || !bloop->head->prev) {
		bloop->bucket++;
		if (bloop->bucket < bloop->blist->buckets) {
			bloop->head = bloop->blist->list[bloop->bucket];
		} else {
			break;
		}
	}

	if (bloop->head) {
		bloop->cur = bloop->head;
		entry = (bloop->head->data) ? bloop->head->data : NULL;
		data = (entry) ? entry->data : NULL;
		bloop->head = bloop->head->next;
	}

	return (data);
}

/*
 * remove and unref the current data
 */
void remove_bucket_loop(struct bucket_loop *bloop) {
	if (bloop->cur) {
		objunref(bloop->cur->data->data);
		LIST_REMOVE_ENTRY(bloop->blist->list[bloop->bucket], bloop->cur);
		bloop->blist->count--;
	}
}

int bucket_list_cnt(struct bucket_list *blist) {
	int ret = -1;

	if (blist) {
		objlock(blist);
		ret = blist->count;
		objunlock(blist);
	}
	return (ret);
}
