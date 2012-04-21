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
	unsigned short	buckets;		/* number of buckets to create 2 ^ n masks hash*/
	int		(*hash_func)(void *data);
	struct		blist_obj *list;		/* array of blist_obj[buckets]*/
};

#define refobj_offset	sizeof(struct ref_obj);

void *objalloc(int size) {
	struct ref_obj *ref;
	size = size + refobj_offset;
	void *robj;

	if ((robj = malloc(size))) {
		memset(robj, 0, size);
		ref = (struct ref_obj*)robj;
		pthread_mutex_init(&ref->lock, NULL);
		ref->magic = REFOBJ_MAGIC;
		ref->cnt++;
		ref->data = robj + refobj_offset;
		return ref->data;
	}
	return NULL;
}

int objref(void *data) {
	int ret = 0;

	if (!data) {
		return ret;
	}

	struct ref_obj *ref = data - refobj_offset;
	if ((ref->magic == REFOBJ_MAGIC) && (ref->cnt)) {
		pthread_mutex_lock(&ref->lock);
		ref->cnt++;
		ret = ref->cnt;
		pthread_mutex_unlock(&ref->lock);
	}
	return ret;
}

int objunref(void *data) {
	int ret = 0;

	if (!data) {
		return ret;
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
	return ret;
}

int objcnt(void *data) {
	int ret = -1;
	struct ref_obj *ref = data - refobj_offset;
	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_lock(&ref->lock);
		ret = ref->cnt;
		pthread_mutex_unlock(&ref->lock);
	}
	return ret;
}

int objlock(void *data) {
	struct ref_obj *ref = data - refobj_offset;

	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_lock(&ref->lock);
	}
	return 0;
}

int objtrylock(void *data) {
	struct ref_obj *ref = data - refobj_offset;

	if (ref->magic == REFOBJ_MAGIC) {
		return (pthread_mutex_trylock(&ref->lock)) ? -1 : 0;
	}
	return -1;
}

int objunlock(void *data) {
	struct ref_obj *ref = data - refobj_offset;

	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_unlock(&ref->lock);
	}
	return 0;
}

struct bucket_list *create_bucketlist(int bitmask, void *hash_function) {
	struct bucket_list *new;
	struct blist_obj *bucket;
	short int buckets, cnt;

	buckets = (1 << bitmask);

	/* allocate session bucket list memory*/
        if (!(new = objalloc(sizeof(*new) + (sizeof(struct blist_obj) * buckets)))) {
		printf("Memory Allocation Error (bucket_list)\n");
		return NULL;
	}

        /*initialise each bucket*/
        new->list = (struct blist_obj *)&new->list;
        for (cnt = 0; cnt < buckets; cnt++) {
		bucket = (struct blist_obj*)&new->list[cnt];
		LIST_INIT(bucket, NULL);
        }

	return new;
}

int addtobucket(struct blist_obj *bucket, void *data) {
	struct ref_obj *ref = data - refobj_offset;

	if (ref->magic == REFOBJ_MAGIC) {
		LIST_ADD(bucket, ref);
	}

	return 1;
}
