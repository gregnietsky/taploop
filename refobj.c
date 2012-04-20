#include <stdlib.h>
#include <pthread.h>
#include <string.h>

/* ref counted objects*/
struct ref_obj {
        int     magic;
        int     cnt;
        pthread_mutex_t         lock;
        void *data;
};

/* bucket list obj*/
struct blist_obj {
        int     bucket;
        int     hash;
        struct  blist_obj *next;
        struct  blist_obj *prev;
        struct  ref_obj *data;
};

/*bucket list to hold hashed objects in buckets*/
struct bucket_list {
        unsigned short  buckets;        /* number of buckets to create 2 ^ n masks hash*/
        struct blist_obj *list;         /* array of blist_obj[buckets]*/
        int     (*hash_func)(void *data);
};

void *objalloc(int size) {
        struct ref_obj *ref;
        size = size+32;
        void *robj;

        if ((robj = malloc(size))) {
                memset(robj, 0, size);
                ref = (struct ref_obj*)robj;
                pthread_mutex_init(&ref->lock, NULL);
                ref->magic = 0xdeadc0de;
                ref->cnt++;
                return robj + 32;
        }
        return NULL;
}

int objref(void *data) {
        int ret = 0;

        if (!data) {
                return ret;
        }

        struct ref_obj *ref = data - 32;
        if ((ref->magic == 0xdeadc0de) && (ref->cnt)) {
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

        struct ref_obj *ref = data - 32;
        if ((ref->magic == 0xdeadc0de) && (ref->cnt)) {
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
        struct ref_obj *ref = data - 32;
        if (ref->magic == 0xdeadc0de) {
                pthread_mutex_lock(&ref->lock);
                ret = ref->cnt;
                pthread_mutex_unlock(&ref->lock);
        }
        return ret;
}

void objlock(void *data) {
        struct ref_obj *ref = data - 32;

        if (ref->magic == 0xdeadc0de) {
                pthread_mutex_lock(&ref->lock);
        }
}

void objunlock(void *data) {
        struct ref_obj *ref = data - 32;

        if (ref->magic == 0xdeadc0de) {
                pthread_mutex_unlock(&ref->lock);
        }
}