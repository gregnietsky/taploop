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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <framework.h>

struct nfq_struct {
	struct nfq_handle *h;
	uint16_t pf;
	int fd;
};

struct nfq_queue {
	struct nfq_struct *nfq;
	struct nfq_q_handle *qh;
	nfqueue_cb cb;
	void *data;
	uint16_t num;
	int fd;
};

struct nfq_list {
	struct bucket_list *queues;
}  *nfqueues = NULL;

static int nfqueue_hash(const void *data, int key) {
	const struct nfq_struct *nfq = data;
	const uint16_t *hashkey = (key) ? data : &nfq->pf;

	return (*hashkey);
}

static void nfqueue_close(void *data) {
	struct nfq_struct *nfq = data;

	nfq_unbind_pf(nfq->h, nfq->pf);
	nfq_close(nfq->h);
}

static void nfqueue_close_q(void *data) {
	struct nfq_queue *nfq_q = data;

	if (nfq_q->qh) {
		nfq_destroy_queue(nfq_q->qh);
	}
	objunref(nfq_q->nfq);

	if (nfqueues) {
		objlock(nfqueues);
		if (objcnt(nfq_q->nfq) == 1) {
			remove_bucket_item(nfqueues->queues, nfq_q->nfq);
		}
		objunlock(nfqueues);
	}
}

static void *nfqueue_thread(void **data) {
        struct nfq_struct *nfq = *data;
	fd_set  rd_set, act_set;
	struct timeval tv;
	int len, selfd;
	char buf[4096];

	FD_ZERO(&rd_set);
	FD_SET(nfq->fd, &rd_set);

	while (framework_threadok(data)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(nfq->fd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			continue;
		} else if (selfd < 0) {
			break;
		}

		if ((FD_ISSET(nfq->fd, &act_set)) &&
		    ((len = recv(nfq->fd, buf, sizeof(buf), 0)) >= 0)) {
			nfq_handle_packet(nfq->h, buf, len);
		}
	}

	return (NULL);
}

static void nfqueue_addlist(struct nfq_struct *nfq) {
	if (!nfqueues && !(nfqueues = objalloc(sizeof(*nfqueues), NULL))) {
		return;
	}

	objlock(nfqueues);
	if (nfqueues->queues || (nfqueues->queues = create_bucketlist(0, nfqueue_hash))) {
		addtobucket(nfqueues->queues, nfq);
	}
	objunlock(nfqueues);
}

static struct nfq_struct *nfqueue_init(uint16_t pf) {
	struct nfq_struct *nfq;

	if (!(nfq = objalloc(sizeof(*nfq), nfqueue_close))) {
		return (NULL);
	}
	nfq->pf = pf;

	if (!(nfq->h = nfq_open())) {
		objunref(nfq);
		return (NULL);
	}

	if (nfq_unbind_pf(nfq->h, pf)) {
		objunref(nfq);
		return (NULL);
	}

	if (nfq_bind_pf(nfq->h, pf)) {
		objunref(nfq);
		return (NULL);
	}

	nfq->fd = nfq_fd(nfq->h);
	nfqueue_addlist(nfq);
	framework_mkthread(nfqueue_thread, NULL, NULL, nfq);

	return (nfq);
}

static int nfqueue_callback(struct nfq_q_handle *qh, struct nfgenmsg *msg, struct nfq_data *nfad, void *data) {
	struct nfq_queue *nfq_q = data;
	char *pkt;
	struct nfqnl_msg_packet_hdr *ph;
	void *mangle = NULL;
	uint32_t ret, mark;
        uint32_t id = 0;
	uint32_t len = 0;
	uint32_t verdict = NF_DROP;

	if ((ph = nfq_get_msg_packet_hdr(nfad))) {
		id = ntohl(ph->packet_id);
	}
	mark = nfq_get_nfmark(nfad);

	if ((len = nfq_get_payload(nfad, &pkt)) <= 0) {
		pkt = NULL;
	}

	if (nfq_q->cb) {
		verdict = nfq_q->cb(nfad, pkt, len, nfq_q->data, &mark, &mangle);
	}

	mark = htonl(mark);

	if (mangle && !(len = objsize(mangle))) {
		objunref(mangle);
		mangle = NULL;
	}

	ret = nfq_set_verdict_mark(qh, id, verdict, mark, len, (mangle) ? mangle : pkt);
	if (mangle) {
		objunref(mangle);
	}

	return (ret);
}

extern struct nfq_queue *nfqueue_attach(uint16_t pf, uint16_t num, uint8_t mode, uint32_t range, nfqueue_cb cb, void *data) {
	struct nfq_queue *nfq_q;

	if (!(nfq_q = objalloc(sizeof(*nfq_q), nfqueue_close_q))) {
		return (NULL);
	}

	objlock(nfqueues);
	if (!(nfqueues && (nfq_q->nfq = bucket_list_find_key(nfqueues->queues, &pf))) && !(nfq_q->nfq = nfqueue_init(pf))) {
		objunlock(nfqueues);
		objunref(nfq_q);
		return (NULL);
	}
	objunlock(nfqueues);

	if (!(nfq_q->qh = nfq_create_queue(nfq_q->nfq->h, num, &nfqueue_callback, nfq_q))) {
		objunref(nfq_q);
		return (NULL);
	}

	if (cb) {
		nfq_q->cb = cb;
	}

	if (data) {
		nfq_q->data = data;
	}

	nfq_set_mode(nfq_q->qh, mode, range);

	return (nfq_q);
}
