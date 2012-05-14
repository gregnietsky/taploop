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

#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "framework.h"

/* socket server thread*/
struct socket_server {
	struct fwsocket *sock;
	void *data;
	socketrecv	client;
	threadcleanup	cleanup;
	socketrecv	connect;
};

/*from sslutils im the only consumer*/
void dtsl_serveropts(struct fwsocket *sock);
void dtlstimeout(struct fwsocket *sock, struct timeval *timeleft, int defusec);
void dtlshandltimeout(struct fwsocket *sock);

int hash_socket(void *data, int key) {
        int ret;
        struct fwsocket *sock = data;
        int *hashkey = (key) ? data : &sock->sock;

        ret = *hashkey;

        return (ret);
}

void closesocket(struct fwsocket *sock) {
	if (sock) {
		setflag(sock, SOCK_FLAG_CLOSE);
		objunref(sock);
	}
}

void clean_fwsocket(void *data) {
	struct fwsocket *sock = data;

	if (sock->ssl) {
		objunref(sock->ssl);
	}

	/*im closing remove from parent list*/
	if (sock->parent) {
		if (sock->parent->children) {
			remove_bucket_item(sock->parent->children, sock);
		}
		objunref(sock->parent);
	}

	/*looks like the server is shut down*/
	if (sock->children) {
		objunref(sock->children);
	}

	if (sock->sock >= 0) {
		close(sock->sock);
	}
}

struct fwsocket *make_socket(int family, int type, int proto, void *ssl) {
	struct fwsocket *si;

	if (!(si = objalloc(sizeof(*si),clean_fwsocket))) {
		return NULL;
	}

	if ((si->sock = socket(family, type, proto)) < 0) {
		objunref(si);
		return NULL;
	};

	if (ssl) {
		si->ssl = ssl;
	}
	si->type = type;
	si->proto = proto;

	return si;
}

struct fwsocket *accept_socket(struct fwsocket *sock) {
	struct fwsocket *si;
	socklen_t salen = sizeof(si->addr.sa);

	if (!(si = objalloc(sizeof(*si),clean_fwsocket))) {
		return NULL;
	}

	objlock(sock);
	if ((si->sock = accept(sock->sock, &si->addr.sa, &salen)) < 0) {
		objunlock(sock);
		objunref(si);
		return NULL;
	}

	si->type = sock->type;
	si->proto = sock->proto;

	if (sock->ssl) {
		tlsaccept(si, sock->ssl);
	}
	objunlock(sock);

	return si;
}

struct fwsocket *_opensocket(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl, int ctype, int backlog) {
	struct	addrinfo hint, *result, *rp;
	struct fwsocket *sock = NULL;
	socklen_t salen = sizeof(struct sockaddr);
	int on = 1;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = family;
	hint.ai_socktype = stype;
	hint.ai_protocol = proto;

	if (getaddrinfo(ipaddr, port, &hint, &result)) {
		return (NULL);
	}

	for(rp = result; rp; rp = result->ai_next) {
		if (!(sock = make_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol, ssl))) {
			continue;
		}
		if ((!ctype && !connect(sock->sock, rp->ai_addr, rp->ai_addrlen)) ||
		    (ctype && !bind(sock->sock, rp->ai_addr, rp->ai_addrlen))) {
			break;
		}
		objunref(sock);
		sock = NULL;
	}

	if (ctype && sock) {
		sock->flags |= SOCK_FLAG_BIND;
		memcpy(&sock->addr.ss, rp->ai_addr, sizeof(sock->addr.ss));
		setsockopt(sock->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
		setsockopt(sock->sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
		switch(sock->type) {
			case SOCK_STREAM:
			case SOCK_SEQPACKET:
				listen(sock->sock, backlog);
				break;
		}
	} else if (sock) {
		getsockname(sock->sock, &sock->addr.sa, &salen);
	}

	freeaddrinfo(result);
	return (sock);
}

struct fwsocket *sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl) {
	return(_opensocket(family, stype, proto, ipaddr, port, ssl, 0, 0));
}

struct fwsocket *udpconnect(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port, ssl, 0, 0));
}

struct fwsocket *tcpconnect(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, ipaddr, port, ssl, 0, 0));
}

struct fwsocket *sockbind(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl, int backlog) {
	return(_opensocket(family, stype, proto, ipaddr, port, ssl, 1, backlog));
}

struct fwsocket *udpbind(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port, ssl, 1, 0));
}

struct fwsocket *tcpbind(const char *ipaddr, const char *port, void *ssl, int backlog) {
	return (_opensocket(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, ipaddr, port, ssl, 1, backlog));
}

void *serv_threadclean(void *data) {
	struct socket_server *fwsel = data;

	/*call cleanup and remove refs to data*/
	if (fwsel->cleanup) {
		fwsel->cleanup(fwsel->data);
	}
	if (fwsel->data) {
		objunref(fwsel->data);
	}

	return NULL;
}

void *socket_serv(void **data) {
	struct socket_server *servdata = *data;
	struct fwsocket *newsock;
	struct fwsocket *sock = servdata->sock;
	struct	timeval	tv;
	fd_set	rd_set, act_set;
	int selfd, sockfd, type, flags;
	struct bucket_loop *bloop;

	objlock(sock);
	FD_ZERO(&rd_set);
	sockfd = sock->sock;
	type = sock->type;
	if (((type == SOCK_DGRAM) && sock->ssl) ||
	    (!(type == SOCK_DGRAM) && (sock->flags & SOCK_FLAG_BIND))) {
		flags = (SOCK_FLAG_BIND & sock->flags);
	} else {
		flags = 0;
	}
	FD_SET(sockfd, &rd_set);
	objunlock(sock);


	if ((type == SOCK_DGRAM) && (flags & SOCK_FLAG_BIND)) {
		dtsl_serveropts(sock);
	} else if (flags & SOCK_FLAG_BIND) {
		sock->children = create_bucketlist(6, hash_socket);
	}

	setflag(sock, SOCK_FLAG_RUNNING);
	while (framework_threadok(data) && testflag(sock, SOCK_FLAG_RUNNING)) {
		objlock(sock);
		if (sock->flags & SOCK_FLAG_CLOSE) {
			ssl_shutdown(sock->ssl);
			sock->flags &= ~SOCK_FLAG_RUNNING;
			objunlock(sock);
			break;
		}
		objunlock(sock);

		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(sockfd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			if ((type == SOCK_DGRAM) && (flags & SOCK_FLAG_BIND)) {
				dtlshandltimeout(sock);
			}
     			continue;
		} else if (selfd < 0) {
			break;
		}

		if ((flags & SOCK_FLAG_BIND) && FD_ISSET(sockfd, &act_set)) {
			switch (type) {
				case SOCK_STREAM:
				case SOCK_SEQPACKET:
					newsock = accept_socket(sock);
					break;
				case SOCK_DGRAM:
					newsock = dtls_listenssl(sock);
					break;
				default:
					newsock = NULL;
					break;
			}

			if (newsock) {
				newsock->flags |= SOCK_FLAG_SPAWN;
				newsock->parent = sock;
				objref(sock);
				addtobucket(sock->children, newsock);
				socketclient(newsock, servdata->data, servdata->client, NULL);
				if (servdata->connect) {
					servdata->connect(newsock, servdata->data);
				}
				objunref(newsock); /*pass ref to thread*/
			}
		} else if (servdata->client && FD_ISSET(sockfd, &act_set)) {
			servdata->client(servdata->sock, servdata->data);
		}
	}
	setflag(sock, SOCK_FLAG_CLOSING);

	/*close children*/
	bloop = init_bucket_loop(sock->children);
	while(bloop && (newsock = next_bucket_loop(bloop))) {
		remove_bucket_loop(bloop);
		objlock(newsock);
		if (newsock->parent) {
			objunref(newsock->parent);
			newsock->parent = NULL;
		}
		objunlock(newsock);
		closesocket(newsock); /*remove ref*/
	}
	stop_bucket_loop(bloop);

	objunref(sock);

	return NULL;
}

void socketserver(struct fwsocket *sock, socketrecv read,
				socketrecv acceptfunc, threadcleanup cleanup, void *data) {
	struct socket_server *servsock;

	if (!sock || !(servsock = objalloc(sizeof(*servsock), NULL))) {
		return;
	}

	servsock->sock = sock;
	servsock->client = read;
	servsock->cleanup = cleanup;
	servsock->connect = acceptfunc;
	servsock->data = data;

	/* grab ref for data and pass servsock*/
	objref(data);
	objref(sock);
	framework_mkthread(socket_serv, serv_threadclean, NULL, servsock);
	objunref(servsock);
}

void socketclient(struct fwsocket *sock, void *data, socketrecv read, threadcleanup cleanup) {
	startsslclient(sock);
	socketserver(sock, read, NULL, cleanup, data);
}
