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

/* socket select thread (read)*/
struct framework_sockdata {
	struct fwsocket *sock;
	void *data;
	socketrecv	read;
	threadcleanup	cleanup;
};

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
		si->ssl = sock->ssl;
		objunlock(sock);
		tlsaccept(si);
	} else {
		objunlock(sock);
	}

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

void *client_threadclean(void *data) {
	struct framework_sockdata *fwsel = data;

	/*call cleanup and remove refs to data*/
	if (fwsel->cleanup) {
		fwsel->cleanup(fwsel->data);
	}
	if (fwsel->data) {
		objunref(fwsel->data);
	}

	return NULL;
}

void *sock_select(void **data) {
	struct framework_sockdata *fwsel = *data;
	fd_set  rd_set, act_set;
	struct  timeval tv;
	int selfd, sock;

	if (!fwsel->sock) {
		return NULL;
	}

	FD_ZERO(&rd_set);
	objlock(fwsel->sock);
	sock = fwsel->sock->sock;
	FD_SET(sock, &rd_set);
	fwsel->sock->flags |= SOCK_FLAG_RUNNING;
	objunlock(fwsel->sock);

	while (framework_threadok(data) && testflag(fwsel->sock, SOCK_FLAG_RUNNING)) {
		objlock(fwsel->sock);
		if (fwsel->sock->flags & SOCK_FLAG_CLOSE) {
			ssl_shutdown(fwsel->sock->ssl);
			fwsel->sock->flags &= ~SOCK_FLAG_RUNNING;
			objunlock(fwsel->sock);
			break;
		}
		objunlock(fwsel->sock);

		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;


		selfd = select(sock + 1, &act_set, NULL, NULL, &tv);

		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			continue;
		} else if (selfd < 0) {
			break;
		}

		if (fwsel->read && FD_ISSET(sock, &act_set)) {
			fwsel->read(fwsel->sock, fwsel->data);
		}
	}
	setflag(fwsel->sock, SOCK_FLAG_CLOSING);
	objunref(fwsel->sock);

	return NULL;
}

void *serv_threadclean(void *data) {
	struct socket_server *tcpsock = data;

	/*call cleanup and remove refs to data*/
	if (tcpsock->cleanup) {
		tcpsock->cleanup(tcpsock->data);
	}
	if (tcpsock->data) {
		objunref(tcpsock->data);
	}

	return NULL;
}

/*
 * tcp thread spawns a thread on each connect
 */
void *socket_serv(void **data) {
	struct socket_server *servdata = *data;
	struct fwsocket *newsock;
	struct fwsocket *sock = servdata->sock;
	struct	timeval	tv;
	fd_set	rd_set, act_set;
	int selfd, sockfd, type;
	struct bucket_loop *bloop;

	objlock(sock);
	sock->children = create_bucketlist(6, hash_socket);
	FD_ZERO(&rd_set);
	sockfd = sock->sock;
	type = sock->type;
	FD_SET(sockfd, &rd_set);
	objunlock(sock);

	if (type == SOCK_DGRAM) {
		dtsl_serveropts(sock);
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
			if (type == SOCK_DGRAM) {
				dtlshandltimeout(sock);
			}
     			continue;
		} else if (selfd < 0) {
			break;
		}

		if (FD_ISSET(sockfd, &act_set)) {
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

void socketclient(struct fwsocket *sock, void *data, socketrecv read, threadcleanup cleanup) {
	struct framework_sockdata *fwsel;

	if (!(fwsel = objalloc(sizeof(*fwsel), NULL))) {
		return;
	}

	fwsel->sock = sock;
	fwsel->data = data;
	fwsel->read = read;

	/* grab ref for data and pass fwsel*/
	startsslclient(sock);
	objref(data);
	objref(sock);
	framework_mkthread(sock_select, client_threadclean, NULL, fwsel);
	objunref(fwsel);
}

void socketserver(struct fwsocket *sock, socketrecv read,
				socketrecv acceptfunc, threadcleanup cleanup, void *data) {
	struct socket_server *servsock;
	int type;

	if (!sock || !(servsock = objalloc(sizeof(*servsock), NULL))) {
		return;
	}

	servsock->sock = sock;
	servsock->client = read;
	servsock->cleanup = cleanup;
	servsock->connect = acceptfunc;
	servsock->data = data;

	/* grab ref for data and pass servsock*/
	objlock(sock);
	type = sock->type;
	objunlock(sock);
	switch(type) {
		case SOCK_STREAM:
		case SOCK_SEQPACKET:
			objref(data);
			objref(sock);
			framework_mkthread(socket_serv, serv_threadclean, NULL, servsock);
			break;
		case SOCK_DGRAM:
			if (sock->ssl) {
				objref(data);
				objref(sock);
				framework_mkthread(socket_serv, serv_threadclean, NULL, servsock);
			} else {
				socketclient(sock, data, read, cleanup);
			}
			break;
	}
	objunref(servsock);
}
