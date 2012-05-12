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
#include <arpa/inet.h>

#include "framework.h"

/* socket select thread (read)*/
struct framework_sockdata {
	struct fwsocket *sock;
	void *data;
	socketrecv	read;
};

/* socket server thread*/
struct socket_server {
	struct fwsocket *sock;
	int backlog;
	void *data;
	socketrecv	client;
	socketrecv	connect;
	threadcleanup	cleanup;
};

/*from sslutils im the only consumer*/
void dtsl_serveropts(struct fwsocket *sock);

void clean_fwsocket(void *data) {
	struct fwsocket *si = data;

	if (si->ssl) {
		objunref(si->ssl);
	}
	if (si->sock >= 0) {
		close(si->sock);
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

	if ((si->sock = accept(sock->sock, &si->addr.sa, &salen)) < 0) {
		objunref(si);
		return NULL;
	}

	si->type = sock->type;
	si->proto = sock->proto;

	if (sock->ssl) {
		si->ssl = sock->ssl;
		tlsaccept(si);
	}

	return si;
}

struct fwsocket *_opensocket(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl, int ctype) {
	struct	addrinfo hint, *result, *rp;
	struct fwsocket *sockfd = NULL;
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
		if (!(sockfd = make_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol, ssl))) {
			continue;
		}
		if ((!ctype && !connect(sockfd->sock, rp->ai_addr, rp->ai_addrlen)) ||
		    (ctype && !bind(sockfd->sock, rp->ai_addr, rp->ai_addrlen))) {
			break;
		}
		objunref(sockfd);
	}

	if (ctype && sockfd) {
		sockfd->flags |= SOCK_FLAG_BIND;
		memcpy(&sockfd->addr.ss, rp->ai_addr, sizeof(sockfd->addr.ss));
		setsockopt(sockfd->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
		setsockopt(sockfd->sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
	} else if (sockfd) {
		getsockname(sockfd->sock, &sockfd->addr.sa, &salen);
	}

	freeaddrinfo(result);
	return (sockfd);
}

struct fwsocket *sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl) {
	return(_opensocket(family, stype, proto, ipaddr, port, ssl, 0));
}

struct fwsocket *udpconnect(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port, ssl, 0));
}

struct fwsocket *tcpconnect(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, ipaddr, port, ssl, 0));
}

struct fwsocket *sockbind(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl) {
	return(_opensocket(family, stype, proto, ipaddr, port, ssl, 1));
}

struct fwsocket *udpbind(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port, ssl, 1));
}

struct fwsocket *tcpbind(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, ipaddr, port, ssl, 1));
}

void *delsock_select(void *data) {
	struct framework_sockdata *fwsel = data;

	objunref(fwsel->data);
	objunref(fwsel->sock);

	return NULL;
}

void *sock_select(void **data) {
	struct framework_sockdata *fwsel = *data;
	fd_set  rd_set, act_set;
	struct  timeval tv;
	int selfd;

	FD_ZERO(&rd_set);
	FD_SET(fwsel->sock->sock, &rd_set);

	while (framework_threadok(data)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(fwsel->sock->sock + 1, &act_set, NULL, NULL, &tv);

		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			continue;
		} else if (selfd < 0) {
			break;
		}

		if (fwsel->read && FD_ISSET(fwsel->sock->sock, &act_set)) {
			fwsel->read(fwsel->sock, fwsel->data);
		}
	}

	return NULL;
}

void *tcpsock_serv_clean(void *data) {
	struct socket_server *tcpsock = data;

	/*call cleanup and remove refs to data*/
	if (tcpsock->cleanup) {
		tcpsock->cleanup(tcpsock->data);
	}

	objunref(tcpsock->data);
	objunref(tcpsock->sock);

	return NULL;
}

/*
 * tcp thread spawns a thread on each connect
 */
void *tcpsock_serv(void **data) {
	struct socket_server *tcpsock = *data;
	struct	timeval	tv;
	fd_set	rd_set, act_set;
	int selfd;
	struct fwsocket *newfd;

	if (listen(tcpsock->sock->sock, tcpsock->backlog)) {
		perror("client sock_serv (listen)");
		objunref(tcpsock->sock);
		return NULL;
	}

	FD_ZERO(&rd_set);
	FD_SET(tcpsock->sock->sock, &rd_set);

	while (framework_threadok(data)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(tcpsock->sock->sock + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
     			continue;
		} else if (selfd < 0) {
			break;
		}

		if ((FD_ISSET(tcpsock->sock->sock, &act_set)) &&
		    (newfd = accept_socket(tcpsock->sock))) {
			socketclient(newfd, tcpsock->data, tcpsock->client);
			if (tcpsock->connect) {
				tcpsock->connect(newfd, tcpsock->data);
			}
		}
	}
	objunref(tcpsock->sock);

	return NULL;
}

void *dtls_serv_clean(void *data) {
	struct socket_server *dtlssock = data;

	/*call cleanup and remove refs to data*/
	if (dtlssock->cleanup) {
		dtlssock->cleanup(dtlssock->data);
	}

	objunref(dtlssock->data);
	objunref(dtlssock->sock);

	return NULL;
}

/*
 * tcp thread spawns a thread on each connect
 */
void *dtls_serv(void **data) {
	struct socket_server *dtlssock = *data;
	struct fwsocket *newsock;

	dtsl_serveropts(dtlssock->sock);

	while (framework_threadok(data)) {
		if (!(newsock = dtls_listenssl(dtlssock->sock))) {
			continue;
		}
		socketclient(newsock, dtlssock->data, dtlssock->client);
		if (dtlssock->connect) {
			dtlssock->connect(newsock, dtlssock->data);
		}
	}
	return NULL;
}

void socketclient(struct fwsocket *sock, void *data, socketrecv read) {
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
	framework_mkthread(sock_select, delsock_select, NULL, fwsel);
	objunref(fwsel);
}

void socketserver(struct fwsocket *sock, int backlog, socketrecv connectfunc,
				socketrecv acceptfunc, threadcleanup cleanup, void *data) {
	struct socket_server *servsock;

	if (!(servsock = objalloc(sizeof(*servsock), NULL))) {
		return;
	}

	servsock->sock = sock;
	servsock->backlog = backlog;
	servsock->client = connectfunc;
	servsock->cleanup = cleanup;
	servsock->connect = acceptfunc;
	servsock->data = data;

	/* grab ref for data and pass servsock*/
	switch(sock->type) {
		case SOCK_STREAM:
			objref(data);
			framework_mkthread(tcpsock_serv, tcpsock_serv_clean, NULL, servsock);
			break;
		case SOCK_DGRAM:
			if (sock->ssl) {
				objref(data);
				framework_mkthread(dtls_serv, dtls_serv_clean, NULL, servsock);
			} else {
				socketclient(sock, data, connectfunc);
			}
			break;
	}
	objunref(servsock);
}
