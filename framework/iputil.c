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
	int sock;
	void *data;
	void *ssl;
	socketrecv	read;
};

/* TCP socket thread*/
struct framework_tcpthread {
	int sock;
	int backlog;
	void *data;
	void *ssl;
	socketrecv	client;
	socketrecv	connect;
	threadcleanup	cleanup;
};

/* DTLS socket thread*/
struct framework_dtlsthread {
	int sock;
	void *data;
	void *ssl;
	socketrecv	client;
	socketrecv	connect;
	threadcleanup	cleanup;
};

int _opensocket(int family, int stype, int proto, const char *ipaddr, const char *port, int ctype, struct sockaddr *addr, socklen_t *slen) {
	struct	addrinfo hint, *result, *rp;
	int sockfd = -1;
	int on = 1;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = family;
	hint.ai_socktype = stype;
	hint.ai_protocol = proto;

	if (getaddrinfo(ipaddr, port, &hint, &result)) {
		return (sockfd);
	}

	for(rp = result; rp; rp = result->ai_next) {
		if ((sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0) {
			continue;
		}
		if (addr && slen) {
			memcpy(addr, rp->ai_addr, *slen);
		}
		if (!ctype && !connect(sockfd, rp->ai_addr, rp->ai_addrlen)) {
			if (slen) {
				*slen = rp->ai_addrlen;
			}
			break;
		} else if (ctype && !bind(sockfd, rp->ai_addr, rp->ai_addrlen)) {
			if (slen) {
				*slen = rp->ai_addrlen;
			}
			break;
		}
		if (addr) {
			memset(addr, 0, *slen);
		}
		close(sockfd);
		sockfd = -1;
	}

	if (ctype && (sockfd >= 0)) {
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
	}

	freeaddrinfo(result);
	return (sockfd);
}

int sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port, struct sockaddr *addr, void *slen) {
	return(_opensocket(family, stype, proto, ipaddr, port, 0, addr, slen));
}

int udpconnect(const char *ipaddr, const char *port, struct sockaddr *addr, void *slen) {
	return (_opensocket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port, 0, addr, slen));
}

int tcpconnect(const char *ipaddr, const char *port, struct sockaddr *addr, void *slen) {
	return (_opensocket(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, ipaddr, port, 0, addr, slen));
}

int sockbind(int family, int stype, int proto, const char *ipaddr, const char *port, struct sockaddr *addr, void *slen) {
	return(_opensocket(family, stype, proto, ipaddr, port, 1, NULL, NULL));
}

int udpbind(const char *ipaddr, const char *port, struct sockaddr *addr, void *slen) {
	return (_opensocket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port, 1, addr, slen));
}

int tcpbind(const char *ipaddr, const char *port, struct sockaddr *addr, void *slen) {
	return (_opensocket(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, ipaddr, port, 1, addr, slen));
}

void *delsock_select(void *data) {
	struct framework_sockdata *fwsel = data;

	objunref(fwsel->data);
	objunref(fwsel->ssl);

	return NULL;
}

void *sock_select(void **data) {
	struct framework_sockdata *fwsel = *data;
	fd_set  rd_set, act_set;
	struct  timeval tv;
	int selfd;

	FD_ZERO(&rd_set);
	FD_SET(fwsel->sock, &rd_set);

	while (framework_threadok(data)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(fwsel->sock + 1, &act_set, NULL, NULL, &tv);

		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			continue;
		} else if (selfd < 0) {
			break;
		}

		if (fwsel->read && FD_ISSET(fwsel->sock, &act_set)) {
			fwsel->read(fwsel->sock, fwsel->data, fwsel->ssl);
		}
	}

	return NULL;
}

void *tcpsock_serv_clean(void *data) {
	struct framework_tcpthread *tcpsock = data;

	/*call cleanup and remove refs to data/ssl*/
	if (tcpsock->cleanup) {
		tcpsock->cleanup(tcpsock->data);
	}

	objunref(tcpsock->data);
	objunref(tcpsock->ssl);

	return NULL;
}

/*
 * tcp thread spawns a thread on each connect
 */
void *tcpsock_serv(void **data) {
	struct framework_tcpthread *tcpsock = *data;
	struct framework_sockdata *tcpcon;
	struct sockaddr *adr;
	unsigned int salen;
	struct	timeval	tv;
	fd_set	rd_set, act_set;
	int selfd;

	if (listen(tcpsock->sock, tcpsock->backlog)) {
		perror("client sock_serv (listen)");
		close(tcpsock->sock);
		return NULL;
	}

	FD_ZERO(&rd_set);
	FD_SET(tcpsock->sock, &rd_set);

	while (framework_threadok(data)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(tcpsock->sock + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
     			continue;
		} else if (selfd < 0) {
			break;
		}

		if (FD_ISSET(tcpsock->sock, &act_set)) {
			if ((tcpcon = objalloc(sizeof(*tcpcon), NULL))) {
				if ((tcpcon->sock = accept(tcpsock->sock, (struct sockaddr *)&adr, &salen))) {
					tcpcon->data = tcpsock->data;
					tcpcon->read = tcpsock->client;
					tcpcon->ssl = tcpsock->ssl;
					if (tcpsock->ssl) {
						tlsaccept(tcpsock->ssl, tcpcon->sock);
					}
					if (tcpsock->connect) {
						tcpsock->connect(tcpcon->sock, tcpsock->data, tcpsock->ssl);
					}
					objref(tcpsock->data);
					objref(tcpsock->ssl);
					framework_mkthread(sock_select, delsock_select, NULL, tcpcon);
				}
				objunref(tcpcon);
			}
		}
	}

	close(tcpsock->sock);

	return NULL;
}

void framework_tcpserver(int sock, int backlog, socketrecv connectfunc, socketrecv acceptfunc, threadcleanup cleanup, void *data, void *ssl) {
	struct framework_tcpthread *tcpsock;

	tcpsock = objalloc(sizeof(*tcpsock), NULL);
	tcpsock->sock = sock;
	tcpsock->backlog = backlog;
	tcpsock->client = connectfunc;
	tcpsock->cleanup = cleanup;
	tcpsock->connect = acceptfunc;
	tcpsock->data = data;
	tcpsock->ssl = ssl;

	/* grab ref for ssl/data and pass tcpsock*/
	objref(data);
	objref(ssl);
	framework_mkthread(tcpsock_serv, tcpsock_serv_clean, NULL, tcpsock);
	objunref(tcpsock);
}

void framework_sockselect(int sock, void *data, void *ssl, socketrecv read) {
	struct framework_sockdata *fwsel;

	fwsel = objalloc(sizeof(*fwsel), NULL);
	fwsel->sock = sock;
	fwsel->data = data;
	fwsel->read = read;
	fwsel->ssl = ssl;

	/* grab ref for ssl/data and pass fwsel*/
	objref(data);
	objref(ssl);
	framework_mkthread(sock_select, delsock_select, NULL, fwsel);
	objunref(fwsel);
}

void framework_tlsclient(int sock, void *data, void *ssl, socketrecv read) {
	if (ssl) {
		tlsconnect(ssl, sock);
	}
	framework_sockselect(sock, data, ssl, read);
}

void framework_dtlsclient(int sock, void *data, void *ssl, socketrecv read) {
	if (ssl) {
		dtlsconnect(ssl, sock);
	}
	framework_sockselect(sock, data, ssl, read);
}

void *dtls_serv_clean(void *data) {
	struct framework_dtlsthread *tcpsock = data;
	/*call cleanup and remove refs to data/ssl*/
	if (tcpsock->cleanup) {
		tcpsock->cleanup(tcpsock->data);
	}

	objunref(tcpsock->data);
	objunref(tcpsock->ssl);

	return NULL;
}

/*
 * tcp thread spawns a thread on each connect
 */
void *dtls_serv(void **data) {
	struct framework_dtlsthread *dtlssock = *data;
	struct framework_sockdata *dtls;
	int on = 1;
	struct sockaddr addr, client;
	socklen_t salen = sizeof(addr);

	getsockname(dtlssock->sock, &addr, &salen);
	dtsl_serveropts(dtlssock->ssl);

	while (framework_threadok(data)) {
		if ((dtls = objalloc(sizeof(*dtls), NULL)) &&
		    (dtls->ssl = dtls_listenssl(dtlssock->ssl, &client, dtlssock->sock))) {
			dtls->sock = socket(addr.sa_family, SOCK_DGRAM, IPPROTO_UDP);
			setsockopt(dtls->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
			setsockopt(dtls->sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
			bind(dtls->sock, &addr, salen);
			connect(dtls->sock, &client, sizeof(client));

			dtls->data = dtlssock->data;
			dtls->read = dtlssock->client;

			dtlsaccept(dtls->ssl, &client, dtls->sock);

			if (dtlssock->connect) {
				dtlssock->connect(dtls->sock, dtls->data, dtls->ssl);
			}
			objref(dtls->data);
			framework_mkthread(sock_select, delsock_select, NULL, dtls);

			objunref(dtls);
		}
	}

	close(dtlssock->sock);

	return NULL;
}

void framework_dtlsserver(int sock, socketrecv connectfunc, socketrecv acceptfunc, threadcleanup cleanup, void *data, void *ssl) {
	struct framework_dtlsthread *dtlssock;

	dtlssock = objalloc(sizeof(*dtlssock), NULL);
	dtlssock->sock = sock;
	dtlssock->client = connectfunc;
	dtlssock->cleanup = cleanup;
	dtlssock->connect = acceptfunc;
	dtlssock->data = data;
	dtlssock->ssl = ssl;

	/* grab ref for ssl/data and pass dtlssock*/
	objref(data);
	objref(ssl);
	framework_mkthread(dtls_serv, dtls_serv_clean, NULL, dtlssock);
	objunref(dtlssock);
}

