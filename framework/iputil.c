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

int sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port) {
	struct	addrinfo hint, *result, *rp;
	int sockfd = -1;

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
		if (!connect(sockfd, rp->ai_addr, rp->ai_addrlen)) {
			break;
		}
		close(sockfd);
	}

	freeaddrinfo(result);
	return (sockfd);
}

int udpconnect(const char *ipaddr, const char *port) {
	return (sockconnect(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port));
}

int tcpconnect(const char *ipaddr, const char *port) {
	return (sockconnect(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, ipaddr, port));
}
