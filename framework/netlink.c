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

#include <netlink/route/link.h>

void nltest(void) {
	struct nl_cache *cache;
	struct rtnl_link *link;
	struct nl_sock *sock;

	if ((rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache)) < 0) {
	}

	if (!(link = rtnl_link_get_by_name(cache, "eth1"))) {
	}

	rtnl_link_put(link);
/*	nl_cache_put(cache);*/
}
