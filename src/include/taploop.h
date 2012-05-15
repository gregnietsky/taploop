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

#include <sys/socket.h>
#include <linux/if_arp.h>

/* taploop structure defining sockets dev names*/
struct taploop {
	char		pname[IFNAMSIZ+1];
	char		pdev[IFNAMSIZ+1];
	unsigned char	hwaddr[ETH_ALEN];
	int		mmap_size;	/*for mmap ring buffer phy sock*/
	int		mmap_blks;	/*for mmap ring buffer phy sock*/
	void		*mmap;		/*mmaap buffer phy sock*/
	struct		iovec *ring;	/*ring buffer phy*/
	struct		bucket_list *socks;
	int		stop;
};

struct bucket_list	*taplist;
