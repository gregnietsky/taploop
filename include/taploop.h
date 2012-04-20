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

typedef struct tl_socket tl_socket;

/* taploop structure defining sockets dev names*/
struct taploop {
	char		pname[IFNAMSIZ+1];
	char		pdev[IFNAMSIZ+1];
	unsigned char	hwaddr[ETH_ALEN];
	int		mmap_size;	/*for mmap ring buffer phy sock*/
	int		mmap_blks;	/*for mmap ring buffer phy sock*/
	void		*mmap;		/*mmaap buffer phy sock*/
	struct		iovec *ring;	/*ring buffer phy*/
	struct		tl_socket *socks;
};

void process_packet(void *buffer, int len, struct taploop *tap, struct tl_socket *sock, struct tl_socket *osock, int offset);

/* tun/tap clone device and client socket*/
char	*tundev;
char	*clsock;

void clientserv_run(void);
