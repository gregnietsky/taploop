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

#ifndef _TL_TLSOCK_H
#define _TL_TLSOCK_H

/*socket flags*/
enum sockopt {
	TL_SOCKET_NONE	= 0,
	/*this is the tap socket */
	TL_SOCKET_VIRT	= 1 << 0,
	/*this is the physical socket */
	TL_SOCKET_PHY	= 1 << 1,
	/*when writing to this socket do so as 802.1q if vid set*/
	TL_SOCKET_8021Q	= 1 << 2
};

/* socket entry*/
struct tl_socket {
	int			sock;
	int			vid;	/* VLAN ID*/
	enum sockopt		flags;
	struct tl_socket	*next;
};

/*void rbuffread(struct taploop *tap);*/
int add_taploop(char *dev, char *name);
int del_taploop(char *dev, char *name);

#endif
