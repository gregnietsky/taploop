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

#ifndef _TL_CLIENT_H
#define _TL_CLIENT_H

#include <sys/socket.h>
#include <stdint.h>
#include <linux/if_arp.h>

enum client_action {
	CA_ADD		=	1 << 0,
	CA_REM		=	1 << 1
};

enum client_acttype {
	CD_TAP		=	1 << 0,
	CD_VLAN		=	1 << 1,
	CD_MACVLAN	=	1 << 2
};

struct client_tap {
	char			device[IFNAMSIZ+1];
	char			name[IFNAMSIZ+1];
};

struct client_mac {
	char			device[IFNAMSIZ+1];
	char			name[IFNAMSIZ+1];
};

struct client_vlan {
	char			device[IFNAMSIZ+1];
	short int		vid;
};

union client_payload {
	struct client_tap	tap;
	struct client_vlan	vlan;
	struct client_mac	macvlan;
};

struct client_command {
	uint16_t len;
	uint16_t csum;
	enum	client_action	action;
	enum	client_acttype	datatype;
	union	client_payload	payload;
};

struct client_response {
	uint16_t len;
	uint16_t csum;
	int	error;
	char	message[128];
};

#endif
