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

#include <stdint.h>
#include <arpa/inet.h>

/*
 * Compare a ip address to a network address of bits long
 * in chunks of 32 bits returns 0 on match
 */
int checkipv6mask(const char *ipaddr, const char *network, uint8_t bits) {
	uint8_t cnt, bytelen, bitlen;
	uint32_t mask, res = 0;
	uint32_t *nw = (uint32_t*)network;
	uint32_t *ip = (uint32_t*)ipaddr;

	/*calculate significant bytes and bits outside boundry*/
	if ((bitlen = bits % 32)) {
		bytelen = (bits - bitlen) / 32;
		bytelen++;
	} else {
		bytelen = bits / 32;
	}

	/*end loop on first mismatch do not check last block*/
	for(cnt = 0;(!res && (cnt < (bytelen - 1)));cnt++) {
		res += nw[cnt] ^ ip[cnt];
	}

	/*process last block if no error sofar*/
	if (!res) {
		mask = (bitlen) ? htonl(~((1 << (32 - bitlen)) - 1)) : -1;
		res += (nw[cnt] & mask) ^ (ip[cnt] & mask);
	}

	return (res);
}
