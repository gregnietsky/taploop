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

/*
 * Acknowledgments [MD5 HMAC http://www.ietf.org/rfc/rfc2104.txt]
 *      Pau-Chen Cheng, Jeff Kraemer, and Michael Oehler, have provided
 *      useful comments on early drafts, and ran the first interoperability
 *      tests of this specification. Jeff and Pau-Chen kindly provided the
 *      sample code and test vectors that appear in the appendix.  Burt
 *      Kaliski, Bart Preneel, Matt Robshaw, Adi Shamir, and Paul van
 *      Oorschot have provided useful comments and suggestions during the
 *      investigation of the HMAC construction.
 */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <ctype.h>

void seedrand(void) {
	int fd = open("/dev/random", O_RDONLY);
	int len;
	char    buf[64];

	len = read(fd, buf, 64);
	RAND_seed(buf, len);
}

int genrand(void *buf, int len) {
	return (RAND_bytes(buf, len));
}

void md5sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2) {
	MD5_CTX c;

	MD5_Init(&c);
	MD5_Update(&c, data, len);
	if (data2) {
		MD5_Update(&c, data2, len2);
	}
	MD5_Final(buff, &c);
}

void md5sum(unsigned char *buff, const void *data, unsigned long len) {
        md5sum2(buff, data, len, NULL, 0);
}

int md5cmp(unsigned char *md51, unsigned char *md52, int len) {
	int cnt;
	int chk = 0;

	for(cnt = 0; cnt < len; cnt ++) {
		chk += md51[cnt] & ~md52[cnt];
	}

	return (chk);
}


void md5hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen) {
	unsigned char	okey[64], ikey[64];
	int		bcnt;

	memset(ikey, 0, 64);
	memset(okey, 0, 64);

	if (klen < 64) {
		memcpy(ikey, key, klen);
		memcpy(okey, key, klen);
	} else {
		md5sum(okey, key, klen);
		memcpy(ikey, okey, klen);
	}

	for (bcnt = 0; bcnt < 64; bcnt++) {
		ikey[bcnt] ^= 0x36;
		okey[bcnt] ^= 0x5c;
	};

	md5sum2(buff, ikey, 64, data, len);
	md5sum2(buff, okey, 64, buff, 16);
}

int strlenzero(const char *str) {
	if (str && strlen(str)) {
		return (0);
	}
	return (1);
}

char *ltrim(char *str) {
	char *cur = str;

	if (strlenzero(str)) {
		return (str);
	}

	while(isspace(cur[0])) {
		cur++;
	}

	return (cur);
}

char *rtrim(const char *str) {
	int len;
	char *cur = (char *)str;

	if (strlenzero(str)) {
		return (cur);
	}

	len = strlen(str) - 1;
	while(len && isspace(cur[len])) {
		cur[len] = '\0';
		len--;
	}

	return (cur);
}

char *trim(const char *str) {
	char *cur = (char*)str;

	cur = ltrim(cur);
	cur = rtrim(cur);
	return (cur);
}
