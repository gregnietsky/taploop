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
 *	Pau-Chen Cheng, Jeff Kraemer, and Michael Oehler, have provided
 *	useful comments on early drafts, and ran the first interoperability
 *	tests of this specification. Jeff and Pau-Chen kindly provided the
 *	sample code and test vectors that appear in the appendix.  Burt
 *	Kaliski, Bart Preneel, Matt Robshaw, Adi Shamir, and Paul van
 *	Oorschot have provided useful comments and suggestions during the
 *	investigation of the HMAC construction.
 */

/*
 * User password crypt function from the freeradius project (addattrpasswd)
 * Copyright (C) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 The FreeRADIUS Server Project
 */

#include <stdint.h>
#include <signal.h>

typedef struct radius_packet radius_packet;

typedef void	(*radius_cb)(struct radius_packet*, void*);
typedef void    *(*threadcleanup)(void*);
typedef void    *(*threadfunc)(void**);
typedef void	(*syssighandler)(int, siginfo_t*, void*);
typedef int     (*threadsighandler)(int, void*);
typedef	int	(*frameworkfunc)(int, char**);
typedef int	(*blisthash)(void*, int);
typedef void	(*objdestroy)(void*);

/*these can be set int the application */
struct framework_core {
	const char *developer;
	const char *email;
	const char *www;
	const char *runfile;
	const char *progname;
	int  year;
	int  flock;
	long	my_pid;
	struct sigaction *sa;
	syssighandler	sig_handler;
};

/*Initialise the framework */
int framework_init(int argc, char *argv[], frameworkfunc callback, struct framework_core *core_info);
/* Setup the run enviroment*/
struct framework_core *framework_mkcore(char *progname, char *name, char *email, char *web, int year, char *runfile, syssighandler sigfunc);
/* Run a thread under the framework */
struct thread_pvt *framework_mkthread(threadfunc, threadcleanup, threadsighandler, void *data);
/* Shutdown framework*/
void framework_shutdown(void);
/* UNIX Socket*/
void framework_unixsocket(char *sock, int protocol, int mask, threadfunc connectfunc, threadcleanup cleanup);
/* Test if the thread is running when passed data from thread */
int framework_threadok(void *data);

/*
 * ref counted objects
 */
int objlock(void *data);
int objtrylock(void *data);
int objunlock(void *data);
int objcnt(void *data);
int objunref(void *data);
int objref(void *data);
void *objalloc(int size, objdestroy);

/*
 * hashed bucket lists
 */
void *create_bucketlist(int bitmask, blisthash hash_function);
int addtobucket(void *blist, void *data);
int bucket_list_cnt(void *blist);
void *bucket_list_find_key(void *list, void *key);

/*
 * iteration through buckets
 */
struct bucket_loop *init_bucket_loop(void *blist);
void stop_bucket_loop(void *bloop);
void *next_bucket_loop(void *bloop);
void remove_bucket_loop(void *bloop);
void remove_bucket_item(void *bucketlist, void *data);

/*include jenkins hash burttlebob*/
uint32_t hashlittle(const void *key, size_t length, uint32_t initval);


/*
 * Utilities RNG/MD5 used from the openssl library
 */
void seedrand(void);
void genrand(void *buf, int len);
void md5sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2);
void md5sum(unsigned char *buff, const void *data, unsigned long len);
int md5cmp(unsigned char *md51, unsigned char *md52, int len);
void md5hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen);

/*IP Utilities*/
int sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port);
int udpconnect(const char *ipaddr, const char *port);
int tcpconnect(const char *ipaddr, const char *port);

/*Radius utilities*/
#define RAD_AUTH_HDR_LEN	20
#define RAD_AUTH_PACKET_LEN	4096
#define RAD_AUTH_TOKEN_LEN	16
#define RAD_MAX_PASS_LEN	128

#define RAD_ATTR_USER_NAME	1	/*string*/
#define RAD_ATTR_USER_PASSWORD	2	/*passwd*/
#define RAD_ATTR_NAS_IP_ADDR	4	/*ip*/
#define RAD_ATTR_NAS_PORT	5	/*int*/
#define RAD_ATTR_SERVICE_TYPE	6	/*int*/
#define RAD_ATTR_ACCTID		44
#define RAD_ATTR_PORT_TYPE	61	/*int*/
#define RAD_ATTR_EAP		79	/*oct*/
#define RAD_ATTR_MESSAGE	80	/*oct*/

enum RADIUS_CODE {
	RAD_CODE_AUTHREQUEST	=	1,
	RAD_CODE_AUTHACCEPT	=	2,
	RAD_CODE_AUTHREJECT	=	3,
	RAD_CODE_ACCTREQUEST	=	4,
	RAD_CODE_ACCTRESPONSE	=	5,
	RAD_CODE_AUTHCHALLENGE	=	11
};

unsigned char *addattr(struct radius_packet *packet, char type, unsigned char *val, char len);
void addattrint(struct radius_packet *packet, char type, unsigned int val);
void addattrip(struct radius_packet *packet, char type, char *ipaddr);
void addattrstr(struct radius_packet *packet, char type, char *str);
void addattrpasswd(struct radius_packet *packet, const char *pw, const char *secret);
struct radius_packet *new_radpacket(unsigned char code, unsigned char id);
int send_radpacket(struct radius_packet *packet, const char *userpass, radius_cb read_cb, void *cb_data);
void add_radserver(const char *ipaddr, const char *auth, const char *acct, const char *secret, int timeout);
unsigned char *radius_attr_first(struct radius_packet *packet);
unsigned char *radius_attr_next(struct radius_packet *packet, unsigned char *attr);

/*easter egg copied from <linux/jhash.h>*/
#define JHASH_INITVAL           0xdeadbeef
#define jenhash(key, length, initval)   hashlittle(key, length, (initval) ? initval : JHASH_INITVAL);

/*
 * atomic flag routines for (obj)->flags
 */
#define clearflag(obj, flag) objlock(obj); \
	obj->flags &= ~flag; \
	objunlock(obj)

#define setflag(obj, flag) objlock(obj); \
	obj->flags |= flag; \
	objunlock(obj)

#define testflag(obj, flag) (objlock(obj) | (obj->flags & flag) | objunlock(obj))

#define FRAMEWORK_MAIN(progname, name, email, www, year, runfile, sighfunc) \
	int  framework_main(int argc, char *argv[]); \
	struct framework_core *core_info; \
	int  main(int argc, char *argv[]) { \
		core_info = framework_mkcore(progname, name, email, www, year, runfile, sighfunc); \
		return (framework_init(argc, argv, framework_main, core_info)); \
	} \
	int  framework_main(int argc, char *argv[])

#define ALLOC_CONST(const_var, val) { \
		char *tmp_char; \
		if (val) { \
			tmp_char = malloc(strlen(val) + 1); \
			strcpy(tmp_char, val); \
			const_var = tmp_char; \
		} else { \
			const_var = NULL; \
		} \
	}
