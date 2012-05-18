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
#include <sys/socket.h>
#include <arpa/inet.h>

/*socket structure*/
union sockstruct {
        struct sockaddr sa;
        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;
        struct sockaddr_storage ss;
};

typedef struct ssldata ssldata;

enum sock_flags {
	SOCK_FLAG_BIND		= 1 << 0,
	SOCK_FLAG_CLOSE		= 1 << 1
};

struct fwsocket {
	int sock;
	int proto;
	int type;
	enum sock_flags flags;
	union sockstruct addr;
	struct ssldata *ssl;
	struct fwsocket *parent;
	struct bucketlist *children;
};

struct config_entry {
        const char *item;
        const char *value;
};

typedef struct radius_packet radius_packet;

/*callback function type def's*/
typedef void	(*radius_cb)(struct radius_packet*, void*);
typedef void    *(*threadcleanup)(void*);
typedef void    *(*threadfunc)(void**);
typedef void	(*syssighandler)(int, siginfo_t*, void*);
typedef int     (*threadsighandler)(int, void*);
typedef	int	(*frameworkfunc)(int, char**);
typedef int	(*blisthash)(const void*, int);
typedef void	(*objdestroy)(void*);
typedef void	(*socketrecv)(struct fwsocket*, void*);
typedef void	(*blist_cb)(void*, void*);
typedef void	(*config_filecb)(struct bucketlist*, const char*, const char*);
typedef void	(*config_catcb)(struct bucketlist*, const char*);
typedef void	(*config_entrycb)(const char*, const char*);

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
int starthreads(void);
void stopthreads(void);

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
void *bucket_list_find_key(void *list, const void *key);
void bucketlist_callback(struct bucketlist *blist, blist_cb callback, void *data2);

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
int genrand(void *buf, int len);
void md5sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2);
void md5sum(unsigned char *buff, const void *data, unsigned long len);
int md5cmp(unsigned char *md51, unsigned char *md52, int len);
void md5hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen);
int strlenzero(const char *str);
char *ltrim(char *str);
char *rtrim(const char *str);
char *trim(const char *str);

/*IP Utilities*/
struct fwsocket *make_socket(int family, int type, int proto, void *ssl);
struct fwsocket *sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl);
struct fwsocket *udpconnect(const char *ipaddr, const char *port, void *ssl);
struct fwsocket *tcpconnect(const char *ipaddr, const char *port, void *ssl);
struct fwsocket *sockbind(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl, int backlog);
struct fwsocket *udpbind(const char *ipaddr, const char *port, void *ssl);
struct fwsocket *tcpbind(const char *ipaddr, const char *port, void *ssl, int backlog);
void closesocket(struct fwsocket *sock);

void socketclient(struct fwsocket *sock, void *data, socketrecv read, threadcleanup cleanup);
void socketserver(struct fwsocket *sock, socketrecv connectfunc, socketrecv acceptfunc, threadcleanup cleanup, void *data);

/*interface functions*/
int delete_kernvlan(char *ifname, int vid);
int create_kernvlan(char *ifname, int vid);
int delete_kernmac(char *macdev);
int create_kernmac(char *ifname, char *macdev, unsigned char *mac);
int interface_bind(char *iface, int protocol, int flags);
void randhwaddr(unsigned char *addr);
int create_tun(const char *ifname, const unsigned char *hwaddr, int flags);
int ifrename(const char *oldname, const char *newname);
int ifdown(const char *ifname);
int ifhwaddr(const char *ifname, unsigned char *hwaddr);

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

unsigned char *addradattr(struct radius_packet *packet, char type, unsigned char *val, char len);
void addradattrint(struct radius_packet *packet, char type, unsigned int val);
void addradattrip(struct radius_packet *packet, char type, char *ipaddr);
void addradattrstr(struct radius_packet *packet, char type, char *str);
struct radius_packet *new_radpacket(unsigned char code, unsigned char id);
int send_radpacket(struct radius_packet *packet, const char *userpass, radius_cb read_cb, void *cb_data);
void add_radserver(const char *ipaddr, const char *auth, const char *acct, const char *secret, int timeout);
unsigned char *radius_attr_first(struct radius_packet *packet);
unsigned char *radius_attr_next(struct radius_packet *packet, unsigned char *attr);

/*SSL Socket utilities*/
void sslstartup(void);
void *tlsv1_init(const char *cacert, const char *cert, const char *key, int verify);
void *sslv2_init(const char *cacert, const char *cert, const char *key, int verify);
void *sslv3_init(const char *cacert, const char *cert, const char *key, int verify);
void *dtlsv1_init(const char *cacert, const char *cert, const char *key, int verify);

int socketread(struct fwsocket *sock, void *buf, int num);
int socketwrite(struct fwsocket *sock, const void *buf, int num);
/*the following are only needed on server side of a dgram connection*/
int socketread_d(struct fwsocket *sock, void *buf, int num, struct sockaddr *addr);
int socketwrite_d(struct fwsocket *sock, const void *buf, int num, struct sockaddr *addr);

void ssl_shutdown(void *ssl);
void tlsaccept(struct fwsocket *sock, struct ssldata *orig);
struct fwsocket *dtls_listenssl(struct fwsocket *sock);
void startsslclient(struct fwsocket *sock);

/*config file parsing functions*/
void initconfigfiles(void);
void unrefconfigfiles(void);
int process_config(const char *configname, const char *configfile);
struct bucket_loop *get_category_loop(const char *configname);
struct bucketlist *get_category_next(struct bucket_loop *cloop, char *name, int len);
struct bucketlist *get_config_category(const char *configname, const char *category);
struct config_entry *get_config_entry(struct bucketlist *categories, const char *item);
void config_file_callback(config_filecb file_cb);
void config_cat_callback(struct bucketlist *categories, config_catcb entry_cb);
void config_entry_callback(struct bucketlist *entries, config_entrycb entry_cb);

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
