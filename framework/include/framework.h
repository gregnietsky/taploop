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

#ifndef _FW_FRAMEWORK_H
#define _FW_FRAMEWORK_H

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
	struct bucket_list *children;
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
typedef void	(*config_filecb)(struct bucket_list*, const char*, const char*);
typedef void	(*config_catcb)(struct bucket_list*, const char*);
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
extern int framework_init(int argc, char *argv[], frameworkfunc callback, struct framework_core *core_info);
/* Setup the run enviroment*/
extern struct framework_core *framework_mkcore(char *progname, char *name, char *email, char *web, int year, char *runfile, syssighandler sigfunc);
/* Run a thread under the framework */
extern struct thread_pvt *framework_mkthread(threadfunc, threadcleanup, threadsighandler, void *data);
/* Shutdown framework*/
extern void framework_shutdown(void);
/* UNIX Socket*/
extern void framework_unixsocket(char *sock, int protocol, int mask, threadfunc connectfunc, threadcleanup cleanup);
/* Test if the thread is running when passed data from thread */
extern int framework_threadok(void *data);
extern int starthreads(void);
extern void stopthreads(void);

/*
 * ref counted objects
 */
extern int objlock(void *data);
extern int objtrylock(void *data);
extern int objunlock(void *data);
extern int objcnt(void *data);
extern int objunref(void *data);
extern int objref(void *data);
extern void *objalloc(int size, objdestroy);

/*
 * hashed bucket lists
 */
extern void *create_bucketlist(int bitmask, blisthash hash_function);
extern int addtobucket(struct bucket_list *blist, void *data);
extern void remove_bucket_item(struct bucket_list *blist, void *data);
extern int bucket_list_cnt(struct bucket_list *blist);
extern void *bucket_list_find_key(struct bucket_list *list, const void *key);
extern void bucketlist_callback(struct bucket_list *blist, blist_cb callback, void *data2);

/*
 * iteration through buckets
 */
extern struct bucket_loop *init_bucket_loop(struct bucket_list *blist);
extern void stop_bucket_loop(struct bucket_loop *bloop);
extern void *next_bucket_loop(struct bucket_loop *bloop);
extern void remove_bucket_loop(struct bucket_loop *bloop);

/*include jenkins hash burttlebob*/
extern uint32_t hashlittle(const void *key, size_t length, uint32_t initval);


/*
 * Utilities RNG/MD5 used from the openssl library
 */
extern void seedrand(void);
extern int genrand(void *buf, int len);
extern void md5sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2);
extern void md5sum(unsigned char *buff, const void *data, unsigned long len);
extern int md5cmp(unsigned char *md51, unsigned char *md52, int len);
extern void md5hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen);
extern int strlenzero(const char *str);
extern char *ltrim(char *str);
extern char *rtrim(const char *str);
extern char *trim(const char *str);

/*IP Utilities*/
extern struct fwsocket *make_socket(int family, int type, int proto, void *ssl);
extern struct fwsocket *sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *udpconnect(const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *tcpconnect(const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *sockbind(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl, int backlog);
extern struct fwsocket *udpbind(const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *tcpbind(const char *ipaddr, const char *port, void *ssl, int backlog);
extern void closesocket(struct fwsocket *sock);

extern void socketclient(struct fwsocket *sock, void *data, socketrecv read, threadcleanup cleanup);
extern void socketserver(struct fwsocket *sock, socketrecv connectfunc, socketrecv acceptfunc, threadcleanup cleanup, void *data);

/*interface functions*/
extern int delete_kernvlan(char *ifname, int vid);
extern int create_kernvlan(char *ifname, unsigned short vid);
extern int delete_kernmac(char *macdev);
extern int create_kernmac(char *ifname, char *macdev, unsigned char *mac);
extern int interface_bind(char *iface, int protocol, int flags);
extern void randhwaddr(unsigned char *addr);
extern int create_tun(const char *ifname, const unsigned char *hwaddr, int flags);
extern int ifrename(const char *oldname, const char *newname);
extern int ifdown(const char *ifname, int flags);
extern int ifup(const char *ifname, int flags);
extern int ifhwaddr(const char *ifname, unsigned char *hwaddr);
extern int set_interface_flags(int ifindex, int set, int clear);
extern int get_iface_index(const char *ifname);
extern int set_interface_addr(int ifindex, const unsigned char *hwaddr);
extern int set_interface_name(int ifindex, const char *name);
extern int set_interface_ipaddr(char *ifname, char *ipaddr);
extern void closenetlink(void);

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

extern unsigned char *addradattr(struct radius_packet *packet, char type, unsigned char *val, char len);
extern void addradattrint(struct radius_packet *packet, char type, unsigned int val);
extern void addradattrip(struct radius_packet *packet, char type, char *ipaddr);
extern void addradattrstr(struct radius_packet *packet, char type, char *str);
extern struct radius_packet *new_radpacket(unsigned char code, unsigned char id);
extern int send_radpacket(struct radius_packet *packet, const char *userpass, radius_cb read_cb, void *cb_data);
extern void add_radserver(const char *ipaddr, const char *auth, const char *acct, const char *secret, int timeout);
extern unsigned char *radius_attr_first(struct radius_packet *packet);
extern unsigned char *radius_attr_next(struct radius_packet *packet, unsigned char *attr);

/*SSL Socket utilities*/
extern void sslstartup(void);
extern void *tlsv1_init(const char *cacert, const char *cert, const char *key, int verify);
extern void *sslv2_init(const char *cacert, const char *cert, const char *key, int verify);
extern void *sslv3_init(const char *cacert, const char *cert, const char *key, int verify);
extern void *dtlsv1_init(const char *cacert, const char *cert, const char *key, int verify);

extern int socketread(struct fwsocket *sock, void *buf, int num);
extern int socketwrite(struct fwsocket *sock, const void *buf, int num);
/*the following are only needed on server side of a dgram connection*/
extern int socketread_d(struct fwsocket *sock, void *buf, int num, struct sockaddr *addr);
extern int socketwrite_d(struct fwsocket *sock, const void *buf, int num, struct sockaddr *addr);

extern void ssl_shutdown(void *ssl);
extern void tlsaccept(struct fwsocket *sock, struct ssldata *orig);
extern struct fwsocket *dtls_listenssl(struct fwsocket *sock);
extern void startsslclient(struct fwsocket *sock);

/*config file parsing functions*/
extern void initconfigfiles(void);
extern void unrefconfigfiles(void);
extern int process_config(const char *configname, const char *configfile);
extern struct bucket_loop *get_category_loop(const char *configname);
extern struct bucket_list *get_category_next(struct bucket_loop *cloop, char *name, int len);
extern struct bucket_list *get_config_category(const char *configname, const char *category);
extern struct config_entry *get_config_entry(struct bucket_list *categories, const char *item);
extern void config_file_callback(config_filecb file_cb);
extern void config_cat_callback(struct bucket_list *categories, config_catcb entry_cb);
extern void config_entry_callback(struct bucket_list *entries, config_entrycb entry_cb);

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
	static int  framework_main(int argc, char *argv[]); \
	static struct framework_core *core_info; \
	int  main(int argc, char *argv[]) { \
		core_info = framework_mkcore(progname, name, email, www, year, runfile, sighfunc); \
		return (framework_init(argc, argv, framework_main, core_info)); \
	} \
	static int  framework_main(int argc, char *argv[])

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

#endif
