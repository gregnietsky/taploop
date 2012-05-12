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

#include <openssl/ssl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <framework.h>

enum SSLTYPE {
	SSL_TLSV1	= 1 << 0,
	SSL_SSLV2	= 1 << 1,
	SSL_SSLV3	= 1 << 2,
	SSL_DTLSV1	= 1 << 3,
	SSL_CLIENT	= 1 << 4,
	SSL_SERVER	= 1 << 5,
	SSL_DTLSCON	= 1 << 6
};

struct ssldata {
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	int flags;
	const SSL_METHOD *meth;
};

#define COOKIE_SECRET_LENGTH 16
unsigned char *cookie_secret = NULL;

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
	struct sockaddr peer;

	if (!cookie_secret) {
		return 0;
	}

	memset(&peer, 0, sizeof(peer));
	BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
	HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH, (const unsigned char*)&peer, sizeof(peer), cookie, cookie_len);

	return 1;
}

int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len) {
	struct sockaddr peer;
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int resultlength;

	if (!cookie_secret) {
		return 0;
	}

	memset(&peer, 0, sizeof(peer));
	BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
	HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH, (const unsigned char*)&peer, sizeof(peer), result, &resultlength);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0) {
		return 1;
	}
	return 0;
}

void free_ssldata(void *data) {
	struct ssldata *ssl = data;

	if (ssl->ssl) {
		SSL_free(ssl->ssl);
	}

	if (ssl->ctx) {
		SSL_CTX_free(ssl->ctx);
	}
}

int verify_callback (int ok, X509_STORE_CTX *ctx) {
	return (1);
}

struct ssldata *sslinit(const char *cacert, const char *cert, const char *key, int verify, const SSL_METHOD *meth, int flags) {
	struct ssldata *ssl;
	struct stat finfo;
	int ret = -1;

	if (!(ssl = objalloc(sizeof(*ssl), free_ssldata))) {
		return NULL;
	}

	ssl->flags = flags;
	ssl->meth = meth;
	if (!(ssl->ctx = SSL_CTX_new(meth))) {
		objunref(ssl);
		return NULL;
	}

	if (!stat(cacert, &finfo)) {
		if (S_ISDIR(finfo.st_mode) && (SSL_CTX_load_verify_locations(ssl->ctx, NULL, cacert) == 1)) {
			ret = 0;
		} else if (SSL_CTX_load_verify_locations(ssl->ctx, cacert, NULL) == 1) {
			ret = 0;
		}
	}

	if (!ret && (SSL_CTX_use_certificate_file(ssl->ctx, cert, SSL_FILETYPE_PEM) == 1)) {
		ret = 0;
	}
	if (!ret && (SSL_CTX_use_PrivateKey_file(ssl->ctx, key, SSL_FILETYPE_PEM) == 1)) {
		ret = 0;
	}

	if (!ret && (SSL_CTX_check_private_key (ssl->ctx) == 1)) {
		ret= 0;
	}

/*	Should create a tmp 512 bit rsa key for RSA ciphers also need DH
	http://www.openssl.org/docs/ssl/SSL_CTX_set_cipher_list.html
	SSL_CTX_set_cipher_list*/

	if (!ret) {
/* XXX CRL verification
		X509_VERIFY_PARAM *param;
		param = X509_VERIFY_PARAM_new();
		X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
		SSL_CTX_set1_param(ctx, param);
		X509_VERIFY_PARAM_free(param);
*/
		SSL_CTX_set_verify(ssl->ctx, verify, verify_callback);
		SSL_CTX_set_verify_depth(ssl->ctx, 1);
	}

	if (ret) {
		objunref(ssl);
		return NULL;
	}

	return ssl;
}

void *tlsv1_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = TLSv1_method();

	return (sslinit(cacert, cert, key, verify, meth, SSL_TLSV1));
}

#ifndef OPENSSL_NO_SSL2
void *sslv2_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = SSLv2_method();

	return (sslinit(cacert, cert, key, verify, meth, SSL_SSLV2));
}
#endif

void *sslv3_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = SSLv3_method();
	struct ssldata *ssl;

	ssl = sslinit(cacert, cert, key, verify, meth, SSL_SSLV3);

	return (ssl);
}

void *dtlsv1_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = DTLSv1_method();
	struct ssldata *ssl;

	ssl = sslinit(cacert, cert, key, verify, meth, SSL_DTLSV1);
/* XXX BIO_CTRL_DGRAM_MTU_DISCOVER*/
	SSL_CTX_set_read_ahead(ssl->ctx, 1);

	return (ssl);
}

void sslsockstart(struct fwsocket *sock, int accept) {
	struct ssldata *ssl = sock->ssl;

	if (!ssl) {
		return;
	}

	ssl->ssl = SSL_new(ssl->ctx);

	if (ssl->ssl) {
		ssl->bio = BIO_new_socket(sock->sock, BIO_NOCLOSE);
		SSL_set_bio(ssl->ssl, ssl->bio, ssl->bio);
		if (accept) {
			SSL_accept(ssl->ssl);
			ssl->flags |= SSL_SERVER;
		} else {
			SSL_connect(ssl->ssl);
			ssl->flags |= SSL_CLIENT;
		}
	} else {
		objunref(ssl);
		sock->ssl = NULL;
		return;
	}
}

void tlsaccept(struct fwsocket *sock) {
	sslsockstart(sock, 1);
}

int socketread_d(struct fwsocket *sock, void *buf, int num, struct sockaddr *addr) {
	struct ssldata *ssl = sock->ssl;
	socklen_t salen = sizeof(*addr);
	int ret;

	if (!ssl || !ssl->ssl) {
		if (addr && (sock->type == SOCK_DGRAM)) {
			ret = recvfrom(sock->sock, buf, num, 0, addr, &salen);
		} else {
			ret = read(sock->sock, buf, num);
		}
		return (ret);
	}

	ret = SSL_read(ssl->ssl, buf, num);
	switch (SSL_get_error(ssl->ssl, ret)) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_READ:
			printf("Want Read\n");
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			printf("Want X509\n");
			break;
		case SSL_ERROR_WANT_WRITE:
			printf("Want write\n");
			break;
		case SSL_ERROR_ZERO_RETURN:
			printf("zero return\n");
			break;
		case SSL_ERROR_SSL:
			printf("SSL ERR\n");
			break;
		case SSL_ERROR_SYSCALL:
			printf("syscall\n");
			break;
		default:
			printf("other\n");
			break;
	}

	return (ret);
}

int socketread(struct fwsocket *sock, void *buf, int num) {
	return (socketread_d(sock, buf, num, NULL));
}

int socketwrite_d(struct fwsocket *sock, const void *buf, int num, struct sockaddr *addr) {
	struct ssldata *ssl = sock->ssl;
	int ret;

	if (!ssl || !ssl->ssl) {
		if (addr && (sock->type == SOCK_DGRAM)) {
			ret = sendto(sock->sock, buf, num, 0, addr, sizeof(*addr));
		} else {
			ret = write(sock->sock, buf, num);
		}
		return (ret);
	}

	ret = SSL_write(ssl->ssl, buf, num);
	switch (SSL_get_error(ssl->ssl, ret)) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_READ:
			printf("Want Read\n");
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			printf("Want X509\n");
			break;
		case SSL_ERROR_WANT_WRITE:
			printf("Want write\n");
			break;
		case SSL_ERROR_ZERO_RETURN:
			printf("zero return\n");
			break;
		case SSL_ERROR_SSL:
			printf("SSL ERR\n");
			break;
		case SSL_ERROR_SYSCALL:
			printf("syscall\n");
			break;
		default:
			printf("other\n");
			break;
	}

	return (ret);
}

int socketwrite(struct fwsocket *sock, const void *buf, int num) {
	return (socketwrite_d(sock, buf, num, NULL));
}

void sslstartup(void) {
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	if ((cookie_secret = malloc(COOKIE_SECRET_LENGTH))) {
		genrand(cookie_secret, COOKIE_SECRET_LENGTH);
	}
}


void dtlssetopts(struct ssldata *ssl, SSL_CTX *ctx, int sock, int flags) {
	struct timeval timeout;

	ssl->bio = BIO_new_dgram(sock, flags);

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(ssl->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(ssl->bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);

	ssl->ssl = SSL_new(ctx);
	SSL_set_bio(ssl->ssl, ssl->bio, ssl->bio);
}

void dtsl_serveropts(struct fwsocket *sock) {
	struct ssldata *ssl = sock->ssl;

	ssl->flags |= SSL_SERVER;

	SSL_CTX_set_cookie_generate_cb(ssl->ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ssl->ctx, verify_cookie);
	SSL_CTX_set_session_cache_mode(ssl->ctx, SSL_SESS_CACHE_OFF);

	ssl->bio = BIO_new_dgram(sock->sock, BIO_NOCLOSE);
	ssl->ssl = SSL_new(ssl->ctx);
	SSL_set_bio(ssl->ssl, ssl->bio, ssl->bio);
	SSL_set_options(ssl->ssl, SSL_OP_COOKIE_EXCHANGE);
}

void dtlsaccept(struct fwsocket *sock) {
	struct ssldata *ssl = sock->ssl;
	struct timeval timeout;

	ssl->flags |= SSL_SERVER;

	BIO_set_fd(ssl->bio, sock->sock, BIO_NOCLOSE);
	BIO_ctrl(ssl->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &sock->addr.sa);

	SSL_accept(ssl->ssl);

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(ssl->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(ssl->bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);

	if (SSL_get_peer_certificate(ssl->ssl)) {
		printf ("A------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl->ssl)), 1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl->ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}
}

struct fwsocket *dtls_listenssl(struct fwsocket *sock) {
	struct ssldata *ssl = sock->ssl;
	struct ssldata *newssl;
	struct fwsocket *newsock;
	struct sockaddr client;
	int on = 1;

	if (!(newssl = objalloc(sizeof(*newssl), free_ssldata))) {
		return NULL;
	}

	newssl->flags |= SSL_DTLSCON;

	dtlssetopts(newssl, ssl->ctx, sock->sock, BIO_NOCLOSE);
	memset(&client, 0, sizeof(client));
	while (DTLSv1_listen(newssl->ssl, &client) <= 0);

	if (!(newsock = make_socket(sock->addr.sa.sa_family, sock->type, sock->proto, newssl))) {
		objunref(newssl);
		return NULL;
	}
	objunref(newssl); /*move this ref to the socket*/
	memcpy(&newsock->addr.sa, &client, sizeof(newsock->addr.sa));

	setsockopt(newsock->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(newsock->sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

	bind(newsock->sock, &sock->addr.sa, sizeof(sock->addr.sa));
	connect(newsock->sock, &newsock->addr.sa, sizeof(newsock->addr.sa));

	dtlsaccept(newsock);

	return newsock;
}

void dtlsconnect(struct fwsocket *sock) {
	struct ssldata *ssl = sock->ssl;

	if (!ssl) {
		return;
	}

	ssl->flags |= SSL_CLIENT;

	dtlssetopts(ssl, ssl->ctx, sock->sock, BIO_CLOSE);
	BIO_ctrl(ssl->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &sock->addr.sa);
	SSL_connect(ssl->ssl);

	if (SSL_get_peer_certificate(ssl->ssl)) {
		printf ("C------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl->ssl)), 1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl->ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}
}


void startsslclient(struct fwsocket *sock) {
	if (!sock->ssl || (sock->ssl->flags & SSL_SERVER)) {
		return;
	}

	switch(sock->type) {
		case SOCK_DGRAM:
			dtlsconnect(sock);
			break;
		case SOCK_STREAM:
			sslsockstart(sock, 0);
			break;
	}
}
