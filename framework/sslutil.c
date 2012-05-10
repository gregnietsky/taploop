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

#include <framework.h>

struct ssldata {
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	const SSL_METHOD *meth;
};

struct ssldata *sslinit(const char *cacert, const char *cert, const char *key, int verify, const SSL_METHOD *meth) {
	struct ssldata *ssl;
	struct stat finfo;
	int ret = -1;

	if (!(ssl = objalloc(sizeof(*ssl), NULL))) {
		return NULL;
	}

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

	if (!ret) {
		SSL_CTX_set_verify(ssl->ctx, verify, NULL);
		SSL_CTX_set_verify_depth(ssl->ctx, 1);
		if (!(ssl->ssl = SSL_new(ssl->ctx))) {
			ret = 0;
		}
	}

	if (ret) {
		SSL_CTX_free(ssl->ctx);
		objunref(ssl);
		if (ssl->ssl) {
			SSL_free(ssl->ssl);
		}
		return NULL;
	}

	return ssl;
}

struct ssldata *tlsv1_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = TLSv1_method();

	return (sslinit(cacert, cert, key, verify, meth));
}

#ifndef OPENSSL_NO_SSL2
struct ssldata *sslv2_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = SSLv2_method();

	return (sslinit(cacert, cert, key, verify, meth));
}
#endif

struct ssldata *sslv3_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = SSLv3_method();

	return (sslinit(cacert, cert, key, verify, meth));
}

struct ssldata *dtlsv1_init(const char *cacert, const char *cert, const char *key, int verify) {
	const SSL_METHOD *meth = DTLSv1_server_method();

	return (sslinit(cacert, cert, key, verify, meth));
}

void sslsockconnect(struct ssldata *ssl, int sock) {
	if ((ssl->bio = BIO_new_socket(sock, BIO_NOCLOSE))) {
		SSL_set_bio(ssl->ssl, ssl->bio, ssl->bio);
		SSL_connect(ssl->ssl);
	}
}

void sslsockaccept(struct ssldata *ssl, int sock) {
	if ((ssl->bio = BIO_new_socket(sock, BIO_NOCLOSE))) {
		SSL_set_bio(ssl->ssl, ssl->bio, ssl->bio);
		SSL_accept(ssl->ssl);
	}
}

int sslread(struct ssldata *ssl, void *buf, int num) {
	return (SSL_read(ssl->ssl, buf, num));
}

int sslwrite(struct ssldata *ssl, const void *buf, int num) {
	return (SSL_write(ssl->ssl, buf, num));
}

void sslstartup(void) {
	SSL_library_init();
	SSL_load_error_strings();
}
