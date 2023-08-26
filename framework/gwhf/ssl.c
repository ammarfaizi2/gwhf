// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "./ssl.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

int gwhf_ssl_init(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;
	const char *CERT_FILE = "./q.pem";
	const char *KEY_FILE = "./q.key";
	const SSL_METHOD *method;
	SSL_CTX *ssl_ctx;

	SSL_library_init();
	SSL_load_error_strings();
	method = TLS_server_method();
	ssl_ctx = SSL_CTX_new(method);
	if (!ssl_ctx)
		return -ENOMEM;

	if (SSL_CTX_use_certificate_file(ssl_ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ssl_ctx);
		return -EINVAL;
	}

	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ssl_ctx);
		return -EINVAL;
	}

	ctxi->ssl_ctx = ssl_ctx;
	return 0;
}

void gwhf_ssl_destroy(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;

	SSL_CTX_free(ctxi->ssl_ctx);
	ctxi->ssl_ctx = NULL;
}

int gwhf_ssl_create_client(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_internal *ctxi = ctx->internal;
	BIO *rbio, *wbio;
	SSL *ssl;

	ssl = SSL_new(ctxi->ssl_ctx);
	if (!ssl)
		return -ENOMEM;

	rbio = BIO_new(BIO_s_mem());
	if (unlikely(!rbio))
		goto out_ssl;

	wbio = BIO_new(BIO_s_mem());
	if (unlikely(!wbio))
		goto out_rbio;

	SSL_set_bio(ssl, rbio, wbio);
	SSL_set_accept_state(ssl);
	cl->ssl = ssl;
	cl->rbio = rbio;
	cl->wbio = wbio;
	return 0;

out_rbio:
	BIO_free(rbio);
out_ssl:
	SSL_free(ssl);
	return -ENOMEM;
}

void gwhf_ssl_destroy_client(struct gwhf_client *cl)
{
	SSL_free(cl->ssl);
	cl->ssl = NULL;
	cl->rbio = NULL;
	cl->wbio = NULL;
}
