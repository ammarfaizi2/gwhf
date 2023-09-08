
#include "./ssl.h"

int gwhf_ssl_init(struct gwhf *ctx)
{
	struct gwhf_init_arg_ssl *ssl_arg = &ctx->init_arg.ssl;
	struct gwhf_internal *ctxi = ctx->internal;
	const char *cert = ssl_arg->cert_file;
	const char *key = ssl_arg->key_file;
	const SSL_METHOD *method;
	SSL_CTX *ssl_ctx;

	SSL_library_init();
	SSL_load_error_strings();
	method = TLS_server_method();
	ssl_ctx = SSL_CTX_new(method);
	if (!ssl_ctx)
		return -ENOMEM;

	if (SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ssl_ctx);
		return -EINVAL;
	}

	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ssl_ctx);
		return -EINVAL;
	}

	ctxi->ssl_ctx = ssl_ctx;
	return 0;
}

void gwhf_ssl_destroy(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;

	if (ctxi->ssl_ctx) {
		SSL_CTX_free(ctxi->ssl_ctx);
		ctxi->ssl_ctx = NULL;
	}
}

int gwhf_ssl_init_client(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_internal *ctxi = ctx->internal;
	BIO *rbio, *wbio;
	SSL *ssl;

	rbio = BIO_new(BIO_s_mem());
	if (!rbio)
		return -ENOMEM;

	wbio = BIO_new(BIO_s_mem());
	if (!wbio)
		goto out_rbio;

	ssl = SSL_new(ctxi->ssl_ctx);
	if (!ssl)
		goto out_wbio;

	SSL_set_bio(ssl, rbio, wbio);
	SSL_set_accept_state(ssl);
	cl->ssl = ssl;
	cl->rbio = rbio;
	cl->wbio = wbio;

	return 0;

out_wbio:
	BIO_free(wbio);
out_rbio:
	BIO_free(rbio);
	return -ENOMEM;
}

void gwhf_ssl_destroy_client(struct gwhf_client *cl)
{
	if (cl->ssl) {
		SSL_free(cl->ssl);
		cl->ssl = NULL;
		cl->rbio = NULL;
		cl->wbio = NULL;
	}
}
