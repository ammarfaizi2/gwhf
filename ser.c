#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static SSL_CTX *gwhf_init_ssl_ctx(void)
{
	const char *CERT_FILE = "q.pem";
	const char *KEY_FILE = "q.key";
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_library_init();
	SSL_load_error_strings();
	method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

static int create_tcp_sock(void)
{
	struct sockaddr_in6 addr;
	int fd, err;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &(int){ 1 }, sizeof(int));

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(60443);
	addr.sin6_addr = in6addr_any;
	err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		perror("bind");
		close(fd);
		return -1;
	}

	err = listen(fd, 5);
	if (err < 0) {
		perror("listen");
		close(fd);
		return -1;
	}

	return fd;
}

int main(void)
{
	bool handshake_ok = false;
	char buf[4096] = { };
	BIO *rbio, *wbio;
	SSL_CTX *ctx;
	SSL *ssl;
	int tcp_fd;
	int cli_fd;

	tcp_fd = create_tcp_sock();
	if (tcp_fd < 0)
		return 1;

	ctx = gwhf_init_ssl_ctx();
	if (!ctx) {
		close(tcp_fd);
		return 1;
	}

	ssl = SSL_new(ctx);
	rbio = BIO_new(BIO_s_mem());
	wbio = BIO_new(BIO_s_mem());
	SSL_set_bio(ssl, rbio, wbio);
	SSL_set_accept_state(ssl);

	cli_fd = accept(tcp_fd, NULL, NULL);
	if (cli_fd < 0) {
		perror("accept");
		close(tcp_fd);
		return 1;
	}

	while (1) {
		ssize_t ret;

		ret = recv(cli_fd, buf, sizeof(buf), 0);
		if (ret < 0) {
			perror("recv");
			break;
		}

		ret = BIO_write(rbio, buf, ret);
		if (ret <= 0) {
			perror("BIO_write");
			break;
		}

		SSL_do_handshake(ssl);

		ret = BIO_read(wbio, buf, sizeof(buf));
		if (ret <= 0) {
			perror("BIO_read");
			break;
		}

		ret = send(cli_fd, buf, ret, 0);
		if (ret < 0) {
			perror("send");
			break;
		}

		printf("handshake\n");
		if (SSL_is_init_finished(ssl)) {
			printf("handshake ok\n");
			handshake_ok = true;
			break;
		}
		memset(buf, 0, sizeof(buf));
	}

	if (!handshake_ok)
		goto out;

	char http_resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello\n";
	int tmp;

	tmp = recv(cli_fd, buf, sizeof(buf), 0);
	printf("recv: %d\n", tmp);
	tmp = BIO_write(rbio, buf, tmp);
	printf("BIO_write: %d\n", tmp);
	tmp = SSL_read(ssl, buf, sizeof(buf));
	printf("SSL_read: %d\n", tmp);
	buf[tmp] = '\0';
	printf("buf: %s\n", buf);

	tmp = SSL_write(ssl, http_resp, sizeof(http_resp) - 1);
	printf("SSL_write: %d\n", tmp);
	tmp = BIO_read(wbio, buf, sizeof(buf));
	printf("BIO_read: %d\n", tmp);
	tmp = send(cli_fd, buf, tmp, 0);
	printf("send: %d\n", tmp);

out:
	close(tcp_fd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	return 0;
}
