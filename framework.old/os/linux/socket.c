
#include <gwhf/socket.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

int gwhf_sock_global_init(void)
{
	return 0;
}

void gwhf_sock_global_destroy(void)
{
}

int gwhf_sock_create(struct gwhf_sock *sk, int af, int type, int prot)
{
	int fd;

	fd = socket(af, type, prot);
	if (fd < 0)
		return -errno;

	sk->fd = fd;
	sk->type = type;
	return 0;
}

int gwhf_sock_bind(struct gwhf_sock *sk, struct sockaddr_gwhf *sg,
		   socklen_t len)
{
	int ret;

	ret = bind(sk->fd, &sg->sa, len);
	if (ret < 0)
		return -errno;

	return 0;
}

int gwhf_sock_listen(struct gwhf_sock *sk, int backlog)
{
	int ret;

	ret = listen(sk->fd, backlog);
	if (ret < 0)
		return -errno;

	return 0;
}

int gwhf_sock_accept(struct gwhf_sock *ret, struct gwhf_sock *sk,
		     struct sockaddr_gwhf *sg, socklen_t *len)
{
	int fd;

	fd = accept(sk->fd, &sg->sa, len);
	if (fd < 0)
		return -errno;

	ret->fd = fd;
	ret->type = sk->type;
	return 0;
}

int gwhf_sock_connect(struct gwhf_sock *sk, struct sockaddr_gwhf *dst,
		      socklen_t len)
{
	int ret;

	ret = connect(sk->fd, &dst->sa, len);
	if (ret < 0)
		return -errno;

	return 0;
}

int gwhf_sock_close(struct gwhf_sock *sk)
{
	int ret;

	if (sk->fd < 0)
		return 0;

	ret = close(sk->fd);
	if (ret < 0)
		return -errno;

	sk->fd = -1;
	return 0;
}
