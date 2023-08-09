
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/*
 * struct sockaddr_gwhf represents an IPv4 or IPv6 address.
 */
struct sockaddr_gwhf {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	};
};

struct gwhf_sock {
	SOCKET	fd;
	int	type;
};

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

int gwhf_sock_global_init(void)
{
	WSADATA wsa_data;
	int ret;

	ret = WSAStartup(MAKEWORD(2,2), &wsa_data);
	if (ret)
		return ret;

	return 0;
}

int gwhf_sock_create(struct gwhf_sock *sk, int af, int type, int prot)
{
	SOCKET fd;

	fd = socket(af, type, prot);
	if (fd == INVALID_SOCKET)
		return WSAGetLastError();

	sk->fd = fd;
	sk->type = type;
	return 0;
}

int gwhf_sock_bind(struct gwhf_sock *sk, struct sockaddr_gwhf *sg,
		   socklen_t len)
{
	int ret;

	ret = bind(sk->fd, (struct sockaddr *)sg, len);
	if (ret == SOCKET_ERROR)
		return WSAGetLastError();

	return 0;
}

int gwhf_sock_listen(struct gwhf_sock *sk, int backlog)
{
	return listen(sk->fd, backlog);
}

int gwhf_sock_accept(struct gwhf_sock *ret, struct gwhf_sock *sk,
		     struct sockaddr_gwhf *sg, socklen_t *len)
{
	SOCKET fd;

	fd = accept(sk->fd, (struct sockaddr *)sg, len);
	if (fd == INVALID_SOCKET)
		return WSAGetLastError();

	ret->fd = fd;
	ret->type = sk->type;
	return 0;
}

int gwhf_sock_connect(struct gwhf_sock *sk, struct sockaddr_gwhf *dst,
		      socklen_t len)
{
	int ret;

	ret = connect(sk->fd, (struct sockaddr *)dst, len);
	if (ret == SOCKET_ERROR)
		return WSAGetLastError();

	return 0;
}
