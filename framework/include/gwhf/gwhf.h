// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef GWHF__GWHF_H
#define GWHF__GWHF_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef GWHF_EXPORT
#define GWHF_EXPORT __attribute__((__visibility__("default")))
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef POSIX_C_SOURCE
#define POSIX_C_SOURCE 200809L
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

struct gwhf;

struct stack16 {
	uint16_t	*data;
	uint16_t	top;
	uint16_t	size;
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
};

struct gwhf_hdr_field_off {
	uint16_t	off_key;
	uint16_t	off_val;
};

struct gwhf_hdr_field_str {
	char		*key;
	char		*val;
};

enum {
	GWHF_CONTENT_LENGTH_INVALID       = -4,
	GWHF_CONTENT_LENGTH_UNINITIALIZED = -3,

	/*
	 * When the client sends "Transfer-Encoding: chunked".
	 */
	GWHF_CONTENT_LENGTH_CHUNKED       = -2,

	/*
	 * When the client does not send a "Content-Length" header
	 * nor "Transfer-Encoding: chunked".
	 */
	GWHF_CONTENT_LENGTH_NOT_PRESENT   = -1,
};

struct gwhf_res_hdr {
	struct gwhf_hdr_field_str	*fields;

	/*
	 * The status code (200, 403, 404, etc.)
	 */
	int16_t				status_code;

	/*
	 * Number of elements in @fields.
	 */
	uint16_t			nr_fields;

	/*
	 * Total required length to construct the response header.
	 */
	uint32_t			total_req_len;
};

struct gwhf_req_hdr {
	char				*buf;
	struct gwhf_hdr_field_off	*fields;

	/*
	 * The length of @buf.
	 */
	uint16_t			buf_len;

	/*
	 * Number of elements in @fields.
	 */
	uint16_t			nr_fields;

	/*
	 * The offset of the request method, URI, query string,
	 * and HTTP version in @buf.
	 */
	uint16_t			off_method;
	uint16_t			off_uri;
	uint16_t			off_qs;
	uint16_t			off_version;

	int64_t				content_length;
};

static inline char *gwhf_req_hdr_get_method(struct gwhf_req_hdr *hdr)
{
	return hdr->buf + hdr->off_method;
}

static inline char *gwhf_req_hdr_get_uri(struct gwhf_req_hdr *hdr)
{
	return hdr->buf + hdr->off_uri;
}

static inline char *gwhf_req_hdr_get_qs(struct gwhf_req_hdr *hdr)
{
	if (hdr->off_qs == (uint16_t)-1)
		return NULL;

	return hdr->buf + hdr->off_qs;
}

static inline char *gwhf_req_hdr_get_version(struct gwhf_req_hdr *hdr)
{
	return hdr->buf + hdr->off_version;
}


GWHF_EXPORT char *gwhf_req_hdr_get_field(struct gwhf_req_hdr *hdr,
					 const char *key);

GWHF_EXPORT int gwhf_res_hdr_add_field(struct gwhf_res_hdr *hdr,
				       const char *key,
				       const char *fmtval, ...);

static inline void gwhf_res_hdr_set_status_code(struct gwhf_res_hdr *hdr,
						int16_t status_code)
{
	hdr->status_code = status_code;
}

static inline int gwhf_res_hdr_set_content_length(struct gwhf_res_hdr *hdr,
						  int64_t content_length)
{
	return gwhf_res_hdr_add_field(hdr, "Content-Length", "%lld",
				      (long long)content_length);
}

static inline int gwhf_res_hdr_set_content_type(struct gwhf_res_hdr *hdr,
						const char *content_type)
{
	return gwhf_res_hdr_add_field(hdr, "Content-Type", "%s", content_type);
}

struct gwhf_client;

GWHF_EXPORT int gwhf_res_body_set_fd(struct gwhf_client *cl, int fd,
				     uint64_t len);

GWHF_EXPORT int gwhf_res_body_set_ref_fd(struct gwhf_client *cl, int fd,
					 uint64_t len);

GWHF_EXPORT int gwhf_res_body_add_buf(struct gwhf_client *cl, const void *buf,
				      uint64_t len);

GWHF_EXPORT int gwhf_res_body_set_ref_buf(struct gwhf_client *cl,
					  const void *buf, uint64_t len);

static inline int gwhf_res_body_add_buf_str(struct gwhf_client *cl,
					    const char *str)
{
	return gwhf_res_body_add_buf(cl, str, strlen(str));
}

enum {
	GWHF_RES_BODY_TYPE_NONE    = 0,
	GWHF_RES_BODY_TYPE_FD      = 1,
	GWHF_RES_BODY_TYPE_REF_FD  = 2,
	GWHF_RES_BODY_TYPE_BUF     = 3,
	GWHF_RES_BODY_TYPE_REF_BUF = 4,
};

struct gwhf_res_body_fd {
	int		fd;
	uint64_t	len;
};

struct gwhf_res_body_buf {
	void		*buf;
	uint64_t	len;
};

struct gwhf_res_body {
	uint8_t		type;
	void		(*callback_done)(void *arg);
	void		*arg;
	uint64_t	off;

	union {
		struct gwhf_res_body_fd		fd;
		struct gwhf_res_body_fd		ref_fd;
		struct gwhf_res_body_buf	buf;
		struct gwhf_res_body_buf	ref_buf;
	};
};

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

/*
 * struct gwhf_socket represents the TCP socket that will
 * be used to listen for incoming connections.
 */
struct gwhf_socket {
	int			fd;
	struct sockaddr_gwhf	bind_data;
};

/*
 * struct gwhf_client represents a client connection. Each
 * client connection will have a single struct gwhf_client.
 */
struct gwhf_client {
	/*
	 * The client socket file descriptor.
	 */
	int			fd;

	/*
	 * The client state. To determine what to do next.
	 */
	uint8_t			state;

	/*
	 * The total number of bytes received request body.
	 */
	int64_t			total_req_body_recv;

	/*
	 * Buffer for request and response.
	 */
	char			*req_buf;
	char			*res_buf;

	/*
	 * The allocated size of @req_buf and @res_buf.
	 *
	 * These two are for optimization purposes by
	 * reducing the number of calls to realloc().
	 */
	uint16_t		req_buf_alloc;
	uint16_t		res_buf_alloc;

	/*
	 * The occupied size of @req_buf and @res_buf. These
	 * two must be less than or equal to the allocated
	 * size.
	 */
	uint16_t		req_buf_len;
	uint16_t		res_buf_len;

	/*
	 * The number of bytes sent from @res_buf.
	 */
	uint16_t		res_buf_sent;


	/*
	 * struct gwhf_client is stored in an array. @id is
	 * the index of the current struct gwhf_client in
	 * the array.
	 */
	uint16_t		id;

	/*
	 * The client address.
	 */
	struct sockaddr_gwhf	addr;

	struct gwhf_req_hdr	req_hdr;
	struct gwhf_res_hdr	res_hdr;
	struct gwhf_res_body	res_body;

	/*
	 * The last activity time. Used to check for timeout.
	 */
	struct timespec		last_act;

	void			*private_data;
	bool			pollout_set;
};

struct gwhf_client_slot {
	struct gwhf_client	*clients;
	struct stack16		stack;
};

enum {
	GWHF_EV_DEFAULT  = 0,
	GWHF_EV_POLL     = 1,
	GWHF_EV_EPOLL    = 2,
	GWHF_EV_IO_URING = 3
};

struct gwhf_epoll {
	int			epoll_fd;
	int			event_fd;
	int			timeout;
	uint16_t		nr_events;
	struct epoll_event	*events;
};

struct gwhf_init_arg {
	uint8_t			ev_type;
	uint16_t		nr_clients;
	uint16_t		bind_port;
	const char		*bind_addr;
	int			listen_backlog;

	union {
		struct {
			uint16_t	max_events;
			int		timeout;
		} epoll;
	};
};

/*
 * struct gwhf represents the main GNU/Weeb HTTP Framework
 * object.
 */
struct gwhf {
	volatile bool			stop;
	struct gwhf_socket		socket;
	struct gwhf_client_slot		client_slot;

	/*
	 * Internal framework data.
	 */
	void				*internal_data;

	union {
		struct gwhf_epoll ep;
	};

	struct timespec			now;
	struct gwhf_init_arg		init_arg;
};

GWHF_EXPORT int gwhf_stack16_init(struct stack16 *s16, uint16_t size);
GWHF_EXPORT void gwhf_stack16_destroy(struct stack16 *s16);
GWHF_EXPORT int __gwhf_stack16_push(struct stack16 *s16, uint16_t num);
GWHF_EXPORT int gwhf_stack16_push(struct stack16 *s16, uint16_t num);
GWHF_EXPORT int __gwhf_stack16_pop(struct stack16 *s16, uint16_t *num);
GWHF_EXPORT int gwhf_stack16_pop(struct stack16 *s16, uint16_t *num);

GWHF_EXPORT void gwhf_destroy(struct gwhf *ctx);
GWHF_EXPORT int gwhf_init(struct gwhf *ctx, const struct gwhf_init_arg *arg);
GWHF_EXPORT int gwhf_run_event_loop(struct gwhf *ctx);

GWHF_EXPORT int gwhf_add_route_header(struct gwhf *ctx,
			int (*callback)(struct gwhf *, struct gwhf_client *));
GWHF_EXPORT int gwhf_add_route_body(struct gwhf *ctx,
			int (*callback)(struct gwhf *, struct gwhf_client *));

enum {
	GWHF_ROUTE_EXECUTED  = 1,
	GWHF_ROUTE_NOT_FOUND = 2,
	GWHF_ROUTE_CONTINUE  = 3,
	GWHF_ROUTE_ERROR     = 4,
};

static inline void *ERR_PTR(long err)
{
	return (void *)err;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return (unsigned long)ptr > (unsigned long)-4096ul;
}

static inline void gwhf_set_stop(struct gwhf *ctx)
{
	ctx->stop = true;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GWHF__GWHF_H */
