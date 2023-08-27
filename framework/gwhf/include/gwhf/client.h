// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd.
 */

#ifndef FRAMEWORK__GWHF__INCLUDE__GWHF__CLIENT_H
#define FRAMEWORK__GWHF__INCLUDE__GWHF__CLIENT_H

#include <gwhf/common.h>
#include <gwhf/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gwhf_http_hdr_field_off {
	uint32_t	off_key;
	uint32_t	off_val;
};

struct gwhf_http_hdr_field_str {
	char		*key;
	char		*val;
};

enum {
	GWHF_CONLEN_UNSET       = -1,
	GWHF_CONLEN_INVALID     = -2,
	GWHF_CONLEN_CHUNKED     = -3,
	GWHF_CONLEN_NOT_PRESENT = -4
};

struct gwhf_http_req_hdr {
	char				*buf;
	struct gwhf_http_hdr_field_off	*hdr_fields;
	int64_t				content_length;
	uint32_t			len;
	uint32_t			off_method;
	uint32_t			off_uri;
	uint32_t			off_qs;
	uint32_t			off_version;
	uint16_t			nr_hdr_fields;
};

struct gwhf_http_req {
	struct gwhf_http_req_hdr	hdr;
	char				*body;
	uint64_t			body_len;
	uint64_t			body_alloc;
};

static inline const char *gwhf_http_req_get_method(struct gwhf_http_req *req)
{
	return req->hdr.buf + req->hdr.off_method;
}

static inline const char *gwhf_http_req_get_uri(struct gwhf_http_req *req)
{
	return req->hdr.buf + req->hdr.off_uri;
}

static inline const char *gwhf_http_req_get_qs(struct gwhf_http_req *req)
{
	if (req->hdr.off_qs == (uint32_t)-1)
		return NULL;

	return req->hdr.buf + req->hdr.off_qs;
}

static inline const char *gwhf_http_req_get_version(struct gwhf_http_req *req)
{
	return req->hdr.buf + req->hdr.off_version;
}

GWHF_EXPORT const char *gwhf_http_req_get_hdr(struct gwhf_http_req *req,
					      const char *key);

int gwhf_http_req_init(struct gwhf_http_req *req);
void gwhf_http_req_destroy(struct gwhf_http_req *req);

struct gwhf_http_res_hdr {
	struct gwhf_http_hdr_field_str	*hdr_fields;
	uint32_t			total_required_len;
	uint16_t			nr_hdr_fields;
	int16_t				status_code;
};

struct gwhf_http_res_body_buf {
	char		*buf;
	uint64_t	len;
};

struct gwhf_http_res_body_fd {
	int		fd;
	uint64_t	len;
};

struct gwhf_http_res_body_callback {
	void		*arg;
	int		(*cb)(void *arg);
	void		(*cb_free)(void *arg);
};

enum {
	GWHF_HTTP_RES_BODY_NONE     = 0,
	GWHF_HTTP_RES_BODY_BUF      = 1,
	GWHF_HTTP_RES_BODY_BUF_REF  = 2,
	GWHF_HTTP_RES_BODY_FD       = 3,
	GWHF_HTTP_RES_BODY_FD_REF   = 4,
	GWHF_HTTP_RES_BODY_CALLBACK = 5
};

struct gwhf_http_res_body {
	uint8_t		type;
	bool		chunked;
	uint64_t	off;
	union {
		struct gwhf_http_res_body_buf		buf;
		struct gwhf_http_res_body_fd		fd;
		struct gwhf_http_res_body_callback	callback;
	};
};

struct gwhf_http_res {
	struct gwhf_http_res_hdr	hdr;
	struct gwhf_http_res_body	body;
};

__gwhf_printf(3, 4)
GWHF_EXPORT int gwhf_http_res_add_hdr(struct gwhf_http_res *res,
				      const char *key,
				      const char *vfmt, ...);

GWHF_EXPORT int gwhf_http_res_del_hdr(struct gwhf_http_res *res,
				      const char *key);

GWHF_EXPORT char *gwhf_http_res_get_hdr(struct gwhf_http_res *res,
					const char *key);

GWHF_EXPORT int gwhf_http_res_add_body_buf(struct gwhf_http_res *res,
					   const void *buf,
					   uint64_t len);

GWHF_EXPORT int gwhf_http_res_set_body_buf_ref(struct gwhf_http_res *res,
					       const void *buf,
					       uint64_t len);

#if !defined(_WIN32)
GWHF_EXPORT int gwhf_http_res_set_body_fd(struct gwhf_http_res *res,
					  int fd,
					  uint64_t len);

GWHF_EXPORT int gwhf_http_res_set_body_fd_ref(struct gwhf_http_res *res,
					      int fd, uint64_t len);
#endif

const char *gwhf_http_code_to_str(int http_code);
int gwhf_http_res_init(struct gwhf_http_res *res);
void gwhf_http_res_destroy(struct gwhf_http_res *res);
int gwhf_http_res_construct_first_res(struct gwhf_http_res *res, char **buf_p,
				      size_t *len_p);

static inline
int gwhf_http_res_set_status_code(struct gwhf_http_res *res, int status_code)
{
	if (status_code < 100 || status_code > 599)
		return -EINVAL;

	res->hdr.status_code = status_code;
	return 0;
}

struct gwhf_buf {
	char		*buf;
	uint32_t	len;
	uint32_t	alloc;
};

enum {
	TCL_IDLE          = 0,

	TCL_TLS_HANDSHAKE = 1,

	TCL_RECV_HEADER   = 2,
	TCL_ROUTE_HEADER  = 3,

	TCL_RECV_BODY     = 4,
	TCL_ROUTE_BODY    = 5,

	TCL_SEND_HEADER   = 6,
	TCL_SEND_BODY     = 7,

	TCL_CLOSE         = 8,
};

struct gwhf_client_stream {
	/*
	 * Request buffer received from the client.
	 */
	struct gwhf_buf			req_buf;

	/*
	 * Response buffer to be sent to the client.
	 */
	struct gwhf_buf			res_buf;

	/*
	 * The number of bytes in |req_buf| that have
	 * been processed.
	 */
	uint32_t			sent_len;

	/*
	 * The HTTP response.
	 */
	struct gwhf_http_res		res;

	/*
	 * The HTTP request.
	 */
	struct gwhf_http_req		req;

	/*
	 * The state of the stream.
	 */
	uint8_t				state;
};

struct gwhf_client {
	/*
	 * The socket file descriptor (TCP only).
	 */
	struct gwhf_sock		fd;

	/*
	 * Client source address.
	 */
	struct sockaddr_gwhf		addr;

	/*
	 * Raw buffer.
	 */
	struct gwhf_buf			raw_recv_buf;
	struct gwhf_buf			raw_send_buf;

	/*
	 * Internal data.
	 */
	void				*data;

	/*
	 * Stream array.
	 */
	struct gwhf_client_stream	*streams;

	/*
	 * The number of streams.
	 */
	uint32_t			nr_streams;

	/*
	 * The index of current used stream.
	 */
	uint32_t			cur_stream;

	/*
	 * Is the pollout set?
	 */
	bool				pollout_set;
};

static inline struct gwhf_client_stream *
gwhf_client_get_cur_stream(struct gwhf_client *cl)
{
	return &cl->streams[cl->cur_stream];
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef FRAMEWORK__GWHF__INCLUDE__GWHF__CLIENT_H */
