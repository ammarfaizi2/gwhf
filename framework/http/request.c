
#define NDEBUG
#include "request.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int parse_method_uri_version_qs(char *buf, char **second_line,
				       struct gwhf_http_req_hdr *hdr)
{
	char *head, *tail;

	assert(!hdr->off_method);
	assert(!hdr->off_uri);
	assert(!hdr->off_qs);
	assert(!hdr->off_version);

	head = buf;

	/*
	 * Find the end of the first line (CR).
	 */
	tail = strchr(head, '\r');
	if (unlikely(!tail))
		return -EINVAL;

	/*
	 * Kill the CR.
	 */
	*tail++ = '\0';

	/*
	 * Make sure the LF is present after the CR.
	 */
	if (unlikely(*tail++ != '\n'))
		return -EINVAL;

	/*
	 * Save the offset of the second line.
	 */
	*second_line = tail;

	/*
	 * @hdr->off_method is already 0u at this point.
	 *
	 * Find the end of the method (space).
	 */
	tail = strchr(head, ' ');
	if (unlikely(!tail))
		return -EINVAL;

	/*
	 * If the method is empty, it's invalid.
	 */
	if (unlikely(tail == head))
		return -EINVAL;

	/*
	 * Kill the space.
	 */
	*tail++ = '\0';

	head = tail;

	/*
	 * The URI must start with a '/'.
	 */
	if (unlikely(head[0] != '/'))
		return -EINVAL;

	/*
	 * Save the offset of the URI.
	 */
	hdr->off_uri = (uint32_t)(head - buf);

	/*
	 * Find the end of the URI (space).
	 */
	tail = strchr(head, ' ');
	if (unlikely(!tail))
		return -EINVAL;

	/*
	 * Validate the HTTP version pattern.
	 * After the space, it must be "HTTP/".
	 */
	if (unlikely(strncmp(tail + 1, "HTTP/", 5u)))
		return -EINVAL;

	/*
	 * Kill the space.
	 */
	*tail++ = '\0';

	/*
	 * Save the offset of the HTTP version.
	 */
	hdr->off_version = (uint32_t)(tail - buf);

	/*
	 * Try to find the query string (optional).
	 */
	head = &buf[hdr->off_uri];
	tail = strchr(head, '?');
	if (tail) {
		/*
		 * Kill the '?' and save the offset of the query string.
		 */
		*tail++ = '\0';
		hdr->off_qs = (uint32_t)(tail - buf);
	} else {
		/*
		 * No query string.
		 */
		hdr->off_qs = -1;
	}

	return 0;
}

static int parse_hdr_req_fields(char *buf, struct gwhf_http_req_hdr *hdr)
{
	struct gwhf_http_hdr_field_off *fields;
	uint16_t nr_fields = 0u;
	uint16_t nr_alloc = 16u; /* Don't realloc() too often. */
	char *ptr, *end;
	int err;

	assert(!hdr->hdr_fields);
	assert(!hdr->nr_hdr_fields);
	assert(hdr->content_length == GWHF_HTTP_CONLEN_UNINITIALIZED);

	hdr->content_length = GWHF_HTTP_CONLEN_NONE;
	ptr = buf;
	if (unlikely(!ptr[0]))
		return 0;

	fields = malloc(nr_alloc * sizeof(*fields));
	if (unlikely(!fields))
		return -ENOMEM;

	err = -EINVAL;
	while (ptr[0]) {
		struct gwhf_http_hdr_field_off *tmp;
		char *key, *val;

		if (ptr[0] == '\r' && ptr[1] == '\n')
			break;

		nr_fields++;

		if (unlikely(nr_fields > nr_alloc)) {
			nr_alloc *= 2;
			tmp = realloc(fields, nr_alloc * sizeof(*fields));
			if (unlikely(!tmp)) {
				err = -ENOMEM;
				goto out_err;
			}
			fields = tmp;
		}

		tmp = &fields[nr_fields - 1];

		/*
		 * Find the key and value separator (':').
		 */
		end = strchr(ptr, ':');
		if (unlikely(!end))
			goto out_err;

		/*
		 * Kill the colon separator (':').
		 */
		*end++ = '\0';

		/*
		 * Save the key offset and make the key lowercase.
		 */
		key = strtolower(ptr);

		/*
		 * Skip the trailing whitespace(s) after the colon separator.
		 */
		while (*end == ' ')
			end++;

		/*
		 * Save the value offset.
		 */
		val = end;

		/*
		 * Find the end of the value (CR).
		 */
		ptr = strchr(end, '\r');
		if (unlikely(!ptr))
			goto out_err;

		/*
		 * Kill the CR.
		 */
		*ptr++ = '\0';

		/*
		 * Make sure the LF is present after the CR.
		 */
		if (unlikely(*ptr++ != '\n'))
			goto out_err;

		/*
		 * The line is good, save the key and value offsets.
		 */
		tmp->off_key = (uint16_t)(key - hdr->buf);
		tmp->off_val = (uint16_t)(val - hdr->buf);
	}

	hdr->hdr_fields = fields;
	hdr->nr_hdr_fields = nr_fields;
	return 0;

out_err:
	free(fields);
	return err;
}

int gwhf_parse_http_req_hdr(const char *buf, size_t buf_len,
			    struct gwhf_http_req_hdr *hdr)
{
	char *crlf, *second_line;
	uint16_t len;
	int ret;

	/*
	 * Don't allow too large request header.
	 */
	if (unlikely(buf_len > UINT16_MAX*2u))
		return -EINVAL;

	/*
	 * The request header must end with "\r\n\r\n".
	 * If it doesn't, we probably don't have the whole
	 * request header yet.
	 */
	if (unlikely(buf_len < 4u))
		return -EAGAIN;

	crlf = strstr(buf, "\r\n\r\n");
	if (unlikely(!crlf))
		return -EAGAIN;

	len = (uint16_t)(crlf - buf) + 4u;
	hdr->buf = memdup_more(buf, len, 1);
	if (unlikely(!hdr->buf))
		return -ENOMEM;

	hdr->buf_len = len;
	hdr->buf[len] = '\0';

	/*
	 * The first line contains the method, URI, and HTTP version.
	 *
	 * It's something like this:
	 * "GET / HTTP/1.1\r\n"
	 *
	 */
	ret = parse_method_uri_version_qs(hdr->buf, &second_line, hdr);
	if (unlikely(ret < 0))
		goto err;

	/*
	 * The second line contains the request header fields.
	 */
	ret = parse_hdr_req_fields(second_line, hdr);
	if (unlikely(ret < 0))
		goto err;

	return (int)len;

err:
	free(hdr->buf);
	memset(hdr, 0, sizeof(*hdr));
	return ret;
}
