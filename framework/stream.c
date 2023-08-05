
#include "stream.h"

static int gwhf_init_client_stream(struct gwhf_client_stream *stream)
{
	int ret;
	stream->state = T_CL_STREAM_IDLE;
	stream->err_str = NULL;

	ret = gwhf_init_http_req_hdr(&stream->req_hdr);
	if (unlikely(ret))
		return ret;

	ret = gwhf_init_http_res_hdr(&stream->res_hdr);
	if (unlikely(ret))
		goto out_req_hdr;

	ret = gwhf_init_http_res_body(&stream->res_body);
	if (unlikely(ret))
		goto out_res_hdr;

	ret = gwhf_init_req_buf(&stream->req_buf);
	if (unlikely(ret))
		goto out_res_body;

	ret = gwhf_init_res_buf(&stream->res_buf);
	if (unlikely(ret))
		goto out_req_buf;

	return 0;

out_req_buf:
	gwhf_destroy_req_buf(&stream->req_buf);
out_res_body:
	gwhf_destroy_http_res_body(&stream->res_body);
out_res_hdr:
	gwhf_destroy_http_res_hdr(&stream->res_hdr);
out_req_hdr:
	gwhf_destroy_http_req_hdr(&stream->req_hdr);
	return ret;
}

static void gwhf_destroy_client_stream(struct gwhf_client_stream *stream)
{
	if (stream->err_str) {
		free(stream->err_str);
		stream->err_str = NULL;
	}

	gwhf_destroy_req_buf(&stream->req_buf);
	gwhf_destroy_res_buf(&stream->res_buf);
	gwhf_destroy_http_res_hdr(&stream->res_hdr);
	gwhf_destroy_http_res_body(&stream->res_body);
	gwhf_destroy_http_req_hdr(&stream->req_hdr);
}

__cold
void gwhf_destroy_client_streams(struct gwhf_client *cl)
{
	uint32_t i;

	if (!cl->streams)
		return;

	for (i = 0; i < cl->nr_streams; i++)
		gwhf_destroy_client_stream(&cl->streams[i]);

	free(cl->streams);
	cl->streams = NULL;
	cl->nr_streams = 0;
}

__hot
int gwhf_init_client_streams(struct gwhf_client *cl, uint32_t nr_streams)
{
	struct gwhf_client_stream *streams;
	uint32_t i;

	assert(!cl->streams);
	assert(!cl->nr_streams);

	streams = calloc(nr_streams, sizeof(*streams));
	if (!streams)
		return -ENOMEM;

	for (i = 0; i < nr_streams; i++) {
		int ret;

		ret = gwhf_init_client_stream(&streams[i]);
		if (ret) {
			while (i--)
				gwhf_destroy_client_stream(&streams[i]);
			free(streams);
			return ret;
		}
	}

	cl->streams = streams;
	cl->nr_streams = nr_streams;
	return 0;
}

static void gwhf_soft_reset_client_stream(struct gwhf_client_stream *stream)
{
	gwhf_destroy_req_buf(&stream->req_buf);
	gwhf_destroy_res_buf(&stream->res_buf);
	gwhf_destroy_http_res_hdr(&stream->res_hdr);
	gwhf_destroy_http_res_body(&stream->res_body);
	gwhf_destroy_http_req_hdr(&stream->req_hdr);
	stream->state = T_CL_STREAM_IDLE;

	if (stream->err_str) {
		free(stream->err_str);
		stream->err_str = NULL;
	}
}

__hot
void gwhf_soft_reset_client_streams(struct gwhf_client *cl)
{
	struct gwhf_client_stream *streams;
	uint32_t i;

	assert(cl->streams);
	assert(cl->nr_streams);

	streams = cl->streams;
	for (i = 0; i < cl->nr_streams; i++)
		gwhf_soft_reset_client_stream(&streams[i]);
}
