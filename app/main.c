
#include <gwhf/gwhf.h>
#include <stdio.h>

static int handle_route_hello(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_res_hdr *hdr = &cl->res_hdr;
	int ret;

	ret = gwhf_res_body_add_buf(cl, "hello", 5);
	if (ret)
		return GWHF_ROUTE_ERROR;

	gwhf_res_hdr_set_status_code(hdr, 200);
	ret |= gwhf_res_hdr_set_content_type(hdr, "text/plain");
	ret |= gwhf_res_hdr_set_content_length(hdr, 5);
	if (ret)
		return GWHF_ROUTE_ERROR;

	return GWHF_ROUTE_EXECUTED;
}

static int handle_route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	return GWHF_ROUTE_EXECUTED;
}

static int handle_route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_req_hdr *hdr = &cl->req_hdr;
	const char *uri;

	uri = gwhf_req_hdr_get_uri(hdr);

	if (!strcmp(uri, "/hello"))
		return handle_route_hello(ctx, cl);

	return GWHF_ROUTE_CONTINUE;
}

int main(void)
{
	struct gwhf ctx;
	int ret;

	ret = gwhf_init(&ctx, NULL);
	if (ret < 0)
		return ret;

	ret = gwhf_add_route_header(&ctx, handle_route_header);
	if (ret < 0)
		goto out;

	ret = gwhf_add_route_body(&ctx, handle_route_body);
	if (ret < 0)
		goto out;

	ret = gwhf_run_event_loop(&ctx);
out:
	gwhf_destroy(&ctx);
	return ret;
}
