
#include <gwhf/gwhf.h>
#include <stdio.h>

static int handle_route_header(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_req_hdr *hdr = &cl->req_hdr;
	const char *uri;

	uri = gwhf_req_hdr_get_uri(hdr);
	printf("uri = %s\n", uri);
	return GWHF_ROUTE_EXECUTED;
}

static int handle_route_body(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_req_hdr *hdr = &cl->req_hdr;
	const char *uri;

	uri = gwhf_req_hdr_get_uri(hdr);
	printf("uri = %s\n", uri);
	return GWHF_ROUTE_EXECUTED;
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
