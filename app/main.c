
#include <gwhf/gwhf.h>
#include <string.h>
#include <stdio.h>

static int handle_req_on_hdr(struct gwhf *ctx, struct gwhf_client *cl, void *arg)
{
	return 0;
}

static int handle_index(struct gwhf *ctx, struct gwhf_client *cl, void *arg)
{
	struct gwhf_client_stream *str = gwhf_client_get_cur_stream(cl);
	const char *uri = gwhf_http_req_get_uri(&str->req);
	int ret;

	if (strcmp(uri, "/"))
		return GWHF_ROUTE_CONTINUE;

	ret = gwhf_http_res_set_body_buf_ref(&str->res, "Hello, world!\n", 14);
	if (ret)
		return GWHF_ROUTE_ERROR;

	ret |= gwhf_http_res_set_status_code(&str->res, 200);
	ret |= gwhf_http_res_add_hdr(&str->res, "Content-Type", "text/plain");
	ret |= gwhf_http_res_add_hdr(&str->res, "Content-Length", "%d", 14);
	if (ret)
		return GWHF_ROUTE_ERROR;

	return GWHF_ROUTE_EXECUTED;
}

static int handle_req_on_body(struct gwhf *ctx, struct gwhf_client *cl, void *arg)
{
	int ret;

	ret = handle_index(ctx, cl, arg);
	if (ret != GWHF_ROUTE_CONTINUE)
		return ret;

	return 0;
}

static int register_routes_on_header(struct gwhf *ctx)
{
	int ret;

	ret = gwhf_route_add_on_header(ctx, &handle_req_on_hdr, NULL, NULL, NULL);
	if (ret)
		return ret;

	return 0;
}

static int register_routes_on_body(struct gwhf *ctx)
{
	int ret;

	ret = gwhf_route_add_on_body(ctx, &handle_req_on_body, NULL, NULL, NULL);
	if (ret)
		return ret;

	return 0;
}

static int register_routes(struct gwhf *ctx)
{
	int ret;

	ret = register_routes_on_header(ctx);
	if (ret)
		return ret;

	ret = register_routes_on_body(ctx);
	if (ret)
		return ret;

	return 0;
}

int main(void)
{
	struct gwhf ctx;
	int ret;

	ret = gwhf_global_init();
	if (ret != 0) {
		fprintf(stderr, "gwhf_global_init(): %s\n", gwhf_strerror(ret));
		return 1;
	}

	ret = gwhf_init(&ctx);
	if (ret != 0) {
		gwhf_global_destroy();
		fprintf(stderr, "gwhf_init(): %s\n", gwhf_strerror(ret));
		return 1;
	}

	ret = register_routes(&ctx);
	if (ret != 0) {
		gwhf_destroy(&ctx);
		gwhf_global_destroy();
		fprintf(stderr, "register_routes(): %s\n", gwhf_strerror(ret));
		return 1;
	}

	printf("Starting...\n");
	ret = gwhf_run(&ctx);
	printf("ret = %d\n", ret);
	gwhf_destroy(&ctx);
	gwhf_global_destroy();
	printf("Exiting...\n");
	return -ret;
}
