
#include <gwhfp/route.h>
#include <gwhfp/controller.h>
#include <cstring>
#include <stdio.h>

namespace gwhfp {

Route::Route(const char *host):
	host_(host)
{
}

Route::~Route(void)
{
}

static bool host_match(const char *host_hdr, const char *host_obj)
{
	if (!host_obj)
		return true;

	if (!host_hdr)
		return false;

	return !strcmp(host_hdr, host_obj);
}

inline
int Route::exec_get(const char *path, struct gwhf *ctx, struct gwhf_client *cl)
{
	auto it = get_routes_.find(path);
	if (it == get_routes_.end())
		return GWHF_ROUTE_CONTINUE;

	struct gwhfp_req req;
	req.ctx = ctx;
	req.cl = cl;
	return it->second(&req);
}

inline
int Route::exec_post(const char *path, struct gwhf *ctx, struct gwhf_client *cl)
{
	auto it = post_routes_.find(path);
	if (it == post_routes_.end())
		return GWHF_ROUTE_CONTINUE;

	struct gwhfp_req req;
	req.ctx = ctx;
	req.cl = cl;
	return it->second(&req);
}

int Route::exec(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_get_cur_stream(cl);
	const char *host = gwhf_get_http_req_hdr(&str->req_hdr, "host");
	const char *method, *path;

	if (!host_match(host, host_))
		return GWHF_ROUTE_CONTINUE;

	method = gwhf_get_http_req_method(&str->req_hdr);
	path = gwhf_get_http_req_uri(&str->req_hdr);
	if (!strcmp(method, "GET"))
		return exec_get(path, ctx, cl);
	else if (!strcmp(method, "POST"))
		return exec_post(path, ctx, cl);

	return GWHF_ROUTE_CONTINUE;
}

} /* namespace gwhfp */
