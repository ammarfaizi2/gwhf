
#include <stdio.h>
#include <gwhfp/gwhfp.h>

#include "app/controllers/index.h"

using gwhfp::Route;
using app::controllers::Index;

static Route *g_main_route;

static Route *init_routes_main(struct gwhf *ctx)
{
	Route *r = new (std::nothrow) Route();

	r->get("/", &Index::index);
	r->get_prefix("/assets/", &Index::static_file);
	g_main_route = r;
	return r;
}

static int exec_routes_main(struct gwhf *ctx, struct gwhf_client *cl, void *arg)
{
	Route *r = reinterpret_cast<Route *>(arg);
	return r->exec(ctx, cl);
}

extern "C" {

int init_routes(struct gwhf *ctx)
{
	Route *r = init_routes_main(ctx);
	if (!r)
		return -ENOMEM;

	return gwhf_add_route_body(ctx, exec_routes_main, r);
}

void destroy_routes(void)
{
	delete g_main_route;
}

} /* extern "C" */
