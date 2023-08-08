
#include "app/controllers/index.h"

namespace app {
namespace controllers {

int Index::index(struct gwhfp_req *req)
{
	struct gwhf_client *cl = req->cl;
	int ret = 0;

	ret |= gwhf_set_http_res_code(cl, 200);
	ret |= gwhf_add_http_res_hdr(cl, "Content-Type", "text/html");
	ret |= gwhf_add_http_res_hdr(cl, "Content-Length", "6");
	ret |= gwhf_add_http_res_body_buf(cl, "Hello\n", 6);
	if (ret)
		return GWHF_ROUTE_ERROR;

	return GWHF_ROUTE_EXECUTE;
}

} /* namespace controllers */
} /* namespace app */
