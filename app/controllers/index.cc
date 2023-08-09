
#include "app/controllers/index.h"

namespace app {
namespace controllers {

int Index::index(struct gwhfp_req *req)
{
	(void)req;
	return view_map("app/views/index.html");
}

int Index::static_file(struct gwhfp_req *req)
{
	struct gwhf_client_stream *str = gwhf_get_cur_stream(cl_);
	const char *uri = gwhf_get_http_req_uri(&str->req_hdr);
	int len, err = 0;
	char text[8192];

	snprintf(text, sizeof(text), "app/public/assets/%s",
		 uri + sizeof("/assets/") - 1);

	return file(text);
}

} /* namespace controllers */
} /* namespace app */
