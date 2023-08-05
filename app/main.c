
#include <gwhf/gwhf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static uint64_t len;
static int idx_fd = -1;

static int index_controller(struct gwhf *ctx, struct gwhf_client *cl)
{
	const char *uri = gwhf_get_http_req_uri(&cl->streams[cl->cur_stream].req_hdr);
	int ret;

	if (strcmp(uri, "/"))
		return GWHF_ROUTE_CONTINUE;

	if (idx_fd < 0) {
		struct stat st;

		idx_fd = open("app/views/index.html", O_RDONLY);
		if (idx_fd < 0)
			return GWHF_ROUTE_ERROR;

		ret = fstat(idx_fd, &st);
		if (ret < 0) {
			close(idx_fd);
			return GWHF_ROUTE_ERROR;
		}

		len = st.st_size;
	}

	ret = gwhf_set_http_res_code(cl, 200);
	ret |= gwhf_set_http_res_body_fd_ref(cl, idx_fd, len);
	ret |= gwhf_add_http_res_hdr(cl, "Content-Type", "text/html");
	ret |= gwhf_add_http_res_hdr(cl, "Content-Length", "%llu", (unsigned long long)len);
	if (ret != 0)
		return GWHF_ROUTE_ERROR;

	return GWHF_ROUTE_EXECUTE;
}

int main(void)
{
	struct gwhf ctx;
	int ret;

	ret = gwhf_init(&ctx);
	if (ret != 0) {
		fprintf(stderr, "gwhf_init failed: %d\n", ret);
		return 1;
	}

	ret = gwhf_add_route_body(&ctx, index_controller);
	if (ret != 0) {
		fprintf(stderr, "gwhf_add_route_body failed: %d\n", ret);
		gwhf_destroy(&ctx);
		return 1;
	}

	ret = gwhf_run(&ctx);
	gwhf_destroy(&ctx);
	return ret;
}
