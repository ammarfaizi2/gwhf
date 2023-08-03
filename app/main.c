
#include <gwhf/gwhf.h>
#include <stdio.h>

int main(void)
{
	struct gwhf ctx;
	int ret;

	ret = gwhf_init(&ctx);
	if (ret != 0) {
		fprintf(stderr, "gwhf_init failed: %d\n", ret);
		return 1;
	}

	ret = gwhf_run(&ctx);
	gwhf_destroy(&ctx);
	return ret;
}
