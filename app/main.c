
#include <gwhf/gwhf.h>
#include <stdio.h>

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

	printf("Starting...\n");
	ret = gwhf_run(&ctx);
	gwhf_destroy(&ctx);
	gwhf_global_destroy();
	printf("Exiting...\n");
	return ret;
}
