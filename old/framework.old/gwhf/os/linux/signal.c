// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Hoody Ltd.
 */

#include "signal.h"
#include <unistd.h>

static struct gwhf *g_gwhf;

static void gwhf_signal_handler(int sig)
{
	char c = '\n';

	if (!g_gwhf)
		return;

	g_gwhf->stop = true;
	if (write(STDOUT_FILENO, &c, 1) < 0)
		exit(1);

	(void)sig;
}

int gwhf_init_signal_handler(struct gwhf *ctx)
{
	struct sigaction sa = { .sa_handler = gwhf_signal_handler };
	struct gwhf_internal *ctxi = ctx->internal;
	struct sigaction old;
	int err;

	g_gwhf = ctx;

	err = sigaction(SIGINT, &sa, &old);
	if (err < 0)
		return -errno;

	ctxi->old_act[0] = old;
	err = sigaction(SIGTERM, &sa, &old);
	if (err < 0) {
		err = -errno;
		goto out_sigint;
	}

	ctxi->old_act[1] = old;
	sa.sa_handler = SIG_IGN;
	err = sigaction(SIGPIPE, &sa, &old);
	if (err < 0) {
		err = -errno;
		goto out_sigterm;
	}

	ctxi->old_act[2] = old;
	return 0;

out_sigterm:
	sigaction(SIGTERM, &ctxi->old_act[1], NULL);
out_sigint:
	sigaction(SIGINT, &ctxi->old_act[0], NULL);
	return err;
}

void gwhf_revert_signal_handler(struct gwhf *ctx)
{
	struct gwhf_internal *ctxi = ctx->internal;

	sigaction(SIGPIPE, &ctxi->old_act[2], NULL);
	sigaction(SIGTERM, &ctxi->old_act[1], NULL);
	sigaction(SIGINT, &ctxi->old_act[0], NULL);
}
