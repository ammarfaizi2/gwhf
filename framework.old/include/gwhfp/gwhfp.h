// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */
#ifndef GWHFP__GWHFP_H
#define GWHFP__GWHFP_H

#include <gwhf/gwhf.h>

struct gwhfp_req {
	struct gwhf *ctx;
	struct gwhf_client *cl;
};

#include <gwhfp/file.h>
#include <gwhfp/route.h>
#include <gwhfp/controller.h>

#endif /* #ifndef GWHFP__GWHFP_H */
