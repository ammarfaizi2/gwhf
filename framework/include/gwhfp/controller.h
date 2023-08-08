// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWHFP__CONTROLLER_H
#define GWHFP__CONTROLLER_H

#include <gwhf/gwhf.h>
#include <memory>

namespace gwhfp {

class GWHF_EXPORT Controller {
public:
	Controller(struct gwhf *ctx);
	~Controller(void);

private:
	struct gwhf *ctx_;
};

} /* namespace gwhfp */

#endif /* #ifndef GWHFP__CONTROLLER_H */
