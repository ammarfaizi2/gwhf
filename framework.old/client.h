// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__CLIENT_H
#define GWHF__FRAMEWORK__CLIENT_H

#include "internal.h"

struct gwhf_client *gwhf_get_client(struct gwhf_client_slot *cs);
void gwhf_put_client(struct gwhf_client_slot *cs, struct gwhf_client *cl);

#endif /* #ifndef GWHF__FRAMEWORK__CLIENT_H */
