// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef GWHF__FRAMEWORK__HELPERS_H
#define GWHF__FRAMEWORK__HELPERS_H

#include <stdint.h>
#include <stdlib.h>

void *memdup(const void *src, size_t len);
void *memdup_more(const void *src, size_t len, size_t more);
size_t url_decode(char *str, size_t len);
char *strtolower(char *str);
char *strtoupper(char *str);

#endif /* #ifndef GWHF__FRAMEWORK__HELPERS_H */
