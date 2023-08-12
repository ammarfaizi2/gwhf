// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <stdlib.h>
#include <string.h>
#include "helpers.h"

/*
 * Just like strcmp(), but case insensitive.
 */
int gwhf_strcmpi(const char *a, const char *b)
{
	int r = 0;

	while (1) {
		char aa = *a++;
		char bb = *b++;

		if (!aa || !bb) {
			r = aa - bb;
			break;
		}

		if (aa >= 'A' && aa <= 'Z')
			aa += 32;

		if (bb >= 'A' && bb <= 'Z')
			bb += 32;

		r = aa - bb;
		if (r)
			break;
	}

	return r;
}

char *gwhf_strdup(const char *s)
{
	size_t l = strlen(s) + 1;
	char *r = malloc(l);

	if (r)
		memcpy(r, s, l);

	return r;
}
