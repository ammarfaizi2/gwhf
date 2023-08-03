// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void *memdup(const void *src, size_t len)
{
	void *ret;

	ret = malloc(len);
	if (!ret)
		return NULL;

	return memcpy(ret, src, len);
}

void *memdup_more(const void *src, size_t len, size_t more)
{
	void *ret;

	ret = malloc(len + more);
	if (!ret)
		return NULL;

	return memcpy(ret, src, len);
}

static int htoi(char *s)
{
	int value;
	int c;

	c = ((unsigned char *)s)[0];
	if (isupper(c))
		c = tolower(c);
	value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

	c = ((unsigned char *)s)[1];
	if (isupper(c))
		c = tolower(c);
	value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

	return (value);
}

size_t url_decode(char *str, size_t len)
{
	char *dest = str;
	char *data = str;

	while (len--) {
		if (*data == '+') {
			*dest = ' ';
		} else if (*data == '%' && len >= 2 &&
			   isxdigit((int) *(data + 1)) &&
			   isxdigit((int) *(data + 2))) {
			*dest = (char) htoi(data + 1);
			data += 2;
			len -= 2;
		} else {
			*dest = *data;
		}
		data++;
		dest++;
	}
	*dest = '\0';
	return dest - str;
}

char *strtolower(char *str)
{
	char *ret = str;

	while (str[0]) {
		str[0] = tolower(str[0]);
		str++;
	}

	return ret;
}
