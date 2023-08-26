// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */
#ifndef FRAMEWORK__GWHF__HELPERS_H
#define FRAMEWORK__GWHF__HELPERS_H

#include "./internal.h"

#ifdef __cplusplus
extern "C" {
#endif

void *memdup(const void *src, size_t len);
void *memdup_more(const void *src, size_t len, size_t more);
size_t url_decode(char *str, size_t len);
char *strtolower(char *str);
char *strtoupper(char *str);
const char *get_mime_type_by_ext(const char *ext);
const char *get_file_ext(const char *path);
int gwhf_strcmpi(const char *a, const char *b);
char *gwhf_strdup(const char *s);
int gwhf_vasprintf(char **strp, const char *fmt, va_list ap);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* #ifndef FRAMEWORK__GWHF__HELPERS_H */
