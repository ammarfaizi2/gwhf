// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>

#include "helpers.h"

__hot
void *memdup(const void *src, size_t len)
{
	void *ret;

	ret = malloc(len);
	if (unlikely(!ret))
		return NULL;

	return memcpy(ret, src, len);
}

__hot
void *memdup_more(const void *src, size_t len, size_t more)
{
	void *ret;

	ret = malloc(len + more);
	if (unlikely(!ret))
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

	return value;
}

__hot
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

__hot
char *strtolower(char *str)
{
	char *ret = str;

	while (str[0]) {
		str[0] = tolower(str[0]);
		str++;
	}

	return ret;
}

__hot
char *strtoupper(char *str)
{
	char *ret = str;

	while (str[0]) {
		str[0] = toupper(str[0]);
		str++;
	}

	return ret;
}

const char *get_mime_type_by_ext(const char *ext)
{
	if (!ext)
		return "application/octet-stream";

	if (!strcmp(ext, "html"))
		return "text/html";
	else if (!strcmp(ext, "css"))
		return "text/css";
	else if (!strcmp(ext, "js"))
		return "application/javascript";
	else if (!strcmp(ext, "png"))
		return "image/png";
	else if (!strcmp(ext, "jpg"))
		return "image/jpeg";
	else if (!strcmp(ext, "jpeg"))
		return "image/jpeg";
	else if (!strcmp(ext, "gif"))
		return "image/gif";
	else if (!strcmp(ext, "svg"))
		return "image/svg+xml";
	else if (!strcmp(ext, "ico"))
		return "image/x-icon";
	else if (!strcmp(ext, "ttf"))
		return "font/ttf";
	else if (!strcmp(ext, "woff"))
		return "font/woff";
	else if (!strcmp(ext, "woff2"))
		return "font/woff2";
	else if (!strcmp(ext, "eot"))
		return "application/vnd.ms-fontobject";
	else if (!strcmp(ext, "otf"))
		return "font/otf";
	else if (!strcmp(ext, "pdf"))
		return "application/pdf";
	else if (!strcmp(ext, "json"))
		return "application/json";
	else if (!strcmp(ext, "xml"))
		return "application/xml";
	else if (!strcmp(ext, "zip"))
		return "application/zip";
	else if (!strcmp(ext, "rar"))
		return "application/x-rar-compressed";
	else if (!strcmp(ext, "7z"))
		return "application/x-7z-compressed";
	else if (!strcmp(ext, "tar"))
		return "application/x-tar";
	else if (!strcmp(ext, "gz"))
		return "application/gzip";
	else if (!strcmp(ext, "bz2"))
		return "application/x-bzip2";
	else if (!strcmp(ext, "xz"))
		return "application/x-xz";
	else if (!strcmp(ext, "mp3"))
		return "audio/mpeg";
	else if (!strcmp(ext, "mp4"))
		return "video/mp4";
	else if (!strcmp(ext, "mkv"))
		return "video/x-matroska";
	else if (!strcmp(ext, "webm"))
		return "video/webm";
	else if (!strcmp(ext, "avi"))
		return "video/x-msvideo";
	else if (!strcmp(ext, "mpeg"))
		return "video/mpeg";
	else if (!strcmp(ext, "mpg"))
		return "video/mpeg";
	else if (!strcmp(ext, "flv"))
		return "video/x-flv";
	else if (!strcmp(ext, "wmv"))
		return "video/x-ms-wmv";
	else if (!strcmp(ext, "webp"))
		return "image/webp";
	else if (!strcmp(ext, "weba"))
		return "audio/webm";
	else if (!strcmp(ext, "wav"))
		return "audio/wav";
	else if (!strcmp(ext, "ogg"))
		return "audio/ogg";
	else if (!strcmp(ext, "ogv"))
		return "video/ogg";
	else if (!strcmp(ext, "ogx"))
		return "application/ogg";
	else if (!strcmp(ext, "oga"))
		return "audio/ogg";
	else if (!strcmp(ext, "srt"))
		return "application/x-subrip";
	else if (!strcmp(ext, "vtt"))
		return "text/vtt";
	else if (!strcmp(ext, "csv"))
		return "text/csv";
	else if (!strcmp(ext, "txt"))
		return "text/plain";
	else if (!strcmp(ext, "md"))
		return "text/markdown";
	else if (!strcmp(ext, "c"))
		return "text/x-c";
	else if (!strcmp(ext, "cpp"))
		return "text/x-c++src";
	else if (!strcmp(ext, "h"))
		return "text/x-c";
	else if (!strcmp(ext, "hpp"))
		return "text/x-c++src";
	else if (!strcmp(ext, "py"))
		return "text/x-python";
	else if (!strcmp(ext, "sh"))
		return "text/x-shellscript";
	else if (!strcmp(ext, "bat"))
		return "text/x-msdos-batch";
	else if (!strcmp(ext, "exe"))
		return "application/x-msdownload";
	else if (!strcmp(ext, "dll"))
		return "application/x-msdownload";
	else if (!strcmp(ext, "jar"))
		return "application/java-archive";
	else if (!strcmp(ext, "class"))
		return "application/java-vm";
	else if (!strcmp(ext, "war"))
		return "application/java-archive";
	else if (!strcmp(ext, "ear"))
		return "application/java-archive";
	else if (!strcmp(ext, "deb"))
		return "application/vnd.debian.binary-package";
	else if (!strcmp(ext, "rpm"))
		return "application/x-rpm";
	else if (!strcmp(ext, "msi"))
		return "application/x-msi";
	else if (!strcmp(ext, "dmg"))
		return "application/x-apple-diskimage";
	else if (!strcmp(ext, "iso"))
		return "application/x-iso9660-image";
	else if (!strcmp(ext, "doc"))
		return "application/msword";
	else if (!strcmp(ext, "docx"))
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
	else if (!strcmp(ext, "xls"))
		return "application/vnd.ms-excel";
	else if (!strcmp(ext, "xlsx"))
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
	else if (!strcmp(ext, "ppt"))
		return "application/vnd.ms-powerpoint";
	else if (!strcmp(ext, "pptx"))
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
	else if (!strcmp(ext, "odt"))
		return "application/vnd.oasis.opendocument.text";
	else if (!strcmp(ext, "ods"))
		return "application/vnd.oasis.opendocument.spreadsheet";
	else if (!strcmp(ext, "odp"))
		return "application/vnd.oasis.opendocument.presentation";
	else if (!strcmp(ext, "odg"))
		return "application/vnd.oasis.opendocument.graphics";
	else if (!strcmp(ext, "odc"))
		return "application/vnd.oasis.opendocument.chart";
	else if (!strcmp(ext, "odb"))
		return "application/vnd.oasis.opendocument.database";
	else if (!strcmp(ext, "odf"))
		return "application/vnd.oasis.opendocument.formula";
	else if (!strcmp(ext, "odm"))
		return "application/vnd.oasis.opendocument.text-master";
	else if (!strcmp(ext, "ott"))
		return "application/vnd.oasis.opendocument.text-template";
	else if (!strcmp(ext, "ots"))
		return "application/vnd.oasis.opendocument.spreadsheet-template";
	else if (!strcmp(ext, "otp"))
		return "application/vnd.oasis.opendocument.presentation-template";
	else if (!strcmp(ext, "otg"))
		return "application/vnd.oasis.opendocument.graphics-template";
	else if (!strcmp(ext, "otc"))
		return "application/vnd.oasis.opendocument.chart-template";
	else if (!strcmp(ext, "otb"))
		return "application/vnd.oasis.opendocument.database-template";
	else if (!strcmp(ext, "otf"))
		return "application/vnd.oasis.opendocument.formula-template";
	else if (!strcmp(ext, "otm"))
		return "application/vnd.oasis.opendocument.text-master-template";
	else if (!strcmp(ext, "oth"))
		return "application/vnd.oasis.opendocument.text-web";
	else if (!strcmp(ext, "kml"))
		return "application/vnd.google-earth.kml+xml";
	else if (!strcmp(ext, "kmz"))
		return "application/vnd.google-earth.kmz";
	else if (!strcmp(ext, "swf"))
		return "application/x-shockwave-flash";
	else if (!strcmp(ext, "rtf"))
		return "application/rtf";
	else if (!strcmp(ext, "ps"))
		return "application/postscript";
	else
		return "application/octet-stream";
}

const char *get_file_ext(const char *path)
{
	const char *last_dot = NULL;
	const char *ret = NULL;

	while (path[0]) {
		if (path[0] == '.')
			last_dot = path;
		path++;
	}

	if (last_dot) {
		ret = last_dot + 1;
		if (!ret[0])
			ret = NULL;
	}

	return ret;
}

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

int gwhf_vasprintf(char **strp, const char *fmt, va_list ap)
{
	va_list ap2, ap3;
	size_t len;
	char *str;

	va_copy(ap2, ap);
	va_copy(ap3, ap2);
	len = (size_t)vsnprintf(NULL, 0, fmt, ap2);
	va_end(ap2);

	str = malloc(len + 1);
	if (unlikely(!str)) {
		va_end(ap3);
		return -ENOMEM;
	}

	vsnprintf(str, len + 1, fmt, ap);
	va_end(ap3);

	*strp = str;
	return 0;
}
