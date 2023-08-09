// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwhfp/controller.h>
#include <gwhfp/file.h>
#include <cstdio>
#include <cstring>

#include "internal.h"

namespace gwhfp {

Controller::Controller(struct gwhf *ctx, struct gwhf_client *cl, Route *route):
	ctx_(ctx),
	cl_(cl),
	route_(route)
{
}

Controller::~Controller(void)
{
}

inline FileFd *Controller::get_file_fd(std::string path)
{
	FileFd *f = static_cast<FileFd *>(route_->get_file(path));

	if (unlikely(!f)) {
		std::unique_ptr<File> file = std::make_unique<FileFd>(path);
		FileFd *ff = static_cast<FileFd *>(file.get());
		if (ff->open() < 0)
			return nullptr;
		if (route_->add_file(path, file) < 0)
			return nullptr;
		f = ff;
	}

	return f;
}

inline FileMap *Controller::get_file_map(std::string path)
{
	FileMap *f = static_cast<FileMap *>(route_->get_file(path));

	if (unlikely(!f)) {
		std::unique_ptr<File> file = std::make_unique<FileMap>(path);
		FileMap *ff = static_cast<FileMap *>(file.get());
		if (ff->open() < 0)
			return nullptr;
		if (route_->add_file(path, file) < 0)
			return nullptr;
		f = ff;
	}

	return f;
}

static int prepare_headers(struct gwhf_client *cl, const char *con_type,
			   uint64_t size)
{
	int ret = 0;

	ret |= gwhf_set_http_res_code(cl, 200);
	ret |= gwhf_add_http_res_hdr(cl, "Content-Type", "%s", con_type);
	ret |= gwhf_add_http_res_hdr(cl, "Content-Length", "%llu", (unsigned long long)size);
	return ret;
}

inline int Controller::__view_fd(FileFd *f)
{
	uint64_t size;
	int err = 0;
	int fd;

	fd = f->get_fd();
	if (unlikely(fd < 0))
		return GWHF_ROUTE_ERROR;

	size = f->get_size();
	err |= prepare_headers(cl_, "text/html", size);
	err |= gwhf_set_http_res_body_fd_ref(cl_, fd, size);
	if (unlikely(err))
		return GWHF_ROUTE_ERROR;

	return GWHF_ROUTE_EXECUTE;
}

inline int Controller::__view_map(FileMap *f)
{
	uint64_t size;
	uint8_t *map;
	int err = 0;

	map = f->get_map();
	if (unlikely(!map))
		return GWHF_ROUTE_ERROR;

	size = f->get_size();
	err |= prepare_headers(cl_, "text/html", size);
	err |= gwhf_set_http_res_body_buf_ref(cl_, map, size);
	if (unlikely(err))
		return GWHF_ROUTE_ERROR;

	return GWHF_ROUTE_EXECUTE;
}

int Controller::view(std::string path)
{
	return view_fd(path);
}

int Controller::view_fd(std::string path)
{
	FileFd *f = get_file_fd(path);
	if (unlikely(!f))
		return GWHF_ROUTE_ERROR;

	return __view_fd(f);
}

int Controller::view_map(std::string path)
{
	FileMap *f = get_file_map(path);
	if (unlikely(!f))
		return GWHF_ROUTE_ERROR;

	return __view_map(f);
}

int Controller::file(std::string path)
{
	return file_fd(path);
}

int Controller::file_fd(std::string path)
{
	const char *p = path.c_str();
	const char *mime;
	uint64_t size;
	int err = 0;
	FileFd *f;
	int fd;

	/*
	 * Don't allow access to the parent directory.
	 */
	if (unlikely(strstr(p, "..")))
		return GWHF_ROUTE_CONTINUE;

	f = get_file_fd(path);
	if (unlikely(!f))
		return GWHF_ROUTE_ERROR;

	fd = f->get_fd();
	if (unlikely(fd < 0))
		return GWHF_ROUTE_ERROR;

	size = f->get_size();
	mime = get_mime_type_by_ext(get_file_ext(p));

	err |= prepare_headers(cl_, mime, size);
	err |= gwhf_set_http_res_body_fd_ref(cl_, fd, size);
	if (unlikely(err))
		return GWHF_ROUTE_ERROR;

	return GWHF_ROUTE_EXECUTE;
}

int Controller::file_map(std::string path)
{
	const char *p = path.c_str();
	const char *mime;
	const char *ext;
	uint64_t size;
	uint8_t *map;
	int err = 0;
	FileMap *f;

	/*
	 * Don't allow access to the parent directory.
	 */
	if (unlikely(strstr(p, "..")))
		return GWHF_ROUTE_CONTINUE;

	f = get_file_map(path);
	if (unlikely(!f))
		return GWHF_ROUTE_ERROR;

	map = f->get_map();
	if (unlikely(!map))
		return GWHF_ROUTE_ERROR;

	size = f->get_size();
	mime = get_mime_type_by_ext(get_file_ext(p));

	err |= prepare_headers(cl_, mime, size);
	err |= gwhf_set_http_res_body_buf_ref(cl_, map, size);
	if (unlikely(err))
		return GWHF_ROUTE_ERROR;

	return GWHF_ROUTE_EXECUTE;
}

} /* namespace gwhfp */
