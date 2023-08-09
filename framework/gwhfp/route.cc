// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwhfp/route.h>
#include <gwhfp/controller.h>
#include <cstring>
#include <stdio.h>

#include "internal.h"

namespace gwhfp {

Route::Route(const char *host):
	host_(host)
{
}

Route::~Route(void)
{
}

static bool host_match(const char *host_hdr, const char *host_obj)
{
	if (!host_obj)
		return true;

	if (!host_hdr)
		return false;

	return !strcmp(host_hdr, host_obj);
}

inline
int Route::exec_prefix(const char *path, struct gwhf *ctx,
		       struct gwhf_client *cl, std::vector<Prefix> &prefix)
{
	for (auto &it : prefix) {
		if (!strncmp(path, it.needle_.c_str(), it.needle_.length())) {
			struct gwhfp_req req;
			req.ctx = ctx;
			req.cl = cl;
			return it.func_(&req);
		}
	}

	return GWHF_ROUTE_CONTINUE;
}

inline
int Route::exec_get_prefix(const char *path, struct gwhf *ctx,
			   struct gwhf_client *cl)
{
	return exec_prefix(path, ctx, cl, get_prefixes_);
}

inline
int Route::exec_post_prefix(const char *path, struct gwhf *ctx,
			    struct gwhf_client *cl)
{
	return exec_prefix(path, ctx, cl, post_prefixes_);
}

inline
int Route::exec_get(const char *path, struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhfp_req req;
	int ret;

	auto it = get_routes_.find(path);
	if (it == get_routes_.end())
		goto out;

	req.ctx = ctx;
	req.cl = cl;
	ret = it->second(&req);
	if (ret != GWHF_ROUTE_CONTINUE)
		return ret;

out:
	return exec_get_prefix(path, ctx, cl);
}

inline
int Route::exec_post(const char *path, struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhfp_req req;
	int ret;

	auto it = post_routes_.find(path);
	if (it == post_routes_.end())
		goto out;

	req.ctx = ctx;
	req.cl = cl;
	ret = it->second(&req);
	if (ret != GWHF_ROUTE_CONTINUE)
		return ret;

out:
	return exec_post_prefix(path, ctx, cl);
}

int Route::exec(struct gwhf *ctx, struct gwhf_client *cl)
{
	struct gwhf_client_stream *str = gwhf_get_cur_stream(cl);
	const char *host = gwhf_get_http_req_hdr(&str->req_hdr, "host");
	const char *method, *path;

	if (!host_match(host, host_))
		return GWHF_ROUTE_CONTINUE;

	method = gwhf_get_http_req_method(&str->req_hdr);
	path = gwhf_get_http_req_uri(&str->req_hdr);
	if (!strcmp(method, "GET"))
		return exec_get(path, ctx, cl);
	else if (!strcmp(method, "POST"))
		return exec_post(path, ctx, cl);

	return GWHF_ROUTE_CONTINUE;
}

int Route::add_file(std::string path, std::unique_ptr<File> &file)
{
	if (unlikely(files_.find(path) != files_.end()))
		return -EEXIST;

	files_[path] = std::move(file);
	return 0;
}

File *Route::get_file(std::string path)
{
	auto it = files_.find(path);
	if (unlikely(it == files_.end()))
		return nullptr;

	return it->second.get();
}

} /* namespace gwhfp */
