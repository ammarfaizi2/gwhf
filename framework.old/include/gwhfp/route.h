// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWHFP__ROUTE_H
#define GWHFP__ROUTE_H

#include <gwhf/gwhf.h>
#include <gwhfp/gwhfp.h>

#include <string>
#include <memory>
#include <functional>
#include <unordered_map>

namespace gwhfp {

class File;

class Prefix {
public:
	inline Prefix(std::string needle,
		      std::function<int(struct gwhfp_req *)> func):
		needle_(needle),
		func_(std::move(func))
	{
	}

	inline ~Prefix(void)
	{
	}

	std::string needle_;
	std::function<int(struct gwhfp_req *)> func_;
};

class Route {
public:
	GWHF_EXPORT Route(const char *host = nullptr);
	GWHF_EXPORT ~Route(void);

	template<typename T>
	void get(const char *path, int (T::*func)(struct gwhfp_req *))
	{
		get_routes_[path] = [func, this](struct gwhfp_req *arg){
			T t(arg->ctx, arg->cl, this);
			return (t.*func)(arg);
		};
	}

	template<typename T>
	void post(const char *path, int (T::*func)(struct gwhfp_req *))
	{
		post_routes_[path] = [func, this](struct gwhfp_req *arg){
			T t(arg->ctx, arg->cl, this);
			return (t.*func)(arg);
		};
	}

	template<typename T>
	void get_prefix(const char *path, int (T::*func)(struct gwhfp_req *))
	{
		get_prefixes_.emplace_back(path,
			[func, this](struct gwhfp_req *arg){
				T t(arg->ctx, arg->cl, this);
				return (t.*func)(arg);
			}
		);
	}

	template<typename T>
	void post_prefix(const char *path, int (T::*func)(struct gwhfp_req *))
	{
		post_prefixes_.emplace_back(path,
			[func, this](struct gwhfp_req *arg){
				T t(arg->ctx, arg->cl, this);
				return (t.*func)(arg);
			}
		);
	}

	GWHF_EXPORT int exec(struct gwhf *ctx, struct gwhf_client *cl);

	int add_file(std::string path, std::unique_ptr<File> &file);
	File *get_file(std::string path);

private:
	int exec_get(const char *path, struct gwhf *ctx,
		     struct gwhf_client *cl);
	int exec_post(const char *path, struct gwhf *ctx,
		      struct gwhf_client *cl);

	int exec_get_prefix(const char *path, struct gwhf *ctx,
			    struct gwhf_client *cl);
	int exec_post_prefix(const char *path, struct gwhf *ctx,
			     struct gwhf_client *cl);
	int exec_prefix(const char *path, struct gwhf *ctx,
			struct gwhf_client *cl,
			std::vector<Prefix> &prefix);

	struct gwhf *ctx_;
	const char *host_;

	std::unordered_map<std::string, std::function<int(struct gwhfp_req *)>>
		get_routes_,
		post_routes_;

	std::vector<Prefix> get_prefixes_, post_prefixes_;
	std::unordered_map<std::string, std::unique_ptr<File>> files_;
};

} /* namespace gwhfp */

#endif /* #ifndef GWHFP__ROUTE_H */
