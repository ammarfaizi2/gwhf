// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWHFP__ROUTE_H
#define GWHFP__ROUTE_H

#include <gwhf/gwhf.h>
#include <gwhfp/gwhfp.h>

#include <string>
#include <functional>
#include <unordered_map>

namespace gwhfp {

class GWHF_EXPORT Route {
public:
	Route(const char *host = nullptr);
	~Route(void);

	template<typename T>
	void get(const char *path, int (T::*func)(struct gwhfp_req *))
	{
		get_routes_[path] = [func](struct gwhfp_req *arg){
			T t(arg->ctx);
			return (t.*func)(arg);
		};
	}

	template<typename T>
	void post(const char *path, int (T::*func)(struct gwhfp_req *))
	{
		post_routes_[path] = [func](struct gwhfp_req *arg){
			T t(arg->ctx);
			return (t.*func)(arg);
		};
	}

	int exec(struct gwhf *ctx, struct gwhf_client *cl);

private:
	int exec_get(const char *path, struct gwhf *ctx,
		     struct gwhf_client *cl);
	int exec_post(const char *path, struct gwhf *ctx,
		      struct gwhf_client *cl);

	struct gwhf *ctx_;
	const char *host_;

	std::unordered_map<std::string, std::function<int(struct gwhfp_req *)>>
		get_routes_,
		post_routes_;
};

} /* namespace gwhfp */

#endif /* #ifndef GWHFP__ROUTE_H */
