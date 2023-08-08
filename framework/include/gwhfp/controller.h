// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWHFP__CONTROLLER_H
#define GWHFP__CONTROLLER_H

#include <gwhf/gwhf.h>
#include <gwhfp/file.h>

#include <memory>

namespace gwhfp {

class Route;
class FileFd;
class FileMap;

class Controller {
public:
	GWHF_EXPORT Controller(struct gwhf *ctx, struct gwhf_client *cl,
			       Route *route);
	GWHF_EXPORT ~Controller(void);
	GWHF_EXPORT int view(std::string path);
	GWHF_EXPORT int view_fd(std::string path);
	GWHF_EXPORT int view_map(std::string path);
	GWHF_EXPORT int file(std::string path);
	GWHF_EXPORT int file_fd(std::string path);
	GWHF_EXPORT int file_map(std::string path);

protected:
	struct gwhf *ctx_;
	struct gwhf_client *cl_;
	Route *route_;

private:
	int __view_fd(FileFd *f);
	int __view_map(FileMap *f);
	FileFd *get_file_fd(std::string path);
	FileMap *get_file_map(std::string path);
};

} /* namespace gwhfp */

#endif /* #ifndef GWHFP__CONTROLLER_H */
