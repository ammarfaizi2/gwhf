// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Hoody Ltd
 */
#ifndef GWHFP__FILE_H
#define GWHFP__FILE_H

#include <gwhf/gwhf.h>
#include <gwhfp/gwhfp.h>
#include <string>

namespace gwhfp {

enum gwhfp_file_type {
	GWHFP_FILE_T     = 0,
	GWHFP_FILE_T_FD  = 1,
	GWHFP_FILE_T_MAP = 2
};

class File {
public:
	File(std::string path, enum gwhfp_file_type type = GWHFP_FILE_T);
	virtual ~File(void);
	virtual int open(void) = 0;
	virtual void close(void) = 0;

	inline uint64_t get_size(void)
	{
		return size_;
	}

	inline enum gwhfp_file_type get_type(void)
	{
		return type_;
	}

protected:
	uint64_t size_;
	std::string path_;
	enum gwhfp_file_type type_;
};

class FileFd: public File {
public:
	GWHF_EXPORT FileFd(std::string path);
	GWHF_EXPORT ~FileFd(void);
	GWHF_EXPORT int open(void) override;
	GWHF_EXPORT void close(void) override;
	GWHF_EXPORT int get_fd(void);

private:
	int fd_;
};

class FileMap: public File {
public:
	GWHF_EXPORT FileMap(std::string path);
	GWHF_EXPORT ~FileMap(void);
	GWHF_EXPORT int open(void) override;
	GWHF_EXPORT void close(void) override;
	GWHF_EXPORT uint8_t *get_map(void);

private:
	uint8_t *map_;
};

} /* namespace gwhfp */

#endif /* #ifndef GWHFP__FILE_H */
