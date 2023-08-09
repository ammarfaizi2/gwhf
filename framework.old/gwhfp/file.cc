// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwhfp/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

#include "internal.h"

namespace gwhfp {

File::File(std::string path, enum gwhfp_file_type type):
	path_(path),
	type_(type)
{
}

File::~File(void)
{
}

FileFd::FileFd(std::string path):
	File(path, GWHFP_FILE_T_FD),
	fd_(-1)
{
}

FileFd::~FileFd(void)
{
	close();
}

void FileFd::close(void)
{
	if (fd_ >= 0) {
		::close(fd_);
		fd_ = -1;
	}
	size_ = 0;
}

int FileFd::get_fd(void)
{
	if (unlikely(fd_ < 0)) {
		return open();
	} else {
		struct stat st;

		if (unlikely(::fstat(fd_, &st) < 0)) {
			close();
			return open();
		}

		if (unlikely(size_ != static_cast<uint64_t>(st.st_size))) {
			close();
			return open();
		}
	}

	return fd_;
}

int FileFd::open(void)
{
	struct stat st;
	int err, fd;

	fd = ::open(path_.c_str(), O_RDONLY);
	if (unlikely(fd < 0))
		return -errno;

	err = ::fstat(fd, &st);
	if (unlikely(err < 0)) {
		err = -errno;
		::close(fd);
		return err;
	}

	/* Close old fd if any. */
	close();
	fd_ = fd;

	size_ = static_cast<uint64_t>(st.st_size);
	return fd_;
}

FileMap::FileMap(std::string path):
	File(path, GWHFP_FILE_T_MAP),
	map_(nullptr)
{
}

FileMap::~FileMap(void)
{
	close();
}

void FileMap::close(void)
{
	if (unlikely(map_)) {
		::munmap(map_, size_);
		map_ = nullptr;
	}
	size_ = 0;
}

uint8_t *FileMap::get_map(void)
{
	if (unlikely(!map_)) {
		open();
	} else {
		struct stat st;

		if (unlikely(::stat(path_.c_str(), &st) < 0)) {
			close();
			open();
			return map_;
		}

		if (unlikely(size_ != static_cast<uint64_t>(st.st_size))) {
			close();
			open();
			return map_;
		}
	}

	return map_;
}

int FileMap::open(void)
{
	struct stat st;
	uint8_t *map;
	int err, fd;

	fd = ::open(path_.c_str(), O_RDONLY);
	if (unlikely(fd < 0))
		return -errno;

	err = ::fstat(fd, &st);
	if (unlikely(err < 0)) {
		err = -errno;
		::close(fd);
		return err;
	}

	map = static_cast<uint8_t *>(::mmap(nullptr, st.st_size, PROT_READ,
					    MAP_SHARED, fd, 0));
	if (unlikely(map == MAP_FAILED)) {
		err = -errno;
		::close(fd);
		return err;
	}

	::close(fd);

	/* Close old map if any. */
	close();
	map_ = map;
	size_ = static_cast<uint64_t>(st.st_size);
	return 0;
}

} /* namespace gwhfp */
