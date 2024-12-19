// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <nvme/types.h>

#include "unvmed.h"

bool unvme_is_abspath(const char *path)
{
	if (path[0] == '/' || path[0] == '~')
		return true;
	return false;
}

char *unvme_get_filepath(char *pwd, const char *filename)
{
	char *str;

	if (unvme_is_abspath(filename))
		return strdup(filename);

	/* +1 for "/" and +1 for "\0" */
	str = malloc(strlen(pwd) + strlen(filename) + 1 + 1);
	assert(str != NULL);

	str[0] = '\0';
	strcat(str, pwd);
	strcat(str, "/");
	strcat(str, filename);

	return str;
}

int unvme_write_file(const char *abspath, void *buf, size_t len)
{
	int ret;
	int fd;

	fd = open(abspath, O_CREAT | O_WRONLY | O_EXCL, 0644);
	if (fd < 0) {
		if (errno == EEXIST)
			fd = open(abspath, O_WRONLY);
		else {
			if (fd == -ENOENT)
			perror("open");
			return -1;
		}
	}

	ret = write(fd, buf, len);
	if (ret < 0) {
		perror("write");
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int unvme_read_file(const char *abspath, void *buf, size_t len)
{
	int ret;
	int fd;

	fd = open(abspath, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	ret = read(fd, buf, len);
	if (ret < 0) {
		perror("read");
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}
