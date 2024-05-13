#include <stdio.h>
#include <string.h>
#include <nvme/types.h>

#include "unvme.h"

static inline bool __is_abspath(const char *path)
{
	if (path[0] == '/' || path[0] == '~')
		return true;
	return false;
}

static inline char *__abspath(char *pwd, const char *filename)
{
	char *str;

	if (__is_abspath(filename))
		return strdup(filename);

	str = malloc(UNVME_PWD_STRLEN);
	assert(str != NULL);

	str[0] = '\0';
	strcat(str, pwd);
	strcat(str, "/");
	strcat(str, filename);

	return str;
}

int unvme_write_file(struct unvme_msg *msg, const char *filename, void *buf, size_t len)
{
	UNVME_FREE char *abspath;
	int ret;
	int fd;

	abspath = __abspath(unvme_msg_pwd(msg), filename);

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

int unvme_read_file(struct unvme_msg *msg, const char *filename, void *buf, size_t len)
{
	UNVME_FREE char *abspath;
	int ret;
	int fd;

	abspath = __abspath(unvme_msg_pwd(msg), filename);

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
