/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */

#ifndef LIBUNVMED_LOG_H
#define LIBUNVMED_LOG_H

extern int __unvmed_logfd;

static inline void unvme_datetime(char *datetime)
{
	struct timeval tv;
	struct tm *tm;
	char usec[16];

	assert(datetime != NULL);

	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);

	strftime(datetime, 32, "%Y-%m-%d %H:%M:%S", tm);

	sprintf(usec, ".%06ld", tv.tv_usec);
	strcat(datetime, usec);
}

static inline void __attribute__((format(printf, 2, 3)))
____unvmed_log(const char *type, const char *fmt, ...)
{
	va_list va;

	if (!__unvmed_logfd)
		return;

	va_start(va, fmt);
	vdprintf(__unvmed_logfd, fmt, va);
	va_end(va);
}

#define __unvmed_log(type, fmt, ...)						\
	do {									\
		char datetime[32];						\
										\
		unvme_datetime(datetime);					\
		____unvmed_log(type, "%-8s| %s | %s: %d: " fmt "\n",		\
			type, datetime, __func__, __LINE__, ##__VA_ARGS__);	\
	} while(0)

#define unvmed_log_info(fmt, ...)	__unvmed_log("INFO", fmt, ##__VA_ARGS__)
#define unvmed_log_err(fmt, ...)	__unvmed_log("ERROR", fmt, ##__VA_ARGS__)
#define unvmed_log_nvme(fmt, ...)	__unvmed_log("NVME", fmt, ##__VA_ARGS__)

/*
 * libunvmed-logs.c
 */
void unvmed_log_cmd_post(const char *bdf, uint32_t sqid, union nvme_cmd *sqe);
void unvmed_log_cmd_cmpl(const char *bdf, struct nvme_cqe *cqe);

#endif
