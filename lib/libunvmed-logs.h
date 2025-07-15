/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */

#ifndef LIBUNVMED_LOG_H
#define LIBUNVMED_LOG_H

extern int __unvmed_logfd;
extern int __log_level;

enum {
	UNVME_LOG_ERR,
	UNVME_LOG_INFO,
	UNVME_LOG_DEBUG,
	UNVME_LOG_LAST = UNVME_LOG_DEBUG,
};

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
____unvmed_log(const int lv, const char *fmt, ...)
{
	va_list va;

	if (!__unvmed_logfd)
		return;

	va_start(va, fmt);
	vdprintf(__unvmed_logfd, fmt, va);
	va_end(va);
}

#define loglv_to_str(lv) (lv == UNVME_LOG_ERR ? "ERROR" : \
		    lv == UNVME_LOG_INFO ? "INFO" : "DEBUG")

#define __unvmed_log(lv, fmt, ...)						\
	do {									\
		if (lv > atomic_load_acquire(&__log_level))			\
			break;							\
										\
		char datetime[32];						\
										\
		unvme_datetime(datetime);					\
		____unvmed_log(lv, "%-8s| %s | %s: %d: " fmt "\n",		\
			loglv_to_str(lv), datetime,				\
			__func__, __LINE__, ##__VA_ARGS__);			\
	} while(0)

#define unvmed_log_err(fmt, ...)	__unvmed_log(UNVME_LOG_ERR, fmt, ##__VA_ARGS__)
#define unvmed_log_info(fmt, ...)	__unvmed_log(UNVME_LOG_INFO, fmt, ##__VA_ARGS__)
#define unvmed_log_debug(fmt, ...)	__unvmed_log(UNVME_LOG_DEBUG, fmt, ##__VA_ARGS__)

/*
 * libunvmed-logs.c
 */
void unvmed_log_cmd_post(const char *bdf, uint32_t sqid, union nvme_cmd *sqe);
void unvmed_log_cmd_cmpl(const char *bdf, struct nvme_cqe *cqe);
void unvmed_log_cmd_vcq_push(struct nvme_cqe *cqe);
void unvmed_log_cmd_vcq_pop(struct nvme_cqe *cqe);

#endif
