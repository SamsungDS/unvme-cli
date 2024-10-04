/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UNVMED_H
#define UNVMED_H

void unvme_datetime(char *datetime, size_t str_len);
int unvme_get_log_fd(void);

#define __unvme_log(type, fmt, ...)							\
	do { 										\
		char buf[550];								\
		char datetime[32];							\
											\
		unvme_datetime(datetime, sizeof(datetime));				\
		int len = snprintf(buf, sizeof(buf),					\
				   "%-8s| %s | %s: %d: " fmt "\n",			\
				   type, datetime, __func__, __LINE__, ##__VA_ARGS__);	\
		write(unvme_get_log_fd(), buf, len);					\
	} while(0)

#define unvme_log_info(fmt, ...)	__unvme_log("INFO", fmt, ##__VA_ARGS__)
#define unvme_log_err(fmt, ...)		__unvme_log("ERROR", fmt, ##__VA_ARGS__)
#define unvme_log_nvme(fmt, ...)	__unvme_log("NVME", fmt, ##__VA_ARGS__)

static inline void unvme_free(void *p)
{
	void **ptr = (void **)p;
	if (*ptr) {
		free(*ptr);
		*ptr = NULL;
	}
}
#define UNVME_FREE __attribute__((cleanup(unvme_free)))

struct unvme_msg;
struct unvme;
union nvme_cmd;
struct nvme_cqe;

/*
 * unvmed-print.c
 */
void unvme_pr_raw(void *vaddr, size_t len);
void unvme_pr_id_ns(void *vaddr);
void unvme_pr_show_regs(struct unvme *u);
void unvme_pr_status(struct unvme *u);

/*
 * unvmed-logs.c
 */
void unvme_log_cmd_post(const char *bdf, uint32_t sqid, union nvme_cmd *sqe);
void unvme_log_cmd_cmpl(const char *bdf, struct nvme_cqe *cqe);

/*
 * unvmed-file.c
 */
int unvme_write_file(struct unvme_msg *msg, const char *filename, void *buf, size_t len);
int unvme_read_file(struct unvme_msg *msg, const char *filename, void *buf, size_t len);

#endif
