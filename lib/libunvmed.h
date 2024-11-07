/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */

#ifndef LIBUNVMED_H
#define LIBUNVMED_H

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/time.h>

/*
 * `libunvmed`-specific structures
 */
struct unvme;
struct unvme_cmd;

#define unvme_declare_ns(name)	\
struct name {			\
	struct unvme *u;	\
				\
	uint32_t nsid;		\
	unsigned int lba_size;	\
	unsigned long nr_lbas;	\
}

unvme_declare_ns(unvme_ns);

#define unvme_declare_sq(name)	\
struct name {			\
	struct nvme_sq *q;	\
	struct unvme_cq *ucq;	\
	struct unvme_cmd *cmds; \
	pthread_spinlock_t lock;\
	bool enabled;		\
}

#define unvme_declare_cq(name)	\
struct name {			\
	struct unvme *u;	\
	struct nvme_cq *q;	\
	pthread_spinlock_t lock;\
	bool enabled;		\
}

unvme_declare_cq(unvme_cq);
unvme_declare_sq(unvme_sq);

#define unvmed_cq_id(ucq)	((ucq)->q->id)
#define unvmed_cq_iv(ucq)	((ucq)->q->vector)
#define unvmed_sq_id(usq)	((usq)->q->id)
#define unvmed_sq_cqid(usq)	(unvmed_cq_id((usq)->ucq))

static inline void unvmed_sq_enter(struct unvme_sq *usq)
{
	pthread_spin_lock(&usq->lock);
}

static inline int unvmed_sq_try_enter(struct unvme_sq *usq)
{
	return pthread_spin_trylock(&usq->lock);
}

static inline void unvmed_sq_exit(struct unvme_sq *usq)
{
	pthread_spin_unlock(&usq->lock);
}

static inline void unvmed_cq_enter(struct unvme_cq *ucq)
{
	pthread_spin_lock(&ucq->lock);
}

static inline void unvmed_cq_exit(struct unvme_cq *ucq)
{
	pthread_spin_unlock(&ucq->lock);
}

static inline bool unvmed_cq_irq_enabled(struct unvme_cq *ucq)
{
	return ucq->q->vector >= 0;
}

/*
 * NVMe spec-based data structures defined in `libvfn`
 */
union nvme_cmd;
struct nvme_cqe;

/*
 * `libvfn`-specific structures
 */
struct nvme_sq;
struct nvme_cq;

void unvmed_init(const char *logfile);

struct unvme *unvmed_get(const char *bdf);
int unvmed_nr_cmds(struct unvme *u);
int unvmed_get_nslist(struct unvme *u, struct unvme_ns **nslist);
struct unvme_ns *unvmed_get_ns(struct unvme *u, uint32_t nsid);

int unvmed_get_max_qid(struct unvme *u);
int unvmed_get_sqs(struct unvme *u, struct nvme_sq **sqs);
int unvmed_get_cqs(struct unvme *u, struct nvme_cq **cqs);
struct unvme_sq *unvmed_get_sq(struct unvme *u, uint32_t qid);
struct unvme_cq *unvmed_get_cq(struct unvme *u, uint32_t qid);

struct unvme *unvmed_init_ctrl(const char *bdf, uint32_t max_nr_ioqs);
int unvmed_init_ns(struct unvme *u, uint32_t nsid, void *identify);
void unvmed_free_ctrl(struct unvme *u);
void unvmed_free_ctrl_all(void);
struct unvme_cmd *unvmed_alloc_cmd(struct unvme *u, int sqid);
void __unvmed_cmd_free(struct unvme_cmd *cmd);
void unvmed_cmd_free(struct unvme_cmd *cmd);
void unvmed_reset_ctrl(struct unvme *u);
int unvmed_create_adminq(struct unvme *u);
int unvmed_enable_ctrl(struct unvme *u, uint8_t iosqes, uint8_t iocqes, uint8_t mps, uint8_t css);
int unvmed_create_cq(struct unvme *u, uint32_t qid, uint32_t qsize, int vector);
int unvmed_delete_cq(struct unvme *u, uint32_t qid);
int unvmed_create_sq(struct unvme *u, uint32_t qid, uint32_t qsize, uint32_t cqid);
int unvmed_delete_sq(struct unvme *u, uint32_t qid);
int unvmed_map_vaddr(struct unvme *u, void *buf, size_t len, uint64_t *iova, unsigned long flags);
int unvmed_unmap_vaddr(struct unvme *u, void *buf);
void *unvmed_cmd_opaque(struct unvme_cmd *cmd);
void unvmed_cmd_set_opaque(struct unvme_cmd *cmd, void *opaque);
void unvmed_cmd_post(struct unvme_cmd *cmd, union nvme_cmd *sqe, unsigned long flags);
struct nvme_cqe *unvmed_cmd_cmpl(struct unvme_cmd *cmd);
struct unvme_cmd *unvmed_get_cmd_from_cqe(struct unvme *u, struct nvme_cqe *cqe);
int __unvmed_cq_run_n(struct unvme *u, struct unvme_cq *ucq, struct nvme_cqe *cqes, int nr_cqes, bool nowait);
int unvmed_cq_run(struct unvme *u, struct unvme_cq *ucq, struct nvme_cqe *cqes);
int unvmed_cq_run_n(struct unvme *u, struct unvme_cq *ucq, struct nvme_cqe *cqes, int min, int max);
void unvmed_sq_update_tail(struct unvme *u, struct unvme_sq *usq);
int unvmed_sq_update_tail_and_wait(struct unvme *u, uint32_t sqid, struct nvme_cqe **cqes);
int __unvmed_map_prp(struct unvme_cmd *cmd, union nvme_cmd *sqe, uint64_t iova, size_t len);

enum unvmed_cmd_flags {
	/* No doorbell update after posting one or more commands */
	UNVMED_CMD_F_NODB	= 1 << 0,
};

int unvmed_id_ns(struct unvme *u, uint32_t nsid, void *buf, unsigned long flags);
int unvmed_id_active_nslist(struct unvme *u, uint32_t nsid, void *buf);
int unvmed_read(struct unvme *u, uint32_t sqid, uint32_t nsid, uint64_t slba,
		uint16_t nlb, void *buf, size_t size, unsigned long flags, void *opaque);
int unvmed_write(struct unvme *u, uint32_t sqid, uint32_t nsid, uint64_t slba,
		 uint16_t nlb, void *buf, size_t size, unsigned long flags, void *opaque);
int unvmed_passthru(struct unvme *u, uint32_t sqid, void *buf, size_t size,
		    union nvme_cmd *sqe, bool read, unsigned long flags);

/*
 * `struct unvme` starts with `struct nvme_ctrl`, so convert easily.
 */
#define __unvmed_ctrl(u)		((struct nvme_ctrl *)(u))

/*
 * `struct nvme_ctrl` of `libvfn` access helpers.
 */
#define unvmed_bdf(u)		(__unvmed_ctrl(u)->pci.bdf)
#define unvmed_reg(u)		(__unvmed_ctrl(u)->regs)

#define unvmed_cqe_status(cqe)	(le16_to_cpu((cqe)->sfp) >> 1)

#define unvmed_read32(u, offset)	\
	le32_to_cpu(mmio_read32(unvmed_reg(u) + (offset)))
#define unvmed_read64(u, offset)	\
	le64_to_cpu(mmio_read64(unvmed_reg(u) + (offset)))
#define unvmed_write32(u, offset, value) \
	mmio_write32(unvmed_reg(u) + (offset), cpu_to_le32((value)))
#define unvmed_write64(u, offset, value) \
	mmio_write64(unvmed_reg(u) + (offset), cpu_to_le64((value)))

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

#endif
