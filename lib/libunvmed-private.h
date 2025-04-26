/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */

#ifndef LIBUNVMED_PRIVATE_H
#define LIBUNVMED_PRIVATE_H

struct unvme_ctx;
struct unvme_cq_reaper;

enum unvme_state {
	UNVME_DISABLED	= 0,
	UNVME_ENABLED,
	UNVME_TEARDOWN,
};

struct unvme {
	/* `ctrl` member must be the first member of `struct unvme` */
	struct nvme_ctrl ctrl;

	enum unvme_state state;

	uint8_t mps;	/* Memory Page Size (2 ^ (12 + @mps)) */

	int nr_sqs;
	int nr_cqs;
	struct list_head sq_list;
	pthread_rwlock_t sq_list_lock;
	struct list_head cq_list;
	pthread_rwlock_t cq_list_lock;

	struct unvme_sq *asq;
	struct unvme_cq *acq;

	struct unvme_sq **sqs;
	struct unvme_cq **cqs;

	/*
	 * Number of in-flight commands whose sq entries have already issued
	 * with the doorbell udpate and cq entries have not been yet fetched.
	 */
	int nr_cmds;

	struct list_head ns_list;
	pthread_rwlock_t ns_list_lock;
	int nr_ns;

	int *efds;
	int nr_efds;
	struct unvme_cq_reaper *reapers;

	struct list_head ctx_list;

	/*
	 * Identify Controller data structure made in the runtime.  Application
	 * should set this pointer to an allocated buffer after issuing
	 * Identify command to the controller.
	 */
	struct nvme_id_ctrl *id_ctrl;

	struct unvme_hmb {
		struct {
			__le64 badd;
			__le32 bsize;
			uint32_t rsvd;
		} *descs;
		uint64_t *descs_vaddr;
		uint64_t descs_iova;
		size_t descs_size;
		int nr_descs;
		uint32_t hsize;
	} hmb;

	struct list_node list;
};

static inline int unvmed_pow(int base, int exp)
{
	int ret = 1;

	while (true) {
		if (exp & 1)
			ret = ret * base;
		exp = exp >> 1;
		if (!exp)
			break;

		base = base * base;
	}

	return ret;
}

struct __unvme_ns {
	unvme_declare_ns();
	struct list_node list;
};

/*
 * SQ and CQ instances should not be freed in the runtime even controller reset
 * happens.  Instances should be remained as is, which means we should reuse
 * the instance when we re-create a queue with the same qid.  This is because
 * application (e.g., fio) may keep trying to issue I/O commands with no-aware
 * of reset behavior.
 */
struct __unvme_sq {
	unvme_declare_sq();
	struct list_node list;
};
#define __to_sq(usq)		((struct unvme_sq *)(usq))

struct __unvme_cq {
	unvme_declare_cq();
	struct list_node list;
};
#define __to_cq(ucq)		((struct unvme_cq *)(ucq))

/*
 * Driver context
 */
enum unvme_ctx_type {
	UNVME_CTX_T_CTRL,
	UNVME_CTX_T_SQ,
	UNVME_CTX_T_CQ,
	UNVME_CTX_T_NS,
};

struct unvme_ctx {
	enum unvme_ctx_type type;

	union {
		struct {
			uint8_t iosqes;
			uint8_t iocqes;
			uint8_t mps;
			uint8_t css;
		} ctrl;

		struct {
			uint32_t qid;
			uint32_t qsize;
			uint32_t cqid;
		} sq;

		struct {
			uint32_t qid;
			uint32_t qsize;
			int vector;
		} cq;

		struct {
			uint32_t nsid;
		} ns;
	};

	struct list_node list;
};

/* Reaped CQ */
struct unvme_rcq {
	struct nvme_cqe *cqe;
	int qsize;
	uint16_t head;
	uint16_t tail;
};

struct unvme_cq_reaper {
	struct unvme *u;
	int refcnt;

	int vector;
	int epoll_fd;
	int efd;
	pthread_t th;
	struct unvme_rcq rcq;
};

/*
 * libunvmed-logs.c
 */
void unvmed_log_cmd_post(const char *bdf, uint32_t sqid, union nvme_cmd *sqe);
void unvmed_log_cmd_cmpl(const char *bdf, struct nvme_cqe *cqe);

#include <sys/syscall.h>
#include <linux/futex.h>

static inline int unvmed_futex_wait(void *addr, int expected)
{
	return syscall(SYS_futex, addr, FUTEX_WAIT, expected, NULL, NULL, 0);
}

static inline int unvmed_futex_wake(void *addr, int n)
{
	return syscall(SYS_futex, addr, FUTEX_WAKE, n, NULL, NULL, 0);
}

static inline int unvmed_cmd_wait(struct unvme_cmd *cmd)
{
	if (!(cmd->flags & UNVMED_CMD_F_WAKEUP_ON_CQE))
		return -EINVAL;

	while (!atomic_load_acquire(&cmd->completed)) {
		if (!unvmed_cq_irq_enabled(cmd->usq->ucq))
			unvmed_cq_run(cmd->u, cmd->usq->ucq, NULL);
		else
			unvmed_futex_wait(&cmd->completed, 0);
	}

	return 0;
}

#endif
