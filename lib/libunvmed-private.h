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

	int nr_sqs;
	int nr_cqs;
	struct list_head sq_list;
	pthread_rwlock_t sq_list_lock;
	struct list_head cq_list;
	pthread_rwlock_t cq_list_lock;

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

	struct list_node list;
};

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

#endif
