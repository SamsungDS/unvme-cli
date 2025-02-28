/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */

#ifndef LIBUNVMED_PRIVATE_H
#define LIBUNVMED_PRIVATE_H

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

/*
 * libunvmed-logs.c
 */
void unvmed_log_cmd_post(const char *bdf, uint32_t sqid, union nvme_cmd *sqe);
void unvmed_log_cmd_cmpl(const char *bdf, struct nvme_cqe *cqe);

#endif
