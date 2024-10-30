// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#include <sys/stat.h>
#include <sys/time.h>

#include <vfn/nvme.h>
#include <vfn/support/atomic.h>

#include <nvme/types.h>

#include <ccan/list/list.h>

#include "libunvmed.h"
#include "libunvmed-private.h"

int __unvmed_logfd = 0;

struct unvme {
	/* `ctrl` member must be the first member of `struct unvme` */
	struct nvme_ctrl ctrl;

	bool enabled;

	int nr_sqs;
	int nr_cqs;
	struct list_head sq_list;
	pthread_rwlock_t sq_list_lock;
	struct list_head cq_list;
	pthread_rwlock_t cq_list_lock;

	int nr_cmds;

	struct list_head ns_list;
	int nr_ns;

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

enum unvme_cmd_state {
	UNVME_CMD_S_INIT		= 0,
	UNVME_CMD_S_SUBMITTED,
	UNVME_CMD_S_COMPLETED,
	UNVME_CMD_S_TO_BE_COMPLETED,
};

struct unvme_cmd {
	struct unvme *u;

	enum unvme_cmd_state state;

	/*
	 * rq->opaque will point to the current structure pointer.
	 */
	struct nvme_rq *rq;
	union nvme_cmd sqe;
	struct nvme_cqe cqe;

	/*
	 * Data buffer for the corresponding NVMe command, this should be
	 * replaced to iommu_dmabuf in libvfn.
	 */
	void *vaddr;

	void *opaque;
};

static LIST_HEAD(unvme_list);

static int unvmed_create_logfile(const char *logfile)
{
	int fd;

	if(mkdir("/var/log", 0755) < 0 && errno != EEXIST)
		return -errno;

	fd = creat(logfile, 0644);
	if (fd < 0)
		return -EINVAL;

	return fd;
}

void unvmed_init(const char *logfile)
{
	if (logfile)
		__unvmed_logfd = unvmed_create_logfile(logfile);
}

struct unvme *unvmed_get(const char *bdf)
{
	struct unvme *u;

	if (!unvme_list.n.next || !unvme_list.n.prev)
		return NULL;

	list_for_each(&unvme_list, u, list) {
		if (!strcmp(u->ctrl.pci.bdf, bdf))
			return u;
	}

	return NULL;
}

int unvmed_nr_cmds(struct unvme *u)
{
	return u->nr_cmds;
}

int unvmed_get_nslist(struct unvme *u, struct unvme_ns **nslist)
{
	struct __unvme_ns *ns;
	int nr_ns = 0;

	if (!nslist) {
		errno = EINVAL;
		return -1;
	}

	if (!u->nr_ns)
		return 0;

	*nslist = calloc(u->nr_ns, sizeof(struct unvme_ns));
	if (!*nslist)
		return -1;

	list_for_each(&u->ns_list, ns, list) {
		assert(nr_ns < u->nr_ns);
		memcpy(&((*nslist)[nr_ns++]), ns, sizeof(struct unvme_ns));
	}

	return nr_ns;
}

struct unvme_ns *unvmed_get_ns(struct unvme *u, uint32_t nsid)
{
	struct __unvme_ns *ns;

	list_for_each(&u->ns_list, ns, list) {
		if (ns->nsid == nsid)
			return (struct unvme_ns *)ns;
	}

	return NULL;
}

int unvmed_get_sqs(struct unvme *u, struct nvme_sq **sqs)
{
	struct unvme_sq *usq;
	int nr_sqs = 0;
	int qid;

	if (!sqs) {
		errno = EINVAL;
		return -1;
	}

	*sqs = calloc(u->nr_sqs, sizeof(struct nvme_sq));
	if (!*sqs)
		return -1;

	for (qid = 0; qid < u->nr_sqs; qid++) {
		usq = unvmed_get_sq(u, qid);
		if (!usq)
			continue;

		memcpy(&((*sqs)[nr_sqs++]), usq->q, sizeof(*(usq->q)));
	}

	return nr_sqs;
}

int unvmed_get_cqs(struct unvme *u, struct nvme_cq **cqs)
{
	struct unvme_cq *ucq;
	int nr_cqs = 0;
	int qid;

	if (!cqs) {
		errno = EINVAL;
		return -1;
	}

	*cqs = calloc(u->nr_cqs, sizeof(struct nvme_cq));
	if (!*cqs)
		return -1;

	for (qid = 0; qid < u->nr_cqs; qid++) {
		ucq = unvmed_get_cq(u, qid);
		if (!ucq | (ucq && !ucq->enabled))
			continue;

		memcpy(&((*cqs)[nr_cqs++]), ucq->q, sizeof(*(ucq->q)));
	}

	return nr_cqs;
}

static struct __unvme_sq *__unvmed_get_sq(struct unvme *u, uint32_t qid)
{
	struct __unvme_sq *curr, *usq = NULL;

	pthread_rwlock_rdlock(&u->sq_list_lock);
	list_for_each(&u->sq_list, curr, list) {
		assert(curr->q != NULL);
		if (unvmed_sq_id(curr) == qid) {
			usq = curr;
			break;
		}
	}
	pthread_rwlock_unlock(&u->sq_list_lock);

	return usq;
}

static struct __unvme_cq *__unvmed_get_cq(struct unvme *u, uint32_t qid)
{
	struct __unvme_cq *curr, *ucq = NULL;

	pthread_rwlock_rdlock(&u->cq_list_lock);
	list_for_each(&u->cq_list, curr, list) {
		assert(curr->q != NULL);
		if (unvmed_cq_id(curr) == qid) {
			ucq = curr;
			break;
		}
	}
	pthread_rwlock_unlock(&u->cq_list_lock);

	return ucq;
}

struct unvme_sq *unvmed_get_sq(struct unvme *u, uint32_t qid)
{
	struct __unvme_sq *usq = __unvmed_get_sq(u, qid);

	if (usq && usq->enabled)
		return __to_sq(usq);
	return NULL;
}

struct unvme_cq *unvmed_get_cq(struct unvme *u, uint32_t qid)
{
	struct __unvme_cq *ucq = __unvmed_get_cq(u, qid);

	if (ucq && ucq->enabled)
		return __to_cq(ucq);
	return NULL;
}

/*
 * Initialize NVMe controller instance in libvfn.  If exists, return the
 * existing one, otherwise it will create new one.  NULL if failure happens.
 */
struct unvme *unvmed_init_ctrl(const char *bdf, uint32_t max_nr_ioqs)
{
	struct nvme_ctrl_opts opts = {0, };
	struct unvme *u;

	u = unvmed_get(bdf);
	if (u)
		return u;

	u = zmalloc(sizeof(struct unvme));

	/*
	 * Zero-based values for I/O queues to pass to `libvfn` excluding the
	 * admin submission/completion queues.
	 */
	opts.nsqr = max_nr_ioqs - 1;
	opts.ncqr = max_nr_ioqs - 1;

	if (nvme_ctrl_init(&u->ctrl, bdf, &opts)) {
		free(u);
		return NULL;
	}

	assert(u->ctrl.opts.nsqr == opts.nsqr);
	assert(u->ctrl.opts.ncqr == opts.ncqr);

	/*
	 * XXX: Since unvme-cli does not follow all the behaviors of the driver, it does
	 * not set up nsqa and ncqa.
	 * Originally, nsqa and ncqa are set through the set feature command, but
	 * we cannot expect the user to send the set feature command.
	 * Therefore, during the `unvme_add`, nsqa and ncqa are set respectively to
	 * nsqr and ncqr.
	 */
	u->ctrl.config.nsqa = opts.nsqr;
	u->ctrl.config.ncqa = opts.ncqr;

	/*
	 * XXX: Maximum number of queues can be created in libvfn.  libvfn
	 * allocates ctrl.sq and ctrl.cq as an array with size of
	 * ctrl.opts.nsqr + 2 and ctrl.opts.ncqr + 2 respectively.  This is
	 * ugly, but we can have it until libvfn exposes these numbers as a
	 * public members.
	 */
	u->nr_sqs = opts.nsqr + 2;
	u->nr_cqs = opts.ncqr + 2;

	list_head_init(&u->sq_list);
	pthread_rwlock_init(&u->sq_list_lock, NULL);
	list_head_init(&u->cq_list);
	pthread_rwlock_init(&u->cq_list_lock, NULL);
	list_head_init(&u->ns_list);
	list_add(&unvme_list, &u->list);
	return u;
}

int unvmed_init_ns(struct unvme *u, uint32_t nsid, void *identify)
{
	struct nvme_id_ns id_ns_local;
	struct nvme_id_ns *id_ns = identify;
	struct __unvme_ns *ns;
	unsigned long flags = 0;
	uint8_t format_idx;
	int ret;

	if (unvmed_get_ns(u, nsid)) {
		errno = EEXIST;
		return -1;
	}

	if (!id_ns) {
		ret = unvmed_id_ns(u, nsid, &id_ns_local, flags);
		if (ret)
			return ret;

		id_ns = &id_ns_local;
	}

	ns = zmalloc(sizeof(struct __unvme_ns));
	if (!ns)
		return -1;

	if (id_ns->nlbaf < 16)
		format_idx = id_ns->flbas & 0xf;
	else
		format_idx = ((id_ns->flbas & 0xf) +
		       (((id_ns->flbas >> 5) & 0x3) << 4));

	ns->nsid = nsid;
	ns->lba_size = 1 << id_ns->lbaf[format_idx].ds;
	ns->nr_lbas = le64_to_cpu((uint64_t)id_ns->nsze);

	list_add_tail(&u->ns_list, &ns->list);
	u->nr_ns++;

	return 0;
}

static int unvmed_free_ns(struct __unvme_ns *ns)
{
	if (!ns) {
		errno = ENODEV;
		return -1;
	}

	list_del(&ns->list);
	free(ns);
	return 0;
}

static struct unvme_sq *unvmed_init_usq(struct unvme *u, uint32_t qid,
					uint32_t qsize)
{
	struct __unvme_sq *usq;

	usq = __unvmed_get_sq(u, qid);
	if (!usq) {
		usq = calloc(1, sizeof(*usq));
		if (!usq)
			return NULL;

		/*
		 * XXX: Not support for different size of qsize
		 */
		usq->cmds = calloc(qsize, sizeof(struct unvme_cmd));
		pthread_spin_init(&usq->lock, 0);
		pthread_rwlock_wrlock(&u->sq_list_lock);
		list_add_tail(&u->sq_list, &usq->list);
		pthread_rwlock_unlock(&u->sq_list_lock);
	}

	return (struct unvme_sq *)usq;
}

static void __unvmed_free_usq(struct __unvme_sq *usq)
{
	list_del(&usq->list);
	free(usq);
}

static void unvmed_free_usq(struct unvme *u, struct __unvme_sq *usq)
{
	pthread_rwlock_wrlock(&u->sq_list_lock);
	__unvmed_free_usq(usq);
	pthread_rwlock_unlock(&u->sq_list_lock);
}

static struct unvme_cq *unvmed_init_ucq(struct unvme *u, uint32_t qid)
{
	struct __unvme_cq *ucq;

	ucq = __unvmed_get_cq(u, qid);
	if (!ucq) {
		ucq = calloc(1, sizeof(*ucq));
		if (!ucq)
			return NULL;
		pthread_spin_init(&ucq->lock, 0);
		pthread_rwlock_wrlock(&u->cq_list_lock);
		list_add_tail(&u->cq_list, &ucq->list);
		pthread_rwlock_unlock(&u->cq_list_lock);
	}

	return (struct unvme_cq *)ucq;
}

static void __unvmed_free_ucq(struct __unvme_cq *ucq)
{
	list_del(&ucq->list);
	free(ucq);
}

static void unvmed_free_ucq(struct unvme *u, struct __unvme_cq *ucq)
{
	pthread_rwlock_wrlock(&u->cq_list_lock);
	__unvmed_free_ucq(ucq);
	pthread_rwlock_unlock(&u->cq_list_lock);
}

/*
 * Free NVMe controller instance from libvfn and the libunvmed.
 */
void unvmed_free_ctrl(struct unvme *u)
{
	struct __unvme_ns *ns, *next_ns;
	struct __unvme_sq *usq, *next_usq;
	struct __unvme_cq *ucq, *next_ucq;

	nvme_close(&u->ctrl);

	pthread_rwlock_wrlock(&u->sq_list_lock);
	list_for_each_safe(&u->sq_list, usq, next_usq, list)
		__unvmed_free_usq(usq);
	pthread_rwlock_unlock(&u->sq_list_lock);

	pthread_rwlock_wrlock(&u->cq_list_lock);
	list_for_each_safe(&u->cq_list, ucq, next_ucq, list)
		__unvmed_free_ucq(ucq);
	pthread_rwlock_unlock(&u->cq_list_lock);

	list_for_each_safe(&u->ns_list, ns, next_ns, list)
		unvmed_free_ns(ns);

	list_del(&u->list);
	free(u);
}

/*
 * Free all the existing controller instances from libvfn and libunvmed.
 */
void unvmed_free_ctrl_all(void)
{
	struct unvme *u, *next;

	list_for_each_safe(&unvme_list, u, next, list)
		unvmed_free_ctrl(u);
}

void __unvmed_cmd_free(struct unvme_cmd *cmd)
{
	nvme_rq_release(cmd->rq);

	cmd->rq = NULL;
	cmd->state = UNVME_CMD_S_INIT;
}

void unvmed_cmd_free(struct unvme_cmd *cmd)
{
	if (cmd->vaddr)
		unvmed_unmap_vaddr(cmd->u, cmd->vaddr);
	__unvmed_cmd_free(cmd);
}

struct unvme_cmd *unvmed_alloc_cmd(struct unvme *u, int sqid)
{
	struct unvme_cmd *cmd;
	struct __unvme_sq *usq;
	struct nvme_rq *rq;

	usq = (struct __unvme_sq *)__unvmed_get_sq(u, sqid);
	if (!usq) {
		errno = EINVAL;
		return NULL;
	}

	rq = nvme_rq_acquire(usq->q);
	if (!rq)
		return NULL;

	cmd = &usq->cmds[rq->cid];
	cmd->u = u;
	cmd->rq = rq;
	rq->opaque = cmd;

	return cmd;
}

static void __unvme_reset_ctrl(struct unvme *u)
{
	uint32_t cc = unvmed_read32(u, NVME_REG_CC);
	uint32_t csts;

	unvmed_write32(u, NVME_REG_CC, cc & ~(1 << NVME_CC_EN_SHIFT));
	while (1) {
		csts = unvmed_read32(u, NVME_REG_CSTS);
		if (!NVME_CSTS_RDY(csts))
			break;
	}
}

static inline void unvmed_disable_sq_all(struct unvme *u)
{
	struct __unvme_sq *usq;

	pthread_rwlock_rdlock(&u->sq_list_lock);
	list_for_each(&u->sq_list, usq, list)
		usq->enabled = false;
	pthread_rwlock_unlock(&u->sq_list_lock);
}

static inline void unvmed_disable_cq_all(struct unvme *u)
{
	struct __unvme_cq *ucq;

	pthread_rwlock_rdlock(&u->cq_list_lock);
	list_for_each(&u->cq_list, ucq, list)
		ucq->enabled = false;
	pthread_rwlock_unlock(&u->cq_list_lock);
}

static inline void unvmed_quiesce_sq_all(struct unvme *u)
{
	struct __unvme_sq *usq;

	pthread_rwlock_rdlock(&u->sq_list_lock);
	list_for_each(&u->sq_list, usq, list)
		unvmed_sq_enter(__to_sq(usq));
	pthread_rwlock_unlock(&u->sq_list_lock);
}

static inline void unvmed_unquiesce_sq_all(struct unvme *u)
{
	struct __unvme_sq *usq;

	pthread_rwlock_rdlock(&u->sq_list_lock);
	list_for_each(&u->sq_list, usq, list)
		unvmed_sq_exit(__to_sq(usq));
	pthread_rwlock_unlock(&u->sq_list_lock);
}

static inline struct nvme_cqe *unvmed_get_cqe(struct unvme_cq *ucq, uint32_t head)
{
	return (struct nvme_cqe *)(ucq->q->vaddr + (head << NVME_CQES));
}

static inline void unvmed_put_cqe(struct unvme_cq *ucq, uint32_t head,
				  uint8_t phase, struct unvme_cmd *cmd)
{
	uint16_t status = (NVME_SCT_PATH << NVME_SCT_SHIFT) |
		NVME_SC_CMD_ABORTED_BY_HOST;
	struct nvme_cqe *__cqe;
	struct nvme_cqe cqe;

	cqe.qw0 = cpu_to_le64(0);
	cqe.sqhd = cpu_to_le16(0);
	cqe.sqid = cpu_to_le16(cmd->rq->sq->id);
	cqe.cid = cmd->rq->cid;
	cqe.sfp = cpu_to_le16((status << 1) | (phase & 1));

	__cqe = unvmed_get_cqe(ucq, head);
	*__cqe = cqe;

	unvmed_log_info("canceled command (sqid=%u, cid=%u)", cqe.sqid, cqe.cid);
}

static inline void unvmed_cancel_sq(struct unvme *u, struct __unvme_sq *usq)
{
	struct unvme_cq *ucq = usq->ucq;
	struct nvme_cqe *cqe;
	struct unvme_cmd *cmd;
	uint32_t head = ucq->q->head;
	uint8_t phase = ucq->q->phase;

	unvmed_cq_enter(ucq);

	while (1) {
		cqe = unvmed_get_cqe(ucq, head);
		if ((le16_to_cpu(cqe->sfp) & 0x1) == phase) {
			cmd = unvmed_get_cmd_from_cqe(u, cqe);
			assert(cmd != NULL);

			cmd->state = UNVME_CMD_S_TO_BE_COMPLETED;

			if (++head == ucq->q->qsize) {
				head = 0;
				phase ^= 0x1;
			}
		} else
			break;
	}

	for (int i = 0; i < usq->q->qsize; i++) {
		cmd = &usq->cmds[i];
		if (cmd->state == UNVME_CMD_S_SUBMITTED) {
			unvmed_put_cqe(ucq, head, phase ^ 1, cmd);

			if (++head == ucq->q->qsize) {
				head = 0;
				phase ^= 0x1;
			}
		}
	}

	unvmed_cq_exit(ucq);
}

static inline void unvmed_cancel_sq_all(struct unvme *u)
{
	struct __unvme_sq *usq;

	pthread_rwlock_rdlock(&u->sq_list_lock);
	list_for_each(&u->sq_list, usq, list)
		unvmed_cancel_sq(u, usq);
	pthread_rwlock_unlock(&u->sq_list_lock);

	/*
	 * Wait for upper layer to complete canceled commands in their CQ
	 * reapding routine.
	 */
	while (LOAD(u->nr_cmds) > 0)
		;
}

/*
 * Reset NVMe controller instance memory resources along with de-asserting
 * controller enable register.  The instance itself will not be freed which can
 * be re-used in later time.
 */
void unvmed_reset_ctrl(struct unvme *u)
{
	__unvme_reset_ctrl(u);

	unvmed_disable_sq_all(u);
	unvmed_disable_cq_all(u);

	/*
	 * Quiesce all submission queues to prevent I/O submission from upper
	 * layer.  The queues should be re-enabled (unquiesced) back once
	 * create I/O queue command is issued.
	 */
	unvmed_quiesce_sq_all(u);

	unvmed_cancel_sq_all(u);

	unvmed_unquiesce_sq_all(u);
	u->enabled = false;
}

int unvmed_create_adminq(struct unvme *u)
{
	struct unvme_sq *usq;
	struct unvme_cq *ucq;

	if (u->enabled) {
		errno = EPERM;
		return -1;
	}

	/*
	 * XXX: libvfn has fixed size of admin queue and it's not exported to
	 * application layer yet.  Once it gets exported as a public, this
	 * hard-coded value should be fixed ASAP.
	 */
#define NVME_AQ_QSIZE	32
	usq = unvmed_init_usq(u, 0, NVME_AQ_QSIZE);
	if (!usq)
		return -1;

	ucq = unvmed_init_ucq(u, 0);
	if (!ucq)
		return -1;

	/*
	 * Do not free() allocated usq and ucq instances unless user gives
	 * 'unvme del <bdf>' to the daemon process.
	 */
	if (nvme_configure_adminq(&u->ctrl, 0))
		return -1;

	usq->q = &u->ctrl.sq[0];
	usq->ucq = __to_cq(ucq);
	usq->enabled = true;

	ucq->q = &u->ctrl.cq[0];
	ucq->enabled = true;

	return 0;
}

int unvmed_enable_ctrl(struct unvme *u, uint8_t iosqes, uint8_t iocqes,
		      uint8_t mps, uint8_t css)
{
	uint32_t cc = unvmed_read32(u, NVME_REG_CC);
	uint32_t csts;

	if (NVME_CC_EN(cc)) {
		errno = EEXIST;
		return -1;
	}

	cc = mps << NVME_CC_MPS_SHIFT |
		iosqes << NVME_CC_IOSQES_SHIFT |
		iocqes << NVME_CC_IOCQES_SHIFT |
		1 << NVME_CC_EN_SHIFT;
	unvmed_write32(u, NVME_REG_CC, cc);

	while (1) {
		csts = unvmed_read32(u, NVME_REG_CSTS);
		if (NVME_CSTS_RDY(csts))
			break;
	}

	u->enabled = true;
	return 0;
}

int unvmed_create_cq(struct unvme *u, uint32_t qid, uint32_t qsize,
		    uint32_t vector)
{
	struct unvme_cq *ucq;

	if (!u->enabled) {
		errno = EPERM;
		return -1;
	}

	ucq = unvmed_init_ucq(u, qid);
	if (!ucq)
		return -1;

	if (nvme_create_iocq(&u->ctrl, qid, qsize, vector)) {
		unvmed_free_ucq(u, (struct __unvme_cq *)ucq);
		return -1;
	}

	ucq->q = &u->ctrl.cq[qid];
	ucq->enabled = true;
	return 0;
}

static void __unvmed_delete_cq(struct unvme *u, uint32_t qid)
{
	struct unvme_cq *ucq;

	ucq = unvmed_get_cq(u, qid);
	if (ucq)
		nvme_discard_cq(&u->ctrl, ucq->q);
}

int unvmed_delete_cq(struct unvme *u, uint32_t qid)
{
	struct unvme_cmd *cmd;
	struct nvme_cmd_delete_q *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, 0);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_delete_q *)&cmd->sqe;
	sqe->opcode = nvme_admin_delete_cq;
	sqe->qid = cpu_to_le16(qid);

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, 0);
	cqe = unvmed_cmd_cmpl(cmd);

	if (nvme_cqe_ok(cqe))
		__unvmed_delete_cq(u, qid);

	unvmed_cmd_free(cmd);
	return unvmed_cqe_status(cqe);
}

int unvmed_create_sq(struct unvme *u, uint32_t qid, uint32_t qsize,
		    uint32_t cqid)
{
	struct unvme_sq *usq;
	struct unvme_cq *ucq;

	if (!u->enabled) {
		errno = EPERM;
		return -1;
	}

	ucq = unvmed_get_cq(u, cqid);
	if (!ucq) {
		errno = ENODEV;
		return -1;
	}

	usq = unvmed_init_usq(u, qid, qsize);
	if (!usq)
		return -1;

	if (nvme_create_iosq(&u->ctrl, qid, qsize, ucq->q, 0)) {
		unvmed_free_usq(u, (struct __unvme_sq *)usq);
		return -1;
	}

	usq->q = &u->ctrl.sq[qid];
	usq->ucq = ucq;
	usq->enabled = true;

	return 0;
}

static void __unvmed_delete_sq(struct unvme *u, uint32_t qid)
{
	struct unvme_sq *usq;

	usq = unvmed_get_sq(u, qid);
	if (usq)
		nvme_discard_sq(&u->ctrl, usq->q);
}

int unvmed_delete_sq(struct unvme *u, uint32_t qid)
{
	struct unvme_cmd *cmd;
	struct nvme_cmd_delete_q *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, 0);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_delete_q *)&cmd->sqe;
	sqe->opcode = nvme_admin_delete_sq;
	sqe->qid = cpu_to_le16(qid);

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, 0);
	cqe = unvmed_cmd_cmpl(cmd);

	if (nvme_cqe_ok(cqe))
		__unvmed_delete_sq(u, qid);

	unvmed_cmd_free(cmd);
	return unvmed_cqe_status(cqe);
}

int unvmed_map_vaddr(struct unvme *u, void *buf, size_t len,
		    uint64_t *iova, unsigned long flags)
{
	struct iommu_ctx *ctx = __iommu_ctx(&u->ctrl);

	if (iommu_map_vaddr(ctx, buf, len, iova, flags))
		return -1;

	return 0;
}

int unvmed_unmap_vaddr(struct unvme *u, void *buf)
{
	struct iommu_ctx *ctx = __iommu_ctx(&u->ctrl);

	return iommu_unmap_vaddr(ctx, buf, NULL);
}

void *unvmed_cmd_opaque(struct unvme_cmd *cmd)
{
	return cmd->opaque;
}

void unvmed_cmd_set_opaque(struct unvme_cmd *cmd, void *opaque)
{
	cmd->opaque = opaque;
}

void unvmed_cmd_post(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		     unsigned long flags)
{
	nvme_rq_post(cmd->rq, (union nvme_cmd *)sqe);

	cmd->state = UNVME_CMD_S_SUBMITTED;
	unvmed_log_cmd_post(unvmed_bdf(cmd->u), cmd->rq->sq->id, sqe);

	if (!(flags & UNVMED_CMD_F_NODB))
		nvme_sq_update_tail(cmd->rq->sq);
}

struct unvme_cmd *unvmed_get_cmd_from_cqe(struct unvme *u, struct nvme_cqe *cqe)
{
	struct unvme_sq *usq;

	/*
	 * Get sq instance by __unvmed_get_sq() instead of unvmed_get_sq()
	 * which returns an enabled sq instance since sq might have been
	 * removed due to some reasons like reset.  Even under reset, caller
	 * might want to seek the command instance for the corresponding
	 * completion queue entry.
	 */
	usq = __to_sq(__unvmed_get_sq(u, cqe->sqid));
	if (!usq)
		return NULL;

	return &usq->cmds[cqe->cid];
}

static struct nvme_cqe *unvmed_get_completion(struct unvme *u,
					      struct unvme_cq *ucq)
{
	struct unvme_cmd *cmd;
	struct nvme_cq *cq = ucq->q;
	struct nvme_cqe *cqe;

	unvmed_cq_enter(ucq);
	cqe = nvme_cq_get_cqe(cq);

	if (cqe) {
		cmd = unvmed_get_cmd_from_cqe(u, cqe);
		assert(cmd != NULL);

		cmd->cqe = *cqe;
		cmd->state = UNVME_CMD_S_COMPLETED;
	}
	unvmed_cq_exit(ucq);

	return cqe;
}

struct nvme_cqe *unvmed_cmd_cmpl(struct unvme_cmd *cmd)
{
	nvme_rq_spin(cmd->rq, &cmd->cqe);

	cmd->state = UNVME_CMD_S_COMPLETED;
	unvmed_log_cmd_cmpl(unvmed_bdf(cmd->u), &cmd->cqe);

	return &cmd->cqe;
}

int __unvmed_cq_run_n(struct unvme *u, struct unvme_cq *ucq,
		      struct nvme_cqe *cqes, int nr_cqes, bool nowait)
{
	struct nvme_cqe *cqe;
	int nr_cmds;
	int nr = 0;

	while (nr < nr_cqes) {
		cqe = unvmed_get_completion(u, ucq);
		if (!cqe) {
			if (nowait)
				break;
			continue;
		}

		memcpy(&cqes[nr++], cqe, sizeof(*cqe));
		unvmed_log_cmd_cmpl(unvmed_bdf(u), cqe);
	}

	do {
		nr_cmds = u->nr_cmds;
	} while (!atomic_cmpxchg(&u->nr_cmds, nr_cmds, nr_cmds - nr));

	return nr;
}

int unvmed_cq_run(struct unvme *u, struct unvme_cq *ucq, struct nvme_cqe *cqes)
{
	return __unvmed_cq_run_n(u, ucq, cqes, 0, true);
}

int unvmed_cq_run_n(struct unvme *u, struct unvme_cq *ucq,
		    struct nvme_cqe *cqes, int min, int max)
{
	int ret;
	int n;

	n = __unvmed_cq_run_n(u, ucq, cqes, min, false);
	if (n < 0)
		return -1;

	ret = n;

	if (ret >= max) {
		nvme_cq_update_head(ucq->q);
		return ret;
	}

	n = __unvmed_cq_run_n(u, ucq, cqes + n, max, true);
	if (n < 0)
		return -1;
	else if (n > 0)
		nvme_cq_update_head(ucq->q);

	return ret + n;
}

static int unvmed_nr_pending_sqes(struct unvme_sq *usq)
{
	struct nvme_sq *sq = usq->q;
	int nr_sqes;

	if (sq->tail >= sq->ptail)
		nr_sqes = sq->tail - sq->ptail;
	else
		nr_sqes = (sq->qsize - sq->ptail) + sq->tail;

	return nr_sqes;
}

void unvmed_sq_update_tail(struct unvme *u, struct unvme_sq *usq)
{
	int nr_sqes;
	int nr_cmds;

	nr_sqes = unvmed_nr_pending_sqes(usq);
	if (!nr_sqes)
		return;

	do {
		nr_cmds = u->nr_cmds;
	} while (!atomic_cmpxchg(&u->nr_cmds, nr_cmds, nr_cmds + nr_sqes));

	nvme_sq_update_tail(usq->q);
}

int unvmed_sq_update_tail_and_wait(struct unvme *u, uint32_t sqid,
				  struct nvme_cqe **cqes)
{
	struct unvme_sq *usq = unvmed_get_sq(u, sqid);
	int nr_sqes;
	int ret;

	if (!usq) {
		errno = EINVAL;
		return -1;
	}

	nr_sqes = unvmed_nr_pending_sqes(usq);
	if (!nr_sqes)
		return 0;

	*cqes = malloc(sizeof(struct nvme_cqe) * nr_sqes);

	nvme_sq_update_tail(usq->q);
	ret = unvmed_cq_run_n(u, usq->ucq, *cqes, nr_sqes, nr_sqes);
	for (int i = 0; ret > 0 && i < ret; i++)
		unvmed_cmd_free(unvmed_get_cmd_from_cqe(u, *cqes + i));

	if (ret != nr_sqes)
		return -1;

	return nr_sqes;
}

int __unvmed_map_prp(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		     uint64_t iova, size_t len)
{
	if (nvme_rq_map_prp(&cmd->u->ctrl, cmd->rq, sqe, iova, len))
		return -1;
	return 0;
}

static int unvmed_map_prp(struct unvme_cmd *cmd, union nvme_cmd *sqe, void *vaddr,
			  size_t len)
{
	uint64_t iova;

	if (unvmed_map_vaddr(cmd->u, vaddr, len, &iova, 0x0))
		return -1;

	cmd->vaddr = vaddr;
	if (!sqe)
		sqe = &cmd->sqe;

	return __unvmed_map_prp(cmd, sqe, iova, len);
}

int unvmed_id_ns(struct unvme *u, uint32_t nsid, void *buf, unsigned long flags)
{
	struct unvme_cmd *cmd;

	struct nvme_cmd_identify *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, 0);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_identify *)&cmd->sqe;
	sqe->opcode = nvme_admin_identify;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cns = cpu_to_le32(0x0);

	if (unvmed_map_prp(cmd, NULL, buf, NVME_IDENTIFY_DATA_SIZE))
		return -1;

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, flags);

	if (flags & UNVMED_CMD_F_NODB)
		return 0;

	cqe = unvmed_cmd_cmpl(cmd);

	unvmed_cmd_free(cmd);
	return unvmed_cqe_status(cqe);
}

int unvmed_id_active_nslist(struct unvme *u, uint32_t nsid, void *buf)
{
	struct unvme_cmd *cmd;

	struct nvme_cmd_identify *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, 0);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_identify *)&cmd->sqe;
	sqe->opcode = nvme_admin_identify;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cns = cpu_to_le32(0x2);

	if (unvmed_map_prp(cmd, NULL, buf, NVME_IDENTIFY_DATA_SIZE))
		return -1;

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, 0);

	cqe = unvmed_cmd_cmpl(cmd);

	unvmed_cmd_free(cmd);
	return unvmed_cqe_status(cqe);
}

int unvmed_read(struct unvme *u, uint32_t sqid, uint32_t nsid,
		uint64_t slba, uint16_t nlb,
		void *buf, size_t size, unsigned long flags, void *opaque)
{
	struct unvme_cmd *cmd;

	struct nvme_cmd_rw *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, sqid);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_rw *)&cmd->sqe;
	sqe->opcode = nvme_cmd_read;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->slba = cpu_to_le64(slba);
	sqe->nlb = cpu_to_le16(nlb);

	if (unvmed_map_prp(cmd, NULL, buf, size))
		return -1;

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, flags);

	if (flags & UNVMED_CMD_F_NODB) {
		cmd->opaque = opaque;
		return 0;
	}

	cqe = unvmed_cmd_cmpl(cmd);

	unvmed_cmd_free(cmd);
	return unvmed_cqe_status(cqe);
}

int unvmed_write(struct unvme *u, uint32_t sqid, uint32_t nsid,
		 uint64_t slba, uint16_t nlb,
		 void *buf, size_t size, unsigned long flags, void *opaque)
{
	struct unvme_cmd *cmd;

	struct nvme_cmd_rw *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, sqid);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_rw *)&cmd->sqe;
	sqe->opcode = nvme_cmd_write;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->slba = cpu_to_le64(slba);
	sqe->nlb = cpu_to_le16(nlb);

	if (unvmed_map_prp(cmd, NULL, buf, size))
		return -1;

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, flags);

	if (flags & UNVMED_CMD_F_NODB) {
		cmd->opaque = opaque;
		return 0;
	}

	cqe = unvmed_cmd_cmpl(cmd);

	unvmed_cmd_free(cmd);
	return unvmed_cqe_status(cqe);
}

int unvmed_passthru(struct unvme *u, uint32_t sqid, void *buf, size_t size,
		    union nvme_cmd *sqe, bool read, unsigned long flags)
{
	struct unvme_cmd *cmd;

	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, sqid);
	if (!cmd)
		return -1;

	memcpy(&cmd->sqe, sqe, sizeof(*sqe));

	if (!cmd->sqe.dptr.prp1 && !cmd->sqe.dptr.prp2) {
		if (unvmed_map_prp(cmd, NULL, buf, size))
			return -1;
	}

	unvmed_cmd_post(cmd, (union nvme_cmd *)&cmd->sqe, flags);

	if (flags & UNVMED_CMD_F_NODB)
		return 0;

	cqe = unvmed_cmd_cmpl(cmd);

	unvmed_cmd_free(cmd);
	return unvmed_cqe_status(cqe);
}
