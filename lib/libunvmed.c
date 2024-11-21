// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#define _GNU_SOURCE

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <vfn/nvme.h>
#include <vfn/support/atomic.h>

#include <nvme/types.h>

#include <ccan/list/list.h>

#include "libunvmed.h"
#include "libunvmed-private.h"

int __unvmed_logfd = 0;

struct unvme_cq_reaper;

enum unvme_state {
	UNVME_DISABLED	= 0,
	UNVME_ENABLED,
	UNVME_TEARDOWN,
};

struct unvme_ctx;

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

	int nr_cmds;

	struct list_head ns_list;
	pthread_rwlock_t ns_list_lock;
	int nr_ns;

	int *efds;
	int nr_efds;
	struct unvme_cq_reaper *reapers;

	struct list_head ctx_list;

	struct list_node list;
};

static inline bool unvme_is_enabled(struct unvme *u)
{
	return u->state == UNVME_ENABLED;
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
 * Driver context
 */
enum unvme_ctx_type {
	UNVME_CTX_T_CTRL,
	UNVME_CTX_T_SQ,
	UNVME_CTX_T_CQ,
	UNVME_CTX_T_NS,
};

struct unvme_ctx_ctrl {
	uint8_t iosqes;
	uint8_t iocqes;
	uint8_t mps;
	uint8_t css;
};

struct unvme_ctx_sq {
	uint32_t qid;
	uint32_t qsize;
	uint32_t cqid;
};

struct unvme_ctx_cq {
	uint32_t qid;
	uint32_t qsize;
	int vector;
};

struct unvme_ctx_ns {
	uint32_t nsid;
};

struct unvme_ctx {
	enum unvme_ctx_type type;

	union {
		struct unvme_ctx_ctrl ctrl;
		struct unvme_ctx_sq sq;
		struct unvme_ctx_cq cq;
		struct unvme_ctx_ns ns;
	};

	struct list_node list;
};

static void *unvmed_rcq_run(void *opaque);

static inline struct unvme_rcq *unvmed_rcq_from_ucq(struct unvme_cq *ucq)
{
	struct unvme *u = ucq->u;

	if (!unvmed_cq_irq_enabled(ucq))
		return NULL;

	return &u->reapers[unvmed_cq_iv(ucq)].rcq;
}

static int unvmed_rcq_push(struct unvme_rcq *q, struct nvme_cqe *cqe)
{
	uint16_t tail = atomic_load_acquire(&q->tail);

	if ((tail + 1) % q->qsize == atomic_load_acquire(&q->head))
		return -EAGAIN;

	q->cqe[tail] = *cqe;
	atomic_store_release(&q->tail, (tail + 1) % q->qsize);
	return 0;
}

static int unvmed_rcq_pop(struct unvme_rcq *q, struct nvme_cqe *cqe)
{
	uint16_t head = atomic_load_acquire(&q->head);

	if (head == atomic_load_acquire(&q->tail))
		return -ENOENT;

	*cqe = q->cqe[head];
	atomic_store_release(&q->head, (head + 1) % q->qsize);
	return 0;
}

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

	pthread_rwlock_rdlock(&u->ns_list_lock);
	list_for_each(&u->ns_list, ns, list) {
		if (ns->nsid == nsid) {
			pthread_rwlock_unlock(&u->ns_list_lock);
			return (struct unvme_ns *)ns;
		}
	}
	pthread_rwlock_unlock(&u->ns_list_lock);

	return NULL;
}

int unvmed_get_max_qid(struct unvme *u)
{
	return u->nr_cqs - 1;
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

int unvmed_cq_wait_irq(struct unvme *u, int vector)
{
	struct epoll_event evs[1];
	uint64_t irq;
	int ret;

	if (vector < 0 || vector >= u->nr_efds) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * epoll_wait might wake up due to signal received with errno EINTR.
	 * To prevent abnormal exit out of epoll_wait, we should continue
	 * if errno == EINTR.
	 */
	do {
		ret = epoll_wait(u->reapers[vector].epoll_fd, evs, 1, -1);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return -1;

	return eventfd_read(u->efds[vector], &irq);
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

static int unvmed_free_irq(struct unvme *u, int vector)
{
	struct unvme_cq_reaper *r = &u->reapers[vector];
	int ret;

	if (atomic_dec_fetch(&r->refcnt) > 0)
		return 0;

	/*
	 * Wake up the blocking threads waiting for the interrupt
	 * events from the device.
	 */
	eventfd_write(r->efd, 1);
	pthread_join(r->th, NULL);

	ret = vfio_disable_irq(&u->ctrl.pci.dev, vector, 1);
	if (ret) {
		unvmed_log_err("failed to disable irq %d", vector);
		return -1;
	}

	return 0;
}

static int unvmed_init_irq(struct unvme *u, int vector)
{
	struct unvme_cq_reaper *r = &u->reapers[vector];
	/* XXX: Currently fixed size of queue is supported */
	const int qsize = 256;

	if (atomic_inc_fetch(&r->refcnt) > 1)
		return 0;

	if (vfio_set_irq(&u->ctrl.pci.dev, &u->efds[vector], vector, 1)) {
		unvmed_log_err("failed to set IRQ for vector %d", vector);
		return -1;
	}

	r->u = u;
	r->vector = vector;
	r->rcq.cqe = malloc(sizeof(struct nvme_cqe) * qsize);
	r->rcq.qsize = qsize;

	pthread_create(&r->th, NULL, unvmed_rcq_run, (void *)r);
	return 0;
}

static int unvmed_init_irqs(struct unvme *u)
{
	int nr_irqs = u->ctrl.pci.dev.irq_info.count;
	int vector;

	u->efds = malloc(sizeof(int) * nr_irqs);
	if (!u->efds)
		return -1;

	u->nr_efds = nr_irqs;
	u->reapers = calloc(u->nr_efds, sizeof(struct unvme_cq_reaper));

	for (vector = 0; vector < nr_irqs; vector++) {
		struct unvme_cq_reaper *r = &u->reapers[vector];
		struct epoll_event e;

		u->efds[vector] = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
		r->epoll_fd = epoll_create1(0);
		r->efd = u->efds[vector];

		e.events = EPOLLIN;
		e.data.fd = r->efd;
		epoll_ctl(r->epoll_fd, EPOLL_CTL_ADD, r->efd, &e);
	}

	return 0;
}

static int unvmed_free_irqs(struct unvme *u)
{
	int vector;

	if (vfio_disable_irq_all(&u->ctrl.pci.dev))
		return -1;

	for (vector = 0; vector < u->nr_efds; vector++)
		unvmed_free_irq(u, vector);

	free(u->reapers);
	u->reapers = NULL;

	free(u->efds);
	u->efds = NULL;
	u->nr_efds = 0;
	return 0;
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

	if (unvmed_init_irqs(u)) {
		unvmed_log_err("failed to initialize IRQs");

		nvme_close(&u->ctrl);
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
	pthread_rwlock_init(&u->ns_list_lock, NULL);
	list_add(&unvme_list, &u->list);
	list_head_init(&u->ctx_list);

	return u;
}

static void __unvmed_free_ns(struct __unvme_ns *ns)
{
	list_del(&ns->list);
	free(ns);
}

static void unvmed_free_ns(struct unvme_ns *ns)
{
	struct unvme *u = ns->u;

	pthread_rwlock_wrlock(&u->ns_list_lock);
	__unvmed_free_ns((struct __unvme_ns *)ns);
	pthread_rwlock_unlock(&u->ns_list_lock);
}

int unvmed_init_ns(struct unvme *u, uint32_t nsid, void *identify)
{
	struct nvme_id_ns *id_ns_local = NULL;
	struct nvme_id_ns *id_ns = identify;
	struct __unvme_ns *ns;
	struct unvme_ns *prev;
	unsigned long flags = 0;
	uint8_t format_idx;
	ssize_t size;
	int ret;

	if (!id_ns) {
		struct unvme_cmd *cmd;
		struct iovec iov;

		size = pgmap((void **)&id_ns_local, NVME_IDENTIFY_DATA_SIZE);
		assert(size == NVME_IDENTIFY_DATA_SIZE);

		cmd = unvmed_alloc_cmd(u, 0, id_ns_local, size);
		if (!cmd) {
			pgunmap(id_ns_local, size);

			unvmed_log_err("failed to allocate a command instance");
			ret = errno;
			return -1;
		}

		iov.iov_base = id_ns_local;
		iov.iov_len = NVME_IDENTIFY_DATA_SIZE;

		ret = unvmed_id_ns(u, cmd, nsid, &iov, 1, flags);
		if (ret)
			return ret;

		id_ns = id_ns_local;
	}

	ns = zmalloc(sizeof(struct __unvme_ns));
	if (!ns) {
		if (id_ns_local)
			pgunmap(id_ns_local, size);
		return -1;
	}

	prev = unvmed_get_ns(u, nsid);
	if (prev)
		unvmed_free_ns(prev);

	if (id_ns->nlbaf < 16)
		format_idx = id_ns->flbas & 0xf;
	else
		format_idx = ((id_ns->flbas & 0xf) +
		       (((id_ns->flbas >> 5) & 0x3) << 4));

	ns->u = u;
	ns->nsid = nsid;
	ns->lba_size = 1 << id_ns->lbaf[format_idx].ds;
	ns->nr_lbas = le64_to_cpu((uint64_t)id_ns->nsze);

	list_add_tail(&u->ns_list, &ns->list);
	u->nr_ns++;

	if (id_ns_local)
		pgunmap(id_ns_local, size);
	return 0;
}

static struct unvme_sq *unvmed_init_usq(struct unvme *u, uint32_t qid,
					uint32_t qsize, struct unvme_cq *ucq)
{
	struct __unvme_sq *usq;

	usq = calloc(1, sizeof(*usq));
	if (!usq)
		return NULL;

	pthread_spin_init(&usq->lock, 0);
	usq->q = &u->ctrl.sq[qid];
	usq->ucq = ucq;
	usq->cmds = calloc(qsize, sizeof(struct unvme_cmd));
	usq->enabled = true;

	pthread_rwlock_wrlock(&u->sq_list_lock);
	list_add_tail(&u->sq_list, &usq->list);
	pthread_rwlock_unlock(&u->sq_list_lock);

	return __to_sq(usq);
}

static void __unvmed_free_usq(struct __unvme_sq *usq)
{
	list_del(&usq->list);

	free(usq->cmds);
	free(usq);
}

static void unvmed_free_usq(struct unvme *u, struct unvme_sq *usq)
{
	pthread_rwlock_wrlock(&u->sq_list_lock);
	__unvmed_free_usq((struct __unvme_sq *)usq);
	pthread_rwlock_unlock(&u->sq_list_lock);
}

static struct unvme_cq *unvmed_init_ucq(struct unvme *u, uint32_t qid)
{
	struct __unvme_cq *ucq;

	ucq = calloc(1, sizeof(*ucq));
	if (!ucq)
		return NULL;

	pthread_spin_init(&ucq->lock, 0);
	ucq->u = u;
	ucq->q = &u->ctrl.cq[qid];
	ucq->enabled = true;

	pthread_rwlock_wrlock(&u->cq_list_lock);
	list_add_tail(&u->cq_list, &ucq->list);
	pthread_rwlock_unlock(&u->cq_list_lock);

	return __to_cq(ucq);
}

static void __unvmed_free_ucq(struct __unvme_cq *ucq)
{
	list_del(&ucq->list);
	free(ucq);
}

static void unvmed_free_ucq(struct unvme *u, struct unvme_cq *ucq)
{
	pthread_rwlock_wrlock(&u->cq_list_lock);
	__unvmed_free_ucq((struct __unvme_cq *)ucq);
	pthread_rwlock_unlock(&u->cq_list_lock);
}

static void unvmed_free_ns_all(struct unvme *u)
{
	struct __unvme_ns *ns, *next_ns;

	list_for_each_safe(&u->ns_list, ns, next_ns, list)
		__unvmed_free_ns(ns);
}

/*
 * Free NVMe controller instance from libvfn and the libunvmed.
 */
void unvmed_free_ctrl(struct unvme *u)
{
	struct __unvme_sq *usq, *next_usq;
	struct __unvme_cq *ucq, *next_ucq;

	/*
	 * Make sure rcq thread to read the proper state value.
	 */
	STORE(u->state, UNVME_TEARDOWN);

	unvmed_free_irqs(u);

	nvme_close(&u->ctrl);

	pthread_rwlock_wrlock(&u->sq_list_lock);
	list_for_each_safe(&u->sq_list, usq, next_usq, list)
		__unvmed_free_usq(usq);
	pthread_rwlock_unlock(&u->sq_list_lock);

	pthread_rwlock_wrlock(&u->cq_list_lock);
	list_for_each_safe(&u->cq_list, ucq, next_ucq, list)
		__unvmed_free_ucq(ucq);
	pthread_rwlock_unlock(&u->cq_list_lock);

	unvmed_free_ns_all(u);

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

	memset(cmd, 0, sizeof(*cmd));
}

void unvmed_cmd_free(struct unvme_cmd *cmd)
{
	if (cmd->buf.flags & UNVME_CMD_BUF_F_IOVA_UNMAP)
		unvmed_unmap_vaddr(cmd->u, cmd->buf.va);

	if (cmd->buf.flags & UNVME_CMD_BUF_F_VA_UNMAP)
		pgunmap(cmd->buf.va, cmd->buf.len);

	__unvmed_cmd_free(cmd);
}

static struct unvme_cmd* __unvmed_cmd_alloc(struct unvme *u, uint16_t sqid)
{
	struct unvme_cmd *cmd;
	struct unvme_sq *usq;
	struct nvme_rq *rq;

	usq = unvmed_get_sq(u, sqid);
	if (!usq) {
		unvmed_log_err("failed to find sq %d", sqid);
		errno = EINVAL;
		return NULL;
	}

	rq = nvme_rq_acquire(usq->q);
	if (!rq) {
		unvmed_log_err("failed to acquire nvme request instance");
		return NULL;
	}

	cmd = &usq->cmds[rq->cid];
	cmd->u = u;
	cmd->rq = rq;

	rq->opaque = cmd;

	return cmd;
}

struct unvme_cmd *unvmed_alloc_cmd(struct unvme *u, uint16_t sqid, void *buf,
				   size_t len)
{
	struct unvme_cmd *cmd;

	void *__buf = NULL;
	ssize_t __len;

	cmd = __unvmed_cmd_alloc(u, sqid);
	if (!cmd)
		return NULL;

	/*
	 * If caller gives NULL buf and non-zero len, it will allocate a user
	 * data buffer and keep the pointer and the size allocated in
	 * cmd->buf.va and cmd->buf.len.  They will be freed up in
	 * unvmed_cmd_free().  But, if caller gives non-NULL buf and non-zero
	 * len, caller *must* free up the user data buffer before or after
	 * unvmed_cmd_free().
	 */
	if (!buf && len) {
		__len = pgmap(&__buf, len);
		if (!__buf) {
			unvmed_log_err("failed to mmap() for data buffer");
			return NULL;
		}

		buf = __buf;
		len = __len;  /* Update length with a newly aligned size */

		cmd->buf.flags |= UNVME_CMD_BUF_F_VA_UNMAP;
	}

	if (buf && len) {
		uint64_t iova;

		if (unvmed_to_iova(u, buf, &iova)) {
			if (unvmed_map_vaddr(u, buf, len, &iova, 0x0)) {
				unvmed_log_err("failed to map vaddr for data buffer");

				if (__buf)
					pgunmap(buf, len);
				__unvmed_cmd_free(cmd);
				return NULL;
			}
			cmd->buf.flags |= UNVME_CMD_BUF_F_IOVA_UNMAP;
		}
	}

	cmd->buf.va = buf;
	cmd->buf.len = len;
	cmd->buf.iov = (struct iovec) {.iov_base = buf, .iov_len = len};

	return cmd;
}

struct unvme_cmd *unvmed_alloc_cmd_nodata(struct unvme *u, uint16_t sqid)
{
	return __unvmed_cmd_alloc(u, sqid);
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
	u->state = UNVME_DISABLED;

	/*
	 * Free up all the namespace instances attached to the current
	 * controller.
	 */
	unvmed_free_ns_all(u);
}

static struct nvme_cqe *unvmed_get_completion(struct unvme *u,
					      struct unvme_cq *ucq);
static void __unvmed_rcq_run(struct unvme_cq *ucq, struct unvme_rcq *rcq)
{
	struct unvme *u = ucq->u;
	struct nvme_cqe *cqe;
	int ret;

	while (true) {
		cqe = unvmed_get_completion(u, ucq);
		if (!cqe)
			break;

		do {
			ret = unvmed_rcq_push(rcq, cqe);
		} while (ret == -EAGAIN);

		nvme_cq_update_head(ucq->q);
	}
}

static void *unvmed_rcq_run(void *opaque)
{
	struct unvme_cq_reaper *r = opaque;
	struct unvme *u = r->u;
	struct unvme_rcq *rcq = &r->rcq;
	int vector = r->vector;

	unvmed_log_info("%s: reaped CQ thread started (vector=%d, tid=%d)",
			unvmed_bdf(u), vector, gettid());

	while (true) {
		struct __unvme_cq *ucq;

		if (unvmed_cq_wait_irq(u, vector))
			goto out;

		if (!atomic_load_acquire(&r->refcnt))
			goto out;

		if (LOAD(u->state) == UNVME_TEARDOWN)
			goto out;

		pthread_rwlock_rdlock(&u->cq_list_lock);
		list_for_each(&u->cq_list, ucq, list) {
			if (unvmed_cq_iv(__to_cq(ucq)) == r->vector)
				__unvmed_rcq_run(__to_cq(ucq), rcq);
		}
		pthread_rwlock_unlock(&u->cq_list_lock);
	}

out:
	unvmed_log_info("%s: reaped CQ thread terminated (vector=%d, tid=%d)",
			unvmed_bdf(u), vector, gettid());

	pthread_exit(NULL);
}

int unvmed_create_adminq(struct unvme *u)
{
	struct unvme_sq *usq;
	struct unvme_cq *ucq;
	const uint16_t qid = 0;
	const uint16_t iv = 0;

	if (unvmed_get_sq(u, 0) || unvmed_get_cq(u, 0)) {
		errno = EEXIST;
		goto out;
	}

	/*
	 * XXX: Non-intr mode currently not supported
	 */
	if (unvmed_init_irq(u, iv))
		goto out;

	if (nvme_configure_adminq(&u->ctrl, qid))
		goto free_irq;

	ucq = unvmed_init_ucq(u, qid);
	if (!ucq)
		goto free_sqcq;

	/*
	 * XXX: libvfn has fixed size of admin queue and it's not exported to
	 * application layer yet.  Once it gets exported as a public, this
	 * hard-coded value should be fixed ASAP.
	 */
#define NVME_AQ_QSIZE	32
	usq = unvmed_init_usq(u, 0, NVME_AQ_QSIZE, ucq);
	if (!usq)
		goto free_ucq;

	return 0;

free_ucq:
	unvmed_free_ucq(u, ucq);
free_sqcq:
	nvme_discard_sq(&u->ctrl, &u->ctrl.sq[qid]);
	nvme_discard_cq(&u->ctrl, &u->ctrl.cq[qid]);
free_irq:
	unvmed_free_irq(u, iv);
out:
	return -1;
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

	u->state = UNVME_ENABLED;
	return 0;
}

int unvmed_create_cq(struct unvme *u, uint32_t qid, uint32_t qsize, int vector)
{
	struct unvme_cq *ucq;

	if (!unvme_is_enabled(u)) {
		errno = EPERM;
		return -1;
	}

	if (vector >= 0 && unvmed_init_irq(u, vector))
		return -1;

	if (nvme_create_iocq(&u->ctrl, qid, qsize, vector))
		return -1;

	ucq = unvmed_init_ucq(u, qid);
	if (!ucq) {
		unvmed_log_err("failed to initialize ucq instance. "
				"discard cq instance from libvfn (qid=%d)",
				qid);
		nvme_discard_cq(&u->ctrl, &u->ctrl.cq[qid]);
		return -1;
	}

	return 0;
}

static void __unvmed_delete_cq(struct unvme *u, struct unvme_cq *ucq)
{
	unvmed_free_irq(u, unvmed_cq_iv(ucq));
	nvme_discard_cq(&u->ctrl, ucq->q);
	unvmed_free_ucq(u, ucq);
}

int unvmed_delete_cq(struct unvme *u, uint32_t qid)
{
	struct unvme_cmd *cmd;
	struct unvme_cq *ucq;
	struct nvme_cmd_delete_q sqe = {0, };
	struct nvme_cqe cqe;

	ucq = unvmed_get_cq(u, qid);
	if (!ucq) {
		errno = EINVAL;
		return -1;
	}

	cmd = unvmed_alloc_cmd_nodata(u, 0);
	if (!cmd)
		return -1;

	sqe.opcode = nvme_admin_delete_cq;
	sqe.qid = cpu_to_le16(qid);

	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);
	unvmed_cmd_cmpl(cmd, &cqe);

	if (nvme_cqe_ok(&cqe))
		__unvmed_delete_cq(u, ucq);

	unvmed_cmd_free(cmd);
	return unvmed_cqe_status(&cqe);
}

int unvmed_create_sq(struct unvme *u, uint32_t qid, uint32_t qsize,
		    uint32_t cqid)
{
	struct unvme_sq *usq;
	struct unvme_cq *ucq;

	if (!unvme_is_enabled(u)) {
		errno = EPERM;
		return -1;
	}

	ucq = unvmed_get_cq(u, cqid);
	if (!ucq) {
		errno = ENODEV;
		return -1;
	}

	if (nvme_create_iosq(&u->ctrl, qid, qsize, ucq->q, 0))
		return -1;

	usq = unvmed_init_usq(u, qid, qsize, ucq);
	if (!usq) {
		unvmed_log_err("failed to initialize usq instance. "
				"discard sq instance from libvfn (qid=%d)",
				qid);
		nvme_discard_sq(&u->ctrl, &u->ctrl.sq[qid]);
		return -1;
	}

	return 0;
}

static void __unvmed_delete_sq(struct unvme *u, struct unvme_sq *usq)
{
	nvme_discard_sq(&u->ctrl, usq->q);
	unvmed_free_usq(u, usq);
}

int unvmed_delete_sq(struct unvme *u, uint32_t qid)
{
	struct unvme_cmd *cmd;
	struct unvme_sq *usq;
	struct nvme_cmd_delete_q sqe = {0, };
	struct nvme_cqe cqe;

	usq = unvmed_get_sq(u, qid);
	if (!usq) {
		errno = EINVAL;
		return -1;
	}

	cmd = unvmed_alloc_cmd_nodata(u, 0);
	if (!cmd)
		return -1;

	sqe.opcode = nvme_admin_delete_sq;
	sqe.qid = cpu_to_le16(qid);

	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);
	unvmed_cmd_cmpl(cmd, &cqe);

	if (nvme_cqe_ok(&cqe))
		__unvmed_delete_sq(u, usq);

	unvmed_cmd_free(cmd);
	return unvmed_cqe_status(&cqe);
}

int unvmed_to_iova(struct unvme *u, void *buf, uint64_t *iova)
{
	struct iommu_ctx *ctx = __iommu_ctx(&u->ctrl);

	return !iommu_translate_vaddr(ctx, buf, iova);
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

void unvmed_cmd_post(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		     unsigned long flags)
{
	nvme_rq_post(cmd->rq, (union nvme_cmd *)sqe);

	cmd->state = UNVME_CMD_S_SUBMITTED;
#ifdef UNVME_DEBUG
	unvmed_log_cmd_post(unvmed_bdf(cmd->u), cmd->rq->sq->id, sqe);
#endif

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

		cmd->state = UNVME_CMD_S_COMPLETED;
	}
	unvmed_cq_exit(ucq);

	return cqe;
}

void unvmed_cmd_cmpl(struct unvme_cmd *cmd, struct nvme_cqe *cqe)
{
	nvme_rq_spin(cmd->rq, cqe);

	cmd->state = UNVME_CMD_S_COMPLETED;
#ifdef UNVME_DEBUG
	unvmed_log_cmd_cmpl(unvmed_bdf(cmd->u), cqe);
#endif
}

int __unvmed_cq_run_n(struct unvme *u, struct unvme_cq *ucq,
		      struct nvme_cqe *cqes, int nr_cqes, bool nowait)
{
	struct unvme_rcq *rcq = unvmed_rcq_from_ucq(ucq);
	struct nvme_cqe __cqe;
	struct nvme_cqe *cqe = &__cqe;
	int nr_cmds;
	int nr = 0;
	int ret;

	while (nr < nr_cqes) {
		if (unvmed_cq_irq_enabled(ucq)) {
			do {
				ret = unvmed_rcq_pop(rcq, &__cqe);
			} while (ret == -ENOENT && !nowait);

			if (ret)
				break;
		} else  {
			cqe = unvmed_get_completion(u, ucq);
			if (!cqe) {
				if (nowait)
					break;
				continue;
			}
		}

		memcpy(&cqes[nr++], cqe, sizeof(*cqe));
#ifdef UNVME_DEBUG
		unvmed_log_cmd_cmpl(unvmed_bdf(u), cqe);
#endif
	}

	do {
		nr_cmds = u->nr_cmds;
	} while (!atomic_cmpxchg(&u->nr_cmds, nr_cmds, nr_cmds - nr));

	return nr;
}

int unvmed_cq_run(struct unvme *u, struct unvme_cq *ucq, struct nvme_cqe *cqes)
{
	return __unvmed_cq_run_n(u, ucq, cqes, ucq->q->qsize - 1, true);
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
		if (!unvmed_cq_irq_enabled(ucq))
			nvme_cq_update_head(ucq->q);
		return ret;
	}

	n = __unvmed_cq_run_n(u, ucq, cqes + n, max - n, true);
	if (n < 0)
		return -1;
	else if (n > 0) {
		if (!unvmed_cq_irq_enabled(ucq))
			nvme_cq_update_head(ucq->q);
	}

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

int unvmed_sq_update_tail(struct unvme *u, struct unvme_sq *usq)
{
	int nr_sqes;
	int nr_cmds;

	nr_sqes = unvmed_nr_pending_sqes(usq);
	if (!nr_sqes)
		return 0;

	do {
		nr_cmds = u->nr_cmds;
	} while (!atomic_cmpxchg(&u->nr_cmds, nr_cmds, nr_cmds + nr_sqes));

	nvme_sq_update_tail(usq->q);
	return nr_sqes;
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

	if (ret != nr_sqes)
		return -1;

	return nr_sqes;
}

int __unvmed_mapv_prp(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		      struct iovec *iov, int nr_iov)
{
	if (nvme_rq_mapv_prp(&cmd->u->ctrl, cmd->rq, sqe, iov, nr_iov))
		return -1;
	return 0;
}

int unvmed_mapv_prp(struct unvme_cmd *cmd, union nvme_cmd *sqe)
{
	return __unvmed_mapv_prp(cmd, sqe, &cmd->buf.iov, 1);
}

int unvmed_id_ns(struct unvme *u, struct unvme_cmd *cmd, uint32_t nsid,
		 struct iovec *iov, int nr_iov, unsigned long flags)
{
	struct nvme_cmd_identify sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_admin_identify;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.cns = cpu_to_le32(0x0);

	if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, 1)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}

	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, flags);

	if (flags & UNVMED_CMD_F_NODB)
		return 0;

	unvmed_cmd_cmpl(cmd, &cqe);
	return unvmed_cqe_status(&cqe);
}

int unvmed_id_active_nslist(struct unvme *u, struct unvme_cmd *cmd,
			    uint32_t nsid, struct iovec *iov, int nr_iov)
{
	struct nvme_cmd_identify sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_admin_identify;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.cns = cpu_to_le32(0x2);

	if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, 1)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}

	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);

	unvmed_cmd_cmpl(cmd, &cqe);
	return unvmed_cqe_status(&cqe);
}

int unvmed_read(struct unvme *u, struct unvme_cmd *cmd, uint32_t nsid,
		uint64_t slba, uint16_t nlb, struct iovec *iov, int nr_iov,
		unsigned long flags, void *opaque)
{
	struct nvme_cmd_rw sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_cmd_read;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.slba = cpu_to_le64(slba);
	sqe.nlb = cpu_to_le16(nlb);

	if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}

	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, flags);

	if (flags & UNVMED_CMD_F_NODB) {
		cmd->opaque = opaque;
		return 0;
	}

	unvmed_cmd_cmpl(cmd, &cqe);
	return unvmed_cqe_status(&cqe);
}

int unvmed_write(struct unvme *u, struct unvme_cmd *cmd, uint32_t nsid,
		 uint64_t slba, uint16_t nlb, struct iovec *iov, int nr_iov,
		 unsigned long flags, void *opaque)
{
	struct nvme_cmd_rw sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_cmd_write;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.slba = cpu_to_le64(slba);
	sqe.nlb = cpu_to_le16(nlb);

	if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}

	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, flags);

	if (flags & UNVMED_CMD_F_NODB) {
		cmd->opaque = opaque;
		return 0;
	}

	unvmed_cmd_cmpl(cmd, &cqe);
	return unvmed_cqe_status(&cqe);
}

int unvmed_passthru(struct unvme *u, struct unvme_cmd *cmd, union nvme_cmd *sqe,
		    bool read, struct iovec *iov, int nr_iov, unsigned long flags)
{
	struct nvme_cqe cqe;

	if (!sqe->dptr.prp1 && !sqe->dptr.prp2) {
		if (__unvmed_mapv_prp(cmd, sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
		}
	}

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, flags);

	if (flags & UNVMED_CMD_F_NODB)
		return 0;

	unvmed_cmd_cmpl(cmd, &cqe);
	return unvmed_cqe_status(&cqe);
}

int unvmed_ctx_init(struct unvme *u)
{
	struct __unvme_sq *usq;
	struct __unvme_cq *ucq;
	struct __unvme_ns *ns;
	struct unvme_ctx *ctx;
	uint32_t cc;

	if (!list_empty(&u->ctx_list)) {
		unvmed_log_err("driver context has already been initialized");
		errno = EEXIST;
		return -1;
	}

	/*
	 * XXX: Driver context for the controller should be managed in a single
	 * rwlock instance for simplicity.
	 */
	ctx = malloc(sizeof(struct unvme_ctx));
	ctx->type = UNVME_CTX_T_CTRL;

	cc = unvmed_read32(u, NVME_REG_CC);
	ctx->ctrl.iosqes = NVME_CC_IOSQES(cc);
	ctx->ctrl.iocqes = NVME_CC_IOCQES(cc);
	ctx->ctrl.mps = NVME_CC_MPS(cc);
	ctx->ctrl.css = NVME_CC_CSS(cc);

	list_add_tail(&u->ctx_list, &ctx->list);

	list_for_each(&u->ns_list, ns, list) {
		ctx = malloc(sizeof(struct unvme_ctx));

		ctx->type = UNVME_CTX_T_NS;
		ctx->ns.nsid = ns->nsid;

		list_add_tail(&u->ctx_list, &ctx->list);
	}

	pthread_rwlock_rdlock(&u->cq_list_lock);
	list_for_each(&u->cq_list, ucq, list) {
		if (!unvmed_cq_id(ucq))
			continue;

		ctx = malloc(sizeof(struct unvme_ctx));

		ctx->type = UNVME_CTX_T_CQ;
		ctx->cq.qid = unvmed_cq_id(__to_cq(ucq));
		ctx->cq.qsize = unvmed_cq_size(__to_cq(ucq));
		ctx->cq.vector = unvmed_cq_iv(__to_cq(ucq));

		list_add_tail(&u->ctx_list, &ctx->list);
	}
	pthread_rwlock_unlock(&u->cq_list_lock);

	pthread_rwlock_rdlock(&u->sq_list_lock);
	list_for_each(&u->sq_list, usq, list) {
		if (!unvmed_sq_id(usq))
			continue;

		ctx = malloc(sizeof(struct unvme_ctx));

		ctx->type = UNVME_CTX_T_SQ;
		ctx->sq.qid = unvmed_sq_id(__to_sq(usq));
		ctx->sq.qsize = unvmed_sq_size(__to_sq(usq));
		ctx->sq.cqid = unvmed_sq_cqid(__to_sq(usq));

		list_add_tail(&u->ctx_list, &ctx->list);
	}
	pthread_rwlock_unlock(&u->sq_list_lock);

	return 0;
}

static int __unvmed_ctx_restore(struct unvme *u, struct unvme_ctx *ctx)
{
	switch (ctx->type) {
		case UNVME_CTX_T_CTRL:
			if (unvmed_create_adminq(u))
				return -1;
			return unvmed_enable_ctrl(u, ctx->ctrl.iosqes,
					ctx->ctrl.iocqes, ctx->ctrl.mps,
					ctx->ctrl.css);
		case UNVME_CTX_T_NS:
			return unvmed_init_ns(u, ctx->ns.nsid, NULL);
		case UNVME_CTX_T_CQ:
			return unvmed_create_cq(u, ctx->cq.qid, ctx->cq.qsize,
					ctx->cq.vector);
		case UNVME_CTX_T_SQ:
			return unvmed_create_sq(u, ctx->sq.qid, ctx->sq.qsize,
					ctx->sq.cqid);
		default:
			return -1;
	}
}

void unvmed_ctx_free(struct unvme *u)
{
	struct unvme_ctx *ctx, *next_ctx;

	list_for_each_safe(&u->ctx_list, ctx, next_ctx, list) {
		list_del(&ctx->list);
		free(ctx);
	}
}

int unvmed_ctx_restore(struct unvme *u)
{
	struct unvme_ctx *ctx;

	list_for_each(&u->ctx_list, ctx, list) {
		if (__unvmed_ctx_restore(u, ctx)) {
			unvmed_ctx_free(u);
			return -1;
		}
	}

	unvmed_ctx_free(u);
	return 0;
}
