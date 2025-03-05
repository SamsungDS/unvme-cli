// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#define _GNU_SOURCE

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <vfn/nvme.h>
#include <vfn/support/atomic.h>

#include <nvme/types.h>
#include <nvme/util.h>

#include <ccan/list/list.h>

#include "libunvmed.h"
#include "libunvmed-private.h"

int __unvmed_logfd = 0;

static inline bool unvme_is_enabled(struct unvme *u)
{
	return u->state == UNVME_ENABLED;
}

static void *unvmed_rcq_run(void *opaque);
static void __unvmed_free_ns(struct __unvme_ns *ns);
static void __unvmed_free_usq(struct __unvme_sq *usq);
static void __unvmed_free_ucq(struct __unvme_cq *ucq);
static void __unvmed_delete_sq_all(struct unvme *u);
static void __unvmed_delete_cq_all(struct unvme *u);

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

int unvmed_parse_bdf(const char *input, char *bdf)
{
	unsigned int domain = 0, bus = 0, dev = 0, func = 0;
	int nr_dot = strcount(input, ".");
	int nr_col = strcount(input, ":");

	switch (nr_dot) {
	case 0:
		switch (nr_col) {
		case 1:
			if (sscanf(input, "%x:%x", &bus, &dev) != 2)
				return -1;
			break;
		case 2:
			if (sscanf(input, "%x:%x:%x",
					&domain, &bus, &dev) != 3)
				return -1;
			break;
		default:
			errno = EINVAL;
			return -1;
		}
		break;
	case 1:
		switch (nr_col) {
		case 0:
			if (sscanf(input, "%x.%d", &dev, &func) != 2)
				return -1;
			break;
		case 1:
			if (sscanf(input, "%x:%x.%d", &bus, &dev, &func) != 3)
				return -1;
			break;
		case 2:
			if (sscanf(input, "%x:%x:%x.%d",
					&domain, &bus, &dev, &func) != 4)
				return -1;
			break;
		default:
			errno = EINVAL;
			return -1;
		}
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	sprintf(bdf, "%04x:%02x:%02x.%1d", domain, bus, dev, func);
	return 0;
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

	pthread_rwlock_rdlock(&u->ns_list_lock);
	list_for_each(&u->ns_list, ns, list) {
		assert(nr_ns < u->nr_ns);
		memcpy(&((*nslist)[nr_ns++]), ns, sizeof(struct unvme_ns));
	}
	pthread_rwlock_unlock(&u->ns_list_lock);

	return nr_ns;
}

static struct __unvme_ns *__unvmed_find_and_get_ns(struct unvme *u,
						   uint32_t nsid, bool get)
{
	struct __unvme_ns *ns;

	pthread_rwlock_rdlock(&u->ns_list_lock);
	list_for_each(&u->ns_list, ns, list) {
		if (ns->nsid == nsid) {
			if (get)
				atomic_inc(&ns->refcnt);
			pthread_rwlock_unlock(&u->ns_list_lock);
			return ns;
		}
	}
	pthread_rwlock_unlock(&u->ns_list_lock);

	return NULL;
}

struct unvme_ns *unvmed_ns_find(struct unvme *u, uint32_t nsid)
{
	return (struct unvme_ns *)__unvmed_find_and_get_ns(u, nsid, false);
}

struct unvme_ns *unvmed_ns_get(struct unvme *u, uint32_t nsid)
{
	return (struct unvme_ns *)__unvmed_find_and_get_ns(u, nsid, true);
}

int __unvmed_ns_put(struct unvme *u, struct unvme_ns *ns)
{
	int refcnt;

	refcnt = atomic_dec_fetch(&ns->refcnt);
	if (!refcnt)
		__unvmed_free_ns((struct __unvme_ns *)ns);

	return refcnt;
}

int unvmed_ns_put(struct unvme *u, struct unvme_ns *ns)
{
	int refcnt;

	pthread_rwlock_wrlock(&u->ns_list_lock);
	refcnt = __unvmed_ns_put(u, ns);
	pthread_rwlock_unlock(&u->ns_list_lock);

	return refcnt;
}

int unvmed_get_sqs(struct unvme *u, struct nvme_sq **sqs)
{
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
		struct unvme_sq *usq;
		usq = unvmed_sq_find(u, qid);
		if (!usq || (usq && !usq->enabled))
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
		ucq = unvmed_cq_find(u, qid);
		if (!ucq | (ucq && !ucq->enabled))
			continue;

		memcpy(&((*cqs)[nr_cqs++]), ucq->q, sizeof(*(ucq->q)));
	}

	return nr_cqs;
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

static struct __unvme_sq *__unvmed_find_and_get_sq(struct unvme *u,
						   uint32_t qid, bool get)
{
	struct __unvme_sq *curr, *usq = NULL;

	pthread_rwlock_rdlock(&u->sq_list_lock);
	list_for_each(&u->sq_list, curr, list) {
		assert(curr->q != NULL);
		if (curr->q->vaddr && unvmed_sq_id(curr) == qid) {
			usq = curr;
			if (get)
				atomic_inc(&usq->refcnt);
			break;
		}
	}
	pthread_rwlock_unlock(&u->sq_list_lock);

	return usq;
}

static struct __unvme_cq *__unvmed_find_and_get_cq(struct unvme *u,
						   uint32_t qid, bool get)
{
	struct __unvme_cq *curr, *ucq = NULL;

	pthread_rwlock_rdlock(&u->cq_list_lock);
	list_for_each(&u->cq_list, curr, list) {
		assert(curr->q != NULL);
		if (unvmed_cq_id(curr) == qid) {
			ucq = curr;
			if (get)
				atomic_inc(&ucq->refcnt);
			break;
		}
	}
	pthread_rwlock_unlock(&u->cq_list_lock);

	return ucq;
}

struct unvme_sq *unvmed_sq_find(struct unvme *u, uint32_t qid)
{
	return __to_sq(__unvmed_find_and_get_sq(u, qid, false));
}

struct unvme_cq *unvmed_cq_find(struct unvme *u, uint32_t qid)
{
	return __to_cq(__unvmed_find_and_get_cq(u, qid, false));
}

struct unvme_sq *unvmed_sq_get(struct unvme *u, uint32_t qid)
{
	return __to_sq(__unvmed_find_and_get_sq(u, qid, true));
}

struct unvme_cq *unvmed_cq_get(struct unvme *u, uint32_t qid)
{
	return __to_cq(__unvmed_find_and_get_cq(u, qid, true));
}

int __unvmed_sq_put(struct unvme *u, struct unvme_sq *usq)
{
	int refcnt;

	/*
	 * We don't have to access refcnt in atomic since no one can access
	 * refcnt under wrlock is acquired.
	 */
	refcnt = atomic_dec_fetch(&usq->refcnt);
	if (!refcnt)
		__unvmed_free_usq((struct __unvme_sq *)usq);

	return refcnt;
}

int __unvmed_cq_put(struct unvme *u, struct unvme_cq *ucq)
{
	int refcnt;

	/*
	 * We don't have to access refcnt in atomic since no one can access
	 * refcnt under wrlock is acquired.
	 */
	refcnt = atomic_dec_fetch(&ucq->refcnt);
	if (!refcnt)
		__unvmed_free_ucq((struct __unvme_cq *)ucq);

	return refcnt;
}

int unvmed_sq_put(struct unvme *u, struct unvme_sq *usq)
{
	int refcnt;

	pthread_rwlock_wrlock(&u->sq_list_lock);
	refcnt = __unvmed_sq_put(u, usq);
	pthread_rwlock_unlock(&u->sq_list_lock);

	return refcnt;
}

int unvmed_cq_put(struct unvme *u, struct unvme_cq *ucq)
{
	int refcnt;

	pthread_rwlock_wrlock(&u->cq_list_lock);
	refcnt = __unvmed_cq_put(u, ucq);
	pthread_rwlock_unlock(&u->cq_list_lock);

	return refcnt;
}

int unvmed_init_id_ctrl(struct unvme *u, void *id_ctrl)
{
	if (!id_ctrl) {
		unvmed_log_err("'id_ctrl' is given NULL");
		errno = EINVAL;
		return -1;
	}

	/*
	 * If the current controller has been identified before, update the
	 * previous @id_ctrl buffer to the newly given one.
	 */
	if (!u->id_ctrl) {
		u->id_ctrl = malloc(sizeof(*u->id_ctrl));
		if (!u->id_ctrl) {
			unvmed_log_err("failed to malloc()");
			return -1;
		}
	}

	memcpy(u->id_ctrl, id_ctrl, sizeof(*u->id_ctrl));
	return 0;
}

static void unvmed_init_irq_rcq(struct unvme *u, int vector)
{
	struct unvme_cq_reaper *r = &u->reapers[vector];
	struct epoll_event e;
	/* XXX: Currently fixed size of queue is supported */
	const int qsize = 256;

	r->u = u;
	r->vector = vector;
	r->rcq.cqe = malloc(sizeof(struct nvme_cqe) * qsize);
	r->rcq.qsize = qsize;
	r->efd = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
	r->epoll_fd = epoll_create1(0);

	e = (struct epoll_event) {
		.events = EPOLLIN,
		.data.fd = r->efd,
	};
	epoll_ctl(r->epoll_fd, EPOLL_CTL_ADD, r->efd, &e);

	u->efds[r->vector] = r->efd;
}

static void unvmed_free_irq_rcq(struct unvme_cq_reaper *r)
{
	struct epoll_event e = {
		.events = EPOLLIN,
		.data.fd = r->efd,
	};

	epoll_ctl(r->epoll_fd, EPOLL_CTL_DEL, r->efd, &e);

	r->u->efds[r->vector] = -1;
	close(r->efd);
	close(r->epoll_fd);
	free(r->rcq.cqe);
	memset(r, 0, sizeof(*r));
}

static int unvmed_free_irq(struct unvme *u, int vector)
{
	struct unvme_cq_reaper *r = &u->reapers[vector];
	int ret;

	if (!atomic_load_acquire(&r->refcnt))
		return 0;

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

	unvmed_free_irq_rcq(r);
	return 0;
}

static int unvmed_init_irq(struct unvme *u, int vector)
{
	struct unvme_cq_reaper *r = &u->reapers[vector];
	int nr_irqs = u->ctrl.pci.dev.irq_info.count;

	if (vector >= nr_irqs) {
		unvmed_log_err("invalid vector %d", vector);
		return -1;
	}

	if (atomic_inc_fetch(&r->refcnt) > 1)
		return 0;

	unvmed_init_irq_rcq(u, vector);

	/*
	 * Note: disable all IRQ enabled first before enabling a specific
	 * interrupt vector to support older kernel (< v6.5) which does not
	 * support dynamic MSI-X interrupt assignment.
	 */
	if (vfio_disable_irq_all(&u->ctrl.pci.dev))
		return -1;

	if (vfio_set_irq(&u->ctrl.pci.dev, &u->efds[0], 0, nr_irqs)) {
		unvmed_log_err("failed to set IRQ for vector %d", vector);

		unvmed_free_irq_rcq(r);
		return -1;
	}

	pthread_create(&r->th, NULL, unvmed_rcq_run, (void *)r);
	return 0;
}

static int unvmed_alloc_irqs(struct unvme *u)
{
	int nr_irqs = u->ctrl.pci.dev.irq_info.count;

	u->efds = malloc(sizeof(int) * nr_irqs);
	if (!u->efds)
		return -1;

	/*
	 * Kenrel vfio-pci documentation says that VFIO_DEVICE_SET_IRQS ioctl
	 * treats @efd -1 as de-assign or skipping a vector during enabling the
	 * interrupt.
	 */
	for (int i = 0; i < nr_irqs; i++)
		u->efds[i] = -1;

	u->nr_efds = nr_irqs;
	u->reapers = calloc(u->nr_efds, sizeof(struct unvme_cq_reaper));
	return 0;
}

static void unvmed_free_irq_all(struct unvme *u)
{
	int vector;

	for (vector = 0; vector < u->nr_efds; vector++)
		unvmed_free_irq(u, vector);
}

static int unvmed_free_irqs(struct unvme *u)
{
	unvmed_free_irq_all(u);

	free(u->reapers);
	u->reapers = NULL;

	free(u->efds);
	u->efds = NULL;
	u->nr_efds = 0;
	return 0;
}

int unvmed_cmb_init(struct unvme *u)
{
	/*
	 * ``nvme_discard_cmb()`` will be called when the device is detached
	 * from the unvmed service by ``unvme del <bdf>``.
	 */
	if (nvme_configure_cmb(&u->ctrl))
		return -1;

	unvmed_log_info("CMB enabled (bar=%d, vaddr=%p, iova=%#lx, size=%#lx)",
			u->ctrl.cmb.bar, u->ctrl.cmb.vaddr, u->ctrl.cmb.iova, u->ctrl.cmb.size);
	return 0;
}

void unvmed_cmb_free(struct unvme *u)
{
	nvme_discard_cmb(&u->ctrl);
}

ssize_t unvmed_cmb_get_region(struct unvme *u, void **vaddr)
{
	/*
	 * We can guarantee that CMB BAR region will never be BAR0 since it's
	 * for controller property registers.
	 */
	if (!u->ctrl.cmb.bar) {
		errno = EINVAL;
		return -1;
	}

	*vaddr = u->ctrl.cmb.vaddr;
	return (ssize_t)u->ctrl.cmb.size;
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

	if (unvmed_alloc_irqs(u)) {
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

static int __unvmed_id_ns(struct unvme *u, uint32_t nsid,
			  struct nvme_id_ns *id_ns)
{
	unsigned long flags = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq;
	struct iovec iov;
	int ret;

	if (!id_ns) {
		unvmed_log_err("'id_ns' is given NULL");
		errno = EINVAL;
		return -1;
	}

	usq = unvmed_sq_find(u, 0);
	if (!usq) {
		unvmed_log_err("failed to find enabled adminq");
		errno = EINVAL;
		return -1;
	}

	cmd = unvmed_alloc_cmd(u, usq, id_ns, sizeof(*id_ns));
	if (!cmd) {
		unvmed_log_err("failed to allocate a command instance");
		return -1;
	}

	iov.iov_base = id_ns;
	iov.iov_len = NVME_IDENTIFY_DATA_SIZE;

	ret = unvmed_id_ns(u, cmd, nsid, &iov, 1, flags);
	if (ret) {
		unvmed_log_err("failed to identify namespace");

		unvmed_cmd_free(cmd);
		return -1;
	}

	unvmed_cmd_free(cmd);
	return 0;
}

int unvmed_init_ns(struct unvme *u, uint32_t nsid, void *identify)
{
	struct nvme_id_ns *id_ns = identify;
	struct __unvme_ns *ns;
	struct unvme_ns *prev;
	uint8_t format_idx;

	if (!id_ns) {
		pgmap((void **)&id_ns, sizeof(struct nvme_id_ns));
		if (!id_ns) {
			unvmed_log_err("failed to allocate a buffer");
			return -1;
		}

		__unvmed_id_ns(u, nsid, id_ns);
	}

	prev = unvmed_ns_get(u, nsid);
	if (!prev) {
		ns = zmalloc(sizeof(struct __unvme_ns));
		if (!ns) {
			if (id_ns != identify)
				pgunmap(id_ns, sizeof(*id_ns));
			return -1;
		}
	} else {
		int refcnt;
		ns = (struct __unvme_ns *)prev;
		if (ns->enabled) {
			refcnt = unvmed_ns_put(u, prev);
			assert(refcnt > 0);
		}
	}

	if (id_ns->nlbaf < 16)
		format_idx = id_ns->flbas & 0xf;
	else
		format_idx = ((id_ns->flbas & 0xf) +
		       (((id_ns->flbas >> 5) & 0x3) << 4));

	ns->u = u;
	ns->nsid = nsid;
	ns->lba_size = 1 << id_ns->lbaf[format_idx].ds;
	ns->nr_lbas = le64_to_cpu((uint64_t)id_ns->nsze);

	ns->format_idx = format_idx;
	ns->mset = (id_ns->flbas >> 4) & 0x1;
	ns->ms = le16_to_cpu(id_ns->lbaf[format_idx].ms);
	ns->dps = id_ns->dps;

	if (!prev) {
		ns->refcnt = 1;

		pthread_rwlock_wrlock(&u->ns_list_lock);
		list_add_tail(&u->ns_list, &ns->list);
		pthread_rwlock_unlock(&u->ns_list_lock);

		u->nr_ns++;
	}

	ns->enabled = true;

	if (id_ns != identify)
		pgunmap(id_ns, sizeof(*id_ns));
	return 0;
}

static int __unvmed_nvm_id_ns(struct unvme *u, uint32_t nsid,
			      struct nvme_nvm_id_ns *nvm_id_ns)
{
	struct unvme_cmd *cmd;
	struct unvme_sq *usq;
	struct iovec iov;
	int ret;

	if (!nvm_id_ns) {
		unvmed_log_err("'nvm_id_ns' is given NULL");
		errno = EINVAL;
		return -1;
	}

	usq = unvmed_sq_find(u, 0);
	if (!usq) {
		unvmed_log_err("failed to find enabled adminq");
		errno = EINVAL;
		return -1;
	}

	cmd = unvmed_alloc_cmd(u, usq, nvm_id_ns, sizeof(*nvm_id_ns));
	if (!cmd) {
		unvmed_log_err("failed to allocate a command instance");
		return -1;
	}

	iov.iov_base = nvm_id_ns;
	iov.iov_len = NVME_IDENTIFY_DATA_SIZE;

	ret = unvmed_nvm_id_ns(u, cmd, nsid, &iov, 1);
	if (ret) {
		unvmed_log_err("failed to identify namespace");

		unvmed_cmd_free(cmd);
		return -1;
	}

	unvmed_cmd_free(cmd);
	return 0;
}

/*
 * Issue an Identify Controller admin command to the given @u and keep the data
 * structure inside of @u->id_ctrl.
 */
static int __unvmed_id_ctrl(struct unvme *u, struct nvme_id_ctrl *id_ctrl)
{
	struct unvme_cmd *cmd;
	struct unvme_sq *usq;
	struct iovec iov;
	int ret;

	if (!id_ctrl) {
		unvmed_log_err("'id_ctrl' is given NULL");
		errno = EINVAL;
		return -1;
	}

	usq = unvmed_sq_find(u, 0);
	if (!usq) {
		unvmed_log_err("failed to find enabled adminq");
		errno = EINVAL;
		return -1;
	}

	cmd = unvmed_alloc_cmd(u, usq, id_ctrl, sizeof(*id_ctrl));
	if (!cmd) {
		unvmed_log_err("failed to allocate a command instance");
		return -1;
	}

	iov.iov_base = id_ctrl;
	iov.iov_len = NVME_IDENTIFY_DATA_SIZE;

	ret = unvmed_id_ctrl(u, cmd, &iov, 1, 0);
	if (ret) {
		unvmed_log_err("failed to identify controller\n");
		unvmed_cmd_free(cmd);
		return -1;
	}

	unvmed_cmd_free(cmd);
	return 0;
}

int unvmed_init_meta_ns(struct unvme *u, uint32_t nsid, void *nvm_id_ns)
{
	struct nvme_nvm_id_ns *__nvm_id_ns = nvm_id_ns;
	struct nvme_id_ctrl *id_ctrl = NULL;
	struct unvme_ns *ns;
	uint32_t elbaf;
	int refcnt;
	int ret = 0;

	ns = unvmed_ns_get(u, nsid);
	if (!ns) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * XXX: Do we really have to issue id-ctrl command here in this library
	 * function rather than letting application issue id-ctrl command prior
	 * to calling this function?
	 */
	if (!u->id_ctrl) {
		pgmap((void **)&id_ctrl, sizeof(struct nvme_id_ctrl));
		if (!id_ctrl) {
			unvmed_log_err("failed to allocate a buffer");
			ret = -1;
			goto out;
		}

		if (__unvmed_id_ctrl(u, id_ctrl)) {
			unvmed_log_err("failed to identify controller");
			pgunmap(id_ctrl, sizeof(struct nvme_id_ctrl));
			ret = -1;
			goto out;
		}

		unvmed_init_id_ctrl(u, id_ctrl);
		pgunmap(id_ctrl, sizeof(struct nvme_id_ctrl));
	}

	/*
	 * Before send ``nvm-id-ns`` command, we have to check whether the
	 * device supports Extended LBA Format by Identify Controller command.
	 */
	if (!(u->id_ctrl->ctratt & NVME_CTRL_CTRATT_ELBAS))
		goto out;

	if (!__nvm_id_ns) {
		pgmap((void **)&__nvm_id_ns, sizeof(struct nvme_nvm_id_ns));
		if (!__nvm_id_ns) {
			unvmed_log_err("failed to allocate a buffer");
			ret = -1;
			goto out;
		}

		__unvmed_nvm_id_ns(u, nsid, __nvm_id_ns);
	}

	elbaf = le32_to_cpu(__nvm_id_ns->elbaf[ns->format_idx]);

	ns->lbstm = le64_to_cpu(__nvm_id_ns->lbstm);
	ns->sts = elbaf & NVME_NVM_ELBAF_STS_MASK;
	ns->pif = (elbaf & NVME_NVM_ELBAF_PIF_MASK) >> 7;
	if (ns->pif == NVME_NVM_PIF_QTYPE && (__nvm_id_ns->pic & 0x8))
		ns->pif = (elbaf & NVME_NVM_ELBAF_QPIF_MASK) >> 9;

out:
	refcnt = unvmed_ns_put(u, ns);
	assert(refcnt > 0);

	if (__nvm_id_ns != nvm_id_ns)
		pgunmap(__nvm_id_ns, sizeof(struct nvme_nvm_id_ns));

	return ret;
}

static struct unvme_sq *unvmed_init_usq(struct unvme *u, uint32_t qid,
					uint32_t qsize, struct unvme_cq *ucq)
{
	struct __unvme_sq *usq;
	bool alloc = false;

	usq = (struct __unvme_sq *)unvmed_sq_get(u, qid);
	if (!usq) {
		usq = calloc(1, sizeof(*usq));
		if (!usq)
			return NULL;
		alloc = true;
	}

	if (usq->enabled) {
		unvmed_log_err("usq is already enabled");
		return NULL;
	}

	pthread_spin_init(&usq->lock, 0);
	usq->q = &u->ctrl.sq[qid];
	usq->ucq = ucq;
	ucq->usq = __to_sq(usq);
	usq->nr_cmds = 0;

	if (alloc) {
		usq->cmds = calloc(qsize, sizeof(struct unvme_cmd));

		pthread_rwlock_wrlock(&u->sq_list_lock);
		list_add_tail(&u->sq_list, &usq->list);
		pthread_rwlock_unlock(&u->sq_list_lock);

		unvmed_sq_get(u, qid);
	}

	usq->enabled = true;
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
	bool alloc = false;

	ucq = (struct __unvme_cq *)unvmed_cq_get(u, qid);
	if (!ucq) {
		ucq = calloc(1, sizeof(*ucq));
		if (!ucq)
			return NULL;
		alloc = true;
	}

	if (ucq->enabled) {
		unvmed_log_err("ucq is already enabled");
		return NULL;
	}

	pthread_spin_init(&ucq->lock, 0);
	ucq->u = u;
	ucq->q = &u->ctrl.cq[qid];

	if (alloc) {
		pthread_rwlock_wrlock(&u->cq_list_lock);
		list_add_tail(&u->cq_list, &ucq->list);
		pthread_rwlock_unlock(&u->cq_list_lock);

		unvmed_cq_get(u, qid);
	}

	ucq->enabled = true;
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

	pthread_rwlock_wrlock(&u->ns_list_lock);
	list_for_each_safe(&u->ns_list, ns, next_ns, list)
		__unvmed_ns_put(u, (struct unvme_ns *)ns);
	pthread_rwlock_unlock(&u->ns_list_lock);
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

	if (u->id_ctrl)
		free(u->id_ctrl);

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

static inline void unvmed_disable_ns_all(struct unvme *u)
{
	struct __unvme_ns *ns;

	pthread_rwlock_rdlock(&u->ns_list_lock);
	list_for_each(&u->ns_list, ns, list)
		ns->enabled = false;
	pthread_rwlock_unlock(&u->ns_list_lock);
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
	uint32_t head;
	uint8_t phase;

	unvmed_cq_enter(ucq);

	/*
	 * Load the latest value of head pointer and phase value right before
	 * starting cancelation since other thread context of the upper layer
	 * might have updated the doorbell recently.
	 */
	head = LOAD(ucq->q->head);
	phase = LOAD(ucq->q->phase);

	/*
	 * Update @cmd->state of the valid cq entries while cq lock is
	 * acquired.  If some of @cmd is not caught in this loop and
	 * @cmd->state still shows UNVME_CMD_S_SUBMITTED, device has failed to
	 * post the cq entry for the corresponding command and we definitely
	 * cancel them by posting a dummy cq entry to the cq.
	 */
	while (1) {
		cqe = unvmed_get_cqe(ucq, head);
		if ((le16_to_cpu(cqe->sfp) & 0x1) != phase) {
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
		if (LOAD(cmd->state) == UNVME_CMD_S_SUBMITTED) {
			unvmed_put_cqe(ucq, head, phase ^ 1, cmd);

			if (++head == ucq->q->qsize) {
				head = 0;
				phase ^= 0x1;
			}
		}
	}

	unvmed_cq_exit(ucq);
}

static void unvmed_cancel_cmd(struct unvme *u, struct __unvme_sq *usq)
{
	struct unvme_cq *ucq = usq->ucq;

	unvmed_cancel_sq(u, usq);

	/*
	 * Wake-up CQ reaper thread in the background if irq is enabled for the
	 * corresponding completion queue to let application reap the canceled
	 * cq entries.
	 */
	if (unvmed_cq_irq_enabled(ucq)) {
		struct unvme_cq_reaper *r = &u->reapers[unvmed_cq_iv(ucq)];
		eventfd_write(r->efd, 1);
	}

	/*
	 * Wait for upper layer to complete canceled commands in their
	 * CQ reapding routine.  @usq>nr_cmds indicates the number of
	 * command which have not been freed by unvmed_cmd_free().
	 */
	while (atomic_load_acquire(&usq->nr_cmds) > 0)
		;
}

static inline void unvmed_cancel_cmd_all(struct unvme *u)
{
	struct __unvme_sq *usq;

	pthread_rwlock_rdlock(&u->sq_list_lock);
	list_for_each(&u->sq_list, usq, list)
		unvmed_cancel_cmd(u, usq);
	pthread_rwlock_unlock(&u->sq_list_lock);
}

/*
 * Reset NVMe controller instance memory resources along with de-asserting
 * controller enable register.  The instance itself will not be freed which can
 * be re-used in later time.
 */
void unvmed_reset_ctrl(struct unvme *u)
{
	__unvme_reset_ctrl(u);

	u->state = UNVME_DISABLED;

	unvmed_disable_sq_all(u);
	unvmed_disable_cq_all(u);
	unvmed_disable_ns_all(u);

	/*
	 * Quiesce all submission queues to prevent I/O submission from upper
	 * layer.  The queues should be re-enabled (unquiesced) back once
	 * create I/O queue command is issued.
	 */
	unvmed_quiesce_sq_all(u);
	unvmed_cancel_cmd_all(u);
	unvmed_unquiesce_sq_all(u);

	/*
	 * Free up all the namespace instances attached to the current
	 * controller.
	 */
	unvmed_free_ns_all(u);

	__unvmed_delete_sq_all(u);
	__unvmed_delete_cq_all(u);
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

	if (u->state != UNVME_DISABLED) {
		errno = EPERM;
		goto out;
	}

	/*
	 * XXX: unvme uses a few libvfn functions which are very helpful for
	 * setting environments.  However, some of them calls `nvme_sync()`
	 * function, which waits its completion queue entry.  This conflicts
	 * with rcq thread in unvme, so temporally disable to  create rcq thread
	 * of admin cq.
	 */

	if (nvme_configure_adminq(&u->ctrl, qid))
		goto out;

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
out:
	return -1;
}

int unvmed_enable_ctrl(struct unvme *u, uint8_t iosqes, uint8_t iocqes,
		      uint8_t mps, uint8_t css)
{
	uint32_t cc = unvmed_read32(u, NVME_REG_CC);
	uint32_t csts;

	if (NVME_CC_EN(cc)) {
		unvmed_log_err("Controller (%s) has already been enabled (CC.EN=1)",
			       unvmed_bdf(u));
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
	struct unvme_sq *adminq;
	struct unvme_cq *ucq;
	struct unvme_cmd *cmd;
	struct nvme_cmd_create_cq sqe = {0, };
	struct nvme_cqe cqe;
	uint16_t qflags = NVME_Q_PC;
	uint16_t iv = 0;

	if (vector >= 0 && unvmed_init_irq(u, vector))
		return -1;

	adminq = unvmed_sq_find(u, 0);
	if (!adminq) {
		errno = EPERM;
		return -1;
	}

	if (nvme_configure_cq(&u->ctrl, qid, qsize, vector)) {
		unvmed_log_err("could not configure io completion queue");
		return -1;
	}

	ucq = unvmed_init_ucq(u, qid);
	if (!ucq) {
		unvmed_log_err("failed to initialize ucq instance. "
				"discard cq instance from libvfn (qid=%d)",
				qid);
		nvme_discard_cq(&u->ctrl, &u->ctrl.cq[qid]);
		return -1;
	}

	cmd = unvmed_alloc_cmd_nodata(u, adminq);
	if (!cmd) {
		unvmed_free_ucq(u, ucq);
		nvme_discard_cq(&u->ctrl, &u->ctrl.cq[qid]);
		return -1;
	}

	if (vector >= 0) {
		qflags |= NVME_CQ_IEN;
		iv = (uint16_t)vector;
	}

	sqe.opcode = nvme_admin_create_cq;
	sqe.qid = cpu_to_le16(qid);
	sqe.prp1 = cpu_to_le64(u->ctrl.cq[qid].iova);
	sqe.qsize = cpu_to_le16((uint16_t)(qsize - 1));
	sqe.qflags = cpu_to_le16(qflags);
	sqe.iv = cpu_to_le16(iv);

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);
	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	unvmed_cmd_free(cmd);
	return 0;
}

static void __unvmed_delete_cq(struct unvme *u, struct unvme_cq *ucq)
{
	struct nvme_cq *cq = ucq->q;
	int vector = unvmed_cq_iv(ucq);
	bool irq = unvmed_cq_irq_enabled(ucq);

	unvmed_cq_put(u, ucq);
	nvme_discard_cq(&u->ctrl, cq);

	if (irq)
		unvmed_free_irq(u, vector);
}

static void __unvmed_delete_cq_all(struct unvme *u)
{
	struct __unvme_cq *ucq, *next;
	struct nvme_cq *cq;

	unvmed_free_irq_all(u);

	pthread_rwlock_wrlock(&u->cq_list_lock);
	list_for_each_safe(&u->cq_list, ucq, next, list) {
		cq = ucq->q;

		unvmed_log_info("Deleting ucq (qid=%d)", unvmed_cq_id(ucq));
		__unvmed_cq_put(u, __to_cq(ucq));
		nvme_discard_cq(&u->ctrl, cq);
	}
	pthread_rwlock_unlock(&u->cq_list_lock);
}

int unvmed_delete_cq(struct unvme *u, uint32_t qid)
{
	struct unvme_cmd *cmd;
	struct unvme_sq *adminq;
	struct unvme_cq *ucq;
	struct nvme_cmd_delete_q sqe = {0, };
	struct nvme_cqe cqe;

	ucq = unvmed_cq_find(u, qid);
	if (!ucq) {
		errno = EINVAL;
		return -1;
	}

	adminq = unvmed_sq_find(u, 0);
	if (!adminq || !unvmed_sq_enabled(adminq)) {
		return -1;
	}

	cmd = unvmed_alloc_cmd_nodata(u, adminq);
	if (!cmd) {
		return -1;
	}

	sqe.opcode = nvme_admin_delete_cq;
	sqe.qid = cpu_to_le16(qid);

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);
	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	if (nvme_cqe_ok(&cqe))
		__unvmed_delete_cq(u, ucq);

	unvmed_cmd_free(cmd);
	return unvmed_cqe_status(&cqe);
}

int unvmed_create_sq(struct unvme *u, uint32_t qid, uint32_t qsize,
		    uint32_t cqid)
{
	struct unvme_sq *usq;
	struct unvme_sq *adminq;
	struct unvme_cq *ucq;
	struct unvme_cmd *cmd;
	struct nvme_cmd_create_sq sqe = {0, };
	struct nvme_cqe cqe;

	if (!unvme_is_enabled(u)) {
		errno = EPERM;
		return -1;
	}

	adminq = unvmed_sq_find(u, 0);
	if (!adminq) {
		errno = EPERM;
		return -1;
	}

	ucq = unvmed_cq_find(u, cqid);
	if (!ucq) {
		errno = ENODEV;
		return -1;
	}

	if (nvme_configure_sq(&u->ctrl, qid, qsize, ucq->q, 0)) {
		unvmed_log_err("could not configure io submission queue\n");
		return -1;
	}

	usq = unvmed_init_usq(u, qid, qsize, ucq);
	if (!usq) {
		unvmed_log_err("failed to initialize usq instance. "
				"discard sq instance from libvfn (qid=%d)",
				qid);
		nvme_discard_sq(&u->ctrl, &u->ctrl.sq[qid]);
		return -1;
	}

	cmd = unvmed_alloc_cmd_nodata(u, adminq);
	if (!cmd) {
		unvmed_free_usq(u, usq);
		nvme_discard_sq(&u->ctrl, &u->ctrl.sq[qid]);
		return -1;
	}

	sqe.opcode = nvme_admin_create_sq;
	sqe.qid = cpu_to_le16(qid);
	sqe.prp1 = cpu_to_le64(u->ctrl.sq[qid].iova);
	sqe.qsize = cpu_to_le16((uint16_t)(qsize - 1));
	sqe.qflags = cpu_to_le16(NVME_Q_PC);
	sqe.cqid = cpu_to_le16((uint16_t)ucq->q->id);

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);
	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);
	unvmed_cmd_free(cmd);
	return 0;
}

static void __unvmed_delete_sq(struct unvme *u, struct unvme_sq *usq)
{
	struct nvme_sq *sq = usq->q;

	unvmed_sq_put(u, usq);
	nvme_discard_sq(&u->ctrl, sq);
}

static void __unvmed_delete_sq_all(struct unvme *u)
{
	struct __unvme_sq *usq, *next;
	struct nvme_sq *sq;

	pthread_rwlock_wrlock(&u->sq_list_lock);
	list_for_each_safe(&u->sq_list, usq, next, list) {
		sq = usq->q;

		unvmed_log_info("Deleting usq (qid=%d)", unvmed_sq_id(usq));
		__unvmed_sq_put(u, __to_sq(usq));
		nvme_discard_sq(&u->ctrl, sq);
	}
	pthread_rwlock_unlock(&u->sq_list_lock);
}

int unvmed_delete_sq(struct unvme *u, uint32_t qid)
{
	struct unvme_cmd *cmd;
	struct unvme_sq *usq, *adminq;
	struct nvme_cmd_delete_q sqe = {0, };
	struct nvme_cqe cqe;

	usq = unvmed_sq_find(u, qid);
	if (!usq) {
		errno = EINVAL;
		return -1;
	}

	adminq = unvmed_sq_find(u, 0);
	if (!adminq || !unvmed_sq_enabled(adminq)) {
		return -1;
	}

	cmd = unvmed_alloc_cmd_nodata(u, adminq);
	if (!cmd) {
		return -1;
	}

	sqe.opcode = nvme_admin_delete_sq;
	sqe.qid = cpu_to_le16(qid);

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);
	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

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

	STORE(cmd->state, UNVME_CMD_S_SUBMITTED);
#ifdef UNVME_DEBUG
	unvmed_log_cmd_post(unvmed_bdf(cmd->u), cmd->rq->sq->id, sqe);
#endif

	if (!(flags & UNVMED_CMD_F_NODB)) {
		int nr_cmds;

		nvme_sq_update_tail(cmd->rq->sq);
		do {
			nr_cmds = cmd->u->nr_cmds;
		} while (!atomic_cmpxchg(&cmd->u->nr_cmds, nr_cmds, nr_cmds + 1));
	}
}

struct unvme_cmd *unvmed_get_cmd_from_cqe(struct unvme *u, struct nvme_cqe *cqe)
{
	struct unvme_sq *usq;

	/*
	 * Get sq instance by unvmed_sq_find() instead of unvmed_sq_get()
	 * which returns an enabled sq instance since sq might have been
	 * removed due to some reasons like reset.  Even under reset, caller
	 * might want to seek the command instance for the corresponding
	 * completion queue entry.
	 */
	usq = unvmed_sq_find(u, cqe->sqid);
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
		/*
		 * XXX: currently SQ:CQ 1:1 mapping is only supported by having
		 * @usq in @ucq->usq to represent the relationship.
		 */
		assert(le16_to_cpu(cqe->sqid) == unvmed_sq_id(ucq->usq));

		cmd = &ucq->usq->cmds[cqe->cid];
		assert(cmd != NULL);

		cmd->state = UNVME_CMD_S_COMPLETED;
	}
	unvmed_cq_exit(ucq);

	return cqe;
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

	nvme_sq_update_tail(usq->q);

	do {
		nr_cmds = u->nr_cmds;
	} while (!atomic_cmpxchg(&u->nr_cmds, nr_cmds, nr_cmds + nr_sqes));

	return nr_sqes;
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
			int ret;
			ret = unvmed_init_ns(u, ctx->ns.nsid, NULL);
			if (ret)
				return ret;
			return unvmed_init_meta_ns(u, ctx->ns.nsid, NULL);
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
