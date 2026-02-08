// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#define _GNU_SOURCE

#include <time.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#include <vfn/nvme.h>
#include <vfn/support/atomic.h>
#include <vfn/vfio/pci.h>
#include <vfn/pci/util.h>

#include <nvme/types.h>
#include <nvme/util.h>

#include <ccan/list/list.h>
#include <json-c/json.h>

#include "libunvmed.h"
#include "libunvmed-private.h"

int __unvmed_logfd = 0;
int __log_level = 0;

static void *unvmed_reaper_run(void *opaque);
static void __unvmed_free_ns(struct __unvme_ns *ns);
static void __unvmed_free_usq(struct unvme *u, struct unvme_sq *usq);
static void __unvmed_free_ucq(struct unvme *u, struct unvme_cq *ucq);
static void __unvmed_delete_sq(struct unvme *u, struct unvme_sq *usq);
static void __unvmed_delete_cq(struct unvme *u, struct unvme_cq *ucq);
static void __unvmed_delete_sq_all(struct unvme *u);
static void __unvmed_delete_cq_all(struct unvme *u);
static void unvmed_delete_iosq_all(struct unvme *u);
static void unvmed_delete_iocq_all(struct unvme *u);
static int unvmed_get_downstream_port(struct unvme *u, char *bdf);
static struct nvme_cqe *unvmed_get_completion(struct unvme *u,
					      struct unvme_cq *ucq);
static struct unvme_cmd *unvmed_get_cmd_from_cqe(struct unvme *u,
						 struct nvme_cqe *cqe);
static int unvmed_get_pcie_cap_offset(char *bdf);
static void __unvmed_cmd_cmpl(struct unvme_cmd *cmd, struct nvme_cqe *cqe);
static void __unvmed_reap_cqe(struct unvme_cq *ucq);

static inline enum unvme_state unvmed_ctrl_get_state(struct unvme *u)
{
	return LOAD(u->state);
}

static bool unvmed_ctrl_set_state(struct unvme *u, enum unvme_state state)
{
	enum unvme_state old;
	bool change = false;

	pthread_spin_lock(&u->lock);
	old = unvmed_ctrl_get_state(u);

	switch (state) {
	case UNVME_DISABLED:
		switch (old) {
		case UNVME_RESETTING:
			change = true;
			break;
		default:
			break;
		}
	case UNVME_ENABLING:
		switch (old) {
		case UNVME_DISABLED:
			change = true;
			break;
		default:
			break;
		}
	case UNVME_ENABLED:
		switch (old) {
		case UNVME_ENABLING:
			change = true;
			break;
		default:
			break;
		}
	case UNVME_RESETTING:
		switch (old) {
		case UNVME_DISABLED:
		case UNVME_ENABLED:
			change = true;
			break;
		default:
			break;
		}
	case UNVME_TEARDOWN:
		switch (old) {
		case UNVME_DISABLED:
		case UNVME_ENABLED:
			change = true;
			break;
		default:
			break;
		}
	default:
		break;
	}

	if (change) {
		STORE(u->state, state);
		unvmed_log_info("set controller state (%s -> %s)",
				unvmed_state_str(old), unvmed_state_str(state));
	} else
		unvmed_log_err("failed to set controller state (%s -> %s)",
				unvmed_state_str(old), unvmed_state_str(state));

	pthread_spin_unlock(&u->lock);
	return change;
}

static int __unvmed_mem_alloc(struct unvme *u, size_t size,
			      struct iommu_dmabuf *buf)
{
	if (iommu_get_dmabuf(__iommu_ctx(&u->ctrl), buf, size, 0x0)) {
		unvmed_log_err("failed to allocate a buffer");
		return -1;
	}

	return 0;
}

static int __unvmed_mem_free(struct unvme *u, struct iommu_dmabuf *buf);

static int __unvmed_vcq_push(struct unvme *u, struct unvme_vcq *q,
			   struct nvme_cqe *cqe)
{
	uint16_t tail;

	pthread_spin_lock(&q->tail_lock);

	tail = atomic_load_acquire(&q->tail);
	if ((tail + 1) % q->qsize == atomic_load_acquire(&q->head)) {
		pthread_spin_unlock(&q->tail_lock);
		return -ENOENT;
	}

	q->cqe[tail] = *cqe;
	atomic_store_release(&q->tail, (tail + 1) % q->qsize);
	unvmed_log_cmd_vcq_push(cqe);

	pthread_spin_unlock(&q->tail_lock);
	return 0;
}

static int unvmed_vcq_pop(struct unvme_vcq *q, struct nvme_cqe *cqe)
{
	uint16_t head = atomic_load_acquire(&q->head);

	if (head == atomic_load_acquire(&q->tail))
		return -ENOENT;

	*cqe = q->cqe[head];
	atomic_store_release(&q->head, (head + 1) % q->qsize);
	unvmed_log_cmd_vcq_pop(cqe);
	return 0;
}

int unvmed_vcq_push(struct unvme *u, struct nvme_cqe *cqe)
{
	struct unvme_cmd *cmd = unvmed_get_cmd_from_cqe(u, cqe);
	struct unvme_vcq *vcq;
	int ret;

	if (!cmd)
		return -ENOENT;

	vcq = unvmed_cmd_get_vcq(cmd);

	ret =  __unvmed_vcq_push(u, vcq, cqe);
	/*
	 * @cmd->state mostly might have been set to
	 * UNVME_CMD_S_TO_BE_COMPLETED before this function, especially in
	 * `unvmed_cmd_cmpl()` in libunvmed context.  But, exteranl app can
	 * also call this function so that we should mark the @cmd as `to be
	 * completed`.
	 */
	if (!ret)
		atomic_store_release(&cmd->state, UNVME_CMD_S_TO_BE_COMPLETED);

	return ret;
}

int __unvmed_vcq_run_n(struct unvme *u, struct unvme_vcq *vcq,
		       struct nvme_cqe *cqes, int nr_cqes, bool nowait)
{
	struct nvme_cqe __cqe;
	struct nvme_cqe *cqe = &__cqe;
	int nr_cmds;
	int nr = 0;
	int ret;

	while (nr < nr_cqes) {
		do {
			ret = unvmed_vcq_pop(vcq, &__cqe);
		} while (ret == -ENOENT && !nowait);

		if (ret)
			break;

		if (cqes)
			memcpy(&cqes[nr], cqe, sizeof(*cqe));
		nr++;
	}

	do {
		nr_cmds = u->nr_cmds;
	} while (!atomic_cmpxchg(&u->nr_cmds, nr_cmds, nr_cmds - nr));

	return nr;
}

int unvmed_vcq_run_n(struct unvme *u, struct unvme_vcq *vcq,
		     struct nvme_cqe *cqes, int min, int max)
{
	int ret;
	int n;

	n = __unvmed_vcq_run_n(u, vcq, cqes, min, false);
	if (n < 0)
		return 0;

	ret = n;

	if (ret >= max)
		return ret;

	n = __unvmed_vcq_run_n(u, vcq, cqes + n, max - n, true);
	if (n < 0)
		return ret;

	return ret + n;
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

void unvmed_init(const char *logfile, int log_level)
{
	if (logfile)
		__unvmed_logfd = unvmed_create_logfile(logfile);

	atomic_store_release(&__log_level, log_level);
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

bool unvmed_ctrl_enabled(struct unvme *u)
{
	return unvmed_ctrl_get_state(u) == UNVME_ENABLED;
}

int unvmed_nr_cmds(struct unvme *u)
{
	return u->nr_cmds;
}

int unvmed_nr_irqs(struct unvme *u)
{
	return u->nr_irqs;
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

int unvmed_get_sqs(struct unvme *u, struct unvme_sq ***sqs)
{
	int nr_sqs = 0;
	int qid;

	if (!sqs) {
		errno = EINVAL;
		return -1;
	}

	*sqs = calloc(u->nr_sqs, sizeof(struct unvme_sq *));
	if (!*sqs)
		return -1;

	for (qid = 0; qid < u->nr_sqs; qid++) {
		struct unvme_sq *usq;
		usq = unvmed_sq_find(u, qid);
		if (!usq || (usq && !usq->enabled))
			continue;

		(*sqs)[nr_sqs++] = usq;
	}

	return nr_sqs;
}

int unvmed_get_cqs(struct unvme *u, struct unvme_cq ***cqs)
{
	struct unvme_cq *ucq;
	int nr_cqs = 0;
	int qid;

	if (!cqs) {
		errno = EINVAL;
		return -1;
	}

	*cqs = calloc(u->nr_cqs, sizeof(struct unvme_cq *));
	if (!*cqs)
		return -1;

	for (qid = 0; qid < u->nr_cqs; qid++) {
		ucq = unvmed_cq_find(u, qid);
		if (!ucq || (ucq && !ucq->enabled))
			continue;

		(*cqs)[nr_cqs++] = ucq;
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

	if (ret < 0) {
		unvmed_log_err("failed to epoll_wait() for vector=%d, errno=%d",
				vector, errno);
		return -1;
	}

	return eventfd_read(u->efds[vector], &irq);
}

static struct unvme_sq *__unvmed_find_and_get_sq(struct unvme *u,
						   uint32_t qid, bool get)
{
	struct unvme_sq *usq = NULL;
	int refcnt;

	if (qid >= u->nr_sqs)
		return NULL;

	pthread_rwlock_rdlock(&u->sqs_lock);
	if (u->sqs[qid]) {
		usq = u->sqs[qid];

		refcnt = atomic_load_acquire(&usq->refcnt);
		while (get && refcnt > 0 &&
				!atomic_cmpxchg(&usq->refcnt, refcnt, refcnt + 1)) {
			refcnt = atomic_load_acquire(&usq->refcnt);
		}

		/* Other context has already fred the @usq instance. */
		if (!refcnt)
			usq = NULL;
	}
	pthread_rwlock_unlock(&u->sqs_lock);

	return usq;
}

static struct unvme_cq *__unvmed_find_and_get_cq(struct unvme *u,
						   uint32_t qid, bool get)
{
	struct unvme_cq *ucq = NULL;
	int refcnt;

	if (qid >= u->nr_cqs)
		return NULL;

	pthread_rwlock_rdlock(&u->cqs_lock);
	if (u->cqs[qid]) {
		ucq = u->cqs[qid];

		refcnt = atomic_load_acquire(&ucq->refcnt);
		while (get && refcnt > 0 &&
				!atomic_cmpxchg(&ucq->refcnt, refcnt, refcnt + 1)) {
			refcnt = atomic_load_acquire(&ucq->refcnt);
		}

		/* Other context has already fred the @ucq instance. */
		if (!refcnt)
			ucq = NULL;
	}
	pthread_rwlock_unlock(&u->cqs_lock);

	return ucq;
}

struct unvme_sq *unvmed_sq_find(struct unvme *u, uint32_t qid)
{
	return __unvmed_find_and_get_sq(u, qid, false);
}

struct unvme_cq *unvmed_cq_find(struct unvme *u, uint32_t qid)
{
	return __unvmed_find_and_get_cq(u, qid, false);
}

struct unvme_sq *unvmed_sq_get(struct unvme *u, uint32_t qid)
{
	return __unvmed_find_and_get_sq(u, qid, true);
}

struct unvme_cq *unvmed_cq_get(struct unvme *u, uint32_t qid)
{
	return __unvmed_find_and_get_cq(u, qid, true);
}

int unvmed_sq_put(struct unvme *u, struct unvme_sq *usq)
{
	int refcnt;

	/*
	 * We don't have to access refcnt in atomic since no one can access
	 * refcnt under wrlock is acquired.
	 */
	refcnt = atomic_dec_fetch(&usq->refcnt);
	if (!refcnt)
		__unvmed_free_usq(u, usq);

	return refcnt;
}

int unvmed_cq_put(struct unvme *u, struct unvme_cq *ucq)
{
	int refcnt;

	/*
	 * We don't have to access refcnt in atomic since no one can access
	 * refcnt under wrlock is acquired.
	 */
	refcnt = atomic_dec_fetch(&ucq->refcnt);
	if (!refcnt)
		__unvmed_free_ucq(u, ucq);

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

static int unvmed_init_irq_reaper(struct unvme *u, int vector)
{
	struct unvme_cq_reaper *r = &u->reapers[vector];
	struct epoll_event e;

	r->u = u;
	r->vector = vector;
	r->efd = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
	if (r->efd < 0) {
		unvmed_log_err("failed to create a eventfd (vector=%d, errno=%d \"%s\")",
				vector, errno, strerror(errno));
		return -1;
	}

	r->epoll_fd = epoll_create1(0);
	if (r->epoll_fd < 0) {
		unvmed_log_err("failed to create a epoll_fd (vector=%d, errno=%d \"%s\")",
				vector, errno, strerror(errno));
		if (errno == EMFILE)  /* Too many open files */
			unvmed_log_err("check `ulimit -n` for open file limitation");

		close(r->efd);
		return -1;
	}


	e = (struct epoll_event) {
		.events = EPOLLIN,
		.data.fd = r->efd,
	};
	epoll_ctl(r->epoll_fd, EPOLL_CTL_ADD, r->efd, &e);

	u->efds[r->vector] = r->efd;
	return 0;
}

static void unvmed_free_irq_reaper(struct unvme_cq_reaper *r)
{
	struct epoll_event e = {
		.events = EPOLLIN,
		.data.fd = r->efd,
	};

	epoll_ctl(r->epoll_fd, EPOLL_CTL_DEL, r->efd, &e);

	r->u->efds[r->vector] = -1;
	close(r->efd);
	close(r->epoll_fd);
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

	unvmed_free_irq_reaper(r);
	return 0;
}

static int unvmed_init_irq(struct unvme *u, int vector)
{
	struct unvme_cq_reaper *r = &u->reapers[vector];
	int nr_irqs = u->nr_irqs;

	if (vector >= nr_irqs) {
		unvmed_log_err("invalid vector %d", vector);
		errno = EINVAL;
		return -1;
	}

	if (atomic_inc_fetch(&r->refcnt) > 1)
		return 0;

	if (unvmed_init_irq_reaper(u, vector)) {
		unvmed_log_err("failed to initialize IRQ reaper (vector=%d)", vector);
		return -1;
	}

	/*
	 * Note: disable all IRQ enabled first before enabling a specific
	 * interrupt vector to support older kernel (< v6.5) which does not
	 * support dynamic MSI-X interrupt assignment.
	 */
	if (vfio_disable_irq(&u->ctrl.pci.dev, 0, u->nr_irqs)) {
		unvmed_log_err("failed to disable all irq vectors");

		unvmed_free_irq_reaper(r);
		return -1;
	}

	if (vfio_set_irq(&u->ctrl.pci.dev, &u->efds[0], 0, nr_irqs)) {
		unvmed_log_err("failed to set IRQ for vector %d", vector);

		unvmed_free_irq_reaper(r);
		return -1;
	}

	pthread_create(&r->th, NULL, unvmed_reaper_run, (void *)r);
	return 0;
}

static inline int unvmed_lower_pow2(int n)
{
	int power = 1;

	if (n <= 1)
		return 0;

	if ((n & (n - 1)) == 0)
		return n >> 1;

	while (power < n)
		power <<= 1;

	return power >> 1;
}

static int unvmed_alloc_irqs(struct unvme *u)
{
	int nr_irqs;

	if (vfio_pci_get_irq_info(&u->ctrl.pci, &u->irq_info)) {
		unvmed_log_err("failed to get &struct vfio_irq_info from libvfn");
		return -1;
	}

	/*
	 * Check whether the IOMMU hardware in the current system supports the
	 * number of IRQs reported by the vfio-pci driver.  For example, AMD
	 * IOMMU hardware actually supports interrupt remapping entry up to 512
	 * entries and kernel returns error if the given number of IRQs are
	 * greater than 512.  So, adjust the maximum number of IRQs which can
	 * be used in the current system with warning.
	 */
	nr_irqs = u->irq_info.count;
	while (nr_irqs > 0 && vfio_disable_irq(&u->ctrl.pci.dev, 0, nr_irqs))
		nr_irqs = unvmed_lower_pow2(nr_irqs);  /* Retry with lower pow-of-2 */

	if (!nr_irqs) {
		unvmed_log_err("failed to adjust number of IRQs (supported=%d)",
				u->irq_info.count);
		return -1;
	}

	if (nr_irqs < u->irq_info.count)
		unvmed_log_info("adjusted number of IRQ to be used in unvmed, %d -> %d",
				u->irq_info.count, nr_irqs);

	u->nr_irqs = nr_irqs;
	u->efds = malloc(sizeof(int) * u->nr_irqs);
	if (!u->efds)
		return -1;

	/*
	 * Kenrel vfio-pci documentation says that VFIO_DEVICE_SET_IRQS ioctl
	 * treats @efd -1 as de-assign or skipping a vector during enabling the
	 * interrupt.
	 */
	for (int i = 0; i < u->nr_irqs; i++)
		u->efds[i] = -1;

	u->nr_efds = u->nr_irqs;
	u->reapers = calloc(u->nr_efds, sizeof(struct unvme_cq_reaper));
	unvmed_log_info("%d IRQ vectors are allocated (supported=%d)",
			u->nr_irqs, u->irq_info.count);
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

struct unvme_cmb *unvmed_cmb(struct unvme *u)
{
	return (struct unvme_cmb *)&u->ctrl.cmb;
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

static bool unvmed_iova_in_cmb(struct unvme *u, uint64_t iova, size_t size)
{
       if (!u->ctrl.cmb.vaddr)
               return false;

       uint64_t cmb_start = u->ctrl.cmb.iova;
       uint64_t cmb_end = u->ctrl.cmb.iova + u->ctrl.cmb.size;

       if (iova >= cmb_start && (iova + size) < cmb_end)
               return true;

       return false;
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

	pthread_spin_init(&u->lock, 0);

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

	u->sqs = calloc(max_nr_ioqs + 1, sizeof(struct unvme_sq *));
	u->cqs = calloc(max_nr_ioqs + 1, sizeof(struct unvme_cq *));
	pthread_rwlock_init(&u->sqs_lock, NULL);
	pthread_rwlock_init(&u->cqs_lock, NULL);

	list_head_init(&u->ns_list);
	pthread_rwlock_init(&u->ns_list_lock, NULL);
	list_add(&unvme_list, &u->list);
	list_head_init(&u->ctx_list);

	list_head_init(&u->mem_list);
	pthread_rwlock_init(&u->mem_list_lock, NULL);

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
	struct unvme_cmd *cmd;
	struct unvme_sq *asq;
	struct iovec iov;
	int ret;

	if (!id_ns) {
		unvmed_log_err("'id_ns' is given NULL");
		errno = EINVAL;
		return -1;
	}

	asq = unvmed_sq_get(u, 0);
	if (!asq) {
		unvmed_log_err("failed to find adminq");
		errno = EINVAL;
		return -1;
	}

	unvmed_sq_enter(asq);
	if (!unvmed_sq_ready(asq)) {
		unvmed_log_err("failed to find enabled adminq");

		unvmed_sq_exit(asq);
		unvmed_sq_put(u, asq);
		errno = EINVAL;
		return -1;
	}

	/*
	 * Retry if @cmd is not allocated at the point since this function is
	 * only called in reset context thread, and we can't simply ensure that
	 * other admin application is running out there.
	 */
	do {
		cmd = unvmed_alloc_cmd(u, asq, NULL, id_ns, sizeof(*id_ns));
	} while (!cmd && errno == EBUSY);

	if (!cmd) {
		unvmed_log_err("failed to allocate a command instance "
				"(errno=%d \"%s\")", errno, strerror(errno));

		unvmed_sq_exit(asq);
		unvmed_sq_put(u, asq);
		return -1;
	}

	cmd->flags = UNVMED_CMD_F_WAKEUP_ON_CQE;

	iov.iov_base = id_ns;
	iov.iov_len = NVME_IDENTIFY_DATA_SIZE;

	ret = unvmed_id_ns(cmd, nsid, &iov, 1);
	if (ret) {
		unvmed_log_err("failed to identify namespace");

		unvmed_cmd_put(cmd);
		unvmed_sq_exit(asq);
		unvmed_sq_put(u, asq);
		return -1;
	}

	unvmed_cmd_put(cmd);
	unvmed_sq_exit(asq);
	unvmed_sq_put(u, asq);
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
	struct unvme_sq *asq;
	struct iovec iov;
	int ret;

	if (!nvm_id_ns) {
		unvmed_log_err("'nvm_id_ns' is given NULL");
		errno = EINVAL;
		return -1;
	}

	asq = unvmed_sq_get(u, 0);
	if (!asq) {
		unvmed_log_err("failed to find adminq");
		errno = EINVAL;
		return -1;
	}

	unvmed_sq_enter(asq);
	if (!unvmed_sq_ready(asq)) {
		unvmed_log_err("failed to find enabled adminq");

		unvmed_sq_exit(asq);
		unvmed_sq_put(u, asq);
		errno = EINVAL;
		return -1;
	}

	/*
	 * Retry if @cmd is not allocated at the point since this function is
	 * only called in reset context thread, and we can't simply ensure that
	 * other admin application is running out there.
	 */
	do {
		cmd = unvmed_alloc_cmd(u, asq, NULL, nvm_id_ns,
				sizeof(*nvm_id_ns));
	} while (!cmd && errno == EBUSY);

	if (!cmd) {
		unvmed_log_err("failed to allocate a command instance "
				"(errno=%d \"%s\")", errno, strerror(errno));

		unvmed_sq_exit(asq);
		unvmed_sq_put(u, asq);
		return -1;
	}

	cmd->flags = UNVMED_CMD_F_WAKEUP_ON_CQE;

	iov.iov_base = nvm_id_ns;
	iov.iov_len = NVME_IDENTIFY_DATA_SIZE;

	ret = unvmed_nvm_id_ns(cmd, nsid, &iov, 1);
	if (ret) {
		unvmed_log_err("failed to identify namespace");

		unvmed_cmd_put(cmd);
		unvmed_sq_exit(asq);
		unvmed_sq_put(u, asq);
		return -1;
	}

	unvmed_cmd_put(cmd);
	unvmed_sq_exit(asq);
	unvmed_sq_put(u, asq);
	return 0;
}

/*
 * Issue an Identify Controller admin command to the given @u and keep the data
 * structure inside of @u->id_ctrl.
 */
static int __unvmed_id_ctrl(struct unvme *u, struct nvme_id_ctrl *id_ctrl)
{
	struct unvme_cmd *cmd;
	struct unvme_sq *asq;
	struct iovec iov;
	int ret;

	if (!id_ctrl) {
		unvmed_log_err("'id_ctrl' is given NULL");
		errno = EINVAL;
		return -1;
	}

	asq = unvmed_sq_get(u, 0);
	if (!asq) {
		unvmed_log_err("failed to find adminq");
		errno = EINVAL;
		return -1;
	}

	unvmed_sq_enter(asq);
	if (!unvmed_sq_ready(asq)) {
		unvmed_log_err("failed to find enabled adminq");

		unvmed_sq_exit(asq);
		unvmed_sq_put(u, asq);
		errno = EINVAL;
		return -1;
	}

	/*
	 * Retry if @cmd is not allocated at the point since this function is
	 * only called in reset context thread, and we can't simply ensure that
	 * other admin application is running out there.
	 */
	do {
		cmd = unvmed_alloc_cmd(u, asq, NULL, id_ctrl, sizeof(*id_ctrl));
	} while (!cmd && errno == EBUSY);

	if (!cmd) {
		unvmed_log_err("failed to allocate a command instance "
				"(errno=%d \"%s\")", errno, strerror(errno));

		unvmed_sq_exit(asq);
		unvmed_sq_put(u, asq);
		return -1;
	}

	cmd->flags = UNVMED_CMD_F_WAKEUP_ON_CQE;

	iov.iov_base = id_ctrl;
	iov.iov_len = NVME_IDENTIFY_DATA_SIZE;

	ret = unvmed_id_ctrl(cmd, &iov, 1);
	if (ret) {
		unvmed_log_err("failed to identify controller");

		unvmed_cmd_put(cmd);
		unvmed_sq_exit(asq);
		unvmed_sq_put(u, asq);
		return -1;
	}

	unvmed_cmd_put(cmd);
	unvmed_sq_exit(asq);
	unvmed_sq_put(u, asq);
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

static int unvmed_cid_init(struct unvme_sq *usq, size_t size)
{
	struct unvme_bitmap *bitmap = &usq->cids;

	bitmap->size = size;
	bitmap->nr_bytes = (size + 8 - 1) / 8;
	bitmap->bits = calloc(bitmap->nr_bytes, sizeof(uint8_t));

	if (!bitmap->bits) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

static void unvmed_cid_free(struct unvme_sq *usq)
{
	struct unvme_bitmap *bitmap = &usq->cids;

	free(bitmap->bits);
}

int unvmed_vcq_init(struct unvme_vcq *vcq, uint32_t qsize)
{
	vcq->head = 0;
	vcq->tail = 0;
	vcq->qsize = qsize;
	pthread_spin_init(&vcq->tail_lock, 0);
	vcq->cqe = malloc(sizeof(struct nvme_cqe) * qsize);

	if (!vcq->cqe) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

void unvmed_vcq_free(struct unvme_vcq *vcq)
{
	free(vcq->cqe);
	memset(vcq, 0, sizeof(struct unvme_vcq));
}

static int unvmed_timer_update(struct unvme_sq *usq, int sec)
{
	struct unvme_timer *timer = &usq->timer;
	struct itimerspec delta = {
		.it_value.tv_sec = sec,
		.it_value.tv_nsec = 0,
		.it_interval.tv_sec = 0,
		.it_interval.tv_nsec = 0,
	};
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	timer->expire.tv_sec = now.tv_sec + delta.it_value.tv_sec;

	if (timer_settime(timer->t, 0, &delta, NULL) < 0) {
		unvmed_log_err("failed to update timer expiration time");
		return -1;
	}

	return 0;
}

static void unvmed_cmd_timeout(struct unvme_cmd *cmd)
{
	const uint16_t status =
		(NVME_SCT_UNVME << NVME_SCT_SHIFT) | NVME_SC_UNVME_TIMED_OUT;
	struct nvme_cqe timeout_cqe = {0, };
	struct unvme_sq *usq = cmd->usq;
	uint16_t qid = unvmed_sq_id(usq);
	struct unvme *u = cmd->u;
	uint16_t cid = cmd->cid;
	int nr_cmds;
	int ret;

	unvmed_log_err("%s: command timeout detected (sqid=%d, cid=%d)",
			unvmed_bdf(u), qid, cid);

	/*
	 * Get @cmd instance here again to prevent double-free attemption for
	 * the normal cq entry coming from the device lately after the timeout
	 * fake cq entry being posted.
	 *
	 * The timedout @cmd instance will never be put(refcnt=0) unless
	 * controller is reset or queue is deleted.
	 */
	cmd = unvmed_cmd_get(usq, cid);
	assert(cmd != NULL);

	STORE(cmd->flags, cmd->flags | UNVMED_CMD_F_TIMEDOUT);

	/* Generate CQE with timeout error status for the specific command */
	timeout_cqe.sqid = cpu_to_le16(qid);
	timeout_cqe.cid = cid;
	timeout_cqe.sfp = cpu_to_le16(status << 1);

	/*
	 * XXX: unvmed_cmd_cmpl has exactly the same code, will be
	 * cleaned up.
	 */
	if (cmd->flags & UNVMED_CMD_F_WAKEUP_ON_CQE) {
		__unvmed_cmd_cmpl(cmd, &timeout_cqe);

		atomic_store_release(&cmd->completed, 1);
		unvmed_futex_wake(&cmd->completed, 1);

		do {
			nr_cmds = u->nr_cmds;
		} while (!atomic_cmpxchg(&u->nr_cmds, nr_cmds, nr_cmds - 1));
	} else {
		do {
			ret = __unvmed_vcq_push(u, &usq->vcq, &timeout_cqe);
		} while (ret == -EAGAIN);
	}

	unvmed_cmd_put(cmd);
}

static void unvmed_timer_handler(union sigval sv)
{
	struct unvme_sq *usq = (struct unvme_sq *)sv.sival_ptr;
	struct unvme_cmd *cmd;
	struct timespec now;
	struct timespec next = {0, };
	bool timedout = false;
	int cid;

	if (!atomic_load_acquire(&usq->timer.active))
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/*
	 * First, check if any command has been expired or not.  We don't
	 * perform the timeout handler in this step since if we do this here,
	 * all the SQs should be quiesced first, but we are not sure that if
	 * any command has been expired or not, so check this out first and if
	 * any, we go further.
	 */
	for (cid = 0; !timedout && cid < usq->qsize - 1; cid++) {
		cmd = unvmed_cmd_get(usq, cid);
		if (!cmd)
			continue;

		/*
		 * If @cmd is expired and @next is not set within
		 * unvmed_cmd_expired(), it's totally okay since timeout
		 * handler will be terminated and freeze the corresponding
		 * queue which means no more commands are coming in.
		 */
		if (unvmed_cmd_expired(cmd, &now, &next))
			timedout = true;

		unvmed_cmd_put(cmd);
	}

	/*
	 * If any is expired, quiesce the corresponding @usq to handle timeout
	 * just like the reset handler.
	 */
	if (timedout) {
		timedout = false;
		memset(&next, 0, sizeof(next));

		unvmed_sq_enter(usq);
		for (cid = 0; cid < usq->qsize - 1; cid++) {
			cmd = unvmed_cmd_get(usq, cid);
			if (!cmd)
				continue;

			if (unvmed_cmd_expired(cmd, &now, &next)) {
				timedout = true;
				unvmed_cmd_timeout(cmd);
			}

			unvmed_cmd_put(cmd);
		}

		/*
		 * If any timedout, we don't unquiesce SQs for debuggability.
		 */
		if (timedout)
			STORE(usq->flags, usq->flags | UNVMED_SQ_F_FROZEN);

		unvmed_sq_exit(usq);

		/*
		 * If there are still pending commands that haven't expired yet,
		 * keep the timer running to check them later.
		 */
		if (next.tv_sec) {
			int delta = next.tv_sec - now.tv_sec;

			unvmed_timer_update(usq, delta > 0 ? delta : 1);
			return;
		}

		atomic_store_release(&usq->timer.active, false);
		unvmed_log_debug("sq%d: command timedout detected, terminated.",
				unvmed_sq_id(usq));
		return;
	}

	/*
	 * Simply check tv_sec only to check whether next expiration time is
	 * set or not, otherwise we update this timer to the next +@u->timeout
	 * seconds.
	 */
	if (!next.tv_sec)
		unvmed_timer_update(usq, usq->ucq->u->timeout);
	else
		unvmed_timer_update(usq, next.tv_sec - now.tv_sec);
}

static int unvmed_timer_init(struct unvme_timer *timer, void *opaque)
{
	struct sigevent sev = {
		.sigev_notify = SIGEV_THREAD,
		.sigev_notify_function = unvmed_timer_handler,
		.sigev_notify_attributes = NULL,
		.sigev_value.sival_ptr = opaque,
	};

	if (timer_create(CLOCK_MONOTONIC, &sev, &timer->t) < 0) {
		unvmed_log_err("failed to create timer");
		return -1;
	}

	atomic_store_release(&timer->active, true);
	return 0;
}

static int unvmed_timer_free(struct unvme_timer *timer)
{
	/*
	 * Make sure that timerout handler not to proceed after timer_delete()
	 * returns.
	 */
	atomic_store_release(&timer->active, false);
	return timer_delete(timer->t);
}

bool unvmed_timer_running(struct unvme_timer *timer)
{
	struct itimerspec curr;

	timer_gettime(timer->t, &curr);

	if (curr.it_value.tv_sec > 0 || curr.it_value.tv_nsec > 0)
		return true;
	return false;
}

static struct unvme_sq *unvmed_init_usq(struct unvme *u, uint32_t qid,
					uint32_t qsize, struct unvme_cq *ucq,
					uint32_t qprio, uint32_t pc,
					uint32_t nvmsetid)
{
	struct unvme_sq *usq;
	bool alloc = false;

	usq = unvmed_sq_get(u, qid);
	if (!usq) {
		usq = calloc(1, sizeof(*usq));
		if (!usq)
			return NULL;
		alloc = true;
	}

	if (usq->enabled) {
		unvmed_log_err("usq is already enabled");
		if (!alloc)
			unvmed_sq_put(u, usq);
		return NULL;
	}

	if (alloc) {
		usq->id = qid;
		pthread_spin_init(&usq->lock, 0);

		usq->cmds = calloc(qsize, sizeof(struct unvme_cmd));

		/*
		 * libvfn manages @rq instances for (@qsize-1).
		 */
		if (unvmed_cid_init(usq, qsize - 1) < 0) {
			free(usq->cmds);
			free(usq);
			return NULL;
		}

		if (unvmed_vcq_init(&usq->vcq, qsize)) {
			if (alloc)
				free(usq);
			return NULL;
		}

		/*
		 * @usq instance is safe to be passed to the timeout hander in
		 * the future since @usq instance will never be freed without
		 * terminating the pending timer.
		 */
		if (unvmed_timer_init(&usq->timer, usq)) {
			unvmed_vcq_free(&usq->vcq);
			unvmed_cid_free(usq);
			free(usq->cmds);
			free(usq);
			return NULL;
		}

		pthread_rwlock_wrlock(&u->sqs_lock);
		u->sqs[qid] = usq;
		if (!qid)
			u->asq = usq;
		usq->refcnt = 1;
		pthread_rwlock_unlock(&u->sqs_lock);
	}

	/*
	 * @qsize, @ucq are changable whenever @usq initialization.
	 * @nr_cmds has to be set to 0.
	 */
	unvmed_sq_enter(usq);
	usq->q = &u->ctrl.sq[qid];
	usq->nr_cmds = 0;
	usq->qsize = qsize;
	usq->qprio = qprio;
	usq->pc = pc;
	usq->nvmsetid = nvmsetid;
	usq->ucq = ucq;
	ucq->usq = usq;
	usq->flags = 0;

	if (!qid)
		u->ctrl.adminq.sq = usq->q;

	unvmed_sq_exit(usq);

	return usq;
}

void unvmed_enable_sq(struct unvme_sq *usq)
{
	atomic_store_release(&usq->enabled, true);
}

static void unvmed_disable_sq(struct unvme_sq *usq)
{
	atomic_store_release(&usq->enabled, false);
}

static void __unvmed_free_usq(struct unvme *u, struct unvme_sq *usq)
{
	uint32_t qid = unvmed_sq_id(usq);

	/*
	 * Prevent accessing @u->sqs array after free(usq) by NULL-ing first.
	 * Otherwise, in other thread context u->cqs[qid] might be corrupted.
	 */
	pthread_rwlock_wrlock(&u->sqs_lock);
	u->sqs[qid] = NULL;
	pthread_rwlock_unlock(&u->sqs_lock);

	unvmed_timer_free(&usq->timer);
	unvmed_cid_free(usq);
	unvmed_vcq_free(&usq->vcq);

	free(usq->cmds);
	free(usq);

	if (!qid)
		u->asq = NULL;
}

static struct unvme_cq *unvmed_init_ucq(struct unvme *u, uint32_t qid,
					uint32_t qsize, int vector, int pc)
{
	struct unvme_cq *ucq;
	bool alloc = false;

	ucq = unvmed_cq_get(u, qid);
	if (!ucq) {
		ucq = calloc(1, sizeof(*ucq));
		if (!ucq)
			return NULL;
		alloc = true;
	}

	if (ucq->enabled) {
		unvmed_log_err("ucq is already enabled");
		if (!alloc)
			unvmed_cq_put(u, ucq);
		return NULL;
	}

	if (alloc) {
		ucq->u = u;
		ucq->id = qid;
		pthread_spin_init(&ucq->lock, 0);

		pthread_rwlock_wrlock(&u->cqs_lock);
		u->cqs[qid] = ucq;
		if (!qid)
			u->acq = ucq;

		ucq->refcnt = 1;
		pthread_rwlock_unlock(&u->cqs_lock);
	}

	/*
	 * @qsize and @vector are changable whenever @ucq initialization.
	 */
	unvmed_cq_enter(ucq);
	ucq->q = &u->ctrl.cq[qid];
	ucq->qsize = qsize;
	ucq->vector = vector;
	ucq->pc = pc;

	if (!qid)
		u->ctrl.adminq.cq = ucq->q;

	unvmed_cq_exit(ucq);

	return ucq;
}

void unvmed_enable_cq(struct unvme_cq *ucq)
{
	atomic_store_release(&ucq->enabled, true);
}

static void __unvmed_free_ucq(struct unvme *u, struct unvme_cq *ucq)
{
	uint32_t qid = unvmed_cq_id(ucq);

	/*
	 * Prevent accessing @u->cqs array after free(ucq) by NULL-ing first.
	 * Otherwise, other thread context like cqe reaper, u->cqs[qid] might
	 * be corrupted.
	 */
	pthread_rwlock_wrlock(&u->cqs_lock);
	u->cqs[qid] = NULL;
	pthread_rwlock_unlock(&u->cqs_lock);

	free(ucq);

	if (!qid)
		u->acq = NULL;
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
	int qid;

	/*
	 * Make sure reaper thread to read the proper state value.
	 */
	unvmed_ctrl_set_state(u, UNVME_TEARDOWN);

	unvmed_free_irqs(u);
	unvmed_hmb_free(u);

	/* Clean up shared memory if allocated */
	if (u->shmem_vaddr && u->shmem_size > 0) {
		if (u->shmem_iova)
			unvmed_unmap_vaddr(u, u->shmem_vaddr);
		munmap(u->shmem_vaddr, u->shmem_size);
		if (u->shmem_fd >= 0)
			close(u->shmem_fd);
		if (u->shmem_name[0])
			shm_unlink(u->shmem_name);
	}

	for (qid = 0; qid < u->nr_sqs; qid++) {
		if (!u->sqs[qid])
			continue;
		__unvmed_free_usq(u, u->sqs[qid]);
	}

	for (qid = 0; qid < u->nr_cqs; qid++) {
		if (!u->cqs[qid])
			continue;
		__unvmed_free_ucq(u, u->cqs[qid]);
	}

	free(u->sqs);
	free(u->cqs);

	nvme_close(&u->ctrl);

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

static int __unvme_reset_ctrl(struct unvme *u)
{
	uint32_t cc;
	uint32_t csts;

	if (!unvmed_ctrl_set_state(u, UNVME_RESETTING)) {
		errno = EBUSY;
		return -1;
	}

	cc = unvmed_read32(u, NVME_REG_CC);
	unvmed_write32(u, NVME_REG_CC, cc & ~(1 << NVME_CC_EN_SHIFT));
	while (1) {
		csts = unvmed_read32(u, NVME_REG_CSTS);
		if (!NVME_CSTS_RDY(csts))
			break;
	}

	return 0;
}

static inline void unvmed_disable_sq_all(struct unvme *u)
{
	struct unvme_sq *usq;
	int qid;

	for (qid = 0; qid < u->nr_sqs; qid++) {
		usq = unvmed_sq_get(u, qid);
		if (!usq)
			continue;
		usq->enabled = false;
		unvmed_sq_put(u, usq);
	}
}

static inline void unvmed_disable_cq_all(struct unvme *u)
{
	struct unvme_cq *ucq;
	int qid;

	for (qid = 0; qid < u->nr_cqs; qid++) {
		ucq = unvmed_cq_get(u, qid);
		if (!ucq)
			continue;
		ucq->enabled = false;
		unvmed_cq_put(u, ucq);
	}
}

static inline void unvmed_disable_ns_all(struct unvme *u)
{
	struct __unvme_ns *ns;

	pthread_rwlock_rdlock(&u->ns_list_lock);
	list_for_each(&u->ns_list, ns, list)
		ns->enabled = false;
	pthread_rwlock_unlock(&u->ns_list_lock);
}

void unvmed_quiesce_sq_all(struct unvme *u)
{
	struct unvme_sq *usq;
	int qid;

	for (qid = 0; qid < u->nr_sqs; qid++) {
		usq = unvmed_sq_get(u, qid);
		if (!usq)
			continue;
		unvmed_sq_enter(usq);
		unvmed_sq_put(u, usq);
	}
}

void unvmed_unquiesce_sq_all(struct unvme *u)
{
	struct unvme_sq *usq;
	int qid;

	for (qid = 0; qid < u->nr_sqs; qid++) {
		usq = unvmed_sq_get(u, qid);
		if (!usq)
			continue;
		unvmed_sq_exit(usq);
		unvmed_sq_put(u, usq);
	}
}

static inline struct nvme_cqe *unvmed_get_cqe(struct unvme_cq *ucq, uint32_t head)
{
	return (struct nvme_cqe *)(ucq->q->mem.vaddr + (head << NVME_CQES));
}

static void __unvmed_cmd_cmpl(struct unvme_cmd *cmd, struct nvme_cqe *cqe)
{
	cmd->cqe = *cqe;
	atomic_store_release(&cmd->state, UNVME_CMD_S_COMPLETED);
	atomic_inc(&cmd->usq->cmd_count[cmd->sqe.opcode]);
	unvmed_log_cmd_cmpl(unvmed_bdf(cmd->u), cqe);
}

/*
 * Returns ``true`` if the given @cmd is woke up and finished.
 */
static bool unvmed_cmd_cmpl(struct unvme_cmd *cmd, struct nvme_cqe *cqe)
{
	struct unvme *u = cmd->u;
	int nr_cmds;

	/*
	 * Mark @cmd to be completed soon to prevent being cancelled by reset
	 * thread context.  For irq case, @cmd will be pushed to @vcq and
	 * during that time, reset thread may think @cmd is in SUBMITTED state
	 * and should be cancelled, but cqe of @cmd has already arrived, so we
	 * should mark here.
	 */
	atomic_store_release(&cmd->state, UNVME_CMD_S_TO_BE_COMPLETED);

	if (cmd->flags & UNVMED_CMD_F_WAKEUP_ON_CQE) {
		__unvmed_cmd_cmpl(cmd, cqe);

		atomic_store_release(&cmd->completed, 1);
		unvmed_futex_wake(&cmd->completed, 1);

		do {
			nr_cmds = u->nr_cmds;
		} while (!atomic_cmpxchg(&u->nr_cmds, nr_cmds, nr_cmds - 1));

		return true;
	}

	return false;
}

static inline void unvmed_put_cqe(struct unvme *u, struct unvme_cq *ucq,
				  struct unvme_cmd *cmd)
{
	uint16_t status = (NVME_SCT_PATH << NVME_SCT_SHIFT) |
		NVME_SC_CMD_ABORTED_BY_HOST;
	struct nvme_cqe cqe;

	cqe.qw0 = cpu_to_le64(0);
	cqe.sqhd = cpu_to_le16(0);
	cqe.sqid = cpu_to_le16(cmd->rq->sq->id);
	cqe.cid = cmd->cid;
	cqe.sfp = cpu_to_le16((status << 1));

	if (!unvmed_cmd_cmpl(cmd, &cqe))
		unvmed_vcq_push(u, &cqe);

	unvmed_log_info("canceled command (sqid=%u, cid=%u)", cqe.sqid, cqe.cid);
}

static inline void unvmed_cancel_sq(struct unvme *u, struct unvme_sq *usq)
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
			if (!cmd) {
				unvmed_log_err("invalid cqe (sqid=%d, cid=%d)",
						le16_to_cpu(cqe->sqid), cqe->cid);
				goto update;
			}

			cmd->state = UNVME_CMD_S_TO_BE_COMPLETED;

			/*
			 * Try to complete the @cmd here since the actual @ucq
			 * will not be reaped at all since callers will look at
			 * @vcq rather than the actual @ucq.
			 */
			if (!unvmed_cmd_cmpl(cmd, cqe))
				unvmed_vcq_push(u, cqe);

update:
			if (++head == ucq->q->qsize) {
				head = 0;
				phase ^= 0x1;
			}
		} else
			break;
	}

	for (int i = 0; i < usq->qsize; i++) {
		cmd = unvmed_get_cmd(usq, i);
		if (!cmd)
			continue;

		if (LOAD(cmd->state) == UNVME_CMD_S_SUBMITTED)
			unvmed_put_cqe(u, ucq, cmd);
	}

	unvmed_cq_exit(ucq);
}

static void unvmed_cq_drain(struct unvme *u, struct unvme_cq *ucq)
{
	struct nvme_cqe *cqe;
	uint32_t head;
	uint8_t phase;

	if (unvmed_cq_irq_enabled(ucq)) {
		struct unvme_cq_reaper *r = &u->reapers[unvmed_cq_iv(ucq)];

		eventfd_write(r->efd, 1);  /* Wake up reaper thread */

		/* Wait for reaper thread to reap the pending cq entries */
		do {
			phase = LOAD(ucq->q->phase);
			head = LOAD(ucq->q->head);

			cqe = unvmed_get_cqe(ucq, head);

			if (!unvmed_get_cmd_from_cqe(u, cqe)) {
				unvmed_log_err("invalid cqe, ignored (sqid=%d, cid=%d)",
						le16_to_cpu(cqe->sqid), cqe->cid);
				nvme_cq_get_cqe(ucq->q);
				continue;
			}
		} while ((le16_to_cpu(cqe->sfp) & 0x1) != phase);
	} else {
		/*
		 * If interrupt is disabled for the @ucq, here we can quiesce
		 * @ucq and reap the cq entries rather than waiting for the
		 * application to reap because appcliation *might* not try to
		 * reap the remaining entries due to some reasons (e.g.,
		 * terminated or scenario does not have reaping).
		 */
		__unvmed_reap_cqe(ucq);
	}
}

static void unvmed_vcq_drain(struct unvme_vcq *vcq)
{
	/* Wait for @vcq to be empty (reaped by application) */
	while (LOAD(vcq->head) != LOAD(vcq->tail))
		;
}

static void unvmed_cancel_cmd(struct unvme *u, struct unvme_sq *usq)
{
	if (!usq->q)
		return;

	/*
	 * Ensure that @usq->ucq to be drained before starting the cancel
	 * behavior which actually _manipulates_ the @vcq itself by pushing
	 * fake cq entries with tail pointer being updated to avoid race.
	 */
	unvmed_cq_drain(u, usq->ucq);
	unvmed_vcq_drain(&usq->vcq);

	unvmed_cancel_sq(u, usq);

	/*
	 * Wait for upper layer to complete canceled commands in their
	 * CQ reapding routine.  @usq>nr_cmds indicates the number of
	 * command which have not been freed by unvmed_cmd_put().
	 */
	while (atomic_load_acquire(&usq->nr_cmds) > 0)
		;
}

static inline void unvmed_cancel_cmd_all(struct unvme *u)
{
	struct unvme_sq *usq;
	int qid;

	for (qid = 0; qid < u->nr_sqs; qid++) {
		usq = unvmed_sq_get(u, qid);
		if (!usq)
			continue;

		unvmed_cancel_cmd(u, usq);
		unvmed_sq_put(u, usq);
	}
}

void unvmed_free_ctx(struct unvme *u)
{
	unvmed_free_ns_all(u);

	__unvmed_delete_sq_all(u);
	__unvmed_delete_cq_all(u);
}

void unvmed_disable_ctx(struct unvme *u)
{
	unvmed_disable_sq_all(u);
	unvmed_disable_cq_all(u);
	unvmed_disable_ns_all(u);
}

static void unvmed_cancel_cmds(struct unvme *u)
{
	/*
	 * Quiesce all submission queues to prevent I/O submission from upper
	 * layer.  The queues should be re-enabled (unquiesced) back once
	 * create I/O queue command is issued.
	 */
	unvmed_quiesce_sq_all(u);
	unvmed_cancel_cmd_all(u);
	unvmed_unquiesce_sq_all(u);
}

void unvmed_reset_ctx(struct unvme *u)
{
	unvmed_disable_ctx(u);
	unvmed_cancel_cmds(u);

	unvmed_ctrl_set_state(u, UNVME_DISABLED);
}

/*
 * Reset NVMe controller instance memory resources along with de-asserting
 * controller enable register.  The instance itself will not be freed which can
 * be re-used in later time.
 */
void unvmed_reset_ctrl(struct unvme *u)
{
	if (__unvme_reset_ctrl(u)) {
		unvmed_log_err("faeild to reset the controller");
		return;
	}

	unvmed_reset_ctx(u);
}

void unvmed_reset_ctrl_graceful(struct unvme *u)
{
	struct unvme_sq *usq;
	int qid;

	unvmed_disable_sq_all(u);
	unvmed_disable_cq_all(u);
	unvmed_disable_ns_all(u);

	/* Quiesce first to get the ownership for all SQs */
	unvmed_quiesce_sq_all(u);

	/*
	 * Wait for all the in-flight commands to complete, meaning that upper
	 * layer application consumed all the completion queue entries that
	 * issued.
	 */
	for (qid = 0; qid < u->nr_sqs; qid++) {
		usq = unvmed_sq_get(u, qid);
		if (!usq)
			continue;

		/*
		 * Update sq tail doorbell since application might have missed
		 * to update tail doorbell after posting commad instances.
		 * We've already quiesced all SQs here in this context, we
		 * should update the missing doorbell update and wait for the
		 * commands to complete gracefully.
		 */
		unvmed_sq_update_tail(u, usq);

		while (atomic_load_acquire(&usq->nr_cmds) > 0)
			;

		unvmed_sq_put(u, usq);
	}

	/*
	 * Unquiesce all SQs here since we already _disabled_ all the queues so
	 * that application has already been stuck issuing commands.  It's
	 * totally safe to unquiesce queues here after @usq->nr_cmds becomes 0.
	 */
	unvmed_unquiesce_sq_all(u);

	unvmed_delete_iosq_all(u);
	unvmed_delete_iocq_all(u);

	__unvme_reset_ctrl(u);

	unvmed_free_ns_all(u);

	__unvmed_delete_sq(u, u->asq);
	__unvmed_delete_cq(u, u->acq);

	unvmed_ctrl_set_state(u, UNVME_DISABLED);
}

/*
 * Called only if @ucq interrupt is enabled (@ucq->vector != -1)
 */
static void __unvmed_reap_cqe(struct unvme_cq *ucq)
{
	struct unvme *u = ucq->u;
	struct unvme_cmd *cmd;
	struct nvme_cqe *cqe;
	int ret;

	unvmed_cq_enter(ucq);
	if (!ucq->q) {
		unvmed_cq_exit(ucq);
		return;
	}

	while (true) {
		cqe = unvmed_get_completion(u, ucq);
		if (!cqe)
			break;

		cmd = unvmed_get_cmd_from_cqe(u, cqe);
		if (!cmd) {
			unvmed_log_err("invalid cqe (sqid=%d, cid=%d)",
					le16_to_cpu(cqe->sqid), cqe->cid);
			continue;
		}

		if (unvmed_cmd_cmpl(cmd, cqe))
			goto up;

		/*
		 * To protect @vcq, we lock @ucq instance here since the only
		 * thread context which races with the current context is
		 * unvmed_cancel_sq where @ucq lock actually held.
		 */
		do {
			ret = unvmed_vcq_push(u, cqe);
		} while (ret == -EAGAIN);

up:
		nvme_cq_update_head(ucq->q);
	}
	unvmed_cq_exit(ucq);
}

static void *unvmed_reaper_run(void *opaque)
{
	struct unvme_cq_reaper *r = opaque;
	struct unvme *u = r->u;
	int vector = r->vector;
	int qid;

	unvmed_log_info("%s: reaped CQ thread started (vector=%d, tid=%d)",
			unvmed_bdf(u), vector, gettid());

	while (true) {
		struct unvme_cq *ucq;

		if (unvmed_cq_wait_irq(u, vector))
			goto out;

		if (!atomic_load_acquire(&r->refcnt))
			goto out;

		if (unvmed_ctrl_get_state(u) == UNVME_TEARDOWN)
			goto out;

		/*
		 * XXX: Reaper thread does not have to iterate all the @cqs
		 * array to find out the corresponding CQ instances.  But, we
		 * can't simply decide the target CQ instances in the beginning
		 * stage since a CQ whose irq vector is the same of the current
		 * reaper thread can always be created even after this reaper
		 * gets started.
		 *
		 * @ucq should be grabbed(get) here in the thread context to
		 * prevent use-after-free, but for now, other reset context
		 * considers reaper thread properly, so will implement later.
		 */
		for (qid = 0; qid < u->nr_cqs; qid++) {
			pthread_rwlock_rdlock(&u->cqs_lock);
			ucq = u->cqs[qid];
			/*
			 * The reason why we should check unvmed_cq_size(ucq)
			 * is that @ucq->q will never be NULL if @ucq instance
			 * is still alive, but the contents of @ucq->q can be
			 * all-zero.  So skip the removed queue.
			 */
			if (ucq && unvmed_cq_iv(ucq) == r->vector)
				__unvmed_reap_cqe(ucq);
			pthread_rwlock_unlock(&u->cqs_lock);
		}
	}

out:
	unvmed_log_info("%s: reaped CQ thread terminated (vector=%d, tid=%d)",
			unvmed_bdf(u), vector, gettid());

	pthread_exit(NULL);
}

static void unvmed_discard_sq(struct unvme *u, uint32_t qid)
{
	struct unvme_sq *usq;

	pthread_rwlock_rdlock(&u->sqs_lock);
	usq = u->sqs[qid];
	if (usq && usq->q) {
		unvmed_sq_enter(usq);
		nvme_discard_sq(&u->ctrl, &u->ctrl.sq[qid]);
		if (u->sqs[qid])
			u->sqs[qid]->q = NULL;
		unvmed_sq_exit(usq);
	}
	pthread_rwlock_unlock(&u->sqs_lock);
}

static void unvmed_discard_cq(struct unvme *u, uint32_t qid)
{
	struct unvme_cq *ucq;

	pthread_rwlock_rdlock(&u->cqs_lock);
	ucq = u->cqs[qid];
	if (ucq && ucq->q) {
		unvmed_cq_enter(ucq);  /* prevent use-after-free for ucq->q */
		nvme_discard_cq(&u->ctrl, ucq->q);
		if (u->cqs[qid])
			ucq->q = NULL;
		unvmed_cq_exit(ucq);
	}
	pthread_rwlock_unlock(&u->cqs_lock);
}

int unvmed_configure_adminq(struct unvme *u, struct unvme_sq *usq,
			    struct unvme_cq *ucq)
{
	uint32_t aqa = unvmed_read32(u, NVME_REG_AQA);

	if (!usq || !ucq) {
		unvmed_log_err("@usq or @ucq is NULL");
		errno = EINVAL;
		return -1;
	}

	aqa = usq->qsize - 1;
	aqa |= (ucq->qsize - 1) << 16;

	unvmed_write32(u, NVME_REG_AQA, cpu_to_le32(aqa));
	unvmed_write64(u, NVME_REG_ASQ, cpu_to_le64(usq->q->mem.iova));
	unvmed_write64(u, NVME_REG_ACQ, cpu_to_le64(ucq->q->mem.iova));

	return 0;
}

int unvmed_create_adminq(struct unvme *u, uint32_t sq_size,
			 uint32_t cq_size, bool irq)
{
	struct unvme_sq *usq;
	struct unvme_cq *ucq;
	const uint16_t qid = 0;
	bool irq_enabled = false;

	if (unvmed_ctrl_get_state(u) != UNVME_DISABLED) {
		errno = EPERM;
		goto out;
	}

	if (irq && u->nr_irqs > 0) {
		if (unvmed_init_irq(u, 0)) {
			unvmed_log_err("failed to initialize irq (nr_irqs=%d, vector=0, errno=%d \"%s\")",
					u->nr_irqs, errno, strerror(errno));
			return -1;
		}

		irq_enabled = true;
	}

	ucq = unvmed_init_cq(u, qid, cq_size, 0, 1);
	if (!ucq) {
		unvmed_log_err("failed to allocate cq memory");
		goto free_irq;
	}

	usq = unvmed_init_sq(u, qid, sq_size, qid, 0, 1, 0);
	if (!usq) {
		unvmed_log_err("failed to allocate sq memory");
		goto free_cq;
	}

	if (unvmed_configure_adminq(u, usq, ucq)) {
		unvmed_log_err("failed to configure adminq");
		goto free_sq;
	}

	/*
	 * Override @q->vector of libvfn in case device has no irq to -1.
	 */
	if (!irq || u->nr_irqs == 0) {
		ucq->q->vector = -1;
		unvmed_cq_iv(ucq) = -1;
	}

	return 0;

free_sq:
	unvmed_free_sq(u, qid);
free_cq:
	unvmed_free_cq(u, qid);
free_irq:
	if (irq_enabled)
		unvmed_free_irq(u, 0);
out:
	return -1;
}

int unvmed_enable_ctrl(struct unvme *u, uint8_t iosqes, uint8_t iocqes,
		      uint8_t mps, uint8_t css, int timeout)
{
	uint32_t cc;
	uint32_t csts;

	if (!unvmed_ctrl_set_state(u, UNVME_ENABLING)) {
		errno = EBUSY;
		return -1;
	}

	cc = unvmed_read32(u, NVME_REG_CC);
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

	u->mps = mps;
	u->timeout = timeout;

	/*
	 * After the device is enabled, we have to enable the adminq.
	 */
	if (u->acq)
		unvmed_enable_cq(u->acq);
	if (u->asq)
		unvmed_enable_sq(u->asq);

	unvmed_ctrl_set_state(u, UNVME_ENABLED);
	return 0;
}

int unvmed_create_cq(struct unvme *u, uint32_t qid, uint32_t qsize, int vector,
		     uint32_t pc)
{
	struct unvme_cq *ucq;
	struct unvme_cmd *cmd;
	struct unvme_sq *asq;
	struct nvme_cmd_create_cq *sqe;
	uint16_t qflags = 0;
	uint16_t iv = 0;

	if (vector >= 0 && unvmed_init_irq(u, vector)) {
		unvmed_log_err("failed to initialize irq (nr_irqs=%d, vector=%d, errno=%d \"%s\")",
				u->nr_irqs, vector, errno, strerror(errno));
		return -1;
	}

	asq = unvmed_sq_get(u, 0);
	if (!asq) {
		unvmed_log_err("failed to find adminq");
		errno = EINVAL;
		return -1;
	}

	if (nvme_configure_cq(&u->ctrl, qid, qsize, vector)) {
		unvmed_log_err("could not configure io completion queue");

		unvmed_sq_put(u, asq);
		return -1;
	}

	unvmed_sq_enter(asq);

	/*
	 * Retry if @cmd is not allocated at the point since this function is
	 * only called in reset context thread, and we can't simply ensure that
	 * other admin application is running out there.
	 */
	do {
		cmd = unvmed_alloc_cmd_nodata(u, asq, NULL);
	} while (!cmd && errno == EBUSY);

	if (!cmd) {
		unvmed_log_err("failed to allocate command instance "
				"(errno=%d \"%s\")", errno, strerror(errno));

		unvmed_sq_exit(asq);
		nvme_discard_cq(&u->ctrl, &u->ctrl.cq[qid]);
		unvmed_sq_put(u, asq);
		return -1;
	}

	cmd->flags = UNVMED_CMD_F_WAKEUP_ON_CQE;

	if (vector >= 0) {
		qflags |= NVME_CQ_IEN;
		iv = (uint16_t)vector;
	}

	if (pc)
		qflags |= NVME_Q_PC;

	sqe = (struct nvme_cmd_create_cq *)&cmd->sqe;
	sqe->opcode = nvme_admin_create_cq;
	sqe->qid = cpu_to_le16(qid);
	sqe->prp1 = cpu_to_le64(u->ctrl.cq[qid].mem.iova);
	sqe->qsize = cpu_to_le16((uint16_t)(qsize - 1));
	sqe->qflags = cpu_to_le16(qflags);
	sqe->iv = cpu_to_le16(iv);

	unvmed_cmd_post(cmd, &cmd->sqe, 0);
	unvmed_sq_exit(asq);

	unvmed_cmd_wait(cmd);

	if (!nvme_cqe_ok(&cmd->cqe)) {
		unvmed_log_err("failed to create iosq with cqe.status=%#x",
				unvmed_cqe_status(&cmd->cqe));

		unvmed_cmd_put(cmd);
		nvme_discard_cq(&u->ctrl, &u->ctrl.cq[qid]);
		unvmed_sq_put(u, asq);
		errno = EINVAL;
		return -1;
	}

	ucq = unvmed_init_ucq(u, qid, qsize, vector, pc);
	if (!ucq) {
		unvmed_log_err("failed to initialize ucq instance. "
				"discard cq instance from libvfn (qid=%d)",
				qid);

		unvmed_cmd_put(cmd);
		nvme_discard_cq(&u->ctrl, &u->ctrl.cq[qid]);
		unvmed_sq_put(u, asq);
		return -1;
	}

	if (vector < 0) {
		ucq->q->vector = -1;
		unvmed_cq_iv(ucq) = -1;
	}

	unvmed_enable_cq(ucq);

	unvmed_cmd_put(cmd);
	unvmed_sq_put(u, asq);
	return 0;
}

static void __unvmed_delete_cq(struct unvme *u, struct unvme_cq *ucq)
{
	uint32_t qid = unvmed_cq_id(ucq);
	int vector = unvmed_cq_iv(ucq);
	bool irq = unvmed_cq_irq_enabled(ucq);

	unvmed_discard_cq(u, qid);
	if (!unvmed_cq_put(u, ucq)) {
		if (irq)
			unvmed_free_irq(u, vector);
	}
}

static void __unvmed_delete_cq_all(struct unvme *u)
{
	struct unvme_cq *ucq;
	int refcnt;
	int qid;

	unvmed_free_irq_all(u);

	for (qid = 0; qid < u->nr_cqs; qid++) {
		ucq = unvmed_cq_get(u, qid);
		if (!ucq)
			continue;

		unvmed_log_info("Deleting ucq (qid=%d)", unvmed_cq_id(ucq));

		/*
		 * @usq has been acquired in the current function, meaning that
		 * if unvmed_cq_put() returns 1, it means it's ready to be
		 * freed up since this was supposed to be freed.
		 */
		refcnt = unvmed_cq_put(u, ucq);
		assert(refcnt > 0);

		unvmed_discard_cq(u, qid);
		unvmed_cq_put(u, ucq);
	}
}

static int unvmed_delete_sq(struct unvme *u, uint32_t qid);
static int unvmed_delete_cq(struct unvme *u, uint32_t qid)
{
	struct unvme_cmd *cmd;
	struct unvme_sq *asq;
	struct nvme_cmd_delete_q *sqe;
	int ret;

	asq = unvmed_sq_get(u, 0);
	if (!asq) {
		unvmed_log_err("failed to find adminq");
		errno = EINVAL;
		return -1;
	}

	unvmed_sq_enter(asq);

	/*
	 * Retry if @cmd is not allocated at the point since this function is
	 * only called in reset context thread, and we can't simply ensure that
	 * other admin application is running out there.
	 */
	do {
		cmd = unvmed_alloc_cmd_nodata(u, asq, NULL);
	} while (!cmd && errno == EBUSY);

	if (!cmd) {
		unvmed_log_err("failed to allocate a command instance "
				"(errno=%d \"%s\")", errno, strerror(errno));

		unvmed_sq_exit(asq);
		return -1;
	}

	cmd->flags = UNVMED_CMD_F_WAKEUP_ON_CQE;

	sqe = (struct nvme_cmd_delete_q *)&cmd->sqe;
	sqe->opcode = nvme_admin_delete_cq;
	sqe->qid = cpu_to_le16(qid);

	unvmed_cmd_post(cmd, &cmd->sqe, 0);
	unvmed_sq_exit(asq);

	unvmed_cmd_wait(cmd);

	if (nvme_cqe_ok(&cmd->cqe)) {
		struct unvme_cq *ucq = unvmed_cq_find(u, qid);
		if (ucq)
			__unvmed_delete_cq(u, ucq);
	}

	ret = unvmed_cqe_status(&cmd->cqe);
	if (ret == 0x10C)
		errno = EILSEQ;

	unvmed_cmd_put(cmd);
	unvmed_sq_put(u, asq);
	return ret;
}

int unvmed_create_sq(struct unvme *u, uint32_t qid, uint32_t qsize,
		    uint32_t cqid, uint32_t qprio, uint32_t pc, uint32_t nvmsetid)
{
	struct unvme_sq *usq;
	struct unvme_cq *ucq;
	struct unvme_cmd *cmd;
	struct unvme_sq *asq;
	struct nvme_cmd_create_sq *sqe;
	uint16_t qflags = 0;

	if (!unvmed_ctrl_enabled(u)) {
		errno = EPERM;
		return -1;
	}

	asq = unvmed_sq_get(u, 0);
	if (!asq) {
		unvmed_log_err("failed to find adminq");
		errno = EINVAL;
		return -1;
	}

	ucq = unvmed_cq_get(u, cqid);
	if (!ucq) {
		unvmed_log_err("failed to get cq instance (qid=%d)", cqid);

		unvmed_sq_put(u, asq);
		errno = ENODEV;
		return -1;
	}

	if (nvme_configure_sq(&u->ctrl, qid, qsize, ucq->q, 0)) {
		unvmed_log_err("could not configure io submission queue");

		unvmed_cq_put(u, ucq);
		unvmed_sq_put(u, asq);
		return -1;
	}

	unvmed_sq_enter(asq);

	/*
	 * Retry if @cmd is not allocated at the point since this function is
	 * only called in reset context thread, and we can't simply ensure that
	 * other admin application is running out there.
	 */
	do {
		cmd = unvmed_alloc_cmd_nodata(u, asq, NULL);
	} while (!cmd && errno == EBUSY);

	if (!cmd) {
		unvmed_log_err("failed to allocate command instance "
				"(errno=%d \"%s\")", errno, strerror(errno));

		unvmed_sq_exit(asq);
		nvme_discard_sq(&u->ctrl, &u->ctrl.sq[qid]);
		unvmed_cq_put(u, ucq);
		unvmed_sq_put(u, asq);
		return -1;
	}

	cmd->flags = UNVMED_CMD_F_WAKEUP_ON_CQE;

	qflags = (qprio & 0x3) << 1;
	if (pc)
		qflags |= NVME_Q_PC;

	sqe = (struct nvme_cmd_create_sq *)&cmd->sqe;
	sqe->opcode = nvme_admin_create_sq;
	sqe->qid = cpu_to_le16(qid);
	sqe->prp1 = cpu_to_le64(u->ctrl.sq[qid].mem.iova);
	sqe->qsize = cpu_to_le16((uint16_t)(qsize - 1));
	sqe->qflags = cpu_to_le16(qflags);
	sqe->rsvd12[0] = cpu_to_le32(nvmsetid);
	sqe->cqid = cpu_to_le16((uint16_t)ucq->id);

	unvmed_cmd_post(cmd, &cmd->sqe, 0);
	unvmed_sq_exit(asq);

	unvmed_cmd_wait(cmd);

	if (!nvme_cqe_ok(&cmd->cqe)) {
		unvmed_log_err("failed to create iosq with cqe.status=%#x",
				unvmed_cqe_status(&cmd->cqe));

		unvmed_cmd_put(cmd);
		nvme_discard_sq(&u->ctrl, &u->ctrl.sq[qid]);
		unvmed_cq_put(u, ucq);
		unvmed_sq_put(u, asq);
		errno = EINVAL;
		return -1;
	}

	usq = unvmed_init_usq(u, qid, qsize, ucq, qprio, pc, nvmsetid);
	if (!usq) {
		unvmed_log_err("failed to initialize usq instance. "
				"discard sq instance from libvfn (qid=%d)",
				qid);
		unvmed_cmd_put(cmd);
		nvme_discard_sq(&u->ctrl, &u->ctrl.sq[qid]);
		unvmed_cq_put(u, ucq);
		unvmed_sq_put(u, asq);
		return -1;
	}
	unvmed_enable_sq(usq);

	unvmed_cmd_put(cmd);
	unvmed_cq_put(u, ucq);
	unvmed_sq_put(u, asq);
	return 0;
}

static void __unvmed_delete_sq(struct unvme *u, struct unvme_sq *usq)
{
	uint32_t qid = unvmed_sq_id(usq);

	unvmed_discard_sq(u, qid);
	unvmed_sq_put(u, usq);
}

static void unvmed_delete_iosq_all(struct unvme *u)
{
	int qid;

	for (qid = 1; qid < u->nr_sqs; qid++) {
		struct unvme_sq *usq = unvmed_sq_find(u, qid);

		if (usq && atomic_load_acquire(&usq->refcnt) > 0) {
			if (unvmed_delete_sq(u, qid) < 0) {
				unvmed_log_err("failed to delete I/O SQ (qid=%d)", qid);
				return;
			}
		}
	}
}

static void unvmed_delete_iocq_all(struct unvme *u)
{
	int qid;

	for (qid = 1; qid < u->nr_cqs; qid++) {
		struct unvme_cq *ucq = unvmed_cq_find(u, qid);

		if (ucq && atomic_load_acquire(&ucq->refcnt) > 0) {
			if (unvmed_delete_cq(u, qid) < 0) {
				unvmed_log_err("failed to delete I/O CQ (qid=%d)", qid);
				return;
			}
		}
	}
}

static void __unvmed_delete_sq_all(struct unvme *u)
{
	struct unvme_sq *usq;
	int refcnt;
	int qid;

	for (qid = 0; qid < u->nr_sqs; qid++) {
		usq = unvmed_sq_get(u, qid);
		if (!usq)
			continue;

		unvmed_log_info("Deleting usq (qid=%d)", unvmed_sq_id(usq));

		/*
		 * @usq has been acquired in the current function, meaning that
		 * if unvmed_sq_put() returns 1, it means it's ready to be
		 * freed up since this was supposed to be freed.
		 */
		refcnt = unvmed_sq_put(u, usq);
		assert(refcnt > 0);

		unvmed_discard_sq(u, qid);
		unvmed_sq_put(u, usq);
	}
}

static int unvmed_delete_sq(struct unvme *u, uint32_t qid)
{
	struct unvme_cmd *cmd;
	struct unvme_sq *asq;
	struct nvme_cmd_delete_q *sqe;
	int ret;

	asq = unvmed_sq_get(u, 0);
	if (!asq) {
		unvmed_log_err("failed to find adminq");
		errno = EINVAL;
		return -1;
	}

	unvmed_sq_enter(asq);

	/*
	 * Retry if @cmd is not allocated at the point since this function is
	 * only called in reset context thread, and we can't simply ensure that
	 * other admin application is running out there.
	 */
	do {
		cmd = unvmed_alloc_cmd_nodata(u, asq, NULL);
	} while (!cmd && errno == EBUSY);

	if (!cmd) {
		unvmed_log_err("failed to allocate command instance "
				"(errno=%d \"%s\")", errno, strerror(errno));

		unvmed_sq_exit(asq);
		unvmed_sq_put(u, asq);
		return -1;
	}

	cmd->flags = UNVMED_CMD_F_WAKEUP_ON_CQE;

	sqe = (struct nvme_cmd_delete_q *)&cmd->sqe;
	sqe->opcode = nvme_admin_delete_sq;
	sqe->qid = cpu_to_le16(qid);

	unvmed_cmd_post(cmd, &cmd->sqe, 0);
	unvmed_sq_exit(asq);

	unvmed_cmd_wait(cmd);

	if (nvme_cqe_ok(&cmd->cqe)) {
		struct unvme_sq *usq = unvmed_sq_find(u, qid);
		if (usq)
			__unvmed_delete_sq(u, usq);
	}

	ret = unvmed_cqe_status(&cmd->cqe);

	unvmed_cmd_put(cmd);
	unvmed_sq_put(u, asq);
	return ret;
}

int unvmed_to_iova(struct unvme *u, void *buf, uint64_t *iova)
{
	struct iommu_ctx *ctx = __iommu_ctx(&u->ctrl);

	return !iommu_translate_vaddr(ctx, buf, iova);
}

ssize_t unvmed_to_vaddr(struct unvme *u, uint64_t iova, void **vaddr)
{
	struct iommu_ctx *ctx = __iommu_ctx(&u->ctrl);
	ssize_t ret;

	ret = iommu_translate_iova(ctx, iova, vaddr);
	if (ret < 0)
		return -1;

	return ret;
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

static void unvmed_cmd_add_timer(struct unvme_cmd *cmd)
{
	int timeout = cmd->u->timeout;

	clock_gettime(CLOCK_MONOTONIC, &cmd->timeout);
	cmd->timeout.tv_sec += timeout;

	if (atomic_load_acquire(&cmd->usq->timer.active) &&
			!unvmed_timer_running(&cmd->usq->timer))
		unvmed_timer_update(cmd->usq, cmd->u->timeout);
}

uint16_t unvmed_cmd_post(struct unvme_cmd *cmd, union nvme_cmd *sqe,
			 unsigned long flags)
{
	uint16_t idx = cmd->rq->sq->tail;
	int nr_cmds;

	sqe->cid = cmd->cid;
	nvme_sq_post(cmd->rq->sq, (union nvme_cmd *)sqe);

	atomic_store_release(&cmd->state, UNVME_CMD_S_SUBMITTED);
	unvmed_log_cmd_post(unvmed_bdf(cmd->u), cmd->rq->sq->id, sqe);

	do {
		nr_cmds = cmd->u->nr_cmds;
	} while (!atomic_cmpxchg(&cmd->u->nr_cmds, nr_cmds, nr_cmds + 1));

	if (cmd->u->timeout)
		unvmed_cmd_add_timer(cmd);

	if (!(flags & UNVMED_CMD_F_NODB))
		nvme_sq_update_tail(cmd->rq->sq);

	return idx;
}

static struct unvme_cmd *unvmed_get_cmd_from_cqe(struct unvme *u,
						 struct nvme_cqe *cqe)
{
	struct unvme_sq *usq;

	/*
	 * We don't have get/put scheme here since @usq instance can only be
	 * freed up in reset context or delete I/O submission queue context and
	 * those behaviors will ensure that all the CQ reaping processes are
	 * stopped(quiesced).
	 */
	usq = unvmed_sq_find(u, le16_to_cpu(cqe->sqid));
	if (!usq)
		return NULL;

	return unvmed_get_cmd(usq, cqe->cid);
}

static struct nvme_cqe *unvmed_get_completion(struct unvme *u,
					      struct unvme_cq *ucq)
{
	struct nvme_cq *cq = ucq->q;
	struct nvme_cqe *cqe;

	cqe = nvme_cq_get_cqe(cq);

	return cqe;
}

/*
 * Called only if @ucq interrupt is disabled (@ucq->vector == -1)
 */
static struct nvme_cqe *__unvmed_get_completion(struct unvme *u,
						struct unvme_sq *usq,
						struct unvme_vcq *vcq,
						struct unvme_cq *ucq)
{
	int ret;
	struct unvme_cmd *cmd;
	struct nvme_cqe __cqe;
	struct nvme_cqe *cqe = &__cqe;
	struct unvme_vcq *__vcq = vcq ? vcq : &usq->vcq;

	ret = unvmed_vcq_pop(__vcq, &__cqe);
	if (ret != -ENOENT) {
		cmd = unvmed_get_cmd(usq, cqe->cid);
		if (cmd) {
			__unvmed_cmd_cmpl(cmd, cqe);
			return cqe;
		} else {
			unvmed_log_err("invalid cqe (sqid=%d, cid=%d)",
					le16_to_cpu(cqe->sqid), cqe->cid);
			return NULL;
		}
	}

	unvmed_cq_enter(ucq);
	cqe = unvmed_get_completion(u, ucq);
	if (cqe) {
		cmd = unvmed_get_cmd(usq, cqe->cid);
		if (cmd && !unvmed_cmd_cmpl(cmd, cqe))
			unvmed_vcq_push(u, cqe);

		nvme_cq_update_head(ucq->q);
		cqe = NULL;
	}
	unvmed_cq_exit(ucq);

	return cqe;
}

int __unvmed_cq_run_n(struct unvme *u, struct unvme_sq *usq, struct unvme_cq *ucq,
		      struct unvme_vcq *vcq, struct nvme_cqe *cqes, int nr_cqes,
		      bool nowait)
{
	struct unvme_vcq *__vcq = vcq ? vcq : &usq->vcq;
	struct nvme_cqe __cqe;
	struct nvme_cqe *cqe = &__cqe;
	struct unvme_cmd *cmd;
	int nr_cmds;
	int nr = 0;
	int ret;

	while (nr < nr_cqes) {
		if (unvmed_cq_irq_enabled(ucq)) {
			do {
				ret = unvmed_vcq_pop(__vcq, &__cqe);
			} while (ret == -ENOENT && !nowait);

			if (ret)
				break;

			cmd = unvmed_get_cmd(usq, cqe->cid);
			if (cmd)
				__unvmed_cmd_cmpl(cmd, cqe);
			else {
				unvmed_log_err("invalid cqe (sqid=%d, cid=%d)",
						le16_to_cpu(cqe->sqid), cqe->cid);
				continue;
			}
		} else {
			cqe = __unvmed_get_completion(u, usq, __vcq, ucq);

			if (!cqe) {
				if (nowait)
					break;
				continue;
			}
		}

		if (cqes)
			memcpy(&cqes[nr], cqe, sizeof(*cqe));
		nr++;
	}

	do {
		nr_cmds = u->nr_cmds;
	} while (!atomic_cmpxchg(&u->nr_cmds, nr_cmds, nr_cmds - nr));

	return nr;
}

int unvmed_cq_run(struct unvme *u, struct unvme_sq *usq, struct unvme_cq *ucq, struct nvme_cqe *cqes)
{
	return __unvmed_cq_run_n(u, usq, ucq, NULL, cqes, ucq->q->qsize - 1, true);
}

int unvmed_cq_run_n(struct unvme *u, struct unvme_sq *usq, struct unvme_cq *ucq,
		    struct unvme_vcq *vcq, struct nvme_cqe *cqes, int min, int max)
{
	int ret;
	int n;

	n = __unvmed_cq_run_n(u, usq, ucq, vcq, cqes, min, false);
	if (n < 0)
		return -1;

	ret = n;

	if (ret >= max)
		return ret;

	n = __unvmed_cq_run_n(u, usq, ucq, vcq, cqes + n, max - n, true);
	if (n < 0)
		return -1;

	return ret + n;
}

static int unvmed_sq_nr_pending_sqes(struct unvme_sq *usq)
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

	nr_sqes = unvmed_sq_nr_pending_sqes(usq);
	if (!nr_sqes)
		return 0;

	nvme_sq_update_tail(usq->q);

	return nr_sqes;
}

static inline int unvmed_pci_get_config(const char *bdf, void *buf,
					off_t offset, size_t size) {
	char *path = NULL;
	int ret;
	int fd;

	ret = asprintf(&path, "/sys/bus/pci/devices/%s/config", bdf);
	if (ret < 0)
		return -1;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		free(path);
		return -1;
	}

	ret = pread(fd, buf, size, offset);
	if (ret < size) {
		unvmed_log_err("failed to read config register");
		close(fd);
		free(path);
		return -1;
	}

	close(fd);
	free(path);
	return 0;
}

static inline int unvmed_pci_backup_config(struct unvme *u, void *config)
{
	return unvmed_pci_get_config(unvmed_bdf(u), config, 0, 0x1000);
}

static inline int unvmed_pci_restore_config(struct unvme *u, void *config)
{
	char *path = NULL;
	int ret;
	int fd;

	ret = asprintf(&path, "/sys/bus/pci/devices/%s/config", unvmed_bdf(u));
	if (ret < 0)
		return -1;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		free(path);
		return -1;
	}

	/*
	 * Restoring PCI configuration space register should proceed without
	 * vfio-pci driver awareness since writing config space registers might
	 * be blocked in vfio-pci driver in the kernel.
	 */
	ret = write(fd, config, 4096);
	if (ret < 0) {
		close(fd);
		free(path);
		return -1;
	}

	close(fd);
	free(path);
	return 0;
}

static int unvmed_pci_backup_state(struct unvme *u, void *config)
{
	return unvmed_pci_backup_config(u, config);
}

static int unvmed_pci_restore_state(struct unvme *u, void *config)
{
	uint32_t csts;

	if (unvmed_pci_restore_config(u, config))
		return -1;

	while (true) {
		csts = unvmed_read32(u, NVME_REG_CSTS);
		if (!NVME_CSTS_RDY(csts))
			break;

		usleep(1000);
	}

	return 0;
}

static void unvmed_quirk_dsp_sleep_after_reset(struct unvme *u)
{
	unsigned long long vendor, device;
	char dsp[13];

	if (unvmed_get_downstream_port(u, dsp))
		return;

	if (pci_device_info_get_ull(dsp, "vendor", &vendor))
		return;

	if (pci_device_info_get_ull(dsp, "device", &device))
		return;

	/*
	 * 8086:7f30: PCI bridge: Intel Corporation Device 7f30 (rev 10).
	 * Sleep 100ms to avoid duplicated TLP to be issued with the same tag.
	 */
	if (vendor == 0x8086 && device == 0x7f30)
		usleep(100000);
}

static int unvmed_pci_wait_reset(struct unvme *u)
{
	uint16_t pcie_offset;
	uint16_t link_status;
	uint64_t bar0;
	char dsp[13];

	if (unvmed_get_downstream_port(u, dsp) < 0) {
		unvmed_log_err("failed to get downstream port while waiting to be reset");
		return -1;
	}

	pcie_offset = unvmed_get_pcie_cap_offset(dsp);
	if (pcie_offset == -1) {
		unvmed_log_err("failed to get PCIe Cap. register offset (0xffff)");
		return -1;
	}

	unvmed_log_debug("waiting for DSP(%s) link to be up ...", dsp);
	while (true) {
		if (unvmed_pci_get_config(dsp, &link_status, pcie_offset + 0x12, 2)) {
			unvmed_log_err("failed to CfgRd (offset=%#x, size=%d)",
					pcie_offset + 0x12, 2);
			return -1;
		}

		/*
		 * Wait for the following bitfield in Link Status Register.
		 *   - [13] Data Link Layer Link Active
		 */
		if (link_status & (1 << 13))
			break;

	}

	unvmed_log_debug("waiting for USP(%s) link to be reset ...",
			unvmed_bdf(u));
	while (true) {
		if (unvmed_pci_get_config(unvmed_bdf(u), &bar0, 0x10, 8)) {
			unvmed_log_err("failed to CfgRd (offset=%#x, size=%d)",
					0x10, 8);
			return -1;
		}

		/*
		 * Wait until BAR0 register to be reset to 0x0
		 */
		if ((bar0 & ~0xfULL) == 0x0)
			break;

		usleep(1000);
	}

	unvmed_quirk_dsp_sleep_after_reset(u);

	unvmed_log_debug("DSP(%s) <-> USP(%s) has been reset successfully",
			dsp, unvmed_bdf(u));
	return 0;
}

int unvmed_subsystem_reset(struct unvme *u)
{
	char config[4096];
	uint32_t csts;

	if (!unvmed_ctrl_set_state(u, UNVME_RESETTING)) {
		errno = EBUSY;
		return -1;
	}

	if (unvmed_pci_backup_state(u, config) < 0) {
		unvmed_log_err("failed to read pci config register");
		return -1;
	}

	unvmed_write32(u, NVME_REG_NSSR, 0x4E564D65);

	/*
	 * NSSR will be handled from device side, not the host side, which
	 * means we should make sure that the PCI config register is reset by
	 * device before preceeding.
	 */
	if (unvmed_pci_wait_reset(u) < 0) {
		unvmed_log_err("failed to wait for PCI to be reset");
		return -1;
	}

	if (unvmed_pci_restore_state(u, config) < 0) {
		unvmed_log_err("failed to write pci config register");
		return -1;
	}

	/*
	 * Wait for the NSSRO bitfield and clear it.
	 */
	while (true) {
		csts = unvmed_read32(u, NVME_REG_CSTS);
		if (NVME_CSTS_NSSRO(csts)) {
			unvmed_write32(u, NVME_REG_CSTS,
					1 << NVME_CSTS_NSSRO_SHIFT);
			break;
		}
	}

	unvmed_reset_ctx(u);

	return 0;
}

int unvmed_flr(struct unvme *u)
{
	char *path = NULL;
	char config[4096];
	uint32_t cap;
	uint16_t control;
	int ret;
	int fd;

	ret = asprintf(&path, "/sys/bus/pci/devices/%s/config", unvmed_bdf(u));
	if (ret < 0)
		return -1;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		ret = fd;
		goto free;
	}


	uint16_t pcie_offset = unvmed_get_pcie_cap_offset(unvmed_bdf(u));
	if (pcie_offset == -1) {
		unvmed_log_err("failed to get PCIe Cap. register offset (0xffff)");
		ret = -1;
		goto close;
	}

	if (unvmed_pci_get_config(unvmed_bdf(u), &cap, pcie_offset + 0x4, 4)) {
		unvmed_log_err("failed to CfgRd (offset=%#x, size=%d)",
				pcie_offset + 0x4, 4);
		ret = -1;
		goto close;
	}

	if (!(cap & (1 << 28))) {
		unvmed_log_err("flr not supported");
		errno = ENOTSUP;
		ret = -1;
		goto close;
	}

	if (!unvmed_ctrl_set_state(u, UNVME_RESETTING)) {
		errno = EBUSY;
		ret = -1;
		goto close;
	}

	ret = unvmed_pci_backup_state(u, config);
	if (ret < 0) {
		unvmed_log_err("failed to read pci config register");
		goto close;
	}

	if (unvmed_pci_get_config(unvmed_bdf(u), &control, pcie_offset + 0x8, 2)) {
		unvmed_log_err("failed to CfgRd (offset=%#x, size=%d)",
				pcie_offset + 0x8, 2);
		ret = -1;
		goto close;
	}

	control |= 1 << 15;
	ret = pwrite(fd, &control, 2, pcie_offset + 0x8);
	if (ret < 0)
		goto close;

	/* Function must complete the FLR within 100ms (PCIe Base Spec. 6.0) */
	usleep(100 * 1000);
	if (unvmed_pci_wait_reset(u) < 0) {
		unvmed_log_err("failed to wait for PCI to be reset");
		ret = -1;
		goto close;
	}

	ret = unvmed_pci_restore_state(u, config);
	if (ret < 0) {
		unvmed_log_err("failed to write pci config register");
		goto close;
	}

	unvmed_reset_ctx(u);
close:
	close(fd);
free:
	free(path);
	return ret;
}

static int unvmed_get_downstream_port(struct unvme *u, char *bdf)
{
	char *path = NULL;
	char *rpath;
	char *last;
	char *dsp;
	int ret;

	ret = asprintf(&path, "/sys/bus/pci/devices/%s", unvmed_bdf(u));
	if (ret < 0)
		return -1;

	rpath = realpath(path, NULL);
	if (!rpath) {
		free(path);
		return -1;
	}

	last = strrchr(rpath, '/');
	if (!last) {
		free(path);
		return -1;
	}

	*last = '\0';

	dsp = strrchr(rpath, '/');
	if (!dsp) {
		free(path);
		return -1;
	}

	strncpy(bdf, ++dsp, 12);
	bdf[12] = '\0';

	free(rpath);
	free(path);
	return 0;
}

static int unvmed_get_pcie_cap_offset(char *bdf)
{
	char *path = NULL;
	uint16_t offset;
	uint16_t cap;
	uint16_t id;
	uint16_t next;
	int ret;
	int fd;

	ret = asprintf(&path, "/sys/bus/pci/devices/%s/config", bdf);
	if (ret < 0)
		return -1;

	fd = open(path, O_RDWR);
	if (fd < 0)
		goto free;

	ret = pread(fd, &offset, 2, 0x34);  /* Firts cap. pointer */
	if (ret < 0)
		goto close;

	ret = -1;
	while (offset < 0x100) {
		if (pread(fd, &cap, 2, offset) < 0)
			goto close;

		id = cap & 0xff;
		next = cap >> 8;

		if (id == 0x10) {  /* PCI Express Cap. ID */
			ret = offset;
			break;
		}

		offset = next;
	}

close:
	close(fd);
free:
	free(path);
	return ret;
}

int unvmed_hot_reset(struct unvme *u)
{
	char *path = NULL;
	char config[4096];
	char dsp[13];
	uint16_t control;
	int ret;
	int fd;

	if (unvmed_get_downstream_port(u, dsp) < 0)
		return -1;

	ret = asprintf(&path, "/sys/bus/pci/devices/%s/config", dsp);
	if (ret < 0)
		return -1;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		ret = fd;
		goto free;
	}

	if (!unvmed_ctrl_set_state(u, UNVME_RESETTING)) {
		errno = EBUSY;
		ret = -1;
		goto close;
	}

	ret = pread(fd, &control, 2, 0x3E);
	if (ret < 0)
		goto close;

	ret = unvmed_pci_backup_state(u, config);
	if (ret < 0) {
		unvmed_log_err("failed to read pci config register");
		goto close;
	}

	control |= 1 << 6;
	ret = pwrite(fd, &control, 2, 0x3E);
	if (ret < 0)
		goto close;

	usleep(2 * 1000);

	control &= ~(1 << 6);
	ret = pwrite(fd, &control, 2, 0x3E);
	if (ret < 0)
		goto close;

	usleep(100 * 1000);
	if (unvmed_pci_wait_reset(u) < 0) {
		unvmed_log_err("failed to wait for PCI to be reset");
		ret = -1;
		goto close;
	}

	ret = unvmed_pci_restore_state(u, config);
	if (ret < 0) {
		unvmed_log_err("failed to write pci config register");
		goto close;
	}

	unvmed_reset_ctx(u);
close:
	close(fd);
free:
	free(path);
	return ret;
}

int unvmed_link_disable(struct unvme *u)
{
	char *path = NULL;
	char config[4096];
	char dsp[13];
	uint16_t pcie_offset;
	uint16_t control;
	int ret;
	int fd;

	if (unvmed_get_downstream_port(u, dsp) < 0)
		return -1;

	ret = asprintf(&path, "/sys/bus/pci/devices/%s/config", dsp);
	if (ret < 0)
		return -1;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		ret = fd;
		goto free;
	}

	if (!unvmed_ctrl_set_state(u, UNVME_RESETTING)) {
		errno = EBUSY;
		ret = -1;
		goto close;
	}

	pcie_offset = unvmed_get_pcie_cap_offset(dsp);
	if (pcie_offset == -1) {
		ret = -1;
		goto close;
	}

	ret = pread(fd, &control, 2, pcie_offset + 0x10);
	if (ret < 0)
		goto close;

	ret = unvmed_pci_backup_state(u, config);
	if (ret < 0) {
		unvmed_log_err("failed to read pci config register");
		goto close;
	}

	control |= 1 << 4;
	ret = pwrite(fd, &control, 2, pcie_offset + 0x10);
	if (ret < 0)
		goto close;

	usleep(2 * 1000);

	control &= ~(1 << 4);
	ret = pwrite(fd, &control, 2, pcie_offset + 0x10);
	if (ret < 0)
		goto close;

	usleep(100 * 1000);
	if (unvmed_pci_wait_reset(u) < 0) {
		unvmed_log_err("failed to wait for PCI to be reset");
		ret = -1;
		goto close;
	}

	ret = unvmed_pci_restore_state(u, config);
	if (ret < 0) {
		unvmed_log_err("failed to write pci config register");
		goto close;
	}

	unvmed_reset_ctx(u);
close:
	close(fd);
free:
	free(path);
	return ret;
}

int unvmed_ctx_init(struct unvme *u)
{
	struct unvme_sq *usq;
	struct unvme_cq *ucq;
	struct __unvme_ns *ns;
	struct unvme_ctx *ctx;
	uint32_t cc, aqa;
	int qid;

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
	aqa = unvmed_read32(u, NVME_REG_AQA);

	ctx->ctrl.iosqes = NVME_CC_IOSQES(cc);
	ctx->ctrl.iocqes = NVME_CC_IOCQES(cc);
	ctx->ctrl.mps = NVME_CC_MPS(cc);
	ctx->ctrl.sq_size = NVME_AQA_ASQS(aqa) + 1;
	ctx->ctrl.cq_size = NVME_AQA_ACQS(aqa) + 1;
	ctx->ctrl.css = NVME_CC_CSS(cc);
	ctx->ctrl.timeout = u->timeout;
	if (u->asq)
		ctx->ctrl.admin_irq = unvmed_cq_iv(u->acq) == 0;

	list_add_tail(&u->ctx_list, &ctx->list);

	list_for_each(&u->ns_list, ns, list) {
		ctx = malloc(sizeof(struct unvme_ctx));

		ctx->type = UNVME_CTX_T_NS;
		ctx->ns.nsid = ns->nsid;

		list_add_tail(&u->ctx_list, &ctx->list);
	}

	for (qid = 1; qid < u->nr_cqs; qid++) {
		ucq = unvmed_cq_get(u, qid);
		if (!ucq)
		       continue;

		ctx = malloc(sizeof(struct unvme_ctx));

		ctx->type = UNVME_CTX_T_CQ;
		ctx->cq.qid = unvmed_cq_id(ucq);
		ctx->cq.qsize = unvmed_cq_size(ucq);
		ctx->cq.vector = unvmed_cq_iv(ucq);
		ctx->cq.pc = ucq->pc;

		list_add_tail(&u->ctx_list, &ctx->list);
		unvmed_cq_put(u, ucq);
	}

	for (qid = 1; qid < u->nr_sqs; qid++) {
		usq = unvmed_sq_get(u, qid);
		if (!usq)
			continue;

		ctx = malloc(sizeof(struct unvme_ctx));

		ctx->type = UNVME_CTX_T_SQ;
		ctx->sq.qid = unvmed_sq_id(usq);
		ctx->sq.qsize = unvmed_sq_size(usq);
		ctx->sq.cqid = unvmed_sq_cqid(usq);
		ctx->sq.qprio = usq->qprio;
		ctx->sq.pc = usq->pc;
		ctx->sq.nvmsetid = usq->nvmsetid;

		list_add_tail(&u->ctx_list, &ctx->list);
		unvmed_sq_put(u, usq);
	}

	return 0;
}

static int __unvmed_ctx_restore(struct unvme *u, struct unvme_ctx *ctx)
{
	switch (ctx->type) {
		case UNVME_CTX_T_CTRL:
			if (unvmed_create_adminq(u, ctx->ctrl.sq_size,
						ctx->ctrl.cq_size,
						ctx->ctrl.admin_irq))
				return -1;
			return unvmed_enable_ctrl(u, ctx->ctrl.iosqes,
					ctx->ctrl.iocqes, ctx->ctrl.mps,
					ctx->ctrl.css, ctx->ctrl.timeout);
		case UNVME_CTX_T_NS:
			int ret;
			ret = unvmed_init_ns(u, ctx->ns.nsid, NULL);
			if (ret)
				return ret;
			return unvmed_init_meta_ns(u, ctx->ns.nsid, NULL);
		case UNVME_CTX_T_CQ:
			return unvmed_create_cq(u, ctx->cq.qid, ctx->cq.qsize,
					ctx->cq.vector, ctx->cq.pc);
		case UNVME_CTX_T_SQ:
			return unvmed_create_sq(u, ctx->sq.qid, ctx->sq.qsize,
					ctx->sq.cqid, ctx->sq.qprio, ctx->sq.pc,
					ctx->sq.nvmsetid);
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

bool unvmed_hmb_allocated(struct unvme *u)
{
	return !!u->hmb.descs;
}

struct unvme_hmb *unvmed_hmb(struct unvme *u)
{
	return &u->hmb;
}

int unvmed_hmb_init(struct unvme *u, uint32_t *bsize, int nr_bsize)
{
	const size_t page_size = unvmed_pow(2, u->mps + 12);
	void *descs = NULL;
	uint64_t iova;
	ssize_t ret;
	size_t memsize;
	size_t hsize = 0;
	int i;

	if (u->hmb.descs) {
		unvmed_log_err("failed to initialize HMB (already exists)");
		errno = EEXIST;
		return -1;
	}

	ret = pgmap(&descs, nr_bsize * sizeof(*u->hmb.descs));
	if (ret < 0) {
		unvmed_log_err("failed to allocate HMB buffer descriptors");
		return -1;
	}
	memsize = ret;

	if (unvmed_map_vaddr(u, descs, ret, &iova, 0x0) < 0) {
		unvmed_log_err("failed to map HMB buffer descriptors to IOMMU");
		goto free;
	}

	u->hmb.descs_vaddr = calloc(nr_bsize, sizeof(uint64_t));
	if (!u->hmb.descs_vaddr) {
		unvmed_log_err("failed to allocate HMB buffer descriptors");
		goto free;
	}

	u->hmb.descs = descs;
	u->hmb.descs_iova = iova;
	u->hmb.descs_size = ret;
	u->hmb.nr_descs = nr_bsize;

	unvmed_log_info("HMB descriptors (vaddr=%p, iova=%#lx, size=%ldbytes)",
			descs, iova, ret);

	for (i = 0; i < nr_bsize; i++) {
		size_t size = bsize[i] * page_size;
		void *buf = NULL;

		ret = pgmap(&buf, size);
		if (ret < 0) {
			unvmed_log_err("failed to allocate HMB buffer");
			goto free;
		}

		if (unvmed_map_vaddr(u, buf, ret, &iova, 0x0) < 0) {
			unvmed_log_err("failed to map HMB buffer to IOMMU");
			goto free;
		}

		u->hmb.descs_vaddr[i] = (uint64_t)buf;
		u->hmb.descs[i].badd = cpu_to_le64(iova);
		u->hmb.descs[i].bsize = cpu_to_le32(bsize[i]);

		hsize += bsize[i];
		unvmed_log_info("HMB descriptor #%d (vaddr=%p, iova=%#lx, size=%ldbytes)",
				i, buf, iova, ret);
	}

	u->hmb.hsize = hsize;
	return 0;
free:
	for (i = 0; i < nr_bsize; i++) {
		size_t size = bsize[i] * page_size;
		if (u->hmb.descs[i].badd) {
			unvmed_unmap_vaddr(u, (void *)u->hmb.descs_vaddr[i]);
			pgunmap((void *)u->hmb.descs_vaddr[i], size);
		}
	}

	if (u->hmb.descs_vaddr)
		free(u->hmb.descs_vaddr);
	unvmed_unmap_vaddr(u, descs);
	pgunmap(descs, memsize);

	memset(&u->hmb, 0, sizeof(u->hmb));

	errno = ENOMEM;
	return -1;
}

int unvmed_hmb_free(struct unvme *u)
{
	const size_t page_size = unvmed_pow(2, u->mps + 12);
	size_t size;
	int i;

	if (!u->hmb.descs) {
		errno = ENOMEM;
		return -1;
	}

	for (i = 0; i < u->hmb.nr_descs; i++) {
		if (u->hmb.descs[i].badd) {
			size = le32_to_cpu(u->hmb.descs[i].bsize) * page_size;

			unvmed_unmap_vaddr(u, (void *)u->hmb.descs_vaddr[i]);
			pgunmap((void *)u->hmb.descs_vaddr[i], size);
			unvmed_log_info("HMB descriptor #%d freed", i);
		}
	}

	if (unvmed_unmap_vaddr(u, u->hmb.descs) < 0)
		unvmed_log_err("failed to unmap HMB buffer descriptors from IOMMU");

	pgunmap(u->hmb.descs, u->hmb.descs_size);

	memset(&u->hmb, 0, sizeof(u->hmb));
	return 0;
}

static int unvmed_mem_add(struct unvme *u, struct iommu_dmabuf *buf)
{
	struct unvme_dmabuf *__buf;

	__buf = calloc(1, sizeof(*__buf));
	if (!__buf)
		return -1;

	__buf->buf.ctx = buf->ctx;
	__buf->buf.vaddr = buf->vaddr;
	__buf->buf.iova = buf->iova;
	__buf->buf.len = buf->len;

	list_add_tail(&u->mem_list, &__buf->list);
	return 0;
}

int unvmed_mem_alloc(struct unvme *u, size_t size, struct iommu_dmabuf *buf)
{
	if (__unvmed_mem_alloc(u, size, buf))
		return -1;

	if (unvmed_mem_add(u, buf)) {
		unvmed_unmap_vaddr(u, buf->vaddr);
		pgunmap(buf->vaddr, buf->len);
		return -1;
	}

	return 0;
}

struct iommu_dmabuf *unvmed_mem_get(struct unvme *u, uint64_t iova)
{
	__autordlock(&u->mem_list_lock);

	struct unvme_dmabuf *buf;

	list_for_each(&u->mem_list, buf, list) {
		if (iova >= buf->buf.iova && iova < buf->buf.iova + buf->buf.len)
			return &buf->buf;
	}

	errno = EINVAL;
	return NULL;
}

static int __unvmed_mem_free(struct unvme *u, struct iommu_dmabuf *buf)
{
	struct unvme_dmabuf *dbuf;
	struct iommu_dmabuf *found;

	found = unvmed_mem_get(u, buf->iova);
	if (!found) {
		errno = EINVAL;
		return -1;
	}

	dbuf = container_of(found, struct unvme_dmabuf, buf);

	unvmed_unmap_vaddr(u, buf->vaddr);
	pgunmap(buf->vaddr, buf->len);

	pthread_rwlock_wrlock(&u->mem_list_lock);
	list_del(&dbuf->list);
	pthread_rwlock_unlock(&u->mem_list_lock);

	free(dbuf);
	return 0;
}

int unvmed_mem_free(struct unvme *u, uint64_t iova)
{
	struct iommu_dmabuf *buf;

	buf = unvmed_mem_get(u, iova);
	if (!buf)
		return -1;

	return __unvmed_mem_free(u, buf);
}

static struct unvme_sq *__unvmed_init_sq(struct unvme *u, uint32_t qid, uint32_t qsize,
					 uint32_t cqid, int qprio, int pc, int nvmsetid,
					 struct iommu_dmabuf *mem)
{
	struct unvme_cq *ucq;
	struct unvme_sq *usq;

	ucq = unvmed_cq_find(u, cqid);
	if (!ucq) {
		unvmed_log_err("failed to find corresponding I/O CQ (qid=%d)",
				cqid);
		errno = ENODEV;
		return NULL;
	}

	if (mem) {
		if (nvme_configure_sq_mem(&u->ctrl, qid, qsize, ucq->q, 0, mem))
			goto err;
	} else {
		if (nvme_configure_sq(&u->ctrl, qid, qsize, ucq->q, 0) < 0)
			goto err;
	}

	usq = unvmed_init_usq(u, qid, qsize, ucq, qprio, pc, nvmsetid);
	if (!usq) {
		unvmed_log_err("failed to initialize usq instance. "
				"discard sq instance from libvfn (qid=%d)",
				qid);
		unvmed_discard_sq(u, qid);
		return NULL;
	}

	return usq;
err:
	unvmed_log_err("failed to configure I/O SQ in libvfn");
	return NULL;
}

static int unvmed_map_iova_to_mem(struct unvme *u, uint64_t iova, size_t size,
				  struct iommu_dmabuf *mem)
{
	void *vaddr;

	if (unvmed_iova_in_cmb(u, iova, size)) {
		mem->ctx = __iommu_ctx(&u->ctrl);
		mem->iova = iova;
		mem->vaddr = u->ctrl.cmb.vaddr + (iova - u->ctrl.cmb.iova);
		mem->len = size;
		return 0;
	}

	if (unvmed_to_vaddr(u, iova, &vaddr) > 0) {
		mem->ctx = __iommu_ctx(&u->ctrl);
		mem->iova = iova;
		mem->vaddr = vaddr;
		mem->len = size;
		return 0;
	}

	unvmed_log_err("failed to map iova 0x%lx to vaddr", iova);
	errno = EINVAL;
	return -1;
}

struct unvme_sq *unvmed_init_sq(struct unvme *u, uint32_t qid, uint32_t qsize, uint32_t cqid,
				int qprio, int pc, int nvmsetid)
{
	return __unvmed_init_sq(u, qid, qsize, cqid, qprio, pc, nvmsetid, NULL);
}

struct unvme_sq *unvmed_init_sq_iova(struct unvme *u, uint32_t qid, uint32_t qsize,
				     uint32_t cqid, int qprio, int pc, int nvmsetid,
				     uint64_t iova)
{
	struct iommu_dmabuf mem;
	size_t size = ALIGN_UP(qsize << NVME_SQES, __VFN_PAGESIZE);

	if (unvmed_map_iova_to_mem(u, iova, size, &mem))
		return NULL;

	return __unvmed_init_sq(u, qid, qsize, cqid, qprio, pc, nvmsetid, &mem);
}

static struct unvme_cq *__unvmed_init_cq(struct unvme *u, uint32_t qid, uint32_t qsize,
					 int vector, int pc, struct iommu_dmabuf *mem)
{
	struct unvme_cq *ucq;

	if (vector >= 0 && unvmed_init_irq(u, vector)) {
		unvmed_log_err("failed to initialize irq (nr_irqs=%d, vector=%d, errno=%d \"%s\")",
				u->nr_irqs, vector, errno, strerror(errno));
		return NULL;
	}

	if (mem) {
		if (nvme_configure_cq_mem(&u->ctrl, qid, qsize, vector, mem) < 0)
			goto err;
	} else {
		if (nvme_configure_cq(&u->ctrl, qid, qsize, vector) < 0)
			goto err;
	}

	ucq = unvmed_init_ucq(u, qid, qsize, vector, pc);
	if (!ucq) {
		unvmed_log_err("failed to initialize ucq instance. "
				"discard cq instance from libvfn (qid=%d)",
				qid);
		unvmed_discard_cq(u, qid);
		return NULL;
	}

	/*
	 * XXX: This should be done in unvmed_init_ucq()
	 */
	if (vector < 0)
		unvmed_cq_iv(ucq) = -1;

	return ucq;
err:
	unvmed_log_err("failed to configure I/O CQ in libvfn");
	return NULL;
}

struct unvme_cq *unvmed_init_cq(struct unvme *u, uint32_t qid, uint32_t qsize, int vector, int pc)
{
	return __unvmed_init_cq(u, qid, qsize, vector, pc, NULL);
}

struct unvme_cq *unvmed_init_cq_iova(struct unvme *u, uint32_t qid, uint32_t qsize,
				     int vector, int pc, uint64_t iova)
{
	struct iommu_dmabuf mem;
	size_t size = ALIGN_UP(qsize << NVME_CQES, __VFN_PAGESIZE);

	if (unvmed_map_iova_to_mem(u, iova, size, &mem))
		return NULL;

	return __unvmed_init_cq(u, qid, qsize, vector, pc, &mem);
}

int unvmed_free_sq(struct unvme *u, uint16_t qid)
{
	struct unvme_sq *usq = unvmed_sq_find(u, qid);

	if (!usq) {
		errno = ENODEV;
		return -1;
	}

	unvmed_disable_sq(usq);
	unvmed_cancel_sq(u, usq);

	__unvmed_delete_sq(u, usq);
	return 0;
}

int unvmed_free_cq(struct unvme *u, uint16_t qid)
{
	struct unvme_cq *ucq = unvmed_cq_find(u, qid);

	if (!ucq) {
		errno = ENODEV;
		return -1;
	}

	__unvmed_delete_cq(u, ucq);
	return 0;
}

struct json_object *unvmed_to_json(struct unvme *u)
{
	struct json_object *status;
	struct unvme_ns *nslist = NULL;
	struct unvme_sq **usqs = NULL;
	struct unvme_cq **ucqs = NULL;
	int nr_ns, nr_sqs, nr_cqs;
	struct unvme_hmb *hmb;
	struct unvme_cmb *cmb;

	status = json_object_new_object();
	if (!status)
		return NULL;

	nr_ns = unvmed_get_nslist(u, &nslist);
	nr_sqs = unvmed_get_sqs(u, &usqs);
	nr_cqs = unvmed_get_cqs(u, &ucqs);
	hmb = unvmed_hmb(u);
	cmb = unvmed_cmb(u);

	json_object_object_add(status, "controller",
			       json_object_new_string(unvmed_bdf(u)));
	json_object_object_add(status, "cc",
			       json_object_new_int(unvmed_read32(u, NVME_REG_CC)));
	json_object_object_add(status, "csts",
			       json_object_new_int(unvmed_read32(u, NVME_REG_CSTS)));
	json_object_object_add(status, "nr_inflight_cmds",
			       json_object_new_int(unvmed_nr_cmds(u)));
	json_object_object_add(status, "nr_irqs",
			       json_object_new_int(unvmed_nr_irqs(u)));

	/* Namespaces */
	struct json_object *ns_array = json_object_new_array();
	for (int i = 0; i < nr_ns; i++) {
		struct unvme_ns *ns = &nslist[i];
		struct json_object *ns_obj = json_object_new_object();

		json_object_object_add(ns_obj, "nsid",
				       json_object_new_int(ns->nsid));
		json_object_object_add(ns_obj, "block_size",
				       json_object_new_int(ns->lba_size));
		json_object_object_add(ns_obj, "meta_size",
				       json_object_new_int(ns->ms));
		json_object_object_add(ns_obj, "nr_blocks",
				       json_object_new_int64(ns->nr_lbas));
		if (ns->ms) {
			char meta_info[64];

			snprintf(meta_info, sizeof(meta_info),
				 "[%d]%s:pi%d:st%d", ns->format_idx,
				 ns->mset ? "dif" : "dix",
				 16 * (ns->pif + 1), ns->sts);
			json_object_object_add(ns_obj, "meta_info",
					       json_object_new_string(meta_info));
		}
		json_object_array_add(ns_array, ns_obj);
	}
	json_object_object_add(status, "ns", ns_array);

	/* Submission Queues */
	struct json_object *sq_array = json_object_new_array();
	for (int i = 0; i < nr_sqs; i++) {
		struct unvme_sq *usq = usqs[i];
		struct json_object *sq_obj = json_object_new_object();

		json_object_object_add(sq_obj, "id",
				       json_object_new_int(usq->id));
		json_object_object_add(sq_obj, "vaddr",
				       json_object_new_int64((uint64_t)usq->q->mem.vaddr));
		json_object_object_add(sq_obj, "iova",
				       json_object_new_int64(usq->q->mem.iova));
		json_object_object_add(sq_obj, "cqid",
				       json_object_new_int(usq->ucq->id));
		json_object_object_add(sq_obj, "qprio",
				       json_object_new_int(usq->qprio));
		json_object_object_add(sq_obj, "pc",
				       json_object_new_int(usq->pc));
		json_object_object_add(sq_obj, "nvmsetid",
				       json_object_new_int(usq->nvmsetid));
		json_object_object_add(sq_obj, "tail",
				       json_object_new_int(usq->q->tail));
		json_object_object_add(sq_obj, "ptail",
				       json_object_new_int(usq->q->ptail));
		json_object_object_add(sq_obj, "qsize",
				       json_object_new_int(usq->qsize));
		json_object_object_add(sq_obj, "nr_cmds",
				       json_object_new_int(usq->nr_cmds));
		json_object_object_add(sq_obj, "refcnt",
				       json_object_new_int(usq->refcnt));
		json_object_array_add(sq_array, sq_obj);
	}
	json_object_object_add(status, "sq", sq_array);

	/* Virtual Completion Queues */
	struct json_object *vcq_array = json_object_new_array();
	for (int i = 0; i < nr_sqs; i++) {
		struct unvme_sq *usq = usqs[i];
		struct json_object *vcq_obj = json_object_new_object();

		json_object_object_add(vcq_obj, "sqid",
				       json_object_new_int(usq->id));
		json_object_object_add(vcq_obj, "head",
				       json_object_new_int(usq->vcq.head));
		json_object_object_add(vcq_obj, "tail",
				       json_object_new_int(usq->vcq.tail));
		json_object_object_add(vcq_obj, "qsize",
				       json_object_new_int(usq->vcq.qsize));
		json_object_array_add(vcq_array, vcq_obj);
	}
	json_object_object_add(status, "vcq", vcq_array);

	/* Completion Queues */
	struct json_object *cq_array = json_object_new_array();
	for (int i = 0; i < nr_cqs; i++) {
		struct unvme_cq *ucq = ucqs[i];
		struct json_object *cq_obj;

		if (!ucq)
			break;

		cq_obj = json_object_new_object();
		json_object_object_add(cq_obj, "id",
				       json_object_new_int(ucq->id));
		json_object_object_add(cq_obj, "vaddr",
				       json_object_new_int64((uint64_t)ucq->q->mem.vaddr));
		json_object_object_add(cq_obj, "iova",
				       json_object_new_int64(ucq->q->mem.iova));
		json_object_object_add(cq_obj, "pc",
				       json_object_new_int64(ucq->pc));
		json_object_object_add(cq_obj, "head",
				       json_object_new_int(ucq->q->head));
		json_object_object_add(cq_obj, "qsize",
				       json_object_new_int(ucq->qsize));
		json_object_object_add(cq_obj, "phase",
				       json_object_new_int(ucq->q->phase));
		json_object_object_add(cq_obj, "iv",
				       json_object_new_int(ucq->vector));
		json_object_object_add(cq_obj, "refcnt",
				       json_object_new_int(ucq->refcnt));
		json_object_array_add(cq_array, cq_obj);
	}
	json_object_object_add(status, "cq", cq_array);

	/* Host Memory Buffer */
	struct json_object *hmb_obj = json_object_new_object();
	json_object_object_add(hmb_obj, "hsize",
			       json_object_new_int((uint32_t)hmb->hsize));
	json_object_object_add(hmb_obj, "descs_addr",
			       json_object_new_int64((uint64_t)hmb->descs_iova));
	json_object_object_add(hmb_obj, "nr_descs",
			       json_object_new_int((uint32_t)hmb->nr_descs));

	struct json_object *hmb_descs = json_object_new_array();
	for (int i = 0; i < hmb->nr_descs; i++) {
		struct json_object *desc_obj = json_object_new_object();

		json_object_object_add(desc_obj, "badd",
				       json_object_new_int64((uint64_t)le64_to_cpu(hmb->descs[i].badd)));
		json_object_object_add(desc_obj, "bsize",
				       json_object_new_int((uint32_t)le32_to_cpu(hmb->descs[i].bsize)));
		json_object_array_add(hmb_descs, desc_obj);
	}
	json_object_object_add(hmb_obj, "descs", hmb_descs);
	json_object_object_add(status, "hmb", hmb_obj);

	/* Controller Memory Buffer */
	struct json_object *cmb_obj = json_object_new_object();
	json_object_object_add(cmb_obj, "bir",
			       json_object_new_int(cmb->bar));
	json_object_object_add(cmb_obj, "size",
			       json_object_new_int((size_t)cmb->size));
	json_object_object_add(cmb_obj, "iova",
			       json_object_new_int64((uint64_t)cmb->iova));
	json_object_object_add(status, "cmb", cmb_obj);

	/* Shared Memory */
	struct json_object *shmem_obj = json_object_new_object();
	if (u->shmem_size > 0) {
		json_object_object_add(shmem_obj, "size",
				       json_object_new_int64((uint64_t)u->shmem_size));
		json_object_object_add(shmem_obj, "vaddr",
				       json_object_new_int64((uint64_t)u->shmem_vaddr));
		json_object_object_add(shmem_obj, "iova",
				       json_object_new_int64(u->shmem_iova));
		json_object_object_add(shmem_obj, "name",
				       json_object_new_string(u->shmem_name));
	}
	json_object_object_add(status, "shmem", shmem_obj);

	free(nslist);
	free(ucqs);
	free(usqs);

	return status;
}
