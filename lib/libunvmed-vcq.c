// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT

#include <vfn/nvme.h>
#include <vfn/support/atomic.h>

#include "libunvmed.h"
#include "libunvmed-private.h"
#include "libunvmed-logs.h"

#define UNVME_VCQ_MAX	4096

/*
 * VCQ ID pool with lock-free free stack (Treiber stack), modeled after
 * nvme_rq_acquire_atomic() / nvme_rq_release_atomic() in libvfn.
 *
 * A fixed-size array of ID slots (__vcq_slots[]) is pre-linked into a free
 * stack at initialization.  Allocation pops from the stack, free pushes back
 * — both lock-free via atomic CAS.
 *
 * A separate mapping array (__vcq_map[]) maps qid -> vcq pointer, since vcq
 * instances live in caller-owned memory (embedded in usq, thread-local, etc.).
 *
 * Slot 0 is reserved so that cmd->vcq == 0 means "no application vcq".
 * Valid IDs range from 1 to (UNVME_VCQ_MAX - 1).
 */
struct unvme_vcq_slot {
	uint32_t qid;
	struct unvme_vcq_slot *next;
};

static struct unvme_vcq_slot __vcq_slots[UNVME_VCQ_MAX];
static struct unvme_vcq_slot *__vcq_free_top;
static struct unvme_vcq *__vcq_map[UNVME_VCQ_MAX];

void unvmed_vcq_pool_init(void)
{
	/* Link slots [1 .. UNVME_VCQ_MAX-1] into the free stack; skip 0 */
	for (int i = 1; i < UNVME_VCQ_MAX; i++) {
		__vcq_slots[i].qid = i;
		__vcq_slots[i].next = (i + 1 < UNVME_VCQ_MAX) ?
						&__vcq_slots[i + 1] : NULL;
	}
	__vcq_free_top = &__vcq_slots[1];
}

static uint32_t unvmed_vcq_acquire(void)
{
	struct unvme_vcq_slot *slot;

	slot = atomic_load_acquire(&__vcq_free_top);

	while (slot && !atomic_cmpxchg(&__vcq_free_top, slot, slot->next))
		;

	if (!slot) {
		errno = ENOSPC;
		return 0;
	}

	return slot->qid;
}

static void unvmed_vcq_release(uint32_t qid)
{
	struct unvme_vcq_slot *slot = &__vcq_slots[qid];

	slot->next = atomic_load_acquire(&__vcq_free_top);

	while (!atomic_cmpxchg(&__vcq_free_top, slot->next, slot))
		;
}

struct unvme_vcq *unvmed_vcq_get(uint32_t qid)
{
	if (qid == 0 || qid >= UNVME_VCQ_MAX)
		return NULL;

	return atomic_load_acquire(&__vcq_map[qid]);
}

int unvmed_vcq_init(struct unvme_vcq *vcq, uint32_t qsize, uint32_t *qid)
{
	uint32_t id;

	id = unvmed_vcq_acquire();
	if (!id)
		return -1;

	vcq->qid = id;
	vcq->head = 0;
	vcq->tail = 0;
	vcq->qsize = qsize;
	pthread_spin_init(&vcq->tail_lock, 0);
	vcq->cqe = malloc(sizeof(struct nvme_cqe) * qsize);

	if (!vcq->cqe) {
		unvmed_vcq_release(id);
		errno = ENOMEM;
		return -1;
	}

	atomic_store_release(&__vcq_map[id], vcq);
	*qid = id;

	unvmed_log_info("vcq initialized (qid=%u, qsize=%u, qaddr=%p)",
			vcq->qid, vcq->qsize, vcq->cqe);
	return 0;
}

void unvmed_vcq_free(struct unvme_vcq *vcq)
{
	uint32_t qid = vcq->qid;

	atomic_store_release(&__vcq_map[qid], NULL);
	unvmed_vcq_release(qid);

	unvmed_log_info("vcq freed (qid=%u, qsize=%u, qaddr=%p)",
			vcq->qid, vcq->qsize, vcq->cqe);

	free(vcq->cqe);
	memset(vcq, 0, sizeof(struct unvme_vcq));
}

static int __unvmed_vcq_push(struct unvme *u, struct unvme_vcq *q,
			     struct nvme_cqe *cqe)
{
	uint16_t tail;

	pthread_spin_lock(&q->tail_lock);

	tail = atomic_load_acquire(&q->tail);
	if ((tail + 1) % q->qsize == atomic_load_acquire(&q->head)) {
		pthread_spin_unlock(&q->tail_lock);
		return -EAGAIN;
	}

	q->cqe[tail] = *cqe;
	atomic_store_release(&q->tail, (tail + 1) % q->qsize);
	unvmed_log_cmd_vcq_push(cqe);

	pthread_spin_unlock(&q->tail_lock);
	return 0;
}

int unvmed_vcq_push(struct unvme *u, struct nvme_cqe *cqe)
{
	struct unvme_cmd *cmd = unvmed_get_cmd_from_cqe(u, cqe);
	struct unvme_vcq *vcq;

	if (!cmd) {
		unvmed_log_err("failed to get command (sqid=%d, cid=%d)",
				cqe->sqid, cqe->cid);
		return -ENOENT;
	}

	vcq = unvmed_cmd_get_vcq(cmd);
	if (!vcq) {
		unvmed_log_debug("failed to get @vcq for cmd (sqid=%d, cid=%d), "
				"skip pushing vcq", cqe->sqid, cqe->cid);
		return -ENODEV;
	}

	return __unvmed_vcq_push(u, vcq, cqe);
}

int unvmed_vcq_pop(struct unvme_vcq *q, struct nvme_cqe *cqe)
{
	uint16_t head = atomic_load_acquire(&q->head);

	if (head == atomic_load_acquire(&q->tail))
		return -ENOENT;

	*cqe = q->cqe[head];
	atomic_store_release(&q->head, (head + 1) % q->qsize);
	unvmed_log_cmd_vcq_pop(cqe);
	return 0;
}

static int __unvmed_vcq_run_n(struct unvme *u, struct unvme_vcq *vcq,
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

void unvmed_vcq_drain(struct unvme_vcq *vcq)
{
	/* Wait for @vcq to be empty (reaped by application) */
	while (LOAD(vcq->head) != LOAD(vcq->tail))
		;
}
