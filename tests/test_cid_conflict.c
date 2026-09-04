/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */
/*
 * Standalone CID-collision negative-test app on libunvmed.
 *
 * Mirrors pme/tests/nvme/generic/exception/lv00_basic/test_cid_conflict_fio.py
 * without fio: two threads share SQ #1.
 *   - reader:    issues Reads with auto-allocated CIDs (the traffic source),
 *                posting READER_BATCH commands concurrently per iteration so
 *                multiple CIDs are in flight at once
 *   - conflicter: issues Reads pinned to CID 0 so libunvmed routes them to
 *                 the shared conflict slot (cmd->injected = INJECT_CONFLICT),
 *                 deliberately colliding with an in-flight CID to provoke
 *                 CMD_ID_CONFLICT completions.
 *
 * Only NVME_SC_SUCCESS and CMD_ID_CONFLICT (0x3) are tolerated; any other
 * status fails the app with non-zero exit.
 *
 * The I/O CQ is created with an IRQ vector (= qid) so the libunvmed reaper
 * thread routes each CQE to the owning thread's VCQ; in polling mode
 * (vector -1) two threads busy-polling the shared CQ contend on the CQ
 * spinlock and stall.
 *
 * Build (from repo root, in the ctests docker container):
 *   meson setup build -Dbuildtype=debug -Dwith-libvfn=/opt/unvme-cli
 *   meson compile -C build test_cid_conflict
 *
 * Run:
 *   test_cid_conflict <bdf> [nsid] [runtime_sec]
 *   e.g. test_cid_conflict 0000:01:00.0 1 30
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <vfn/nvme.h>

#include "libunvmed.h"

/*
 * NVMe status: SCT=0 (Generic), SC = sfp>>1 & 0xff.  CMD_ID_CONFLICT is
 * SC=0x03; SUCCESS is SC=0.
 */
#define NVME_SC_SUCCESS         0x0
#define NVME_SC_CMD_ID_CONFLICT 0x3

#define QID     1
#define QSIZE   64
#define READER_BATCH 4   /* reads posted concurrently per reader iteration */
#define READER_DELAY_US 200   /* max random delay (us) between reader batches */

struct ctx {
	struct unvme *u;
	struct unvme_sq *usq;
	struct unvme_ns *ns;
	uint32_t nsid;
	int runtime;
	volatile bool stop;
	uint64_t posts;    /* cmds posted to the device (both threads) */
	uint64_t success;  /* NVME_SC_SUCCESS */
	uint64_t conflict; /* NVME_SC_CMD_ID_CONFLICT */
};

/* Thread-local VCQ, like the fio engine (libunvmed-engine.c:35). */
static __thread struct unvme_vcq __vcq;
static __thread uint32_t __vcq_qid;

/*
 * Account a completed command's status.  SUCCESS (normal completion) and
 * CMD_ID_CONFLICT (device rejecting a duplicate CID) are the only expected
 * outcomes; any other status is a real error and fails the app.
 */
static int tolerate(struct ctx *c, uint16_t status)
{
	int sc = status & 0x7ff;
	if (sc != NVME_SC_SUCCESS && sc != NVME_SC_CMD_ID_CONFLICT) {
		fprintf(stderr, "unexpected status: 0x%x\n", sc);
		return -1;
	}

	if (sc == NVME_SC_SUCCESS)
		c->success++;
	else
		c->conflict++;

	return 0;
}

/*
 * Allocate, prep and post one Read (auto CID) without waiting; returns the
 * posted cmd or NULL.  Caller batches several then waits for all, so the reads
 * are simultaneously in flight and exercise genuine multi-CID overlap on the
 * SQ rather than a single synchronous outstanding command.
 */
static struct unvme_cmd *post_read(struct ctx *c)
{
	struct unvme_cmd *cmd = unvmed_alloc_cmd_nodata(c->u, c->usq, NULL);
	if (!cmd)
		return NULL;

	unvmed_sq_enter(c->usq);
	cmd->vcq = __vcq_qid;

	/* nlb is 0-based; 1 block. */
	if (unvmed_cmd_prep_read(cmd, c->nsid, 0, 0, 0, 0, 0, 0, 0, false,
				 NULL, 0, NULL, NULL) < 0) {
		unvmed_sq_exit(c->usq);
		unvmed_cmd_put(cmd);
		return NULL;
	}

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	c->posts++;
	unvmed_sq_exit(c->usq);
	return cmd;
}

/* Wait for a posted cmd and account its status. */
static int reap_read(struct ctx *c, struct unvme_cmd *cmd)
{
	unvmed_cmd_wait(cmd);
	uint16_t st = unvmed_cqe_status(&cmd->cqe);
	unvmed_cmd_put(cmd);
	return tolerate(c, st);
}

/*
 * Issue READER_BATCH Reads concurrently: post all, then wait for all.  Several
 * reads in flight at once spread traffic across multiple auto-allocated CIDs
 * and keep the SQ occupied while the conflicter's CID-0 command collides,
 * without the premature-CID-free cascade a single synchronous outstanding
 * command triggers (one outstanding cmd makes the reaper misroute a CONFLICT
 * CQE onto the resident slot, the host frees the CID early, and the next post
 * collides with the still-in-flight resident on the device).
 */
static int issue_read(struct ctx *c)
{
	struct unvme_cmd *cmds[READER_BATCH];
	int ret = 0;

	for (int i = 0; i < READER_BATCH; i++) {
		cmds[i] = post_read(c);
		if (!cmds[i])
			ret = -1;
	}

	for (int i = 0; i < READER_BATCH; i++) {
		if (cmds[i] && reap_read(c, cmds[i]) < 0)
			ret = -1;
	}

	return ret;
}

/*
 * Issue one Read pinned to CID 0; if 0 is in flight libunvmed allocates from
 * the shared conflict slot instead of the per-CID table (cmd->injected =
 * INJECT_CONFLICT), deliberately colliding to provoke CMD_ID_CONFLICT.  A read
 * needs no data buffer, so there is no DMA allocation to manage.
 */
static int issue_conflict_read(struct ctx *c)
{
	uint16_t cid = 0;
	struct unvme_cmd *cmd = unvmed_alloc_cmd_cid(c->u, c->usq, &cid,
						     __vcq_qid);
	if (!cmd) {
		/* EBUSY = conflict slot already outstanding; benign, retry. */
		return 0;
	}

	unvmed_sq_enter(c->usq);
	cmd->vcq = __vcq_qid;

	/* nlb is 0-based; 1 block. */
	if (unvmed_cmd_prep_read(cmd, c->nsid, 0, 0, 0, 0, 0, 0, 0, false,
				 NULL, 0, NULL, NULL) < 0) {
		unvmed_sq_exit(c->usq);
		unvmed_cmd_put(cmd);
		return -1;
	}

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	c->posts++;
	unvmed_sq_exit(c->usq);

	unvmed_cmd_wait(cmd);
	uint16_t st = unvmed_cqe_status(&cmd->cqe);
	unvmed_cmd_put(cmd);
	return tolerate(c, st);
}

/*
 * Sleep a random 0..READER_DELAY_US microseconds before each reader batch.
 * Without a gap the reader re-posts fast enough that its own earlier-batch
 * CID 0 is still outstanding when the next batch reuses it, producing a runaway
 * conflict count that swamps the conflicter-driven collision this test means to
 * exercise.  The jitter keeps conflict at a moderate, steady rate.
 */
static void reader_random_delay(void)
{
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = (rand() % (READER_DELAY_US + 1)) * 1000,
	};
	nanosleep(&ts, NULL);
}

static void *reader_fn(void *arg)
{
	struct ctx *c = arg;
	srand(0x51524541);  /* fixed seed; time(NULL) unavailable in this context */

	if (unvmed_vcq_init(&__vcq, c->usq->ucq->qsize, &__vcq_qid)) {
		fprintf(stderr, "reader: vcq_init failed\n");
		c->stop = true;
		return (void *)1;
	}

	while (!c->stop) {
		reader_random_delay();
		if (issue_read(c) < 0) {
			c->stop = true;
			break;
		}
	}

	return NULL;
}

static void *conflicter_fn(void *arg)
{
	struct ctx *c = arg;

	if (unvmed_vcq_init(&__vcq, c->usq->ucq->qsize, &__vcq_qid)) {
		fprintf(stderr, "conflicter: vcq_init failed\n");
		c->stop = true;
		return (void *)1;
	}

	while (!c->stop) {
		if (issue_conflict_read(c) < 0) {
			c->stop = true;
			break;
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <bdf> [nsid] [runtime_sec]\n",
			argv[0]);
		return 1;
	}

	const char *bdf = argv[1];
	uint32_t nsid = (argc > 2) ? (uint32_t)atoi(argv[2]) : 1;
	int runtime = (argc > 3) ? atoi(argv[3]) : 30;

	unvmed_init(NULL, UNVME_LOG_INFO);

	struct unvme *u = unvmed_init_ctrl(bdf, 4);
	if (!u) {
		fprintf(stderr, "unvmed_init_ctrl(%s) failed: %m\n", bdf);
		return 1;
	}

	/*
	 * init_ctrl leaves the controller disabled (CC.En=0).  Create the admin
	 * queue and enable the controller so admin commands (e.g. the Identify
	 * Namespace inside unvmed_init_ns) can run.  Mirrors `unvme start` +
	 * `unvme enable` defaults: iosqes=6, iocqes=4, mps=log2(pagesize)-12.
	 */
	if (unvmed_create_adminq(u, QSIZE, QSIZE, false)) {
		fprintf(stderr, "unvmed_create_adminq failed: %m\n");
		unvmed_put(u);
		return 1;
	}

	uint8_t mps = __builtin_ctz(getpagesize()) - 12;
	if (unvmed_enable_ctrl(u, 6, 4, mps, 0, 0, 0)) {
		fprintf(stderr, "unvmed_enable_ctrl failed: %m\n");
		unvmed_put(u);
		return 1;
	}

	/*
	 * Namespaces are not enumerated automatically; issue an Identify
	 * Namespace (CNS 0h) to populate the ns instance before unvmed_ns_get().
	 */
	if (unvmed_init_ns(u, nsid, NULL)) {
		fprintf(stderr, "unvmed_init_ns(nsid=%u) failed: %m\n", nsid);
		unvmed_put(u);
		return 1;
	}

	struct unvme_ns *ns = unvmed_ns_get(u, nsid);
	if (!ns) {
		fprintf(stderr, "nsid %u not found\n", nsid);
		unvmed_put(u);
		return 1;
	}

	/*
	 * Create I/O CQ #1 then SQ #1 (issues Create I/O CQ/SQ admin commands
	 * and enables the queues, unlike unvmed_init_sq which only allocates).
	 * Vector is set to the queue id (=1) so the reaper thread receives CQE
	 * interrupts and routes each CQE to the owning thread's VCQ; with the CQ
	 * in polling mode (vector -1) two threads busy-polling the shared CQ
	 * contend on the CQ spinlock and stall.
	 */
	if (unvmed_init_irq(u, QID, UNVMED_IRQ_F_REAPER)) {
		fprintf(stderr, "unvmed_init_irq failed: %m\n");
		unvmed_ns_put(u, ns);
		unvmed_put(u);
		return 1;
	}
	if (unvmed_create_cq(u, QID, QSIZE, QID, 1)) {
		fprintf(stderr, "unvmed_create_cq failed: %m\n");
		unvmed_ns_put(u, ns);
		unvmed_put(u);
		return 1;
	}
	if (unvmed_create_sq(u, QID, QSIZE, QID, 0, 1, 0)) {
		fprintf(stderr, "unvmed_create_sq failed: %m\n");
		unvmed_ns_put(u, ns);
		unvmed_put(u);
		return 1;
	}
	struct unvme_sq *usq = unvmed_sq_get(u, QID);
	if (!usq) {
		fprintf(stderr, "unvmed_sq_get(%d) failed: %m\n", QID);
		unvmed_ns_put(u, ns);
		unvmed_put(u);
		return 1;
	}

	struct ctx c = {
		.u = u,
		.usq = usq,
		.ns = ns,
		.nsid = nsid,
		.runtime = runtime,
		.stop = false,
	};

	pthread_t tr, tc;
	pthread_create(&tr, NULL, reader_fn, &c);
	pthread_create(&tc, NULL, conflicter_fn, &c);

	/*
	 * Print per-second deltas: cmds posted to and completed by the device in
	 * that second, split by status (success vs CID conflict).
	 */
	uint64_t prev_posts = 0, prev_success = 0, prev_conflict = 0;
	for (int elapsed = 1; elapsed <= runtime; elapsed++) {
		sleep(1);
		if (c.stop)
			break;
		uint64_t d_posts = c.posts - prev_posts;
		uint64_t d_success = c.success - prev_success;
		uint64_t d_conflict = c.conflict - prev_conflict;
		printf("[%2d/%ds] post=%lu  success=%lu  conflict=%lu\n",
		       elapsed, runtime,
		       (unsigned long)d_posts, (unsigned long)d_success,
		       (unsigned long)d_conflict);
		fflush(stdout);
		prev_posts = c.posts;
		prev_success = c.success;
		prev_conflict = c.conflict;
	}
	c.stop = true;

	void *r1 = NULL, *r2 = NULL;
	pthread_join(tr, &r1);
	pthread_join(tc, &r2);

	unvmed_ns_put(u, ns);
	unvmed_put(u);

	if (r1 || r2) {
		fprintf(stderr, "FAIL: a worker reported an unexpected status\n");
		return 1;
	}

	uint64_t total = c.success + c.conflict;
	printf("PASS: %d sec of CID conflict on %s nsid=%u completed — "
	       "total=%lu  post=%lu  success=%lu  conflict=%lu\n",
	       runtime, bdf, nsid, (unsigned long)total,
	       (unsigned long)c.posts, (unsigned long)c.success,
	       (unsigned long)c.conflict);
	return 0;
}
