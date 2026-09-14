/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */
/*
 * Standalone per-command timeout test app on libunvmed.
 *
 * Verifies unvmed_cmd_post_timeout() lets each in-flight command carry its
 * own timeout instead of the controller-wide value (&struct unvme.timeout):
 *   1. sentinel (-1) still falls back to the disabled controller-wide value
 *   2. an explicit per-cmd override times out on its own regardless of that
 *   3. a timed-out SQ is left not-ready and disabled
 *   4. a later, shorter per-cmd deadline correctly preempts an
 *      already-armed, longer one on the same SQ
 *   5. a per-cmd deadline still fires on schedule after real traffic
 *      completes on the same SQ
 *
 * Cases 1-2 and 4 post with UNVMED_CMD_F_NODB so the device never sees them;
 * only the timeout path can produce a CQE. Case 5 mixes in genuine
 * doorbell-rung commands (no PRP buffer, nlb=0) before the final NODB
 * command.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <vfn/nvme.h>

#include "libunvmed.h"

#define QID   1
#define QID2  2
#define QID3  3
#define QSIZE 64

static double elapsed_sec(struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) +
	       (now.tv_nsec - start->tv_nsec) / 1e9;
}

static struct unvme_cmd *post_no_doorbell(struct unvme *u, struct unvme_sq *usq,
					   uint32_t nsid, uint16_t cid,
					   int timeout_ms)
{
	struct unvme_cmd *cmd = unvmed_alloc_cmd_cid(u, usq, &cid, -1);
	if (!cmd)
		return NULL;

	if (unvmed_cmd_prep_read(cmd, nsid, 0, 0, 0, 0, 0, 0, 0, false,
				  NULL, 0, NULL, NULL) < 0) {
		unvmed_cmd_put(cmd);
		return NULL;
	}

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;

	unvmed_sq_enter(usq);
	if (timeout_ms == -1)
		unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags | UNVMED_CMD_F_NODB);
	else
		unvmed_cmd_post_timeout(cmd, &cmd->sqe,
					 cmd->flags | UNVMED_CMD_F_NODB, timeout_ms);
	unvmed_sq_exit(usq);

	return cmd;
}

/* Bounded alternative to unvmed_cmd_wait(), which blocks indefinitely. */
static bool wait_for_cqe(struct unvme_cmd *cmd, double wait_sec)
{
	struct timespec start;
	clock_gettime(CLOCK_MONOTONIC, &start);

	while (elapsed_sec(&start) < wait_sec) {
		if (le16_to_cpu(cmd->cqe.sfp))
			return true;
		usleep(10 * 1000);
	}
	return le16_to_cpu(cmd->cqe.sfp) != 0;
}

struct worker_ctx {
	struct unvme *u;
	struct unvme_sq *usq;
	uint32_t nsid;
	uint16_t cid;
	int timeout_ms;
	double elapsed;
	bool timed_out;
};

static void *timeout_worker(void *arg)
{
	struct worker_ctx *w = arg;
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);

	struct unvme_cmd *cmd = post_no_doorbell(w->u, w->usq, w->nsid,
						  w->cid, w->timeout_ms);
	if (!cmd) {
		fprintf(stderr, "worker cid=%u: post failed\n", w->cid);
		return (void *)1;
	}

	unvmed_cmd_wait(cmd);
	w->elapsed = elapsed_sec(&start);
	w->timed_out = unvmed_cqe_status(&cmd->cqe) == -ETIMEDOUT;
	unvmed_cmd_put(cmd);

	return NULL;
}

/* @timeout_ms is generous here -- this traffic isn't the thing under test. */
static bool post_real_rw(struct unvme *u, struct unvme_sq *usq,
			 uint32_t nsid, uint16_t cid, bool write, int timeout_ms)
{
	struct unvme_cmd *cmd = unvmed_alloc_cmd_cid(u, usq, &cid, -1);
	if (!cmd)
		return false;

	unvmed_sq_enter(usq);

	int ret;
	if (write)
		ret = unvmed_cmd_prep_write(cmd, nsid, 0, 0, 0, 0, 0, 0, 0,
					    false, NULL, 0, NULL, NULL);
	else
		ret = unvmed_cmd_prep_read(cmd, nsid, 0, 0, 0, 0, 0, 0, 0,
					   false, NULL, 0, NULL, NULL);
	if (ret < 0) {
		unvmed_sq_exit(usq);
		unvmed_cmd_put(cmd);
		return false;
	}

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post_timeout(cmd, &cmd->sqe, cmd->flags, timeout_ms);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	bool ok = unvmed_cqe_status(&cmd->cqe) != -ETIMEDOUT;
	unvmed_cmd_put(cmd);

	return ok;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <bdf> [nsid]\n", argv[0]);
		return 1;
	}

	const char *bdf = argv[1];
	uint32_t nsid = (argc > 2) ? (uint32_t)atoi(argv[2]) : 1;
	int failed = 0;

	unvmed_init(NULL, UNVME_LOG_INFO);

	struct unvme *u = unvmed_init_ctrl(bdf, 4);
	if (!u) {
		fprintf(stderr, "unvmed_init_ctrl(%s) failed: %m\n", bdf);
		return 1;
	}

	if (unvmed_create_adminq(u, QSIZE, QSIZE, false)) {
		fprintf(stderr, "unvmed_create_adminq failed: %m\n");
		unvmed_put(u);
		return 1;
	}

	uint8_t mps = __builtin_ctz(getpagesize()) - 12;

	/* Controller-wide timeout intentionally disabled (0): isolates the
	 * per-cmd override from any controller-wide fallback below. */
	if (unvmed_enable_ctrl(u, 6, 4, mps, 0, 0, 0)) {
		fprintf(stderr, "unvmed_enable_ctrl failed: %m\n");
		unvmed_put(u);
		return 1;
	}

	if (unvmed_init_ns(u, nsid, NULL)) {
		fprintf(stderr, "unvmed_init_ns(nsid=%u) failed: %m\n", nsid);
		unvmed_put(u);
		return 1;
	}

	if (unvmed_init_irq(u, QID, UNVMED_IRQ_F_REAPER)) {
		fprintf(stderr, "unvmed_init_irq failed: %m\n");
		unvmed_put(u);
		return 1;
	}
	if (unvmed_create_cq(u, QID, QSIZE, QID, 1)) {
		fprintf(stderr, "unvmed_create_cq failed: %m\n");
		unvmed_put(u);
		return 1;
	}
	if (unvmed_create_sq(u, QID, QSIZE, QID, 0, 1, 0)) {
		fprintf(stderr, "unvmed_create_sq failed: %m\n");
		unvmed_put(u);
		return 1;
	}
	struct unvme_sq *usq = unvmed_sq_get(u, QID);
	if (!usq) {
		fprintf(stderr, "unvmed_sq_get(%d) failed: %m\n", QID);
		unvmed_put(u);
		return 1;
	}

	printf("[1/5] legacy unvmed_cmd_post(), controller timeout disabled: "
	       "expect no timeout within 3s\n");
	struct unvme_cmd *cmd1 = post_no_doorbell(u, usq, nsid, 1, -1);
	if (!cmd1) {
		fprintf(stderr, "FAIL: case 1 post failed\n");
		unvmed_put(u);
		return 1;
	}
	bool completed = wait_for_cqe(cmd1, 3.0);
	if (completed) {
		fprintf(stderr, "FAIL: case 1 unexpectedly completed/timed out "
				"(status=0x%x)\n", unvmed_cqe_status(&cmd1->cqe));
		failed = 1;
	} else {
		printf("PASS: case 1 stayed pending for 3s as expected\n");
	}
	unvmed_cmd_put(cmd1);

	printf("[2/5] unvmed_cmd_post_timeout(timeout_ms=2000): expect timeout "
	       "around 2s\n");
	struct timespec start2;
	clock_gettime(CLOCK_MONOTONIC, &start2);
	struct unvme_cmd *cmd2 = post_no_doorbell(u, usq, nsid, 2, 2000);
	if (!cmd2) {
		fprintf(stderr, "FAIL: case 2 post failed\n");
		unvmed_put(u);
		return 1;
	}
	unvmed_cmd_wait(cmd2);
	double elapsed2 = elapsed_sec(&start2);
	int status2 = unvmed_cqe_status(&cmd2->cqe);
	if (status2 != -ETIMEDOUT || elapsed2 < 1.5 || elapsed2 >= 4.0) {
		fprintf(stderr, "FAIL: case 2 status=%d elapsed=%.2fs "
				"(expected -ETIMEDOUT around 2s)\n",
			status2, elapsed2);
		failed = 1;
	} else {
		printf("PASS: case 2 timed out after %.2fs\n", elapsed2);
	}
	unvmed_cmd_put(cmd2);

	printf("[3/5] usq state right after case 2's timeout: expect "
	       "unvmed_sq_ready()==false and usq->enabled==false\n");
	if (unvmed_sq_ready(usq) || usq->enabled) {
		fprintf(stderr, "FAIL: case 3 usq still ready/enabled after "
				"timeout (ready=%d enabled=%d)\n",
			unvmed_sq_ready(usq), usq->enabled);
		failed = 1;
	} else {
		printf("PASS: case 3 usq is not-ready and disabled after "
		       "timeout\n");
	}

	/* Fresh SQ: QID is frozen from case 2's timeout. */
	printf("[4/5] concurrent timeouts (1000ms, 4000ms) on a fresh SQ: "
	       "expect each to expire near its own deadline\n");
	if (unvmed_init_irq(u, QID2, UNVMED_IRQ_F_REAPER)) {
		fprintf(stderr, "FAIL: case 4 unvmed_init_irq failed: %m\n");
		unvmed_put(u);
		return 1;
	}
	if (unvmed_create_cq(u, QID2, QSIZE, QID2, 1)) {
		fprintf(stderr, "FAIL: case 4 unvmed_create_cq failed: %m\n");
		unvmed_put(u);
		return 1;
	}
	if (unvmed_create_sq(u, QID2, QSIZE, QID2, 0, 1, 0)) {
		fprintf(stderr, "FAIL: case 4 unvmed_create_sq failed: %m\n");
		unvmed_put(u);
		return 1;
	}
	struct unvme_sq *usq2 = unvmed_sq_get(u, QID2);
	if (!usq2) {
		fprintf(stderr, "FAIL: case 4 unvmed_sq_get(%d) failed: %m\n",
			QID2);
		unvmed_put(u);
		return 1;
	}

	struct worker_ctx w_long = { .u = u, .usq = usq2, .nsid = nsid,
				      .cid = 3, .timeout_ms = 4000 };
	struct worker_ctx w_short = { .u = u, .usq = usq2, .nsid = nsid,
				       .cid = 4, .timeout_ms = 1000 };

	pthread_t t_long, t_short;
	pthread_create(&t_long, NULL, timeout_worker, &w_long);
	/* Small stagger so the 4000ms post lands first, then the 1000ms post
	 * re-arms the shared per-SQ timer ahead of it. */
	usleep(50 * 1000);
	pthread_create(&t_short, NULL, timeout_worker, &w_short);

	pthread_join(t_long, NULL);
	pthread_join(t_short, NULL);

	if (!w_short.timed_out || w_short.elapsed < 0.5 || w_short.elapsed >= 3.0) {
		fprintf(stderr, "FAIL: case 4 short(1s) timed_out=%d elapsed=%.2fs\n",
			w_short.timed_out, w_short.elapsed);
		failed = 1;
	} else {
		printf("PASS: case 4 short(1s) timed out after %.2fs\n",
		       w_short.elapsed);
	}
	if (!w_long.timed_out || w_long.elapsed < 3.0 || w_long.elapsed >= 6.0) {
		fprintf(stderr, "FAIL: case 4 long(4s) timed_out=%d elapsed=%.2fs\n",
			w_long.timed_out, w_long.elapsed);
		failed = 1;
	} else {
		printf("PASS: case 4 long(4s) timed out after %.2fs\n",
		       w_long.elapsed);
	}

	printf("[5/5] real R/W traffic (8000ms) completed first, then stuck "
	       "NODB (10000ms) posted last on the same SQ: expect the traffic "
	       "to complete normally and the stuck cmd to time out around 10s\n");
	if (unvmed_init_irq(u, QID3, UNVMED_IRQ_F_REAPER)) {
		fprintf(stderr, "FAIL: case 5 unvmed_init_irq failed: %m\n");
		unvmed_put(u);
		return 1;
	}
	if (unvmed_create_cq(u, QID3, QSIZE, QID3, 1)) {
		fprintf(stderr, "FAIL: case 5 unvmed_create_cq failed: %m\n");
		unvmed_put(u);
		return 1;
	}
	if (unvmed_create_sq(u, QID3, QSIZE, QID3, 0, 1, 0)) {
		fprintf(stderr, "FAIL: case 5 unvmed_create_sq failed: %m\n");
		unvmed_put(u);
		return 1;
	}
	struct unvme_sq *usq3 = unvmed_sq_get(u, QID3);
	if (!usq3) {
		fprintf(stderr, "FAIL: case 5 unvmed_sq_get(%d) failed: %m\n", QID3);
		unvmed_put(u);
		return 1;
	}

	int rw_ok = 0, rw_total = 20;
	bool write4 = false;
	for (int i = 0; i < rw_total; i++) {
		if (post_real_rw(u, usq3, nsid, 2, write4, 8000))
			rw_ok++;
		write4 = !write4;
	}

	if (rw_ok != rw_total) {
		fprintf(stderr, "FAIL: case 5 traffic: %d/%d real R/W completed "
				"without timing out\n", rw_ok, rw_total);
		failed = 1;
	} else {
		printf("PASS: case 5 traffic: %d/%d real R/W completed normally\n",
		       rw_ok, rw_total);
	}

	/* Nothing else is ever posted to usq3 after this, so there's no
	 * later doorbell ring that could catch this NODB command up. */
	struct timespec start4;
	clock_gettime(CLOCK_MONOTONIC, &start4);
	struct unvme_cmd *cmd4 = post_no_doorbell(u, usq3, nsid, 1, 10000);
	if (!cmd4) {
		fprintf(stderr, "FAIL: case 5 stuck cmd post failed\n");
		unvmed_put(u);
		return 1;
	}

	unvmed_cmd_wait(cmd4);
	double elapsed4 = elapsed_sec(&start4);
	int status4 = unvmed_cqe_status(&cmd4->cqe);
	unvmed_cmd_put(cmd4);
	if (status4 != -ETIMEDOUT || elapsed4 < 8.5 || elapsed4 >= 12.0) {
		fprintf(stderr, "FAIL: case 5 stuck cmd status=%d elapsed=%.2fs "
				"(expected -ETIMEDOUT around 10s)\n",
			status4, elapsed4);
		failed = 1;
	} else {
		printf("PASS: case 5 stuck cmd timed out after %.2fs\n", elapsed4);
	}

	unvmed_put(u);

	if (failed) {
		fprintf(stderr, "FAIL: one or more per-cmd timeout cases "
				"failed\n");
		return 1;
	}

	printf("PASS: all per-cmd timeout cases on %s nsid=%u completed\n",
	       bdf, nsid);
	return 0;
}
