/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */
/*
 * Standalone app demonstrating app-driven interrupt vectors on libunvmed.
 *
 * Drives an I/O interrupt vector from the application itself instead of
 * letting libunvmed start a reaper thread for it.  With a reaper thread the
 * app can never observe an interrupt: the thread drains the eventfd and reaps
 * the CQ behind the app's back, so by the time the app looks the CQ head has
 * already moved.  Without UNVMED_IRQ_F_REAPER (the default, flags of 0) the
 * vector is still fully set up -- libunvmed still creates, owns and closes the
 * eventfd VFIO signals -- but starts no thread and reaps nothing, so the app
 * waits on the raw eventfd (unvmed_irq_efd()) and reads it directly.
 *
 * The app creates an admin queue pair on vector 0 (with UNVMED_IRQ_F_REAPER,
 * so admin commands complete through unvmed_cmd_wait()) and an I/O queue pair
 * on vector 1 (flags of 0, no reaper).  Two threads then share the I/O queue:
 *   - submitter: posts NR_READS Reads, one at a time.
 *   - main:      owns the vector's eventfd and reaps completions in its own
 *                event loop, the way a no-reaper vector is meant to be driven.
 *
 * Build (from repo root, in the ctests docker container):
 *   meson setup build -Dbuildtype=debug -Dwith-libvfn=/opt/unvme-cli
 *   meson compile -C build test_irq_no_reaper
 *
 * Run:
 *   test_irq_no_reaper <bdf> [nsid]
 *   e.g. test_irq_no_reaper 0000:01:00.0 1
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <sys/eventfd.h>

#include <vfn/nvme.h>

#include "libunvmed.h"

#define ADMINQ_SIZE		16
#define IOQ_SIZE		16
#define IO_VECTOR		1
#define DEFAULT_NSID		1
#define NR_READS		8

static void die(const char *msg)
{
	fprintf(stderr, "%s: %m\n", msg);
	exit(EXIT_FAILURE);
}

/*
 * Bring the controller up ready for I/O: init the PCI device, create the admin
 * queue pair on vector 0 (with a reaper, so admin commands complete through
 * unvmed_cmd_wait()), enable the controller, and identify the namespace.
 *
 * Vector 0's reaper must be initialized before the admin CQ is created:
 * unvmed_create_adminq(..., irq=true) wires the CQ to vector 0, and
 * __unvmed_init_cq() refuses a vector whose reaper is not alive with EINVAL.
 */
static struct unvme *init_controller(const char *bdf, uint32_t nsid,
				     struct unvme_ns **ns_out)
{
	struct unvme *u = unvmed_init_ctrl(bdf, 2);
	if (!u)
		die("failed to init controller");

	if (unvmed_init_irq(u, 0, UNVMED_IRQ_F_REAPER))
		die("failed to init adminq irq");
	if (unvmed_create_adminq(u, ADMINQ_SIZE, ADMINQ_SIZE, true))
		die("failed to create admin queue");

	if (unvmed_enable_ctrl(u, 6, 4, __builtin_ctz(getpagesize()) - 12, 0, 0, 30))
		die("failed to enable controller");

	if (unvmed_init_ns(u, nsid, NULL))
		die("failed to identify namespace");
	*ns_out = unvmed_ns_get(u, nsid);
	if (!*ns_out)
		die("failed to get namespace instance");

	return u;
}

/*
 * Create the I/O CQ and SQ on vector IO_VECTOR.  The caller must have
 * initialized that vector's IRQ (here with flags of 0, no reaper) first.
 */
static void create_io_queues(struct unvme *u, struct unvme_cq **ucq_out,
			     struct unvme_sq **usq_out)
{
	if (unvmed_create_cq(u, IO_VECTOR, IOQ_SIZE, IO_VECTOR, 1))
		die("failed to create iocq");
	*ucq_out = unvmed_cq_get(u, IO_VECTOR);
	if (!*ucq_out)
		die("failed to get iocq");

	if (unvmed_create_sq(u, IO_VECTOR, IOQ_SIZE, IO_VECTOR, 0, 1, 0))
		die("failed to create iosq");
	*usq_out = unvmed_sq_get(u, IO_VECTOR);
	if (!*usq_out)
		die("failed to get iosq");
}

static void teardown(struct unvme *u, struct unvme_ns *ns,
		     struct unvme_cq *ucq, struct unvme_sq *usq,
		     void *data, struct unvme_vcq *vcq)
{
	if (vcq->vcqe)
		unvmed_vcq_free(vcq);
	if (data)
		unvmed_pgunmap(data);
	if (usq)
		unvmed_sq_put(u, usq);
	if (ucq)
		unvmed_cq_put(u, ucq);
	if (ns)
		unvmed_ns_put(u, ns);
	unvmed_put(u);
}

struct submitter_ctx {
	struct unvme *u;
	struct unvme_sq *usq;
	uint32_t nsid;
	void *data;
	ssize_t data_len;
	int nr_reads;
	uint32_t vcq_qid;
};

/*
 * Post NR_READS Reads one at a time.  cmd->vcq is pinned to main's vcq so the
 * CQE lands there regardless of which thread posted the command; main reaps
 * it.  No unvmed_cmd_wait() here: the NO_REAPER contract forbids the reaping
 * thread from waiting on the commands it reaps.
 */
static void *submitter_fn(void *arg)
{
	struct submitter_ctx *ctx = arg;
	struct iovec iov = { .iov_base = ctx->data, .iov_len = ctx->data_len };

	for (int i = 0; i < ctx->nr_reads; i++) {
		struct unvme_cmd *cmd = unvmed_alloc_cmd(ctx->u, ctx->usq, NULL,
							 ctx->data, ctx->data_len);
		if (!cmd)
			die("submitter: failed to alloc read cmd");

		cmd->vcq = ctx->vcq_qid;
		if (unvmed_cmd_prep_read(cmd, ctx->nsid, 0, 0, 0, 0, 0, 0, 0,
					 false, &iov, 1, NULL, NULL))
			die("submitter: failed to prep read");
		unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	}

	return NULL;
}

/*
 * Event loop: wait on the vector's eventfd, then reap exactly one completion
 * with unvmed_cq_run_n().  Runs until every posted Read has been reaped.
 *
 * @vcq is required even on a NO_REAPER vector: with no reaper thread the first
 * cq_run_n() pass reads the raw HW CQ and pushes the CQE to @vcq, but
 * __unvmed_get_completion() reports it as "not mine yet" to its caller, so
 * without a real @vcq to land in the CQE is lost and cq_run_n() spins forever.
 */
static int reap_loop(struct unvme *u, struct unvme_sq *usq, struct unvme_cq *ucq,
		     struct unvme_vcq *vcq, int efd)
{
	int nr_reaped = 0;

	while (nr_reaped < NR_READS) {
		struct pollfd pfd = { .fd = efd, .events = POLLIN };
		struct nvme_cqe cqe;
		uint64_t count;

		if (poll(&pfd, 1, 5000) <= 0)
			return -1;

		if (eventfd_read(efd, &count) < 0)
			return -1;

		if (unvmed_cq_run_n(u, usq, ucq, vcq, &cqe, 1, 1) != 1)
			return -1;

		nr_reaped++;
		printf("reaped cqe %d/%d (count=%lu, status=0x%x)\n",
		       nr_reaped, NR_READS, (unsigned long)count,
		       (le16_to_cpu(cqe.sfp) >> 1) & 0x7ff);

		unvmed_cmd_put(unvmed_get_cmd(usq, cqe.cid));
	}

	return 0;
}

int main(int argc, char *argv[])
{
	const char *bdf;
	uint32_t nsid = DEFAULT_NSID;
	struct unvme *u = NULL;
	struct unvme_ns *ns = NULL;
	struct unvme_cq *ucq = NULL;
	struct unvme_sq *usq = NULL;
	void *data = NULL;
	ssize_t data_len;
	struct unvme_vcq vcq = { 0, };
	uint32_t vcq_qid;
	struct submitter_ctx sctx = { 0, };
	pthread_t submitter;
	int efd = -1;
	int ret = EXIT_FAILURE;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <bdf> [nsid]\n", argv[0]);
		return 1;
	}
	bdf = argv[1];
	if (argc > 2)
		nsid = (uint32_t)strtoul(argv[2], NULL, 0);

	unvmed_init(NULL, UNVME_LOG_INFO);

	u = init_controller(bdf, nsid, &ns);

	/*
	 * Vector 1 with flags of 0 (no reaper): no reaper thread, the app
	 * owns the eventfd.  Must precede create_cq() on this vector --
	 * __unvmed_init_cq() requires a live vector, and a no-reaper vector's
	 * refcnt is "alive" once init_irq publishes it (no thread behind it).
	 */
	if (unvmed_nr_irqs(u) <= IO_VECTOR)
		die("controller does not expose enough irq vectors");
	if (unvmed_init_irq(u, IO_VECTOR, 0))
		die("failed to init irq without reaper");

	create_io_queues(u, &ucq, &usq);

	data_len = unvmed_pgmap(u, &data, ns->lba_size);
	if (data_len < 0)
		die("failed to alloc read buffer");

	/* main's vcq: the submitter tags its cmds with this qid so their CQEs land here. */
	if (unvmed_vcq_init(&vcq, ucq->qsize, &vcq_qid))
		die("failed to init vcq");

	efd = unvmed_irq_efd(u, IO_VECTOR);
	if (efd < 0)
		die("failed to get irq efd");
	printf("polling eventfd (fd=%d) for %d read completion(s)...\n",
	       efd, NR_READS);

	sctx = (struct submitter_ctx) {
		.u = u, .usq = usq, .nsid = nsid,
		.data = data, .data_len = data_len, .nr_reads = NR_READS,
		.vcq_qid = vcq_qid,
	};
	if (pthread_create(&submitter, NULL, submitter_fn, &sctx))
		die("failed to start submitter thread");

	ret = reap_loop(u, usq, ucq, &vcq, efd) ? EXIT_FAILURE : EXIT_SUCCESS;

	pthread_join(submitter, NULL);
	teardown(u, ns, ucq, usq, data, &vcq);
	return ret;
}
