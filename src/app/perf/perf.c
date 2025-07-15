// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This program is modified from libvfn perf example tool [1].
 *
 * [1] https://github.com/SamsungDS/libvfn/blob/main/examples/perf.c.
 */

#include <errno.h>
#include <sys/uio.h>

#include <ccan/str/str.h>
#include <nvme/types.h>
#include <vfn/nvme.h>

#include <libunvmed.h>
#include "perf.h"

static bool draining, io_rand;
static unsigned int queued;
static uint64_t nsze, slba;
const int data_size = 4096;

static struct {
	unsigned long completed, completed_quantum;
	uint64_t ttotal, tmin, tmax;
} stats;

struct iod {
	uint64_t tsubmit;
	struct nvme_cmd_rw sqe;
};

static int unvmed_perf_issue(struct unvme_cmd *cmd)
{
	struct iod *iod = (struct iod *)cmd->opaque;

	if (io_rand)
		slba = rand() % nsze;
	else {
		if (unlikely(++slba == nsze))
			slba = 0;
	}

	iod->sqe.slba = cpu_to_le64(slba);
	iod->tsubmit = get_ticks();

	unvmed_cmd_post(cmd, (union nvme_cmd *)&iod->sqe, UNVMED_CMD_F_NODB);

	queued++;
	return 0;
}

static void unvmed_perf_complete(struct unvme_cmd *cmd)
{
	struct iod *iod = (struct iod *)cmd->opaque;
	uint64_t diff;

	stats.completed_quantum++;
	queued--;

	diff = get_ticks() - iod->tsubmit;
	stats.ttotal += diff;

	if (unlikely(diff < stats.tmin))
		stats.tmin = diff;

	if (unlikely(diff > stats.tmax))
		stats.tmax = diff;

	if (unlikely(draining)) {
		unvmed_cmd_free(cmd);
		return;
	}

	unvmed_perf_issue(cmd);
}

static void unvmed_perf_update_stats(bool warmup, unsigned long interval)
{
	float iops, mbps;

	iops = (float)stats.completed_quantum / interval;
	mbps = iops * 512 / (1024 * 1024);

	printf("%10s iops %10.2f  mbps %10.2f\n", warmup ? "(warmup)" : "", iops, mbps);

	stats.completed += stats.completed_quantum;
	stats.completed_quantum = 0;
}

static int unvmed_perf_reap(struct unvme *u, struct unvme_sq *usq, struct unvme_cmd *cmd)
{
	struct unvme_cq *ucq = usq->ucq;
	struct nvme_cqe *cqe = calloc(1, sizeof(struct nvme_cqe));
	int reaped = 0;
	int ret;

	do {
		ret = __unvmed_cq_run_n(u, usq, ucq, cqe, 1, true);
		if (!ret)
			break;
		reaped++;

		unvmed_perf_complete(unvmed_get_cmd_from_cqe(u, cqe));
	} while (1);

	if (reaped) {
		nvme_cq_update_head(ucq->q);
	}

	return reaped;
}

int unvmed_perf(struct unvme *u, uint32_t sqid, uint32_t nsid,
		const char *io_pattern, bool rand, int io_depth,
		uint32_t sec_runtime, uint32_t sec_warmup,
		uint32_t update_interval)
{
	struct unvme_cmd *cmd;
	struct unvme_ns *ns;

	uint64_t update_stats, start = get_ticks();
	uint64_t twarmup, trun, tupdate;
	bool warmup = (sec_warmup > 0);
	float iops, mbps, lavg, lmin, lmax;
	unsigned int to_submit = io_depth;

	twarmup = sec_warmup * __vfn_ticks_freq;
	trun = sec_runtime * __vfn_ticks_freq;
	tupdate = update_interval * __vfn_ticks_freq;
	update_stats = tupdate;

	uint64_t total_duration = twarmup + trun;
	uint64_t current, elapsed = 0;

	memset(&stats, 0x0, sizeof(stats));
	stats.tmin = UINT64_MAX;
	queued = 0;
	slba = 0;
	draining = false;
	io_rand = rand;

	uint64_t iova;
	void *mem;
	void *mem_per_cmd;
	int ret;

	struct unvme_sq *usq;

	ns = unvmed_ns_get(u, nsid);
	if (!ns) {
		printf("Do 'unvme id-ns %s -n %d --init' first\n", unvmed_bdf(u), nsid);
		return -ENODEV;
	}
	nsze = ns->nr_lbas;

	mem = mmap(NULL, io_depth * data_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (!mem) {
		printf("failed to allocate memory");
		return -errno;
	}

	ret = unvmed_map_vaddr(u, mem, io_depth * data_size, &iova, 0);
	if (ret) {
		printf("failed to map buffers to iommu");
		ret = -errno;
		goto out;
	}

	mem_per_cmd = mem;

	usq = unvmed_sq_get(u, sqid);
	unvmed_cq_get(u, unvmed_sq_cqid(usq));

	do {
		struct iod *iod;

		cmd = unvmed_alloc_cmd(u, usq, NULL, mem_per_cmd, data_size);
		if (!cmd)
			return -1;

		iod = calloc(1, sizeof(*iod));

		iod->sqe.nsid = cpu_to_le32(nsid);
		iod->sqe.opcode = streq(io_pattern, "read")? nvme_cmd_read : nvme_cmd_write;
		iod->sqe.dptr.prp1 = cpu_to_le64(iova);
		iod->sqe.nlb = cpu_to_le16((data_size / ns->lba_size) - 1);

		mem_per_cmd += data_size;
		iova += data_size;

		cmd->opaque = iod;

		unvmed_perf_issue(cmd);
	} while (true && --to_submit > 0);

	unvmed_sq_update_tail(u, usq);

	do {
		while (!unvmed_perf_reap(u, usq, cmd))
			;

		unvmed_sq_update_tail(u, usq);

		current = get_ticks();
		elapsed = current - start;

		if (elapsed >= update_stats) {
			unvmed_perf_update_stats(warmup, update_interval);
			if ((elapsed >= twarmup) && warmup) {
				warmup = false;
				memset(&stats, 0x0, sizeof(stats));
				stats.tmin = UINT64_MAX;
			}
			update_stats = update_stats + tupdate;
		}

		if (elapsed >= total_duration)
			break;

	} while (true);

	iops = (float)stats.completed / sec_runtime;
	mbps = iops * 512 / (1024 * 1024);
	lmin = (float)stats.tmin * 1000 * 1000 / __vfn_ticks_freq;
	lmax = (float)stats.tmax * 1000 * 1000 / __vfn_ticks_freq;
	lavg = ((float)stats.ttotal * 1000 * 1000 / __vfn_ticks_freq) / stats.completed;

	printf("iops       mbps       lavg       lmin       lmax\n");
	printf("---------- ---------- ---------- ---------- ----------\n");
	printf("%10.2f %10.2f %10.2f %10.2f %10.2f\n", iops, mbps, lavg, lmin, lmax);

	draining = true;

	unvmed_sq_update_tail(u, usq);

	do {
		unvmed_perf_reap(u, usq, cmd);
	} while (queued);

	unvmed_cq_put(u, usq->ucq);
	unvmed_sq_put(u, usq);

	ret = unvmed_unmap_vaddr(u, mem);
	if (ret) {
		printf("failed to unmap buffers from iommu\n");
		ret = -errno;
	}

out:
	if (munmap(mem, io_depth * data_size)) {
		printf("failed to munmap\n");
		return -errno;
	}

	return ret;
}
