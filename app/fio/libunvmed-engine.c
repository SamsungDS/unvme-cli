// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include "config-host.h"
#include "fio.h"
#include "optgroup.h"

#undef cpu_to_le64
#undef cpu_to_be64
#undef cpu_to_le32
#undef cpu_to_be32
#undef cpu_to_le16
#undef cpu_to_be16

#include <nvme/types.h>
#include <vfn/nvme.h>
#include "libunvmed.h"

#define libunvmed_log(fmt, ...)						\
	do {								\
		fprintf(stdout, "libunvmed: "fmt, ##__VA_ARGS__);	\
	} while (0)


struct libunvmed_options {
	struct thread_data *td;
	unsigned int nsid;
	unsigned int sqid;
};

static struct fio_option options[] = {
	{
		.name = "nsid",
		.lname = "Namespace ID",
		.type = FIO_OPT_INT,
		.off1 = offsetof(struct libunvmed_options, nsid),
		.help = "Namespace ID",
		.def = "0",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "sqid",
		.lname = "Submission queue ID",
		.type = FIO_OPT_INT,
		.off1 = offsetof(struct libunvmed_options, sqid),
		.help = "Submission queue ID",
		.def = "0",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = NULL,
	},
};

struct libunvmed_data {
	struct fio_file *f;

	/*
	 * `ctrl` and `ns` are shared instances among threads(jobs).
	 */
	struct unvme *u;
	struct unvme_ns *ns;

	/*
	 * Size of original buffer of `td->orig_buffer`.
	 */
	ssize_t orig_buffer_size;
	uint64_t orig_buffer_iova;

	/*
	 * Target I/O submission queue instance per a thread.  A submission
	 * queue is fully dedicated to a thread(job), which means totally
	 * non-sharable.
	 */
	struct unvme_sq *usq;
	struct unvme_cq *ucq;

	unsigned int nr_queued;
	struct nvme_cqe *cqes;
};

static pthread_mutex_t g_serialize = PTHREAD_MUTEX_INITIALIZER;
/* Device instances; *must* be serialized to update */
static FLIST_HEAD(g_devices);

static inline int ilog2(uint32_t i)
{
	int log = -1;

	while (i) {
		i >>= 1;
		log++;
	}
	return log;
}

static inline char *libunvmed_to_bdf(struct fio_file *f)
{
	char *str = f->file_name;
	int nr_dots = 2;

	while (*str && nr_dots > 0) {
		if (*str == '.') {
			*str = ':';
			nr_dots--;
		}
		str++;
	}

	return f->file_name;
}

static inline uint64_t libunvmed_to_iova(struct thread_data *td, void *buf)
{
	struct libunvmed_data *ld = td->io_ops_data;
	uint64_t offset = (uint64_t)(buf - (void *)td->orig_buffer);

	return ld->orig_buffer_iova + (uint64_t)offset;
}

static int libunvmed_check_constraints(struct thread_data *td)
{
	struct libunvmed_options *o = td->eo;

	/*
	 * `libunvmed` ioengine does not support process-based job executions
	 * to bind the current process to `vfio-pci` kernel driver with
	 * multiple threads to share the device.
	 */
	if (!td->o.use_thread) {
		libunvmed_log("'--thread' option is required\n");
		return 1;
	}

	/*
	 * `libunvmed` only supports a single target device(filename) for a
	 * job(thread) to simplify device initialization.
	 */
	if (td->o.nr_files != 1) {
		libunvmed_log("'--filename=' should have a single device\n");
		return 1;
	}

	if (!o->nsid) {
		libunvmed_log("'--nsid=' option should have a target nsid\n");
		return 1;
	}

	if (!o->sqid) {
		libunvmed_log("'--sqid=' option should have a submission queue id\n");
		return 1;
	}

	return 0;
}

static int libunvmed_init_data(struct thread_data *td)
{
	struct libunvmed_options *o = td->eo;
	/* libunvmed ioengine supports a single --filename= for a job */
	struct fio_file *f = td->files[0];
	const char *bdf = libunvmed_to_bdf(f);
	struct libunvmed_data *ld;
	struct unvme *u;
	struct unvme_ns *ns;

	if (td->io_ops_data)
		goto out;

	ld = calloc(1, sizeof(*ld));
	ld->cqes = calloc(td->o.iodepth, sizeof(struct nvme_cqe));

	u = unvmed_get(bdf);
	if (!u) {
		libunvmed_log("failed to get unvme controller instance %s\n", bdf);
		return -EINVAL;
	}

	ns = unvmed_get_ns(u, o->nsid);
	if (!ns) {
		libunvmed_log("failed to get unvme namespace instance (bdf=%s, nsid=%u)\n", bdf, o->nsid);
		return -EINVAL;
	}

	/* Set accessor to device controller and namespace instance */
	ld->u = u;
	ld->ns = ns;

	td->io_ops_data = ld;

out:
	return 0;
}

static int fio_libunvmed_init(struct thread_data *td)
{
	int ret;

	ret = libunvmed_check_constraints(td);
	if (ret)
		return ret;

	ret = pthread_mutex_lock(&g_serialize);
	if (ret)
		return ret;

	ret = libunvmed_init_data(td);
	if (ret)
		goto unlock;

	pthread_mutex_unlock(&g_serialize);
	return 0;

unlock:
	pthread_mutex_unlock(&g_serialize);
	return ret;
}

static int fio_libunvmed_open_file(struct thread_data *td, struct fio_file *f)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;
	struct unvme *u = ld->u;
	int ret;

	ld->f = f;

	ld->usq = unvmed_get_sq(u, o->sqid);
	if (!ld->usq) {
		libunvmed_log("submission queue (--sqid=%d) not found\n", o->sqid);
		return -1;
	}

	ld->ucq = ld->usq->ucq;

	ret = pthread_mutex_lock(&g_serialize);
	if (ret) {
		libunvmed_log("failed to grab mutex lock\n");
		return ret;
	}

	/*
	 * .open_file() is not called in trim-only workloads at all.  To avoid
	 * 0-sized memory allocation, we should check the orig_buffer_size
	 * here.
	 */
	if (ld->orig_buffer_size) {
		ret = unvmed_map_vaddr(u, td->orig_buffer, ld->orig_buffer_size,
				&ld->orig_buffer_iova, 0);
		if (ret)
			libunvmed_log("failed to map io_u buffers to iommu\n");
	}

	pthread_mutex_unlock(&g_serialize);
	return ret;
}

static int fio_libunvmed_close_file(struct thread_data *td,
				 struct fio_file *f)
{
	struct libunvmed_data *ld = td->io_ops_data;
	int ret;

	ret = pthread_mutex_lock(&g_serialize);
	if (ret) {
		libunvmed_log("failed to grab mutex lock\n");
		return ret;
	}

	if (td->orig_buffer) {
		ret = unvmed_unmap_vaddr(ld->u, td->orig_buffer);
		if (ret)
			libunvmed_log("failed to unmap io_u buffers from iommu\n");
	}

	free(ld->cqes);
	free(ld);

	pthread_mutex_unlock(&g_serialize);
	return ret;
}

static int fio_libunvmed_iomem_alloc(struct thread_data *td, size_t total_mem)
{
	struct libunvmed_data *ld = td->io_ops_data;
	ssize_t size;
	void *ptr;
	int ret;

	ret = pthread_mutex_lock(&g_serialize);
	if (ret) {
		libunvmed_log("failed to grab mutex lock\n");
		return ret;
	}

	size = pgmap(&ptr, total_mem);
	if (size < total_mem) {
		libunvmed_log("failed to allocate memory (size=%ld bytes)\n", total_mem);
		pthread_mutex_unlock(&g_serialize);
		return 1;
	}

	td->orig_buffer = (char *)ptr;
	ld->orig_buffer_size = size;

	pthread_mutex_unlock(&g_serialize);
	return 0;
}

static void fio_libunvmed_iomem_free(struct thread_data *td)
{
	struct libunvmed_data *ld = td->io_ops_data;

	pthread_mutex_lock(&g_serialize);
	if (td->orig_buffer)
		pgunmap(td->orig_buffer, ld->orig_buffer_size);
	pthread_mutex_unlock(&g_serialize);
}

static enum fio_q_status fio_libunvmed_rw(struct thread_data *td,
					  struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;

	struct unvme_ns *ns = ld->ns;
	struct unvme_cmd *cmd;
	struct nvme_cmd_rw sqe = {0, };

	uint64_t iova;
	uint64_t slba;
	uint32_t nlb;

	cmd = unvmed_alloc_cmd(ld->u, unvmed_sq_id(ld->usq));
	if (!cmd)
		return FIO_Q_BUSY;

	slba = io_u->offset >> ilog2(ns->lba_size);
	nlb = (io_u->xfer_buflen >> ilog2(ns->lba_size)) - 1;  /* zero-based */

	sqe.opcode = (io_u->ddir == DDIR_READ) ? nvme_cmd_read : nvme_cmd_write;
	sqe.nsid = cpu_to_le32(ns->nsid);
	sqe.slba = cpu_to_le64(slba);
	sqe.nlb = cpu_to_le16(nlb);

	/*
	 * XXX: Making a decision whether PRP or SGL is to be used should be
	 * done in the driver library in sometime later.
	 */
	iova = libunvmed_to_iova(td, io_u->xfer_buf);
	if (__unvmed_map_prp(cmd, (union nvme_cmd *)&sqe, iova,
				io_u->xfer_buflen)) {
		unvmed_cmd_free(cmd);
		return -errno;
	}

	unvmed_cmd_set_opaque(cmd, io_u);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, UNVMED_CMD_F_NODB);
	return FIO_Q_QUEUED;
}

static enum fio_q_status fio_libunvmed_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;
	int ret;

	if (ld->nr_queued == td->o.iodepth)
		return FIO_Q_BUSY;

	if (unvmed_sq_try_enter(ld->usq))
		return FIO_Q_BUSY;

	if (!ld->usq->enabled) {
		unvmed_sq_exit(ld->usq);
		return FIO_Q_BUSY;
	}

	fio_ro_check(td, io_u);

	switch (io_u->ddir) {
	case DDIR_READ:
	case DDIR_WRITE:
		ret = fio_libunvmed_rw(td, io_u);
		break;
	default:
		unvmed_sq_exit(ld->usq);
		return -ENOTSUP;
	}

	ld->nr_queued++;

	unvmed_sq_exit(ld->usq);
	return ret;
}

static int fio_libunvmed_commit(struct thread_data *td)
{
	struct libunvmed_data *ld = td->io_ops_data;
	int nr_sqes;

	nr_sqes = unvmed_sq_update_tail(ld->u, ld->usq);
	io_u_mark_submit(td, nr_sqes);

	return 0;
}

static struct io_u *fio_libunvmed_event(struct thread_data *td, int event)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct unvme *u = ld->u;
	struct nvme_cqe *cqe = &ld->cqes[event];
	struct unvme_cmd *cmd = unvmed_get_cmd_from_cqe(u, cqe);
	struct io_u *io_u;

	assert(cmd != NULL);

	io_u = (struct io_u *)unvmed_cmd_opaque(cmd);

	if (nvme_cqe_ok(cqe))
		io_u->error = 0;
	else
		io_u->error = le16_to_cpu(cqe->sfp) >> 1;

	__unvmed_cmd_free(cmd);

	ld->nr_queued--;
	return io_u;
}

static int fio_libunvmed_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct nvme_cqe *cqes = ld->cqes;
	struct unvme_cq *ucq = ld->usq->ucq;
	int ret;

	ret = unvmed_cq_run_n(ld->u, ucq, cqes, min, max);
	if (ret < 0)
		return -errno;

	return ret;
}

static int fio_libunvmed_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct libunvmed_data *ld;
	int ret;

	/*
	 * It's called before fio_libunvmed_init() so that we should initialize
	 * controller here in this step.
	 */
	ret = fio_libunvmed_init(td);
	if (ret)
		return ret;

	ld = td->io_ops_data;

	f->real_file_size = ld->ns->lba_size * ld->ns->nr_lbas;
	fio_file_set_size_known(f);

	return 0;
}
static struct ioengine_ops ioengine_libunvmed_cmd = {
	.name = "libunvmed",
	.version = FIO_IOOPS_VERSION,
	.options = options,
	.option_struct_size = sizeof(struct libunvmed_options),
	.flags = FIO_DISKLESSIO | FIO_NODISKUTIL | FIO_NOEXTEND |
			FIO_MEMALIGN | FIO_RAWIO,

	.init = fio_libunvmed_init,
	.open_file = fio_libunvmed_open_file,
	.close_file = fio_libunvmed_close_file,
	.get_file_size = fio_libunvmed_get_file_size,

	.iomem_alloc = fio_libunvmed_iomem_alloc,
	.iomem_free = fio_libunvmed_iomem_free,

	.queue = fio_libunvmed_queue,
	.commit = fio_libunvmed_commit,
	.event = fio_libunvmed_event,
	.getevents = fio_libunvmed_getevents,
};

static void fio_init fio_libunvmed_register(void)
{
	register_ioengine(&ioengine_libunvmed_cmd);
}

static void fio_exit fio_libunvmed_unregister(void)
{
	unregister_ioengine(&ioengine_libunvmed_cmd);
}
