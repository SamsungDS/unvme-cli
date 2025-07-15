// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "config-host.h"
#include "fio.h"
#include "optgroup.h"
#include "crc/crc-t10dif.h"
#include "crc/crc64.h"

#undef cpu_to_le64
#undef cpu_to_be64
#undef cpu_to_le32
#undef cpu_to_be32
#undef cpu_to_le16
#undef cpu_to_be16

#include <nvme/types.h>
#include <ccan/str/str.h>

#undef atomic_load_acquire
#undef atomic_store_release
#include <vfn/nvme.h>

#include "libunvmed.h"

#include "verify.h"

#define libunvmed_log(fmt, ...)						\
	do {								\
		fprintf(stdout, "libunvmed: "fmt, ##__VA_ARGS__);	\
	} while (0)


struct libunvmed_options {
	struct thread_data *td;
	unsigned int nsid;
	unsigned int sqid;
	uint64_t prp1_offset;
	unsigned int enable_sgl;
	unsigned int dtype;
	unsigned int dspec;
	unsigned int dsm;
	unsigned int cmb_data;
	unsigned int cmb_list;
	unsigned char meta_err_injection;
	char *meta_error_injection;

	/*
	 * io_uring_cmd ioengine options
	 */
	unsigned int write_mode;
	unsigned int deac;
	unsigned int readfua;
	unsigned int writefua;
	unsigned int verify_mode;
	unsigned int md_per_io_size;
	unsigned int apptag;
	unsigned int apptag_mask;
	unsigned int pi_act;
	unsigned int prchk;
	char *pi_chk;
};

/*
 * write_mode type ported from io_uring_cmd with cmd_type=nvme.  We don't
 * rename the enum values for the future merge in upstream.
 */
enum uring_cmd_write_mode {
	FIO_URING_CMD_WMODE_WRITE = 1,
	FIO_URING_CMD_WMODE_UNCOR,
	FIO_URING_CMD_WMODE_ZEROES,
	FIO_URING_CMD_WMODE_VERIFY,
};

enum uring_cmd_verify_mode {
	FIO_URING_CMD_VMODE_READ = 1,
	FIO_URING_CMD_VMODE_COMPARE,
};

enum libunvmed_error_injections {
	UNVME_ERR_GUARD = 1,
	UNVME_ERR_REFTAG,
	UNVME_ERR_ILBRT,
	UNVME_ERR_LBAT,
};

static int libunvmed_cb_meta_error_injection(void *data, const char *str)
{
	struct libunvmed_options *o = data;

	if (strstr(str, "GUARD"))
		o->meta_err_injection |= UNVME_ERR_GUARD;
	if (strstr(str, "REFTAG"))
		o->meta_err_injection |= UNVME_ERR_REFTAG;
	if (strstr(str, "ILBRT"))
		o->meta_err_injection |= UNVME_ERR_ILBRT;
	if (strstr(str, "LBAT"))
		o->meta_err_injection |= UNVME_ERR_LBAT;

	return 0;
}

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
		.help = "Submission queue ID.  If not given, each SQ will be assigned for each job",
		.def = "0",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "prp1_offset",
		.lname = "Offset value (< MPS) of PRP1 in case of PRP mode",
		.type = FIO_OPT_INT,
		.off1 = offsetof(struct libunvmed_options, prp1_offset),
		.help = "Configure offset value (< MPS) to PRP1 to introduce unaligned PRP1",
		.def = "0",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "enable_sgl",
		.lname = "Use SGL for data buffer",
		.type = FIO_OPT_BOOL,
		.off1 = offsetof(struct libunvmed_options, enable_sgl),
		.help = "Use SGL for data buffer",
		.def = "0",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "dtype",
		.lname = "Directive Type in CDW12",
		.type = FIO_OPT_INT,
		.off1 = offsetof(struct libunvmed_options, dtype),
		.help = "Directive Type",
		.def = "0",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "dspec",
		.lname = "Directive Specific in CDW13",
		.type = FIO_OPT_INT,
		.off1 = offsetof(struct libunvmed_options, dspec),
		.help = "Directive Specific",
		.def = "0",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "dsm",
		.lname = "Dataset Management in CDW13",
		.type = FIO_OPT_INT,
		.off1 = offsetof(struct libunvmed_options, dsm),
		.help = "Dataset Management",
		.def = "0",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "cmb_data",
		.lname = "Place Read/Write data in CMB",
		.type = FIO_OPT_BOOL,
		.off1 = offsetof(struct libunvmed_options, cmb_data),
		.help = "Place read/write data buffer within CMB",
		.def = "0",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "cmb_list",
		.lname = "Place Read/Write PRP list or SGL segment in CMB",
		.type = FIO_OPT_BOOL,
		.off1 = offsetof(struct libunvmed_options, cmb_list),
		.help = "Place read/write PRP list or SGL segment within CMB",
		.def = "0",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "meta_error_injection",
		.lname = "Inject metadata errors",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct libunvmed_options, meta_error_injection),
		.help = "Inject some metadata relative errors to command or buffer",
		.def = NULL,
		.cb = libunvmed_cb_meta_error_injection,
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	/* --ioengine=io_uring_cmd --cmd_type=nvme options */
	{
		.name	= "readfua",
		.lname	= "Read fua flag support",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libunvmed_options, readfua),
		.help	= "Set FUA flag (force unit access) for all Read operations",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "writefua",
		.lname	= "Write fua flag support",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libunvmed_options, writefua),
		.help	= "Set FUA flag (force unit access) for all Write operations",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "write_mode",
		.lname	= "Additional Write commands support (Write Uncorrectable, Write Zeores)",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct libunvmed_options, write_mode),
		.help	= "Issue Write Uncorrectable or Zeroes command instead of Write command",
		.def	= "write",
		.posval = {
			  { .ival = "write",
			    .oval = FIO_URING_CMD_WMODE_WRITE,
			    .help = "Issue Write commands for write operations"
			  },
			  { .ival = "uncor",
			    .oval = FIO_URING_CMD_WMODE_UNCOR,
			    .help = "Issue Write Uncorrectable commands for write operations"
			  },
			  { .ival = "zeroes",
			    .oval = FIO_URING_CMD_WMODE_ZEROES,
			    .help = "Issue Write Zeroes commands for write operations"
			  },
			  { .ival = "verify",
			    .oval = FIO_URING_CMD_WMODE_VERIFY,
			    .help = "Issue Verify commands for write operations"
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "verify_mode",
		.lname	= "Do verify based on the configured command (e.g., Read or Compare command)",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct libunvmed_options, verify_mode),
		.help	= "Issue Read or Compare command in the verification phase",
		.def	= "read",
		.posval = {
			  { .ival = "read",
			    .oval = FIO_URING_CMD_VMODE_READ,
			    .help = "Issue Read commands in the verification phase"
			  },
			  { .ival = "compare",
			    .oval = FIO_URING_CMD_VMODE_COMPARE,
			    .help = "Issue Compare commands in the verification phase"
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name   = "md_per_io_size",
		.lname  = "Separate Metadata Buffer Size per I/O",
		.type   = FIO_OPT_INT,
		.off1   = offsetof(struct libunvmed_options, md_per_io_size),
		.def    = "0",
		.help   = "Size of separate metadata buffer per I/O (Default: 0)",
		.category = FIO_OPT_C_ENGINE,
		.group  = FIO_OPT_G_INVALID,
	},
	{
		.name	= "pi_act",
		.lname	= "Protection Information action (PRACT)",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libunvmed_options, pi_act),
		.def	= "1",
		.help	= "Protection Information Action bit (pi_act=1 or pi_act=0)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name   = "pi_chk",
		.lname  = "Protection Information check",
		.type   = FIO_OPT_STR_STORE,
		.off1   = offsetof(struct libunvmed_options, pi_chk),
		.def    = NULL,
		.help   = "Control of Protection Information Checking (pi_chk=GUARD,REFTAG,APPTAG)",
		.category = FIO_OPT_C_ENGINE,
		.group  = FIO_OPT_G_INVALID,
	},
	{
		.name	= "apptag",
		.lname	= "Application tag for end-to-end Protection Information",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct libunvmed_options, apptag),
		.def	= "0x1234",
		.help	= "Application Tag used in Protection Information field (Default: 0x1234)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "apptag_mask",
		.lname	= "Application tag mask",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct libunvmed_options, apptag_mask),
		.def	= "0xffff",
		.help	= "Application Tag Mask used with Application Tag (Default: 0xffff)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "deac",
		.lname	= "Deallocate bit for write zeroes command",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libunvmed_options, deac),
		.help	= "Set DEAC (deallocate) flag for write zeroes command",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
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
	 * iomem buffers for prp1_offset (unaligned case)
	 */
	void *prp_iomem;
	size_t prp_iomem_size;
	size_t prp_iomem_usize;  /* unit size in bytes */
#define libunvmed_prp_iomem(ld, io_u)  \
	((ld)->prp_iomem + ((io_u)->index * (ld)->prp_iomem_usize))

	/*
	 * A memory page for a PRP list, which is a value for PRP2, if
	 * required.  By default, libunvmed uses default memory page.
	 */
	void *prp_list_iomem;
	size_t prp_list_iomem_size;

	/*
	 * metadata buffer and size
	 */
	void *mbuf;
	size_t mlen;
	uint64_t mbuf_iova;

	/*
	 * for --rw=trim or randtrim (TRIM-only) workload and --rw=[r]w(write)
	 * with --trim_backlog=N is given.  If --trim_backlog is given N, TRIMs
	 * probabily will be issued among N number of WRITEs and this case,
	 * @io_u->xfer_buf == NULL.
	 * If --rw=trimwrite is given, TRIM @io_u is given with @io_u->xfer_buf
	 * != NULL by fio so that libunvmed does not have to prepare it's own
	 * buffer.
	 */
	void *trim_iomem;
	size_t trim_iomem_size;
	uint64_t trim_iomem_iova;

	/*
	 * Target I/O submission queue instance per a thread.  A submission
	 * queue is fully dedicated to a thread(job), which means totally
	 * non-sharable.
	 */
	struct unvme_sq *usq;
	struct unvme_cq *ucq;

	unsigned int nr_queued;
	struct nvme_cqe *cqes;

	uint32_t cdw12_flags[DDIR_RWDIR_CNT];
	uint32_t cdw13_flags[DDIR_RWDIR_CNT];
	uint8_t write_opcode;
};

struct nvme_16b_guard_dif {
	__be16 guard;
	__be16 apptag;
	__be32 srtag;
};

struct nvme_64b_guard_dif {
	__be64 guard;
	__be16 apptag;
	uint8_t srtag[6];
};

/*
 * This meta buffer pointer will be stored each io_u instances to verify
 * protection information.
 */
struct libunvmed_meta_options {
	void *mbuf;
	size_t mlen;

	/*
	 * interval means where the pi data located.  It depends on metadata
	 * size and pi location in device format.
	 */
	uint32_t interval;
	uint16_t apptag;
	uint16_t apptag_mask;
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

static void libunvmed_to_bdf(struct fio_file *f, char *bdf)
{
	char *str = f->file_name;
	int nr_dots = strcount(str, ".");

	/* '1.0' means '0000:00:01.0' */
	while (*str && nr_dots > 1) {
		if (*str == '.') {
			*str = ':';
			nr_dots--;
		}
		str++;
	}

	unvmed_parse_bdf(f->file_name, bdf);
}

static inline uint64_t libunvmed_to_iova(struct thread_data *td, void *buf)
{
	struct libunvmed_data *ld = td->io_ops_data;
	uint64_t offset = (uint64_t)(buf - (void *)td->orig_buffer);

	return ld->orig_buffer_iova + (uint64_t)offset;
}

static inline uint64_t libunvmed_to_meta_iova(struct thread_data *td, void *mbuf)
{
	struct libunvmed_data *ld = td->io_ops_data;
	uint64_t offset = (uint64_t)(mbuf - (void *)ld->mbuf);

	return ld->mbuf_iova + (uint64_t)offset;
}

static inline int libunvmed_pi_enabled(struct unvme_ns *ns)
{
	return (ns->dps & NVME_NS_DPS_PI_MASK);
}

static inline int libunvmed_ns_meta_is_dif(struct unvme_ns *ns)
{
	return ns->mset;
}

static inline uint64_t libunvmed_get_slba(struct io_u *io_u, struct unvme_ns *ns)
{
	if (libunvmed_ns_meta_is_dif(ns))
		return io_u->offset / (ns->lba_size + ns->ms);
	else
		return io_u->offset >> ilog2(ns->lba_size);
}

static inline uint32_t libunvmed_get_nlba(struct io_u *io_u, struct unvme_ns *ns)
{
	if (libunvmed_ns_meta_is_dif(ns))
		return (io_u->xfer_buflen / (ns->lba_size + ns->ms)) - 1;  /* zero-based */
	else
		return (io_u->xfer_buflen >> ilog2(ns->lba_size)) - 1;  /* zero-based */
}

static inline void libunvmed_inject_err_to_meta(uint8_t *data)
{
	*data ^= 1;
}

static void *__cmb_ptr;
static int libunvmed_cmb_alloc(struct thread_data *td, void **ptr, size_t len)
{
	struct libunvmed_data *ld = td->io_ops_data;

	void *cmb;
	ssize_t size;

	size = unvmed_cmb_get_region(ld->u, &cmb);
	if (size <= 0) {
		libunvmed_log("failed to get CMB memory region\n");
		return -1;
	}

	if (!__cmb_ptr)
		__cmb_ptr = cmb;

	len = ROUND_UP(len, getpagesize());

	if (__cmb_ptr + len > cmb + size) {
		libunvmed_log("failed to allocate data buffer in CMB memory, "
				"Reduce --iodepth to fit in CMB area (%#lx > %#lx bytes).\n",
				len, size);
		return -1;
	}

	*ptr = __cmb_ptr;
	__cmb_ptr += len;
	return 0;
}

static void libunvmed_cmb_free_all(struct thread_data *td)
{
	__cmb_ptr = NULL;
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

	if (o->enable_sgl && o->prp1_offset) {
		libunvmed_log("'--sgl' should be used without '--prp1_offset'\n");
		return 1;
	}

	return 0;
}

static int libunvmed_init_data(struct thread_data *td)
{
	struct libunvmed_options *o = td->eo;
	/* libunvmed ioengine supports a single --filename= for a job */
	struct fio_file *f = td->files[0];
	char bdf[32];
	struct libunvmed_data *ld;
	struct unvme *u;
	struct unvme_ns *ns;
	uint32_t lba_size;
	ssize_t ret;
	size_t mlen;

	if (td->io_ops_data)
		goto out;

	libunvmed_to_bdf(f, bdf);

	ld = calloc(1, sizeof(*ld));
	ld->cqes = calloc(td->o.iodepth, sizeof(struct nvme_cqe));

	u = unvmed_get(bdf);
	if (!u) {
		libunvmed_log("failed to get unvme controller instance %s\n", bdf);
		return -EINVAL;
	}

	ns = unvmed_ns_get(u, o->nsid);
	if (!ns) {
		libunvmed_log("failed to get unvme namespace instance (bdf=%s, nsid=%u)\n", bdf, o->nsid);
		return -EINVAL;
	}

	/* Set accessor to device controller and namespace instance */
	ld->u = u;
	ld->ns = ns;

	/*
	 * The given ``bs`` may not be fit with the namespace format.  To prevent
	 * variable error cases, we have to handle this as an error and notice to user.
	 */
	if (!libunvmed_ns_meta_is_dif(ns))
		lba_size = ns->lba_size;
	else
		lba_size = ns->lba_size + ns->ms;

	for_each_rw_ddir(ddir) {
		if (td->o.min_bs[ddir] % lba_size || td->o.max_bs[ddir] % lba_size) {
			libunvmed_log("bs must be multiple of %d\n", lba_size);
			return -EINVAL;
		}

		if (ddir != DDIR_TRIM && ns->ms && !libunvmed_ns_meta_is_dif(ns) &&
		    (o->md_per_io_size < (td->o.max_bs[ddir] / lba_size) * ns->ms)) {
			libunvmed_log("md_per_io_size must be >= %d\n", (uint32_t)((td->o.max_bs[ddir] / lba_size) * ns->ms));
			return -EINVAL;
		}
	}

	/*
	 * md_per_io_size indicates the whole metadata buffer size.  Prepare the
	 * buffer to transfer metadata and map the virtual address to IOMMU.
	 */
	if (!libunvmed_ns_meta_is_dif(ns) && o->md_per_io_size) {
		mlen = o->md_per_io_size * td->o.iodepth;
		ld->mlen = pgmap(&ld->mbuf, mlen);
		if (ld->mlen < 0) {
			libunvmed_log("failed to mmap() for meta buffer");
			return -ENOMEM;
		}

		if (unvmed_map_vaddr(u, ld->mbuf, ld->mlen, &ld->mbuf_iova, 0)) {
			libunvmed_log("failed to map vaddr for metadata\n");
			pgunmap(ld->mbuf, ld->mlen);
			return -EINVAL;
		}
	} else if (o->md_per_io_size)
		libunvmed_log("md_per_io_size will be ignored\n");

	if (td->o.td_ddir == TD_DDIR_TRIM) {
		ld->trim_iomem_size = td->o.iodepth * sizeof(struct nvme_dsm_range) * NVME_DSM_MAX_RANGES;
		ret = pgmap(&ld->trim_iomem, ld->trim_iomem_size);
		if (ret < 0) {
			libunvmed_log("failed to mmap() for TRIM buffer\n");
			return -ENOMEM;
		}

		ld->trim_iomem_size = ret;

		if (unvmed_map_vaddr(u, ld->trim_iomem, ld->trim_iomem_size,
					&ld->trim_iomem_iova, 0)) {
			libunvmed_log("failed to map vaddr for TRIM buffer\n");
			pgunmap(ld->trim_iomem, ld->trim_iomem_size);
			return -EINVAL;
		}
	}

	td->io_ops_data = ld;
out:
	return 0;
}

static int fio_libunvmed_init(struct thread_data *td)
{
	struct libunvmed_data *ld;
	struct libunvmed_options *o = td->eo;
	int ret;

	ret = libunvmed_check_constraints(td);
	if (ret)
		return ret;

	ret = pthread_mutex_lock(&g_serialize);
	if (ret)
		return ret;

	/*
	 * If called twice, return directly here.
	 */
	if (td->io_ops_data) {
		pthread_mutex_unlock(&g_serialize);
		return 0;
	}

	ret = libunvmed_init_data(td);
	if (ret)
		goto unlock;

	ld = td->io_ops_data;

	if (td_write(td)) {
		switch (o->write_mode) {
		case FIO_URING_CMD_WMODE_UNCOR:
			ld->write_opcode = nvme_cmd_write_uncor;
			break;
		case FIO_URING_CMD_WMODE_ZEROES:
			ld->write_opcode = nvme_cmd_write_zeroes;
			if (o->deac)
				ld->cdw12_flags[DDIR_WRITE] |= NVME_IO_DEAC << 16;
			break;
		case FIO_URING_CMD_WMODE_VERIFY:
			ld->write_opcode = nvme_cmd_verify;
			break;
		default:
			ld->write_opcode = nvme_cmd_write;
			if (o->dtype) {
				ld->cdw12_flags[DDIR_WRITE] |=
					(o->dtype * NVME_IO_DTYPE_STREAMS) << 16;
			}
			if (o->dspec)
				ld->cdw13_flags[DDIR_WRITE] |= o->dspec << 16;

			if (o->dsm)
				ld->cdw13_flags[DDIR_WRITE] |= o->dsm & 0xff;

			break;
		}
	}

	if (o->readfua)
		ld->cdw12_flags[DDIR_READ] |= NVME_IO_FUA << 16;
	if (o->writefua)
		ld->cdw12_flags[DDIR_WRITE] |= NVME_IO_FUA << 16;

	pthread_mutex_unlock(&g_serialize);
	return 0;

unlock:
	pthread_mutex_unlock(&g_serialize);
	return ret;
}

static void fio_libunvmed_cleanup(struct thread_data *td)
{
	struct libunvmed_data *ld = td->io_ops_data;
	int refcnt;

	if (td->o.td_ddir == TD_DDIR_TRIM) {
		unvmed_unmap_vaddr(ld->u, ld->trim_iomem);
		pgunmap(ld->trim_iomem, ld->trim_iomem_size);
	}

	refcnt = unvmed_ns_put(ld->u, ld->ns);
	assert(refcnt >= 0);

	if (ld->mbuf) {
		unvmed_unmap_vaddr(ld->u, ld->mbuf);
		pgunmap(ld->mbuf, ld->mlen);
	}

	free(ld->cqes);
	free(ld);
}

static int libunvmed_parse_prchk(struct libunvmed_options *o)
{
	if (!o->pi_chk)
		return 0;

	if (strstr(o->pi_chk, "GUARD"))
		o->prchk |= NVME_IO_PRINFO_PRCHK_GUARD;
	if (strstr(o->pi_chk, "APPTAG"))
		o->prchk |= NVME_IO_PRINFO_PRCHK_APP;
	if (strstr(o->pi_chk, "REFTAG"))
		o->prchk |= NVME_IO_PRINFO_PRCHK_REF;

	if (o->prchk != 0)
		return 0;
	else
		return -1;
}

static int fio_libunvmed_open_file(struct thread_data *td, struct fio_file *f)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;
	struct unvme *u = ld->u;
	int ret;

	ld->f = f;

	ret = pthread_mutex_lock(&g_serialize);
	if (ret) {
		libunvmed_log("failed to grab mutex lock\n");
		return ret;
	}

	if (!o->sqid)
		o->sqid = td->thread_number;

	ld->usq = unvmed_sq_get(u, o->sqid);
	if (!ld->usq) {
		libunvmed_log("submission queue (--sqid=%d) not found\n", o->sqid);
		pthread_mutex_unlock(&g_serialize);
		return -1;
	}

	/*
	 * unvmed daemon itself has grabbed the first usq instance and the
	 * very first fio job should grab the second refcnt, and the following
	 * attempts should be rejected until libunvmed supports multi-jobs for
	 * a single queue.
	 */
	if (atomic_load_acquire(&ld->usq->refcnt) > 2) {
		libunvmed_log("submission queue (--sqid=%d) already in use\n", o->sqid);
		unvmed_sq_put(u, ld->usq);
		pthread_mutex_unlock(&g_serialize);
		return -1;
	}

	ld->ucq = unvmed_cq_get(u, unvmed_sq_cqid(ld->usq));
	if (!ld->ucq) {
		libunvmed_log("completion queue (--cqid=%d) not found\n",
				unvmed_sq_cqid(ld->usq));
		unvmed_sq_put(u, ld->usq);
		pthread_mutex_unlock(&g_serialize);
		return -1;
	}

	if (td->o.iodepth >= unvmed_sq_size(ld->usq)) {
		libunvmed_log("--iodepth=%d is greater than SQ queue size %d\n",
				td->o.iodepth, unvmed_sq_size(ld->usq));
		ret = -1;
		goto out;
	}

	/*
	 * .open_file() is not called in trim-only workloads at all.  To avoid
	 * 0-sized memory allocation, we should check the orig_buffer_size
	 * here.
	 */
	if (ld->orig_buffer_size) {
		if (o->cmb_data)
			unvmed_to_iova(u, td->orig_buffer, &ld->orig_buffer_iova);
		else {
			ret = unvmed_map_vaddr(u, td->orig_buffer, ld->orig_buffer_size,
					&ld->orig_buffer_iova, 0);
			if (ret) {
				libunvmed_log("failed to map io_u buffers to iommu\n");
				ret = -1;
				goto out;
			}
		}
	}

	if (ld->prp_iomem) {
		uint64_t iova;

		ret = unvmed_map_vaddr(u, ld->prp_iomem, ld->prp_iomem_size,
				&iova, 0);
		if (ret) {
			libunvmed_log("failed to map prp iomem to iommu\n");
			ret = -1;
			goto out;
		}
	}

	if (libunvmed_parse_prchk(o)) {
		libunvmed_log("'pi_chk=' has neither GUARD, APPTAG, or REFTAG\n");
		ret = -1;
		goto out;
	}

	if (o->write_mode != FIO_URING_CMD_WMODE_WRITE && !td_write(td)) {
		libunvmed_log("'readwrite=|rw=' has no write\n");
		ret = -1;
		goto out;
	}

out:
	if (ret) {
		unvmed_cq_put(u, ld->ucq);
		unvmed_sq_put(u, ld->usq);
	}
	pthread_mutex_unlock(&g_serialize);
	return ret;
}

static int fio_libunvmed_close_file(struct thread_data *td,
				 struct fio_file *f)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;
	int ret;

	ret = pthread_mutex_lock(&g_serialize);
	if (ret) {
		libunvmed_log("failed to grab mutex lock\n");
		return ret;
	}

	if (ld->prp_iomem) {
		ret = unvmed_unmap_vaddr(ld->u, ld->prp_iomem);
		if (ret)
			libunvmed_log("failed to unmap prp iomem from iommu\n");
	}

	if (td->orig_buffer && !o->cmb_data) {
		ret = unvmed_unmap_vaddr(ld->u, td->orig_buffer);
		if (ret)
			libunvmed_log("failed to unmap io_u buffers from iommu\n");
	}

	unvmed_cq_put(ld->u, ld->ucq);
	unvmed_sq_put(ld->u, ld->usq);

	pthread_mutex_unlock(&g_serialize);

	return ret;
}

static int fio_libunvmed_iomem_alloc(struct thread_data *td, size_t total_mem)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;

	uint64_t max_bs = td_max_bs(td);
	uint64_t max_units = td->o.iodepth;

	ssize_t size;
	void *ptr;
	int ret;

	ret = pthread_mutex_lock(&g_serialize);
	if (ret) {
		libunvmed_log("failed to grab mutex lock\n");
		return ret;
	}

	if (o->cmb_data) {
		if (libunvmed_cmb_alloc(td, &ptr, total_mem)) {
			pthread_mutex_unlock(&g_serialize);
			return 1;
		}

		size = total_mem;
	} else {
		size = pgmap(&ptr, total_mem);
		if (size < total_mem) {
			libunvmed_log("failed to allocate memory (size=%ld bytes)\n", total_mem);
			pthread_mutex_unlock(&g_serialize);
			return 1;
		}
	}

	td->orig_buffer = (char *)ptr;
	ld->orig_buffer_size = size;

	if (o->prp1_offset) {
		ld->prp_iomem_usize = max_bs + getpagesize();
		ld->prp_iomem_size = pgmap(&ld->prp_iomem,
				ld->prp_iomem_usize * max_units);
	}

	if (o->cmb_list) {
		size = getpagesize() * td->o.iodepth;
		if (libunvmed_cmb_alloc(td, &ptr, size)) {
			pthread_mutex_unlock(&g_serialize);
			return 1;
		}

		ld->prp_list_iomem = ptr;
		ld->prp_list_iomem_size = size;
	}

	pthread_mutex_unlock(&g_serialize);
	return 0;
}

static void fio_libunvmed_iomem_free(struct thread_data *td)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;

	pthread_mutex_lock(&g_serialize);

	if (ld->prp_iomem)
		pgunmap(ld->prp_iomem, ld->prp_iomem_size);

	if (td->orig_buffer && !o->cmb_data)
		pgunmap(td->orig_buffer, ld->orig_buffer_size);
	else if (o->cmb_data)
		libunvmed_cmb_free_all(td);

	pthread_mutex_unlock(&g_serialize);
}

static int fio_libunvmed_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;
	struct libunvmed_meta_options *mo;

	mo = calloc(1, sizeof(*mo));
	if (!mo) {
		libunvmed_log("failed to allocate meta options\n");
		return -ENOMEM;
	}

	if (!libunvmed_ns_meta_is_dif(ld->ns) && o->md_per_io_size) {
		mo->mbuf = ld->mbuf + (o->md_per_io_size * io_u->index);
		mo->mlen = o->md_per_io_size;
	}

	if (!o->pi_act) {
		mo->apptag = o->apptag;
		mo->apptag_mask = o->apptag_mask;
	}

	io_u->engine_data = mo;

	if (td->o.td_ddir == TD_DDIR_TRIM) {
		io_u->buflen = sizeof(struct nvme_dsm_range) * NVME_DSM_MAX_RANGES * io_u->index;
		io_u->buf = ld->trim_iomem + io_u->buflen;
	}

	return 0;
}

static void fio_libunvmed_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct libunvmed_meta_options *mo = io_u->engine_data;

	free(mo);
	io_u->engine_data = NULL;
}

static void libunvmed_fill_pi_16b_guard(struct thread_data *td, struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;
	struct libunvmed_meta_options *mo = io_u->engine_data;
	struct unvme_ns *ns = ld->ns;
	struct nvme_16b_guard_dif *pi;
	void *buf = io_u->xfer_buf;
	void *mbuf = mo->mbuf;
	uint32_t lba_idx = 0;
	uint64_t slba = libunvmed_get_slba(io_u, ns);
	uint32_t nlb = libunvmed_get_nlba(io_u, ns);
	uint16_t guard;

	if (ns->dps & NVME_NS_DPS_PI_FIRST) {
		if (libunvmed_ns_meta_is_dif(ns))
			mo->interval = ns->lba_size;
		else
			mo->interval = 0;
	} else {
		if (libunvmed_ns_meta_is_dif(ns))
			mo->interval = ns->lba_size + ns->ms - sizeof(struct nvme_16b_guard_dif);
		else
			mo->interval = ns->ms - sizeof(struct nvme_16b_guard_dif);
	}

	if (io_u->ddir == DDIR_READ)
		return;

	while (lba_idx <= nlb) {
		if (libunvmed_ns_meta_is_dif(ns))
			pi = (struct nvme_16b_guard_dif *)(buf + mo->interval);
		else
			pi = (struct nvme_16b_guard_dif *)(mbuf + mo->interval);

		if (o->prchk & NVME_IO_PRINFO_PRCHK_GUARD) {
			if (libunvmed_ns_meta_is_dif(ns))
				guard = fio_crc_t10dif(0, buf, mo->interval);
			else {
				guard = fio_crc_t10dif(0, buf, ns->lba_size);
				guard = fio_crc_t10dif(guard, mbuf, mo->interval);
			}
			pi->guard = cpu_to_be16(guard);
			if (o->meta_err_injection & UNVME_ERR_GUARD)
				libunvmed_inject_err_to_meta((uint8_t *)&(pi->guard));
		}

		if (o->prchk & NVME_IO_PRINFO_PRCHK_APP)
			pi->apptag = cpu_to_be16(mo->apptag & mo->apptag_mask);

		if (o->prchk & NVME_IO_PRINFO_PRCHK_REF) {
			pi->srtag = cpu_to_be32((uint32_t)slba + lba_idx);
			if (o->meta_err_injection & UNVME_ERR_REFTAG)
				libunvmed_inject_err_to_meta((uint8_t *)&(pi->srtag));
		}

		buf += ns->lba_size;
		if (libunvmed_ns_meta_is_dif(ns))
			buf += ns->ms;
		else
			mbuf += ns->ms;

		lba_idx++;
	}
}

static void libunvmed_fill_pi_64b_guard(struct thread_data *td, struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;
	struct libunvmed_meta_options *mo = io_u->engine_data;
	struct unvme_ns *ns = ld->ns;
	struct nvme_64b_guard_dif *pi;
	void *buf = io_u->xfer_buf;
	void *mbuf = mo->mbuf;
	uint32_t lba_idx = 0;
	uint64_t slba = libunvmed_get_slba(io_u, ns);
	uint32_t nlb = libunvmed_get_nlba(io_u, ns);
	uint64_t guard;

	if (ns->dps & NVME_NS_DPS_PI_FIRST) {
		if (libunvmed_ns_meta_is_dif(ns))
			mo->interval = ns->lba_size;
		else
			mo->interval = 0;
	} else {
		if (libunvmed_ns_meta_is_dif(ns))
			mo->interval = ns->lba_size + ns->ms - sizeof(struct nvme_64b_guard_dif);
		else
			mo->interval = ns->ms - sizeof(struct nvme_64b_guard_dif);
	}

	while (lba_idx <= nlb) {
		if (libunvmed_ns_meta_is_dif(ns))
			pi = (struct nvme_64b_guard_dif *)(buf + mo->interval);
		else
			pi = (struct nvme_64b_guard_dif *)(mbuf + mo->interval);

		if (o->prchk & NVME_IO_PRINFO_PRCHK_GUARD) {
			if (libunvmed_ns_meta_is_dif(ns))
				guard = fio_crc64_nvme(0, buf, mo->interval);
			else {
				guard = fio_crc64_nvme(0, buf, ns->lba_size);
				guard = fio_crc64_nvme(guard, mbuf, mo->interval);
			}
			pi->guard = cpu_to_be64(guard);
			if (o->meta_err_injection & UNVME_ERR_GUARD)
				libunvmed_inject_err_to_meta((uint8_t *)&(pi->guard));
		}

		if (o->prchk & NVME_IO_PRINFO_PRCHK_APP)
			pi->apptag = cpu_to_be16(mo->apptag & mo->apptag_mask);

		if (o->prchk & NVME_IO_PRINFO_PRCHK_REF) {
			put_unaligned_be48(slba + lba_idx, pi->srtag);
			if (o->meta_err_injection & UNVME_ERR_REFTAG)
				libunvmed_inject_err_to_meta((uint8_t *)&(pi->srtag));
		}

		buf += ns->lba_size;
		if (libunvmed_ns_meta_is_dif(ns))
			buf += ns->ms;
		else
			mbuf += ns->ms;

		lba_idx++;
	}
}

static void libunvmed_fill_pi(struct thread_data *td, struct io_u *io_u,
			      struct nvme_cmd_rw *sqe)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;
	struct unvme_ns *ns = ld->ns;

	uint64_t slba = libunvmed_get_slba(io_u, ns);

	/*
	 * Fill the metadata to buffer (or meta buffer). The metadata includes
	 * guard, apptag and reftag.  This will be ignored if PRACT is set to 1.
	 */
	if (!o->pi_act) {
		switch (ns->pif) {
		case NVME_NVM_PIF_16B_GUARD:
			libunvmed_fill_pi_16b_guard(td, io_u);
			break;
		case NVME_NVM_PIF_32B_GUARD:
			break;
		case NVME_NVM_PIF_64B_GUARD:
			libunvmed_fill_pi_64b_guard(td, io_u);
			break;
		default:
			break;
		}
	}

	/*
	 * Fill the tags and flags to SQE.
	 * XXX: The storage tag is not supported, yet.
	 */
	if (o->pi_act)
		sqe->control |= NVME_IO_PRINFO_PRACT;
	sqe->control |= o->prchk;

	if (o->prchk & NVME_IO_PRINFO_PRCHK_APP) {
		sqe->apptag = cpu_to_le16(o->apptag);
		sqe->appmask = cpu_to_le16(o->apptag_mask);
		if (o->meta_err_injection & UNVME_ERR_LBAT)
			libunvmed_inject_err_to_meta((uint8_t *)&(sqe->apptag));
	}

	if (o->prchk & NVME_IO_PRINFO_PRCHK_REF) {
		switch (ns->dps & NVME_NS_DPS_PI_MASK) {
		case NVME_NS_DPS_PI_TYPE1:
		case NVME_NS_DPS_PI_TYPE2:
			if (ns->pif == NVME_NVM_PIF_16B_GUARD)
				sqe->reftag = cpu_to_le32((uint32_t)slba);
			else if (ns->pif == NVME_NVM_PIF_64B_GUARD) {
				sqe->reftag = cpu_to_le32(slba & 0xffffffff);
				sqe->cdw3 = cpu_to_le32(((slba >> 32) & 0xffff));
			}
			break;
		case NVME_NS_DPS_PI_TYPE3:
			break;
		default:
			break;
		}
		if (o->meta_err_injection & UNVME_ERR_ILBRT)
			libunvmed_inject_err_to_meta((uint8_t *)&(sqe->reftag));
	}
}

static enum fio_q_status fio_libunvmed_rw(struct thread_data *td,
					  struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;
	struct libunvmed_meta_options *mo = io_u->engine_data;

	struct unvme_ns *ns = ld->ns;
	struct unvme_cmd *cmd;
	struct nvme_cmd_rw sqe = {0, };

	uint64_t slba = libunvmed_get_slba(io_u, ns);
	uint32_t nlb = libunvmed_get_nlba(io_u, ns);
	uint8_t read_opcode = nvme_cmd_read;

	void *buf = io_u->xfer_buf;
	void *list = NULL;
	size_t len = io_u->xfer_buflen;
	void *mbuf = mo->mbuf;
	size_t mlen = mo->mlen;
	int ret;

	if (o->prp1_offset)
		buf = libunvmed_prp_iomem(ld, io_u);

	if (mlen)
		cmd = unvmed_alloc_cmd_meta(ld->u, ld->usq, NULL, buf, len, mbuf, mlen);
	else
		cmd = unvmed_alloc_cmd(ld->u, ld->usq, NULL, buf, len);
	if (!cmd)
		return FIO_Q_BUSY;

	/*
	 * Copy the original write data buffer to the newly allocated buffer.
	 */
	if (o->prp1_offset && io_u->ddir == DDIR_WRITE)
		memcpy(buf + o->prp1_offset, io_u->xfer_buf, io_u->xfer_buflen);

	/*
	 * If READ command belongs to the verification phase and the
	 * verify_mode=compare, convert READ to COMPARE command.
	 */
	if (io_u->flags & IO_U_F_VER_LIST && io_u->ddir == DDIR_READ &&
			o->verify_mode == FIO_URING_CMD_VMODE_COMPARE) {
		populate_verify_io_u(td, io_u);
		read_opcode = nvme_cmd_compare;
		io_u_set(td, io_u, IO_U_F_VER_IN_DEV);
	}

	sqe.opcode = (io_u->ddir == DDIR_READ) ? read_opcode : ld->write_opcode;
	sqe.nsid = cpu_to_le32(ns->nsid);
	sqe.slba = cpu_to_le64(slba);
	((union nvme_cmd *)&sqe)->cdw12 =
		cpu_to_le32(ld->cdw12_flags[io_u->ddir] | nlb);
	((union nvme_cmd *)&sqe)->cdw13 =
		cpu_to_le32(ld->cdw13_flags[io_u->ddir]);

	/*
	 * Set metadata to SQE and buffer
	 */
	if (libunvmed_pi_enabled(ns))
		libunvmed_fill_pi(td, io_u, &sqe);

	/*
	 * XXX: Making a decision whether PRP or SGL is to be used should be
	 * done in the driver library in sometime later.
	 */
	cmd->buf.iov = (struct iovec) {
		.iov_base = buf + o->prp1_offset,
		.iov_len = io_u->xfer_buflen,
	};

	if (o->cmb_list)
		list = ld->prp_list_iomem + (io_u->index * getpagesize());

	if (o->enable_sgl) {
		sqe.flags |= NVME_CMD_FLAGS_PSDT_SGL_MPTR_CONTIG <<
			NVME_CMD_FLAGS_PSDT_SHIFT;
		ret = __unvmed_mapv_sgl_seg(cmd, (union nvme_cmd *)&sqe,
				list, &cmd->buf.iov, 1);
	} else
		ret = __unvmed_mapv_prp_list(cmd, (union nvme_cmd *)&sqe,
				list, &cmd->buf.iov, 1);

	if (ret) {
		unvmed_cmd_free(cmd);
		return -errno;
	}

	if (mbuf) {
		uint64_t iova;
		if (o->enable_sgl) {
			libunvmed_log("metadata with sgl is not supported yet\n");
			return -EINVAL;
		}

		iova = libunvmed_to_meta_iova(td, mbuf);
		sqe.mptr = cpu_to_le64(iova);
	}

	cmd->opaque = io_u;
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, UNVMED_CMD_F_NODB);
	return FIO_Q_QUEUED;
}

static enum fio_q_status fio_libunvmed_trim(struct thread_data *td,
					    struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;

	struct unvme_ns *ns = ld->ns;
	struct unvme_cmd *cmd;
	union nvme_cmd sqe = {0, };

	const size_t dsm_range_size = 4096;
	struct nvme_dsm_range *range;
	uint64_t slba = libunvmed_get_slba(io_u, ns);
	uint32_t nlb = libunvmed_get_nlba(io_u, ns);

	void *buf = io_u->xfer_buf;

	/*
	 * Case for --trim_backlog=N is given for verify TRIM-ed logical
	 * blocks.  In this case, fio is not giving @xfer_buf as valid buffer,
	 * but @xfer_buflen is still > 0.
	 */
	if (!io_u->xfer_buf && io_u->xfer_buflen > 0)
		buf = io_u->buf;

	cmd = unvmed_alloc_cmd(ld->u, ld->usq, NULL, buf, dsm_range_size);
	if (!cmd)
		return FIO_Q_BUSY;

	range = cmd->buf.va;

	sqe.opcode = nvme_cmd_dsm;
	sqe.nsid = cpu_to_le32(ns->nsid);
	sqe.cdw10 = 0;  /* XXX: Currently single-region of DSM is supported */
	sqe.cdw11 = NVME_DSMGMT_AD;

	range->cattr = 0;
	range->nlb = cpu_to_le32(nlb + 1);
	range->slba = cpu_to_le64(slba);

	if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, &cmd->buf.iov, 1)) {
		unvmed_cmd_free(cmd);
		return -errno;
	}

	cmd->opaque = io_u;
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, UNVMED_CMD_F_NODB);
	return FIO_Q_QUEUED;
}

static enum fio_q_status fio_libunvmed_fsync(struct thread_data *td,
					     struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;

	struct unvme_ns *ns = ld->ns;
	struct unvme_cmd *cmd;
	union nvme_cmd sqe = {0, };

	cmd = unvmed_alloc_cmd_nodata(ld->u, ld->usq, NULL);
	if (!cmd)
		return FIO_Q_BUSY;

	sqe.opcode = nvme_cmd_flush;
	sqe.nsid = cpu_to_le32(ns->nsid);

	cmd->opaque = io_u;
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
	case DDIR_TRIM:
		ret = fio_libunvmed_trim(td, io_u);
		break;
	case DDIR_SYNC:
		ret = fio_libunvmed_fsync(td, io_u);
		break;
	default:
		unvmed_sq_exit(ld->usq);
		io_u->error = -ENOTSUP;
		return FIO_Q_COMPLETED;
	}

	ld->nr_queued++;

	unvmed_sq_exit(ld->usq);
	return ret;
}

static int fio_libunvmed_commit(struct thread_data *td)
{
	struct libunvmed_data *ld = td->io_ops_data;
	int nr_sqes;

	if (unvmed_sq_try_enter(ld->usq))
		return 0;

	if (!ld->usq->enabled) {
		/*
		 * If @usq driver context is still alive for the current fio
		 * application, we can go update the tail doorbell, otherwise
		 * we should stop here.
		 */
		if (atomic_load_acquire(&ld->usq->refcnt) == 1) {
			unvmed_sq_exit(ld->usq);
			return 0;
		}
	}

	nr_sqes = unvmed_sq_update_tail(ld->u, ld->usq);
	unvmed_sq_exit(ld->usq);

	io_u_mark_submit(td, nr_sqes);
	return 0;
}

static int libunvmed_verify_pi_16b_guard(struct thread_data *td, struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;
	struct libunvmed_meta_options *mo = io_u->engine_data;
	struct unvme_ns *ns = ld->ns;
	struct nvme_16b_guard_dif *pi;
	void *buf = io_u->xfer_buf;
	void *mbuf = mo->mbuf;
	uint32_t lba_idx = 0;
	uint64_t slba = libunvmed_get_slba(io_u, ns);
	uint32_t nlb = libunvmed_get_nlba(io_u, ns);

	while (lba_idx <= nlb) {
		if (libunvmed_ns_meta_is_dif(ns))
			pi = (struct nvme_16b_guard_dif *)(buf + mo->interval);
		else
			pi = (struct nvme_16b_guard_dif *)(mbuf + mo->interval);

		/*
		 * When the namespace is formatted for Type 1 or 2, if the apptag
		 * values are all `1`s, the pi validation will be skipped.
		 */
		if (((ns->dps & NVME_NS_DPS_PI_MASK) == NVME_NS_DPS_PI_TYPE1 ||
		    (ns->dps & NVME_NS_DPS_PI_MASK) == NVME_NS_DPS_PI_TYPE2) &&
		    be16_to_cpu(pi->apptag) == 0xffff)
			goto next;

		/*
		 * When the namespace is formatted for Type 3, if the apptag
		 * and reftag values are all `1`s, the pi validation will be skipped.
		 */
		if ((ns->dps & NVME_NS_DPS_PI_TYPE3) == NVME_NS_DPS_PI_TYPE3 &&
		    be16_to_cpu(pi->apptag) == 0xffff &&
		    be32_to_cpu(pi->srtag) == 0xffffffff)
			goto next;

		if (o->prchk & NVME_IO_PRINFO_PRCHK_GUARD) {
			uint16_t guard = be16_to_cpu(pi->guard);
			uint16_t guard_exp;
			if (libunvmed_ns_meta_is_dif(ns))
				guard_exp = fio_crc_t10dif(0, buf, mo->interval);
			else {
				guard_exp = fio_crc_t10dif(0, buf, ns->lba_size);
				guard_exp = fio_crc_t10dif(guard_exp, mbuf, mo->interval);
			}
			if (guard != guard_exp) {
				libunvmed_log("Guard check error, guard=%#x, expected=%#x\n", guard, guard_exp);
				return -EIO;
			}
		}

		if (o->prchk & NVME_IO_PRINFO_PRCHK_APP) {
			uint16_t at = be16_to_cpu(pi->apptag & mo->apptag_mask);
			uint16_t at_exp = mo->apptag & mo->apptag_mask;
			if (at != at_exp) {
				libunvmed_log("Apptag check error, apptag=%#x, expected=%#x\n", at, at_exp);
				return -EIO;
			}
		}

		if (o->prchk & NVME_IO_PRINFO_PRCHK_REF) {
			switch (ns->dps & NVME_NS_DPS_PI_MASK) {
			case NVME_NS_DPS_PI_TYPE1:
			case NVME_NS_DPS_PI_TYPE2:
				uint32_t rt = be32_to_cpu(pi->srtag);
				uint32_t rt_exp = (uint32_t)slba + lba_idx;
				if (rt != rt_exp) {
					libunvmed_log("Reftag check error, reftag=%#x, expected=%#x\n", rt, rt_exp);
					return -EIO;
				}
				break;
			case NVME_NS_DPS_PI_TYPE3:
				break;
			default:
				assert(false);
			}
		}

next:
		buf += ns->lba_size;
		if (libunvmed_ns_meta_is_dif(ns))
			buf += ns->ms;
		else
			mbuf += ns->ms;

		lba_idx++;
	}

	return 0;
}

static int libunvmed_verify_pi_64b_guard(struct thread_data *td, struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;
	struct libunvmed_meta_options *mo = io_u->engine_data;
	struct unvme_ns *ns = ld->ns;
	struct nvme_64b_guard_dif *pi;
	void *buf = io_u->xfer_buf;
	void *mbuf = mo->mbuf;
	uint32_t lba_idx = 0;
	uint64_t slba = libunvmed_get_slba(io_u, ns);
	uint32_t nlb = libunvmed_get_nlba(io_u, ns);

	while (lba_idx <= nlb) {
		if (libunvmed_ns_meta_is_dif(ns))
			pi = (struct nvme_64b_guard_dif *)(buf + mo->interval);
		else
			pi = (struct nvme_64b_guard_dif *)(mbuf + mo->interval);
		/*
		 * When the namespace is formatted for Type 1 or 2, if the apptag
		 * values are all `1`s, the pi validation will be skipped.
		 */
		if (((ns->dps & NVME_NS_DPS_PI_MASK) == NVME_NS_DPS_PI_TYPE1 ||
		    (ns->dps & NVME_NS_DPS_PI_MASK) == NVME_NS_DPS_PI_TYPE2) &&
		    be16_to_cpu(pi->apptag) == 0xffff)
			goto next;

		/*
		 * When the namespace is formatted for Type 3, if the apptag
		 * and reftag values are all `1`s, the pi validation will be skipped.
		 */
		if ((ns->dps & NVME_NS_DPS_PI_MASK) == NVME_NS_DPS_PI_TYPE3 &&
		    be16_to_cpu(pi->apptag) == 0xffff &&
		    get_unaligned_be48(pi->srtag) == 0xffffffffffff)
			goto next;

		if (o->prchk & NVME_IO_PRINFO_PRCHK_GUARD) {
			uint64_t guard = be64_to_cpu(pi->guard);
			uint64_t guard_exp;
			if (libunvmed_ns_meta_is_dif(ns))
				guard_exp = fio_crc64_nvme(0, buf, mo->interval);
			else {
				guard_exp = fio_crc64_nvme(0, buf, ns->lba_size);
				guard_exp = fio_crc64_nvme(guard_exp, mbuf, mo->interval);
			}
			if (guard != guard_exp) {
				libunvmed_log("Guard check error, guard=%#lx, expected=%#lx\n", guard, guard_exp);
				return -EIO;
			}
		}

		if (o->prchk & NVME_IO_PRINFO_PRCHK_APP) {
			uint16_t at = be16_to_cpu(pi->apptag & mo->apptag_mask);
			uint16_t at_exp = mo->apptag & mo->apptag_mask;
			if (at != at_exp) {
				libunvmed_log("Apptag check error, apptag=%#x, expected=%#x\n", at, at_exp);
				return -EIO;
			}
		}

		if (o->prchk & NVME_IO_PRINFO_PRCHK_REF) {
			switch (ns->dps & NVME_NS_DPS_PI_MASK) {
			case NVME_NS_DPS_PI_TYPE1:
			case NVME_NS_DPS_PI_TYPE2:
				uint64_t rt = get_unaligned_be48(pi->srtag);
				uint64_t rt_exp = slba + lba_idx;
				if (rt != rt_exp) {
					libunvmed_log("Reftag check error, reftag=%#lx, expected=%#lx\n", rt, rt_exp);
					return -EIO;
				}
				break;
			case NVME_NS_DPS_PI_TYPE3:
				break;
			default:
				assert(false);
			}
		}

next:
		buf += ns->lba_size;
		if (libunvmed_ns_meta_is_dif(ns))
			buf += ns->ms;
		else
			mbuf += ns->ms;

		lba_idx++;
	}

	return 0;
}

static int libunvmed_verify_pi(struct thread_data *td, struct io_u *io_u)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct unvme_ns *ns = ld->ns;

	if (ns->pif == NVME_NVM_PIF_16B_GUARD)
		return libunvmed_verify_pi_16b_guard(td, io_u);
	else if (ns->pif == NVME_NVM_PIF_32B_GUARD) {
		libunvmed_log("Not support 32B guard PI\n");
		return -EINVAL;
	}
	else if (ns->pif == NVME_NVM_PIF_64B_GUARD)
		return libunvmed_verify_pi_64b_guard(td, io_u);

	return -EINVAL;
}

static struct io_u *fio_libunvmed_event(struct thread_data *td, int event)
{
	struct libunvmed_data *ld = td->io_ops_data;
	struct libunvmed_options *o = td->eo;

	struct nvme_cqe *cqe = &ld->cqes[event];
	struct unvme_cmd *cmd = &ld->usq->cmds[cqe->cid];
	struct unvme_ns *ns = ld->ns;
	struct io_u *io_u;

	assert(le16_to_cpu(cqe->sqid) == unvmed_sq_id(ld->usq));
	assert(cmd != NULL);

	io_u = (struct io_u *)cmd->opaque;

	if (nvme_cqe_ok(cqe))
		io_u->error = 0;
	else {
		io_u->error = le16_to_cpu(cqe->sfp) >> 1;
		goto ret;
	}

	/*
	 * Copy read data to the original buffer for verify phase
	 */
	if (o->prp1_offset && io_u->ddir == DDIR_READ)
		memcpy(io_u->xfer_buf, cmd->buf.iov.iov_base, io_u->xfer_buflen);

	if (libunvmed_pi_enabled(ns) &&
	     io_u->ddir == DDIR_READ && !o->pi_act) {
		io_u->error = libunvmed_verify_pi(td, io_u);
	}

ret:
	unvmed_cmd_free(cmd);

	ld->nr_queued--;

	if ((int)io_u->error > 0)
		io_u_set(td, io_u, IO_U_F_DEVICE_ERROR);
	else
		io_u_clear(td, io_u, IO_U_F_DEVICE_ERROR);
	io_u->error = abs((int)io_u->error);

	return io_u;
}

static int fio_libunvmed_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	struct libunvmed_data *ld = td->io_ops_data;

	/*
	 * This function's called before .open_file() when the read_iolog
	 * option is enabled meaning that @ld->usq can be NULL.
	 */
	if (td->o.read_iolog_file && !ld->usq)
		return 0;

	struct nvme_cqe *cqes = ld->cqes;
	struct unvme_cq *ucq = ld->usq->ucq;
	int ret;

	ret = unvmed_cq_run_n(ld->u, ld->usq, ucq, cqes, min, max);
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

static char *fio_libunvmed_errdetails(struct thread_data *td, struct io_u *io_u)
{
	unsigned int sct = (io_u->error >> 8) & 0x7;
	unsigned int sc = io_u->error & 0xff;
#define MAXERRDETAIL 1024
#define MAXMSGCHUNK 128
	char *msg, msgchunk[MAXMSGCHUNK];

	if (!(io_u->flags & IO_U_F_DEVICE_ERROR))
		return NULL;

	msg = calloc(1, MAXERRDETAIL);
	strcpy(msg, "libunvmed: ");

	snprintf(msgchunk, MAXMSGCHUNK, "%s: ", io_u->file->file_name);
	strlcat(msg, msgchunk, MAXERRDETAIL);

	strlcat(msg, "cq entry status (", MAXERRDETAIL);

	snprintf(msgchunk, MAXMSGCHUNK, "status=0x%x(sct=0x%02x, sc=0x%02x))",
		 io_u->error, sct, sc);

	strlcat(msg, msgchunk, MAXERRDETAIL);

	return msg;
}

static struct ioengine_ops ioengine_libunvmed_cmd = {
	.name = "libunvmed",
	.version = FIO_IOOPS_VERSION,
	.options = options,
	.option_struct_size = sizeof(struct libunvmed_options),
	.flags = FIO_DISKLESSIO | FIO_NODISKUTIL | FIO_NOEXTEND |
			FIO_MEMALIGN | FIO_RAWIO,

	.init = fio_libunvmed_init,
	.cleanup = fio_libunvmed_cleanup,
	.open_file = fio_libunvmed_open_file,
	.close_file = fio_libunvmed_close_file,
	.get_file_size = fio_libunvmed_get_file_size,

	.iomem_alloc = fio_libunvmed_iomem_alloc,
	.iomem_free = fio_libunvmed_iomem_free,

	.io_u_init = fio_libunvmed_io_u_init,
	.io_u_free = fio_libunvmed_io_u_free,

	.queue = fio_libunvmed_queue,
	.commit = fio_libunvmed_commit,
	.event = fio_libunvmed_event,
	.getevents = fio_libunvmed_getevents,
	.errdetails = fio_libunvmed_errdetails,
};

static void fio_init fio_libunvmed_register(void)
{
	register_ioengine(&ioengine_libunvmed_cmd);
}

static void fio_exit fio_libunvmed_unregister(void)
{
	unregister_ioengine(&ioengine_libunvmed_cmd);
}
