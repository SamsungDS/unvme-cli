// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/msg.h>
#include <sys/time.h>

#include <ccan/opt/opt.h>
#include <ccan/str/str.h>
#include <nvme/types.h>
#include <vfn/pci.h>
#include <vfn/nvme.h>

#include "libunvmed.h"
#include "unvme.h"
#include "unvmed.h"

#define unvme_err_return(err, fmt, ...)					\
	do {								\
		unvme_pr_err("ERROR: "fmt"\n\n", ##__VA_ARGS__);	\
		unvme_cmd_help(argv[1], desc, opts);			\
		return err;						\
	} while(0)

static void unvme_pr_cqe(struct nvme_cqe *cqe)
{
	uint32_t sct, sc;

	sct = (cqe->sfp >> 9) & 0x7;
	sc = (cqe->sfp >> 1) & 0xff;

	unvme_pr_err("CQ entry: sqid=%#x, cid=%#x, dw0=%#x, dw1=%#x, sct=%#x, sc=%#x\n",
			cqe->sqid, cqe->cid, cqe->dw0, cqe->dw1, sct, sc);
}

static void unvme_pr_cqe_status(int status)
{
	uint8_t type = (status >> 8) & 0x7;
	uint8_t code = status & 0xff;

	unvme_pr_err("CQE status: type=%#x, code=%#x\n", type, code);
}

static inline void __unvme_cmd_pr(const char *format, void *buf, size_t len,
			   void (*pr)(void *))
{
	if (streq(format, "binary"))
		unvme_pr_raw(buf, len);
	else if (streq(format, "normal"))
		pr(buf);
	else
		assert(false);
}

static void unvme_cmd_pr_raw(void *buf, size_t len)
{
	__unvme_cmd_pr("binary", buf, len, NULL);
}

static bool __is_nvme_device(const char *bdf)
{
	unsigned long long class;
	__unvme_free char *path = NULL;
	char buf[32];
	int ret;
	int fd;

	ret = asprintf(&path, "/sys/bus/pci/devices/%s/class", bdf);
	assert(ret > 0);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0) {
		close(fd);
		return false;
	}
	buf[ret] = '\0';

	class = strtoull(buf, NULL, 16);
	return ((class >> 8) & 0xffff) == 0x108;
}

static int unvmed_pci_bind(const char *bdf)
{
	const char *target = "vfio-pci";
	unsigned long long vendor, device;

	if (pci_device_info_get_ull(bdf, "vendor", &vendor)) {
		perror("pci_device_info_get_ull");
		return -1;
	}

	if (pci_device_info_get_ull(bdf, "device", &device)) {
		perror("pci_device_info_get_ull");
		return -1;
	}

	pci_unbind(bdf);

	if (pci_driver_new_id(target, vendor, device)) {
		if (pci_bind(bdf, target)) {
			perror("pci_bind");
			return -1;
		}
	}

	return 0;
}

static int unvmed_pci_unbind(const char *bdf)
{
	return pci_unbind(bdf);
}

int unvme_list(int argc, char *argv[], struct unvme_msg *msg)
{
	struct dirent *entry;
	char *bdf;
	DIR *dfd;
	bool help = false;
	const char *desc =
		"Print NVMe PCI device(s) in the current system as PCI BDF\n"
		"(Bus-Device-Function) format. It requires unvmed to figure\n"
		"out whether each device is attached to unvmed service or not.";

	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(2, argc, argv, opts, opt_log_stderr, help, desc);

	dfd = opendir("/sys/bus/pci/devices");
	if (!dfd)
		unvme_pr_return(ENOENT, "unvme: failed to open sysfs\n");

	unvme_pr("NVMe device    \tAttached\tDriver      \n");
        unvme_pr("---------------\t--------\t------------\n");
	while ((entry = readdir(dfd))) {
		if (streq(entry->d_name, ".") || streq(entry->d_name, ".."))
			continue;

		bdf = entry->d_name;
		if (!__is_nvme_device(bdf))
			continue;

		unvme_pr("%-15s\t%-8s\t%-12s\n", bdf,
				unvmed_get(bdf) ? "yes" : "no",
				pci_get_driver(bdf));
	}

	closedir(dfd);

	return 0;
}

int unvme_add(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	bool help = false;
	uint32_t nr_ioqs = 1;

	const char *desc =
		"Register a given target <device> to unvmed service by binding\n"
		"it to 'vfio-pci' kernel driver to support user-space I/O.";

	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--nr-ioqs", opt_set_uintval, opt_show_uintval, &nr_ioqs,
				"[O] Maxinum number of I/O queues to create (defaults to 1)"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (u)
		unvme_err_return(EPERM, "Do 'unvme del %s' first", bdf);

	if (nr_ioqs < 1)
		unvme_err_return(EINVAL, "'--nr-ioqs=' should be greater than 0");

	if (unvmed_pci_bind(bdf))
		unvme_err_return(errno, "failed to bind PCI device");

	if (!unvmed_init_ctrl(bdf, nr_ioqs))
		unvme_err_return(errno, "failed to initialize unvme");

	return 0;
}

int unvme_del(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	bool help = false;

	const char *desc =
		"Delete a given target <device> from unvmed service by unbinding\n"
		"it from 'vfio-pci' kernel driver";

	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", bdf);

	unvmed_free_ctrl(u);

	if (unvmed_pci_unbind(bdf))
		unvme_err_return(errno, "failed to unbind %s\n", bdf);

	return 0;
}

int unvme_show_regs(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	const char *desc =
		"Show NVMe controller properties (registers in MMIO space).";

	bool help = false;
	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", bdf);

	unvme_pr_show_regs(u);
	return 0;
}

int unvme_status(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	bool help = false;

	const char *desc =
		"Show status of a given target <device> in unvmed.\n"
		"The status includes CC, CSTS and Submission/Completion Queue.";

	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", bdf);

	unvme_pr_status(u);

	return 0;
}

int unvme_enable(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	bool help = false;
	const char *desc =
		"Enable NVMe controller along with setting up admin queues.\n"
		"It will wait for CSTS.RDY to be 1 after setting CC.EN to 1.";

	uint32_t iosqes = 6;
	uint32_t iocqes = 4;
	uint32_t mps = 0;
	uint32_t css = 0;

	struct opt_table opts[] = {
		OPT_WITH_ARG("-s|--iosqes", opt_set_uintval, opt_show_uintval, &iosqes, "[O] I/O Submission Queue entry Size (2^n) (default: 6)"),
		OPT_WITH_ARG("-c|--iocqes", opt_set_uintval, opt_show_uintval, &iocqes, "[O] I/O Completion Queue entry Size (2^n) (default: 4)"),
		OPT_WITH_ARG("-m|--mps", opt_set_uintval, opt_show_uintval, &mps, "[O] Memory Page Size (2^(12+n)) (default: 0)"),
		OPT_WITH_ARG("-i|--css", opt_set_uintval, opt_show_uintval, &css, "[O] I/O Command Set Selected (default: 0)"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (iosqes > 0xf)
		unvme_err_return(EINVAL, "invalid -s|--iosqes");
	if (iocqes > 0xf)
		unvme_err_return(EINVAL, "invalid -c|--iocqes");
	if (mps > 0xf)
		unvme_err_return(EINVAL, "invalid -m|--mps");
	if (css > 0x7)
		unvme_err_return(EINVAL, "invalid -i|--css");

	if (unvmed_create_adminq(u))
		unvme_err_return(errno, "failed to create adminq");

	if (unvmed_enable_ctrl(u, iosqes, iocqes, mps, css))
		unvme_err_return(errno, "failed to enable controller");

	return 0;
}

int unvme_create_iocq(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	uint32_t qid = 0;
	uint32_t qsize = 0;
	uint32_t vector = 0;
	bool help = false;
	const char *desc =
		"Submit a Create I/O Completion Queue admin command to the target\n"
		"<device>. DMA address of the queue will be allocated and configured\n"
		"by libvfn.";

	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--qid", opt_set_uintval, opt_show_uintval, &qid, "[M] Completion Queue ID to create"),
		OPT_WITH_ARG("-z|--qsize", opt_set_uintval, opt_show_uintval, &qsize, "[M] Queue size (1-based)"),
		OPT_WITH_ARG("-v|--vector", opt_set_uintval, opt_show_uintval, &vector, "[O] Interrupt vector (defaults to 0)"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (!qid)
		unvme_err_return(EINVAL, "-q|--qid required");
	if (!qsize)
		unvme_err_return(EINVAL, "-z|--qsize required");

	if (unvmed_get_cq(u, qid))
		unvme_err_return(EEXIST, "CQ (qid=%u) already exists", qid);

	return unvmed_create_cq(u, qid, qsize, vector);
}

int unvme_delete_iocq(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	uint32_t qid = 0;
	bool help = false;
	const char *desc =
		"Submit a Delete I/O Completion Queue admin command to the target <device>.";

	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--qid", opt_set_uintval, opt_show_uintval, &qid, "[M] Completion Queue ID to delete"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (!qid)
		unvme_err_return(EINVAL, "-q|--qid required");

	if (!unvmed_get_cq(u, qid))
		unvme_err_return(ENODEV, "CQ (qid=%u) does not exist", qid);

	return unvmed_delete_cq(u, qid);
}

int unvme_create_iosq(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	uint32_t qid = 0;
	uint32_t qsize = 0;
	uint32_t cqid = 0;
	bool help = false;
	const char *desc =
		"Submit a Create I/O Submission Queue admin command to the target\n"
		"<device>. DMA address of the queue will be allocated and configured\n"
		"by libvfn.";

	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--qid", opt_set_uintval, opt_show_uintval, &qid, "[M] Submission Queue ID to create"),
		OPT_WITH_ARG("-z|--qsize", opt_set_uintval, opt_show_uintval, &qsize, "[M] Queue size (1-based)"),
		OPT_WITH_ARG("-c|--cqid", opt_set_uintval, opt_show_uintval, &cqid, "[M] Completion Queue ID"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (!qid)
		unvme_err_return(EINVAL, "-q|--qid required");
	if (!qsize)
		unvme_err_return(EINVAL, "-z|--qsize required");
	if (!cqid)
		unvme_err_return(EINVAL, "-c|--cqid required");

	if (unvmed_get_sq(u, qid))
		unvme_err_return(EEXIST, "SQ (qid=%u) already exists", qid);

	return unvmed_create_sq(u, qid, qsize, cqid);
}

int unvme_delete_iosq(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	uint32_t qid = 0;
	bool help = false;
	const char *desc =
		"Submit a Delete I/O Submission Queue admin command\n"
		"to the target <device>.";

	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--qid", opt_set_uintval, opt_show_uintval, &qid, "[M] Submission Queue ID to delete"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (!qid)
		unvme_err_return(EINVAL, "-q|--qid required");

	if (!unvmed_get_sq(u, qid))
		unvme_err_return(ENODEV, "SQ (qid=%u) does not exist", qid);

	return unvmed_delete_sq(u, qid);
}

int unvme_id_ns(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	uint32_t nsid = 0;
	char *format= "normal";
	bool nodb = false;
	bool help = false;
	const char *desc =
		"Submit an Identify Namespace admin command to the target <device>.";

	struct opt_table opts[] = {
		OPT_WITH_ARG("-n|--namespace-id", opt_set_uintval, opt_show_uintval, &nsid, "[M] Namespace ID"),
		OPT_WITH_ARG("-o|--output-format", opt_set_charp, opt_show_charp, &format, "[O] Output format: [normal|binary], defaults to normal"),
		OPT_WITHOUT_ARG("-N|--nodb", opt_set_bool, &nodb, "[O] Don't update tail doorbell of the submission queue"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	const size_t size = NVME_IDENTIFY_DATA_SIZE;
	__unvme_free void *buf;
	unsigned long flags = 0;
	int ret;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first",
				unvme_msg_bdf(msg));

	if (!nsid)
		unvme_err_return(EINVAL, "-n|--namespace-id required");
	if (!unvmed_get_sq(u, 0))
		unvme_err_return(EPERM, "'enable' must be executed first");

	buf = malloc(size);
	if (!buf)
		unvme_err_return(ENOMEM, "failed to malloc() for buffer");

	if (nodb)
		flags |= UNVMED_CMD_F_NODB;

	ret = unvmed_id_ns(u, nsid, buf, flags);
	if (!ret && !nodb)
		__unvme_cmd_pr(format, buf, size, unvme_pr_id_ns);
	else if (ret > 0)
		unvme_pr_cqe_status(ret);

	return ret;
}

int unvme_read(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	uint32_t sqid = 0;
	uint32_t nsid = 0;
	uint64_t slba = 0;
	uint32_t nlb = 0;
	uint32_t data_size= 0;
	char *data = NULL;
	bool nodb = false;
	bool help = false;
	const char *desc =
		"Submit a Read I/O command to the given submission queue of the\n"
		"target <device>. To run this command, I/O queue MUST be created.\n"
		"Read data from the namespace can be printed to stdout or a file\n"
		"configured by -d|--data.";

	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--sqid", opt_set_uintval, opt_show_uintval, &sqid, "[M] Submission queue ID"),
		OPT_WITH_ARG("-n|--namespace-id", opt_set_uintval, opt_show_uintval, &nsid, "[M] Namespace ID"),
		OPT_WITH_ARG("-s|--start-block", opt_set_ulongval, opt_show_ulongval, &slba, "[M] Start LBA"),
		OPT_WITH_ARG("-c|--block-count", opt_set_uintval, opt_show_uintval, &nlb, "[M] Number of logical block (0-based)"),
		OPT_WITH_ARG("-z|--data-size", opt_set_uintval_bi, opt_show_uintval_bi, &data_size, "[M] Read data buffer size in bytes"),
		OPT_WITH_ARG("-d|--data", opt_set_charp, opt_show_charp, &data, "[O] File to write read data"),
		OPT_WITHOUT_ARG("-N|--nodb", opt_set_bool, &nodb, "[O] Don't update tail doorbell of the submission queue"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	__unvme_free char *filepath = NULL;
	__unvme_free void *buf;
	unsigned long flags = 0;
	int ret;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (!sqid)
		unvme_err_return(EINVAL, "-q|--sqid required");
	if (!nsid)
		unvme_err_return(EINVAL, "-n|--namespace-id required");
	if (!unvmed_get_sq(u, sqid))
		unvme_err_return(ENOENT, "'create-iosq' must be executed first");

	buf = malloc(data_size);
	if (!buf)
		unvme_err_return(ENOMEM, "failed to malloc() for buffer");

	if (nodb)
		flags |= UNVMED_CMD_F_NODB;

	if (data)
		filepath = unvme_get_filepath(unvme_msg_pwd(msg), data);

	ret = unvmed_read(u, sqid, nsid, slba, nlb, buf, data_size, flags);
	if (!ret && !nodb) {
		if (!filepath)
			unvme_cmd_pr_raw(buf, data_size);
		else
			unvme_write_file(filepath, buf, data_size);
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);

	return ret;
}

int unvme_write(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	uint32_t sqid = 0;
	uint32_t nsid = 0;
	uint64_t slba = 0;
	uint32_t nlb = 0;
	uint32_t data_size = 0;
	char *data = NULL;
	bool nodb = false;
	bool help = false;
	const char *desc =
		"Submit a Write command to the given submission queue of the\n"
		"target <device>. To run this command, I/O queue MUST be created.\n"
		"WRite data file can be given as -d|--data with a file path.";

	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--sqid", opt_set_uintval, opt_show_uintval, &sqid, "[M] Submission queue ID"),
		OPT_WITH_ARG("-n|--namespace-id", opt_set_uintval, opt_show_uintval, &nsid, "[M] Namespace ID"),
		OPT_WITH_ARG("-s|--start-block", opt_set_ulongval, opt_show_ulongval, &slba, "[M] Start LBA"),
		OPT_WITH_ARG("-c|--block-count", opt_set_uintval, opt_show_uintval, &nlb, "[M] Number of logical block (1-based)"),
		OPT_WITH_ARG("-z|--data-size", opt_set_uintval_bi, opt_show_uintval_bi, &data_size, "[O] Logical block size in bytes"),
		OPT_WITH_ARG("-d|--data", opt_set_charp, opt_show_charp, &data, "[M] File to write as write data"),
		OPT_WITHOUT_ARG("-N|--nodb", opt_set_bool, &nodb, "[O] Don't update tail doorbell of the submission queue"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	__unvme_free char *filepath = NULL;
	__unvme_free void *buf;
	unsigned long flags = 0;
	int ret;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (!sqid)
		unvme_err_return(EINVAL, "-q|--sqid required");
	if (!nsid)
		unvme_err_return(EINVAL, "-n|--namespace-id required");
	if (!data)
		unvme_err_return(EINVAL, "-d|--data required");
	if (!unvmed_get_sq(u, sqid))
		unvme_err_return(ENOENT, "'create-iosq' must be executed first");

	buf = malloc(data_size);
	if (!buf)
		unvme_err_return(ENOMEM, "failed to malloc() for buffer");

	if (nodb)
		flags |= UNVMED_CMD_F_NODB;

	if (data)
		filepath = unvme_get_filepath(unvme_msg_pwd(msg), data);

	if (unvme_read_file(filepath, buf, data_size))
		unvme_err_return(ENOENT, "failed to read data from file %s", filepath);

	ret = unvmed_write(u, sqid, nsid, slba, nlb, buf, data_size, flags);
	if (ret > 0)
		unvme_pr_cqe_status(ret);

	return ret;
}

int unvme_passthru(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	bool help = false;
	const char *desc =
		"Submit a passthru command to the given submission queue of the\n"
		"target <device>. To run this command, queue MUST be created.\n"
		"Passthru command SQE can be built with the options provided.\n"
		"\n"
		"User can inject specific values to PRP1 and PRP2 in DPTR with --prp1, --prp2\n"
		"options, but it might cause system crash without protection by IOMMU.";

	uint32_t sqid = 0;
	uint32_t nsid = 0;
	int opcode = -1;
	uint32_t flags = 0;
	uint32_t rsvd = 0;
	uint32_t data_len = 0;
	uint32_t cdw2 = 0;
	uint32_t cdw3 = 0;
	/* To figure out whether --prp1=, --prp2= are given or not */
	char *prp1 = NULL;
	char *prp2 = NULL;
	uint32_t cdw10 = 0;
	uint32_t cdw11 = 0;
	uint32_t cdw12 = 0;
	uint32_t cdw13 = 0;
	uint32_t cdw14 = 0;
	uint32_t cdw15 = 0;
	char *input = NULL;
	bool show_cmd = false;
	bool dry_run = false;
	bool read = false;
	bool write = false;
	bool nodb = false;

	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--sqid", opt_set_uintval, opt_show_uintval, &sqid, "[O] Submission queue ID, defaults to 0"),
		OPT_WITH_ARG("-o|--opcode", opt_set_intval, opt_show_intval, &opcode, "[M] Operation code"),
		OPT_WITH_ARG("-f|--flags", opt_set_uintval, opt_show_uintval, &flags, "[O] Command flags in CDW0[15:8]"),
		OPT_WITH_ARG("-R|--rsvd", opt_set_uintval, opt_show_uintval, &rsvd, "[O] Reserved field"),
		OPT_WITH_ARG("-n|--namespace-id", opt_set_uintval, opt_show_uintval, &nsid, "[O] Namespace ID, Mandatory if --sqid > 0"),
		OPT_WITH_ARG("-l|--data-len", opt_set_uintval_bi, opt_show_uintval_bi, &data_len, "[O] Data length in bytes"),
		OPT_WITH_ARG("-2|--cdw2", opt_set_uintval, opt_show_uintval, &cdw2, "[O] Command dword 2"),
		OPT_WITH_ARG("-3|--cdw3", opt_set_uintval, opt_show_uintval, &cdw3, "[O] Command dword 3"),
		OPT_WITH_ARG("--prp1", opt_set_charp, opt_show_charp, &prp1, "[O] PRP1 in DPTR (for injection)"),
		OPT_WITH_ARG("--prp2", opt_set_charp, opt_show_charp, &prp2, "[O] PRP2 in DPTR (for injection)"),
		OPT_WITH_ARG("-4|--cdw10", opt_set_uintval, opt_show_uintval, &cdw10, "[O] Command dword 10"),
		OPT_WITH_ARG("-5|--cdw11", opt_set_uintval, opt_show_uintval, &cdw11, "[O] Command dword 11"),
		OPT_WITH_ARG("-6|--cdw12", opt_set_uintval, opt_show_uintval, &cdw12, "[O] Command dword 12"),
		OPT_WITH_ARG("-7|--cdw13", opt_set_uintval, opt_show_uintval, &cdw13, "[O] Command dword 13"),
		OPT_WITH_ARG("-8|--cdw14", opt_set_uintval, opt_show_uintval, &cdw14, "[O] Command dword 14"),
		OPT_WITH_ARG("-9|--cdw15", opt_set_uintval, opt_show_uintval, &cdw15, "[O] Command dword 15"),
		OPT_WITH_ARG("-i|--input-file", opt_set_charp, opt_show_charp, &input, "[M] File to write (in write direction)"),
		OPT_WITHOUT_ARG("-s|--show-command", opt_set_bool, &show_cmd, "[O] Show command before sending"),
		OPT_WITHOUT_ARG("-d|--dry-run", opt_set_bool, &dry_run, "[O] Show command instead of sending"),
		OPT_WITHOUT_ARG("-r|--read", opt_set_bool, &read, "[O] Set read data direction "),
		OPT_WITHOUT_ARG("-w|--write", opt_set_bool, &write, "[O] Set write data direction "),
		OPT_WITHOUT_ARG("-N|--nodb", opt_set_bool, &nodb, "[O] Don't update tail doorbell of the submission queue"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	__unvme_free char *filepath = NULL;
	__unvme_free void *buf;
	unsigned long cmd_flags = 0;
	union nvme_cmd sqe = {0, };
	int ret;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "do 'unvme add %s' first", unvme_msg_bdf(msg));
	if (opcode < 0)
		unvme_err_return(EINVAL, "-o|--opcode must be specified");
	if (sqid && !nsid)
		unvme_err_return(EINVAL, "-n|--namespace-id must be specified when io-passthru command (sqid=%d)", sqid);
	if (read && write)
		unvme_err_return(EINVAL, "-r and -w option cannot be set at the same time");
	if (!unvmed_get_sq(u, sqid))
		unvme_err_return(ENOENT, "Submission queue not exists (sqid=%d)", sqid);

	/*
	 * If both -r and -w are not given, decide the data direction by the
	 * opcode.
	 */
	if (!read && !write) {
		switch (opcode & 0x3) {
		case 0x1:
			write = true;
			break;
		case 0x2:
			read = true;
			break;
		default:
			break;
		}
	}

	if (write && !input)
		unvme_err_return(EINVAL, "-i|--input-file must be specified");

	buf = malloc(data_len);
	if (!buf)
		unvme_err_return(ENOMEM, "failed to malloc() for buffer");

	if (write) {
		filepath = unvme_get_filepath(unvme_msg_pwd(msg), input);
		if (unvme_read_file(filepath, buf, data_len))
			unvme_err_return(ENOENT, "failed to read data from file %s", filepath);
	}

	sqe.opcode = (uint8_t)opcode;
	sqe.flags = (uint8_t)flags;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.cdw2 = cpu_to_le32(cdw2);
	sqe.cdw3 = cpu_to_le32(cdw3);

	/*
	 * Override prp1 and prp2 if they are given to inject specific values
	 */
	if (prp1)
		sqe.dptr.prp1 = strtoull(prp1, NULL, 0);
	if (prp2)
		sqe.dptr.prp2 = strtoull(prp2, NULL, 0);

	sqe.cdw10 = cpu_to_le32(cdw10);
	sqe.cdw11 = cpu_to_le32(cdw11);
	sqe.cdw12 = cpu_to_le32(cdw12);
	sqe.cdw13 = cpu_to_le32(cdw13);
	sqe.cdw14 = cpu_to_le32(cdw14);
	sqe.cdw15 = cpu_to_le32(cdw15);

	if (show_cmd || dry_run) {
		uint32_t *entry = (uint32_t *)&sqe;
		for (int dw = 0; dw < 16; dw++)
			unvme_pr("cdw%d\t\t: 0x%08x\n", dw, *(entry + dw));
	}
	if (dry_run)
		return 0;

	if (nodb)
		cmd_flags |= UNVMED_CMD_F_NODB;

	ret = unvmed_passthru(u, sqid, buf, data_len, &sqe, read, cmd_flags);
	if (!ret && !nodb) {
		if (read)
			unvme_cmd_pr_raw(buf, data_len);
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);

	return ret;
}

int unvme_update_sqdb(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	bool help = false;
	const char *desc =
		"Update submission queue tail doorbell to issue all the pending written\n"
		"submission queue entries by `--nodb` options.  This command will wait for\n"
		"the pending commands in the submission queue to complete.";

	uint64_t sqid = UINT64_MAX;
	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--sqid", opt_set_ulongval, opt_show_ulongval, &sqid, "[M] Submission queue ID"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	__unvme_free struct nvme_cqe *cqes = NULL;
	int nr_sqes;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (sqid == UINT64_MAX)
		unvme_err_return(EINVAL, "-q|--sqid required");
	if (!unvmed_get_sq(u, sqid))
		unvme_err_return(ENOENT, "'create-iosq' must be executed first");

	nr_sqes = unvmed_sq_update_tail_and_wait(u, sqid, &cqes);
	if (nr_sqes < 0)
		unvme_err_return(errno, "failed to update sq and wait cq");

	if (!nr_sqes)
		return 0;

	unvme_pr_err("waiting for %d CQ entries ...\n", nr_sqes);
	for (int i = 0; i < nr_sqes; i++) {
		unvme_pr_cqe(&cqes[i]);
	}

	return 0;
}

int unvme_reset(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *u = unvmed_get(bdf);
	const char *desc =
		"Reset NVMe controller by setting CC.EN to 0 and wait for CSTS.RDY register\n"
		"to be 0 which represents reset completed.  To re-enable the controller,\n"
		"`enable` should be executed again.";

	bool help = false;
	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!u)
		unvme_err_return(EPERM, "Do 'unvme add %s' first", bdf);

	unvmed_reset_ctrl(u);
	return 0;
}
