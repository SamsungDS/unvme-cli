#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <vfn/pci.h>
#include <vfn/nvme.h>

#include "unvme.h"

#define unvmed_err_return(err, fmt, ...)				\
	do {								\
		unvme_pr_err("ERROR: "fmt"\n\n", ##__VA_ARGS__);	\
		unvme_cmd_help(argv[1], desc, opts);			\
		opt_free_table();					\
		return err;						\
	} while(0)

static inline int unvme_sq_nr_pending(struct nvme_sq *sq)
{
	if (sq->tail >= sq->ptail)
		return sq->tail - sq->ptail;
	return (sq->qsize - sq->ptail) + sq->tail;
}

static inline int unvme_sq_update_tail_and_wait(struct nvme_sq *sq,
						struct nvme_cqe **cqes)
{
	int nr_sqes = unvme_sq_nr_pending(sq);

	if (!nr_sqes)
		return 0;

	*cqes = malloc(sizeof(struct nvme_cqe) * nr_sqes);

	nvme_sq_update_tail(sq);
	nvme_cq_wait_cqes(sq->cq, *cqes, nr_sqes, NULL);

	return nr_sqes;
}

static void unvme_pr_sqe(int sqid, union nvme_cmd *sqe)
{
	unvme_pr_err("SQ entry: sqid=%#x, cid=%#x, opcode=%#x\n",
			sqid, sqe->cid, sqe->opcode);
}

static void unvme_pr_cqe(struct nvme_cqe *cqe)
{
	uint32_t sct, sc;

	sct = (cqe->sfp >> 9) & 0x7;
	sc = (cqe->sfp >> 1) & 0xff;

	unvme_pr_err("CQ entry: sqid=%#x, cid=%#x, dw0=%#x, dw1=%#x, sct=%#x, sc=%#x\n",
			cqe->sqid, cqe->cid, cqe->dw0, cqe->dw1, sct, sc);
}

static void unvme_cmd_pr_cqe(struct unvme_cmd *cmd)
{
	unvme_pr_cqe(&cmd->cqe);
}

static void unvme_cmd_pr(const char *format, struct unvme_msg *msg,
			      struct unvme_cmd *cmd, void (*pr)(void *))
{
	if (streq(format, "binary")) {
		unvmed_pr_raw(cmd->vaddr, cmd->len);
		unvme_msg_update_len(msg, cmd->len);
	} else if (streq(format, "normal"))
		pr(cmd->vaddr);
	else
		assert(false);
}

static void unvme_cmd_pr_raw(struct unvme_msg *msg, struct unvme_cmd *cmd)
{
	unvme_cmd_pr("binary", msg, cmd, NULL);
}

static int __bind(char *bdf, char *target)
{
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

static bool __is_nvme_device(const char *bdf)
{
	unsigned long long class;
	UNVME_FREE char *path;
	char buf[32];
	int ret;
	int fd;

	asprintf(&path, "/sys/bus/pci/devices/%s/class", bdf);
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

	unvme_pr("%-20s  %-4s\n", "NVMe device", "Attached");
        unvme_pr("------------------------------\n");
	while ((entry = readdir(dfd))) {
		if (streq(entry->d_name, ".") || streq(entry->d_name, ".."))
			continue;

		bdf = entry->d_name;
		if (!__is_nvme_device(bdf))
			continue;

		unvme_pr("%-20s  %-4s\n", bdf, unvmed_ctrl(bdf) ? "yes" : "no");
	}

	closedir(dfd);

	opt_free_table();
	return 0;
}

int unvme_add(int argc, char *argv[], struct unvme_msg *msg)
{
	char *bdf = unvme_msg_bdf(msg);
	struct unvme *unvme;
	bool help = false;

	const char *desc =
		"Register a given target <device> to unvmed service by binding\n"
		"it to 'vfio-pci' kernel driver to support user-space I/O.";

	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	unvme = unvmed_alloc(bdf);
	if (!unvme)
		unvmed_err_return(ENOMEM, "failed to allocate unvmed");

	__bind(bdf, "vfio-pci");
	nvme_ctrl_init(&unvme->ctrl, bdf, NULL);

	opt_free_table();
	return 0;
}

int unvme_del(int argc, char *argv[], struct unvme_msg *msg)
{
	char *bdf = unvme_msg_bdf(msg);
	bool help = false;
	int ret;

	const char *desc =
		"Delete a given target <device> from unvmed service by unbinding\n"
		"it from 'vfio-pci' kernel driver";

	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	ret = unvmed_free(bdf);
	if (ret < 0)
		unvmed_err_return(-ret, "failed to free controller instance\n");

	ret = pci_unbind(bdf);
	if (ret)
		unvmed_err_return(errno, "failed to unbind %s\n", bdf);

	opt_free_table();
	return 0;
}

int unvme_show_regs(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *unvme = unvmed_ctrl(bdf);
	const char *desc =
		"Show NVMe controller properties (registers in MMIO space).";

	bool help = false;
	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme)
		unvmed_err_return(EPERM, "Do 'unvme add %s' first", bdf);

	unvmed_pr_show_regs(unvme->ctrl.regs);
	return 0;
}

int unvme_enable(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *unvme = unvmed_ctrl(bdf);
	bool help = false;
	const char *desc =
		"Enable NVMe controller along with setting up admin queues.\n"
		"It will wait for CSTS.RDY to be 1 after setting CC.EN to 1.";

	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unsigned long sq_flags = 0;
	int ret = 0;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme)
		unvmed_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (nvme_configure_adminq(&unvme->ctrl, sq_flags)) {
		perror("nvme_configure_adminq");
		ret = errno;
		goto out;
	}

	if (nvme_enable(&unvme->ctrl)) {
		perror("nvme_enable");
		ret = errno;
	}
	unvme->init = true;

out:
	opt_free_table();
	return ret;
}

int unvme_create_iocq(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *unvme = unvmed_ctrl(unvme_msg_bdf(msg));
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

	int ret = 0;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme)
		unvmed_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (!unvme->init)
		unvmed_err_return(EPERM, "'enable' must be executed first");

	if (!qid)
		unvmed_err_return(EINVAL, "-q|--qid required");
	if (!qsize)
		unvmed_err_return(EINVAL, "-z|--qsize required");

	if (nvme_create_iocq(&unvme->ctrl, qid, qsize, vector)) {
		perror("nvme_create_iocq");
		ret = errno;
		goto out;
	}

out:
	opt_free_table();
	return ret;
}

int unvme_create_iosq(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *unvme = unvmed_ctrl(unvme_msg_bdf(msg));
	uint32_t qid = 0;
	uint32_t qsize = 0;
	uint32_t cqid = 0;
	struct nvme_cq *cq;
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

	int ret = 0;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme)
		unvmed_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (!unvme->init)
		unvmed_err_return(EPERM, "'enable' must be executed first");

	if (!qid)
		unvmed_err_return(EINVAL, "-q|--qid required");
	if (!qsize)
		unvmed_err_return(EINVAL, "-z|--qsize required");
	if (!cqid)
		unvmed_err_return(EINVAL, "-c|--cqid required");

	cq = &unvme->ctrl.cq[cqid];

	if (!cq->vaddr)
		unvmed_err_return(ENOENT, "CQ (qid=%u) not exist", cqid);

	if (nvme_create_iosq(&unvme->ctrl, qid, qsize, cq, 0x0)) {
		perror("nvme_create_iosq");
		ret = errno;
		goto out;
	}

out:
	opt_free_table();
	return ret;
}

int unvme_id_ns(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *unvme = unvmed_ctrl(unvme_msg_bdf(msg));
	uint32_t nsid = 0;
	char *format= "normal";
	bool nodb = false;
	bool help = false;
	const char *desc =
		"Submit an Identify Namespace admin command to the target <device>.";

	struct opt_table opts[] = {
		OPT_WITH_ARG("-n|--namespace-id", opt_set_uintval, opt_show_uintval, &nsid, "[M] Namespace ID"),
		OPT_WITH_ARG("-o|--output-format", opt_set_charp, opt_show_charp, &format, "[O] Output format: [normal|binary], defatuls to normal"),
		OPT_WITHOUT_ARG("-N|--nodb", opt_set_bool, &nodb, "[O] Don't update tail doorbell of the submission queue"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	UNVME_FREE_CMD struct unvme_cmd *cmd = NULL;
	struct nvme_cmd_identify *sqe;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme)
		unvmed_err_return(EPERM, "Do 'unvme add %s' first",
				unvme_msg_bdf(msg));

	if (!nsid)
		unvmed_err_return(EINVAL, "-n|--namespace-id required");
	if (!unvme_sq(unvme, 0))
		unvmed_err_return(EPERM, "'enable' must be executed first");

	cmd = unvme_cmd_alloc(unvme, 0, 4096);
	if (!cmd)
		unvmed_err_return(ENOMEM, "failed to allocate unvme_cmd");

	sqe = (struct nvme_cmd_identify *)&cmd->sqe;

	sqe->opcode = 0x6;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cns = 0x0;
	if (nvme_rq_map_prp(&unvme->ctrl, cmd->rq, (union nvme_cmd *)sqe,
				cmd->iova, cmd->len))
		unvmed_err_return(ENODEV, "failed to map PRP buffer");

	unvme_cmd_post(cmd, !nodb);
	if (nodb) {
		unvme_pr_sqe(0, &cmd->sqe);
		cmd->should_free = false;
		goto out;
	}
	if (!unvme_cmd_cmpl(cmd))
		unvme_cmd_pr(format, msg, cmd, unvmed_pr_id_ns);
	else
		unvme_cmd_pr_cqe(cmd);

out:
	opt_free_table();
	return 0;
}

int unvme_read(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *unvme = unvmed_ctrl(unvme_msg_bdf(msg));
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

	UNVME_FREE_CMD struct unvme_cmd *cmd = NULL;
	struct nvme_cmd_rw *sqe;
	void *vaddr;
	ssize_t len;
	int ret = 0;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme)
		unvmed_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (!sqid)
		unvmed_err_return(EINVAL, "-q|--sqid required");
	if (!nsid)
		unvmed_err_return(EINVAL, "-n|--namespace-id required");
	if (!unvme_sq(unvme, sqid))
		unvmed_err_return(ENOENT, "'create-iosq' must be executed first");

	cmd = unvme_cmd_alloc(unvme, sqid, data_size);
	if (!cmd)
		unvmed_err_return(ENOMEM, "failed to allocate unvme_cmd");

	vaddr = cmd->vaddr;
	len = cmd->len;
	sqe = (struct nvme_cmd_rw *)&cmd->sqe;

	sqe->opcode = 0x2;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->slba = cpu_to_le64(slba);
	sqe->nlb = cpu_to_le16(nlb);
	if (nvme_rq_map_prp(&unvme->ctrl, cmd->rq, (union nvme_cmd *)sqe,
				cmd->iova, cmd->len))
		unvmed_err_return(ENODEV, "failed to map PRP buffer");

	unvme_cmd_post(cmd, !nodb);
	if (nodb) {
		unvme_pr_sqe(0, &cmd->sqe);
		cmd->should_free = false;
		goto out;
	}
	if (!unvme_cmd_cmpl(cmd)) {
		if (!data)
			unvme_cmd_pr_raw(msg, cmd);
		else
			unvme_write_file(msg, data, vaddr, len);
	} else
		unvme_cmd_pr_cqe(cmd);
out:
	opt_free_table();
	return ret;
}

int unvme_write(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *unvme = unvmed_ctrl(unvme_msg_bdf(msg));
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

	UNVME_FREE_CMD struct unvme_cmd *cmd = NULL;
	struct nvme_cmd_rw *sqe;
	void *vaddr;
	ssize_t len;
	int ret = 0;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme)
		unvmed_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (!sqid)
		unvmed_err_return(EINVAL, "-q|--sqid required");
	if (!nsid)
		unvmed_err_return(EINVAL, "-n|--namespace-id required");
	if (!data)
		unvmed_err_return(EINVAL, "-d|--data required");
	if (!unvme_sq(unvme, sqid))
		unvmed_err_return(ENOENT, "'create-iosq' must be executed first");

	cmd = unvme_cmd_alloc(unvme, sqid, data_size);
	if (!cmd)
		unvmed_err_return(ENOMEM, "failed to allocate unvme_cmd");

	vaddr = cmd->vaddr;
	len = cmd->len;
	sqe = (struct nvme_cmd_rw *)&cmd->sqe;

	if (unvme_read_file(msg, data, vaddr, len))
		unvmed_err_return(ENOENT, "failed to read data from file %s", data);

	sqe->opcode = 0x1;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->slba = cpu_to_le64(slba);
	sqe->nlb = cpu_to_le16(nlb);

	if (nvme_rq_map_prp(&unvme->ctrl, cmd->rq, (union nvme_cmd *)sqe,
				cmd->iova, cmd->len))
		unvmed_err_return(ENODEV, "failed to map PRP buffer");

	unvme_cmd_post(cmd, !nodb);
	if (nodb) {
		unvme_pr_sqe(0, &cmd->sqe);
		cmd->should_free = false;
		goto out;
	}
	if (unvme_cmd_cmpl(cmd))
		unvme_cmd_pr_cqe(cmd);
out:
	opt_free_table();
	return ret;
}

int unvme_io_passthru(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *unvme = unvmed_ctrl(unvme_msg_bdf(msg));
	bool help = false;
	const char *desc =
		"Submit a I/O passthru command to the given submission queue of the\n"
		"target <device>. To run this command, I/O queue MUST be created.\n"
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
	bool read = false;
	bool write = false;
	bool nodb = false;

	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--sqid", opt_set_uintval, opt_show_uintval, &sqid, "[M] Submission queue ID"),
		OPT_WITH_ARG("-o|--opcode", opt_set_intval, opt_show_intval, &opcode, "[M] Operation code"),
		OPT_WITH_ARG("-f|--flags", opt_set_uintval, opt_show_uintval, &flags, "[O] Command flags in CDW0[15:8]"),
		OPT_WITH_ARG("-R|--rsvd", opt_set_uintval, opt_show_uintval, &rsvd, "[O] Reserved field"),
		OPT_WITH_ARG("-n|--namespace-id", opt_set_uintval, opt_show_uintval, &nsid, "[M] Namespace ID"),
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
		OPT_WITHOUT_ARG("-r|--read", opt_set_bool, &read, "[O] Set read data direction "),
		OPT_WITHOUT_ARG("-w|--write", opt_set_bool, &write, "[O] Set write data direction "),
		OPT_WITHOUT_ARG("-N|--nodb", opt_set_bool, &nodb, "[O] Don't update tail doorbell of the submission queue"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	UNVME_FREE_CMD struct unvme_cmd *cmd = NULL;
	union nvme_cmd *sqe;
	void *vaddr = NULL;
	int ret = 0;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme)
		unvmed_err_return(EPERM, "do 'unvme add %s' first", unvme_msg_bdf(msg));
	if (!sqid)
		unvmed_err_return(EINVAL, "-q|--sqid must be specified");
	if (opcode < 0)
		unvmed_err_return(EINVAL, "-o|--opcode must be specified");
	if (!nsid)
		unvmed_err_return(EINVAL, "-n|--namespace-id must be specified");
	if (read && write)
		unvmed_err_return(EINVAL, "-r and -w option cannot be set at the same time");
	if (!unvme_sq(unvme, sqid))
		unvmed_err_return(ENOENT, "I/O queue not exists (sqid=%d)", sqid);

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
		unvmed_err_return(EINVAL, "-i|--input-file must be specified");

	cmd = unvme_cmd_alloc(unvme, sqid, data_len);
	if (!cmd)
		unvmed_err_return(ENOMEM, "failed to allocate unvme_cmd");

	vaddr = cmd->vaddr;
	data_len = cmd->len;
	sqe = (union nvme_cmd *)&cmd->sqe;

	if (data_len) {
		if (nvme_rq_map_prp(&unvme->ctrl, cmd->rq, (union nvme_cmd *)sqe,
					cmd->iova, cmd->len))
			unvmed_err_return(ENODEV, "failed to map PRP buffer");

		if (write) {
			if (unvme_read_file(msg, input, vaddr, data_len)) {
				ret = errno;
				goto out;
			}
		}
	}

	sqe->opcode = (uint8_t)opcode;
	sqe->flags = (uint8_t)flags;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cdw2 = cpu_to_le32(cdw2);
	sqe->cdw3 = cpu_to_le32(cdw3);

	/*
	 * Override prp1 and prp2 if they are given to inject specific values
	 */
	if (prp1)
		sqe->dptr.prp1 = strtoull(prp1, NULL, 0);
	if (prp2)
		sqe->dptr.prp2 = strtoull(prp2, NULL, 0);

	sqe->cdw10 = cpu_to_le32(cdw10);
	sqe->cdw11 = cpu_to_le32(cdw11);
	sqe->cdw12 = cpu_to_le32(cdw12);
	sqe->cdw13 = cpu_to_le32(cdw13);
	sqe->cdw14 = cpu_to_le32(cdw14);
	sqe->cdw15 = cpu_to_le32(cdw15);

	unvme_cmd_post(cmd, !nodb);
	if (nodb) {
		unvme_pr_sqe(0, &cmd->sqe);
		cmd->should_free = false;
		goto out;
	}
	if (!unvme_cmd_cmpl(cmd)) {
		if (read)
			unvme_cmd_pr_raw(msg, cmd);
	} else
		unvme_cmd_pr_cqe(cmd);
out:
	opt_free_table();
	return ret;
}

int unvme_update_sqdb(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *unvme = unvmed_ctrl(unvme_msg_bdf(msg));
	bool help = false;
	const char *desc =
		"Update submission queue tail doorbell to issue all the pending written\n"
		"submission queue entries by `--nodb` options.  This command will wait for\n"
		"the pending commands in the submission queue to complete.";

	uint64_t sqid = UINT64_MAX;
	struct opt_table opts[] = {
		OPT_WITH_ARG("-q|--sqid", opt_set_uintval, opt_show_uintval, &sqid, "[M] Submission queue ID"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	struct nvme_sq *sq;
	UNVME_FREE struct nvme_cqe *cqes;
	struct unvme_cmd *cmd, *next;
	int nr_sqes;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme)
		unvmed_err_return(EPERM, "Do 'unvme add %s' first", unvme_msg_bdf(msg));

	if (sqid == UINT64_MAX)
		unvmed_err_return(EINVAL, "-q|--sqid required");
	if (!(sq = unvme_sq(unvme, sqid)))
		unvmed_err_return(ENOENT, "'create-iosq' must be executed first");

	nr_sqes = unvme_sq_nr_pending(sq);
	if (!nr_sqes)
		unvmed_err_return(ENODATA, "no pending sq entries to update");

	unvme_sq_update_tail_and_wait(sq, &cqes);

	list_for_each_safe(&unvme->cmd_list, cmd, next, list) {
		if (cmd->rq->sq->id == sqid) {
			unvme_cmd_free(&cmd);
		}
	}

	unvme_pr_err("waiting for %d CQ entries ...\n", nr_sqes);
	for (int i = 0; i < nr_sqes; i++) {
		unvme_pr_cqe(&cqes[i]);
	}

	opt_free_table();
	return 0;
}

int unvme_reset(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *bdf = unvme_msg_bdf(msg);
	struct unvme *unvme = unvmed_ctrl(bdf);
	const char *desc =
		"Reset NVMe controller by setting CC.EN to 0 and wait for CSTS.RDY register\n"
		"to be 0 which represents reset completed.  To re-enable the controller,\n"
		"`enable` should be executed again.";

	bool help = false;
	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	int ret;

	unvme_parse_args(3, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme)
		unvmed_err_return(EPERM, "Do 'unvme add %s' first", bdf);

	ret = nvme_reset(&unvme->ctrl);
	if (ret)
		unvmed_err_return(errno, "failed to reset %s controller", bdf);

	for (int i = 0; i < unvme->ctrl.opts.nsqr + 2; i++)
		nvme_discard_sq(&unvme->ctrl, &unvme->ctrl.sq[i]);

	for (int i = 0; i < unvme->ctrl.opts.ncqr + 2; i++)
		nvme_discard_cq(&unvme->ctrl, &unvme->ctrl.cq[i]);

	unvme->init = false;

	opt_free_table();
	return 0;
}
