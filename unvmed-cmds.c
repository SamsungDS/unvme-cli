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
#include <sys/stat.h>
#include <sys/sysinfo.h>

#include <ccan/str/str.h>
#include <nvme/types.h>
#include <vfn/pci.h>
#include <vfn/nvme.h>

#include "libunvmed.h"
#include "unvme.h"
#include "unvmed.h"
#include "app/perf/perf.h"

#include "argtable3/argtable3.h"

extern __thread struct unvme_msg *__msg;

/*
 * Overrided exit() function which should be called by the external apps.
 */
void exit(int status)
{
	if (__msg) {
		unvmed_log_err("job (pid=%d) has been terminated (err=%d)",
				unvme_msg_pid(__msg), status);
	}

	unvme_exit_job(status);
	pthread_exit(NULL);
}

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
	char *path = "/sys/module/vfio_pci";
	const char *target = "vfio-pci";
	unsigned long long vendor, device;
	struct stat st;

	if (stat(path, &st) || !S_ISDIR(st.st_mode)) {
		unvme_pr_err("'%s' kernel module is not loaded.  "
				"Try 'modprobe %s'.\n", target, target);
		errno = ENOENT;
		return -1;
	}

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
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Print NVMe PCI device(s) in the current system as PCI BDF\n"
		"(Bus-Device-Function) format. It requires unvmed to figure\n"
		"out whether each device is attached to unvmed service or not.";

	void *argtable[] = {
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	dfd = opendir("/sys/bus/pci/devices");
	if (!dfd) {
		unvme_pr_err("failed to open sysfs\n");
		ret = ENOENT;
		goto out;
	}

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
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_add(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *nrioqs;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Register a given target <device> to unvmed service by binding\n"
		"it to 'vfio-pci' kernel driver to support user-space I/O.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nrioqs = arg_int0("q", "nr-ioqs", "<n>", "[O] Maximum number of "
			"I/O queues to create (defaults: # of cpu)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	/* Set default argument values prior to parsing */
	arg_intv(nrioqs) = get_nprocs();

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (u)
		goto out;

	if (arg_intv(nrioqs) < 1) {
		unvme_pr_err("'--nr-ioqs=' should be greater than 0\n");
		ret = EINVAL;
		goto out;
	}

	if (unvmed_pci_bind(arg_strv(dev))) {
		unvme_pr_err("failed to bind PCI device to vfio-pci driver\n");
		ret = errno;
		goto out;
	}

	if (!unvmed_init_ctrl(arg_strv(dev), arg_intv(nrioqs))) {
		unvme_pr_err("failed to initialize unvme\n");
		ret = errno;
		goto out;
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_del(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Delete a given target <device> from unvmed service by unbinding\n"
		"it from 'vfio-pci' kernel driver";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u)
		goto out;

	unvmed_free_ctrl(u);

	if (unvmed_pci_unbind(arg_strv(dev))) {
		unvme_pr_err("failed to unbind PCI device from vfio-pci driver\n");
		ret = errno;
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_show_regs(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Show NVMe controller properties (registers in MMIO space).";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	unvme_pr_show_regs(u);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_status(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Show status of a given target <device> in unvmed.\n"
		"The status includes CC, CSTS and Submission/Completion Queue.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	unvme_pr_status(u);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_enable(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_lit *no_adminq;
	struct arg_int *iosqes;
	struct arg_int *iocqes;
	struct arg_int *mps;
	struct arg_int *css;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Enable NVMe controller along with setting up admin queues.\n"
		"It will wait for CSTS.RDY to be 1 after setting CC.EN to 1.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		no_adminq = arg_lit0(NULL, "no-adminq", "[O] Enable device without creating admin queues"),
		iosqes = arg_int0("s", "iosqes", "<n>", "[O] I/O Sumission Queue Entry Size (2^n) (default: 6)"),
		iocqes = arg_int0("c", "iocqes", "<n>", "[O] I/O Completion Queue Entry Size (2^n) (default: 4)"),
		mps = arg_int0("m", "mps", "<n>", "[O] Memory Page Size (2^(12+n)) (default: 0)"),
		css = arg_int0("i", "css", "<n>", "[O] I/O Command Set Selected  (default: 0)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	/* Set default argument values prior to parsing */
	arg_intv(iosqes) = 6;
	arg_intv(iocqes) = 4;
	arg_intv(mps) = 0;
	arg_intv(css) = 0;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_intv(iosqes) > 0xf) {
		unvme_pr_err("invalid -s|--iosqes\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_intv(iocqes) > 0xf) {
		unvme_pr_err("invalid -c|--iocqes\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_intv(mps) > 0xf) {
		unvme_pr_err("invalid -m|--mps\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_intv(css) > 0x7) {
		unvme_pr_err("invalid -i|--css\n");
		ret = EINVAL;
		goto out;
	}

	if (!arg_boolv(no_adminq) && unvmed_create_adminq(u)) {
		unvme_pr_err("failed to create adminq\n");
		ret = errno;
		goto out;
	}

	if (unvmed_enable_ctrl(u, arg_intv(iosqes), arg_intv(iocqes),
				arg_intv(mps), arg_intv(css))) {
		unvme_pr_err("failed to enable controller\n");
		ret = errno;
		goto out;
	}

	if (arg_boolv(no_adminq)) {
		unvme_pr_err("Warning: Admin queues are not created.  "
				"The following admin commands will not work\n");
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_create_iocq(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *qid;
	struct arg_int *qsize;
	struct arg_int *vector;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit a Create I/O Completion Queue admin command to the target\n"
		"<device>. DMA address of the queue will be allocated and configured\n"
		"by libvfn.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		qid = arg_int1("q", "qid", "<n>", "[M] Completion Queue ID to create"),
		qsize = arg_int1("z", "qsize", "<n>", "[M] Queue size (1-based)"),
		vector = arg_int0("v", "vector", "<n>", "[O] Interrupt vector (defaults: -1)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	/* Set default argument values prior to parsing */
	arg_intv(vector) = -1;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (!unvmed_get_sq(u, 0)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(qid) > unvmed_get_max_qid(u)) {
		unvme_pr_err("invalid -q|--qid\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_intv(vector) < 0)
		arg_intv(vector) = -1;

	if (unvmed_get_cq(u, arg_intv(qid))) {
		unvme_pr_err("failed to create cq (qid=%u) (exists)\n", arg_intv(qid));
		ret = EEXIST;
		goto out;
	}

	if (unvmed_create_cq(u, arg_intv(qid), arg_intv(qsize), arg_intv(vector))) {
		unvme_pr_err("failed to create cq\n");
		ret = errno;
	}
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_delete_iocq(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *qid;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit a Delete I/O Completion Queue admin command to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		qid = arg_int1("q", "qid", "<n>", "[M] Completion Queue ID to delete"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (!unvmed_get_sq(u, 0)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (!unvmed_get_cq(u, arg_intv(qid))) {
		unvme_pr_err("failed to delete cq (qid=%u) (not exists)\n", arg_intv(qid));
		ret = ENOMEDIUM;
		goto out;
	}

	if (unvmed_delete_cq(u, arg_intv(qid))) {
		unvme_pr_err("failed to delete iocq\n");
		ret = errno;
	}
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_create_iosq(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *qid;
	struct arg_int *qsize;
	struct arg_int *cqid;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit a Create I/O Submission Queue admin command to the target\n"
		"<device>. DMA address of the queue will be allocated and configured\n"
		"by libvfn.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		qid = arg_int1("q", "qid", "<n>", "[M] Submission Queue ID to create"),
		qsize = arg_int1("z", "qsize", "<n>", "[M] Queue size (1-based)"),
		cqid = arg_int1("c", "cqid", "<n>", "[M] Completion Queue ID"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (!unvmed_get_sq(u, 0)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(qid) > unvmed_get_max_qid(u)) {
		unvme_pr_err("invalid -q|--qid\n");
		ret = EINVAL;
		goto out;
	}

	if (unvmed_get_sq(u, arg_intv(qid))) {
		unvme_pr_err("failed to create iosq (qid=%u) (exists)\n", arg_intv(qid));
		ret = EEXIST;
		goto out;
	}

	if (unvmed_create_sq(u, arg_intv(qid), arg_intv(qsize), arg_intv(cqid))) {
		unvme_pr_err("failed to create iosq\n");
		ret = errno;
	}
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_delete_iosq(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *qid;
	struct arg_lit *help;
	struct arg_end *end;
	const char *desc =
		"Submit a Delete I/O Submission Queue admin command\n"
		"to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		qid = arg_int1("q", "qid", "<n>", "[M] Submission Queue ID to delete"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (!unvmed_get_sq(u, 0)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (!unvmed_get_sq(u, arg_intv(qid))) {
		unvme_pr_err("failed to delete iosq (qid=%u) (not exists)\n", arg_intv(qid));
		ret = ENOMEDIUM;
		goto out;
	}

	if (unvmed_delete_sq(u, arg_intv(qid))) {
		unvme_pr_err("failed to delete iosq\n");
		ret = errno;
	}
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_id_ns(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *nsid;
	struct arg_str *format;
	struct arg_lit *nodb;
	struct arg_lit *init;
	struct arg_lit *help;
	struct arg_end *end;
	const char *desc =
		"Submit an Identify Namespace admin command to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nsid = arg_int1("n", "nsid", "<n>", "[M] Namespace ID"),
		format = arg_str0("o", "output-format", "[normal|binary]", "[O] Output format: [normal|binary] (defaults: normal)"),
		nodb = arg_lit0("N", "nodb", "[O] Don't update tail doorbell of the submission queue"),
		init = arg_lit0(NULL, "init", "[O] Initialize namespace instance and keep it in unvmed driver"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	const size_t size = NVME_IDENTIFY_DATA_SIZE;
	ssize_t len;
	void *buf = NULL;
	unsigned long flags = 0;
	int ret;

	/* Set default argument values prior to parsing */
	arg_strv(format) = "normal";

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (!unvmed_get_sq(u, 0)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	len = pgmap(&buf, size);
	if (!buf) {
		unvme_pr_err("failed to allocate buffer\n");
		ret = errno;
		goto out;
	}

	if (arg_boolv(nodb))
		flags |= UNVMED_CMD_F_NODB;

	ret = unvmed_id_ns(u, arg_intv(nsid), buf, len, flags);
	if (!ret && !arg_boolv(nodb)) {
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_ns);
		if (arg_boolv(init))
			unvmed_init_ns(u, arg_intv(nsid), buf);
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);

	if (!(flags & UNVMED_CMD_F_NODB))
		pgunmap(buf, len);

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_id_active_nslist(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *nsid;
	struct arg_str *format;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit an Identify Active Namespace List admin command to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nsid = arg_int1("n", "nsid", "<n>", "[M] Namespace ID"),
		format = arg_str0("o", "output-format", "[normal|binary]", "[O] Output format: [normal|binary] (defaults: normal)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	const size_t size = NVME_IDENTIFY_DATA_SIZE;
	ssize_t len;
	void *buf = NULL;
	int ret;

	/* Set default argument values prior to parsing */
	arg_strv(format) = "normal";

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (!unvmed_get_sq(u, 0)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	len = pgmap(&buf, size);
	if (!buf) {
		unvme_pr_err("failed to allocate buffer\n");
		ret = errno;
		goto out;
	}

	ret = unvmed_id_active_nslist(u, arg_intv(nsid), buf, len);
	if (!ret)
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_active_nslist);
	else if (ret > 0)
		unvme_pr_cqe_status(ret);

	pgunmap(buf, len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_read(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *sqid;
	struct arg_int *nsid;
	struct arg_dbl *slba;
	struct arg_int *nlb;
	struct arg_int *data_size;
	struct arg_file *data;
	struct arg_lit *nodb;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit a Read I/O command to the given submission queue of the\n"
		"target <device>. To run this command, I/O queue MUST be created.\n"
		"Read data from the namespace can be printed to stdout or a file\n"
		"configured by -d|--data.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
                sqid = arg_int1("q", "sqid", "<n>", "[M] Submission queue ID"),
                nsid = arg_int1("n", "namespace-id", "<n>", "[M] Namespace ID"),
                slba = arg_dbl1("s", "start-block", "<n>", "[M] Start LBA"),
		nlb = arg_int1("c", "block-count", "<n>", "[M] Number of logical block (0-based)"),
		data_size = arg_int1("z", "data-size", "<n>", "[M] Read data buffer size in bytes"),
		data = arg_file0("d", "data", "<output>", "[O] File to write read data"),
		nodb = arg_lit0("N", "nodb", "[O] Don't update tail doorbell of the submission queue"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	__unvme_free char *filepath = NULL;
	void *buf = NULL;
	unsigned long flags = 0;
	ssize_t len;
	int ret;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (!unvmed_get_sq(u, arg_intv(sqid))) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	len = pgmap(&buf, arg_intv(data_size));
	if (!buf) {
		unvme_pr_err("failed to allocate buffer\n");
		ret = errno;
		goto out;
	}

	if (arg_boolv(nodb))
		flags |= UNVMED_CMD_F_NODB;

	if (arg_boolv(data))
		filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(data));

	ret = unvmed_read(u, arg_intv(sqid), arg_intv(nsid), arg_dblv(slba),
			arg_intv(nlb), buf, len, flags, NULL);
	if (!ret && !arg_boolv(nodb)) {
		if (!filepath)
			unvme_cmd_pr_raw(buf, arg_intv(data_size));
		else
			unvme_write_file(filepath, buf, arg_intv(data_size));
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);

	if (!(flags & UNVMED_CMD_F_NODB))
		pgunmap(buf, len);

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_write(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *sqid;
	struct arg_int *nsid;
	struct arg_dbl *slba;
	struct arg_int *nlb;
	struct arg_int *data_size;
	struct arg_file *data;
	struct arg_lit *nodb;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit a Write command to the given submission queue of the\n"
		"target <device>. To run this command, I/O queue MUST be created.\n"
		"WRite data file can be given as -d|--data with a file path.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
                sqid = arg_int1("q", "sqid", "<n>", "[M] Submission queue ID"),
                nsid = arg_int1("n", "namespace-id", "<n>", "[M] Namespace ID"),
                slba = arg_dbl1("s", "start-block", "<n>", "[M] Start LBA"),
		nlb = arg_int1("c", "block-count", "<n>", "[M] Number of logical block (0-based)"),
		data_size = arg_int1("z", "data-size", "<n>", "[O] Logical block size in bytes"),
		data = arg_file1("d", "data", "<input>", "[M] File to write as write data"),
		nodb = arg_lit0("N", "nodb", "[O] Don't update tail doorbell of the submission queue"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	__unvme_free char *filepath = NULL;
	void *buf = NULL;
	unsigned long flags = 0;
	ssize_t len;
	int ret;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (!unvmed_get_sq(u, arg_intv(sqid))) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	len = pgmap(&buf, arg_intv(data_size));
	if (!buf) {
		unvme_pr_err("failed to allocate buffer\n");
		ret = errno;
		goto out;
	}

	if (arg_boolv(nodb))
		flags |= UNVMED_CMD_F_NODB;

	if (arg_boolv(data))
		filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(data));

	if (unvme_read_file(filepath, buf, arg_intv(data_size))) {
		unvme_pr_err("failed to read file %s\n", filepath);
		ret = ENOENT;
		goto free;
	}

	ret = unvmed_write(u, arg_intv(sqid), arg_intv(nsid), arg_dblv(slba),
			arg_intv(nlb), buf, len, flags, NULL);
	if (ret > 0)
		unvme_pr_cqe_status(ret);

free:
	if (ret || (!ret && !(flags & UNVMED_CMD_F_NODB)))
		pgunmap(buf, len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_passthru(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *sqid;
	struct arg_int *nsid;
	struct arg_int *opcode;
	struct arg_int *flags;
	struct arg_int *rsvd;
	struct arg_int *data_len;
	struct arg_int *cdw2;
	struct arg_int *cdw3;
	/* To figure out whether --prp1=, --prp2= are given or not */
	struct arg_str *prp1;
	struct arg_str *prp2;
	struct arg_int *cdw10;
	struct arg_int *cdw11;
	struct arg_int *cdw12;
	struct arg_int *cdw13;
	struct arg_int *cdw14;
	struct arg_int *cdw15;
	struct arg_file *input;
	struct arg_lit *show_cmd;
	struct arg_lit *dry_run;
	struct arg_lit *read;
	struct arg_lit *write;
	struct arg_lit *nodb;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit a passthru command to the given submission queue of the\n"
		"target <device>. To run this command, queue MUST be created.\n"
		"Passthru command SQE can be built with the options provided.\n"
		"\n"
		"User can inject specific values to PRP1 and PRP2 in DPTR with --prp1, --prp2\n"
		"options, but it might cause system crash without protection by IOMMU.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
                sqid = arg_int0("q", "sqid", "<n>", "[O] Submission queue ID"),
                nsid = arg_int0("n", "namespace-id", "<n>", "[O] Namespace ID, Mandatory if --sqid > 0"),
		opcode = arg_int1("o", "opcode", "<int>", "[M] Operation code"),
		flags = arg_int0("f", "flags", "<n>", "[O] Command flags in CDW0[15:8]"),
		rsvd = arg_int0("R", "rsvd", "<n>", "[O] Reserved field"),
		data_len = arg_int0("l", "data-len", "<n>", "[O] Data length in bytes"),
		cdw2 = arg_int0("2", "cdw2", "<n>", "[O] Command dword 2"),
		cdw3 = arg_int0("3", "cdw3", "<n>", "[O] Command dword 3"),
		prp1 = arg_str0(NULL, "prp1", "<ptr>", "[O] PRP1 in DPTR (for injection)"),
		prp2 = arg_str0(NULL, "prp2", "<ptr>", "[O] PRP2 in DPTR (for injection)"),
		cdw10 = arg_int0("4", "cdw10", "<n>", "[O] Command dword 10"),
		cdw11 = arg_int0("5", "cdw11", "<n>", "[O] Command dword 11"),
		cdw12 = arg_int0("6", "cdw12", "<n>", "[O] Command dword 12"),
		cdw13 = arg_int0("7", "cdw13", "<n>", "[O] Command dword 13"),
		cdw14 = arg_int0("8", "cdw14", "<n>", "[O] Command dword 14"),
		cdw15 = arg_int0("9", "cdw15", "<n>", "[O] Command dword 15"),
		input = arg_file0("i", "input-file", "<input>", "[M] File to write (in write direction)"),
		show_cmd = arg_lit0("s", "show-command", "[O] Show command before sending"),
		dry_run = arg_lit0("d", "dry-run", "[O] Show command instead of sending"),
		read = arg_lit0("r", "read", "[O] Set read data direction"),
		write = arg_lit0("w", "write", "[O] Set write data direction"),
		nodb = arg_lit0("N", "nodb", "[O] Don't update tail doorbell of the submission queue"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	__unvme_free char *filepath = NULL;
	void *buf;
	ssize_t len;
	unsigned long cmd_flags = 0;
	bool _write = false;
	bool _read = false;
	union nvme_cmd sqe = {0, };
	int ret;

	/* Set default argument values prior to parsing */
	arg_intv(opcode) = -1;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_boolv(sqid) && !arg_boolv(nsid)) {
		unvme_pr_err("invalid -n|--namespace-id\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_boolv(read) && arg_boolv(write)) {
		unvme_pr_err("invalid -r|--read and -w|--write\n");
		ret = EINVAL;
		goto out;
	}

	if (!unvmed_get_sq(u, arg_intv(sqid))) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	_write = arg_boolv(write);
	_read = arg_boolv(read);

	/*
	 * If both -r and -w are not given, decide the data direction by the
	 * opcode.
	 */
	if (!_read && !_write) {
		switch (arg_intv(opcode) & 0x3) {
		case 0x1:
			_write = true;
			break;
		case 0x2:
			_read = true;
			break;
		default:
			break;
		}
	}

	if (_write && !arg_filev(input)) {
		unvme_pr_err("invalid -i|--input-file\n");
		ret = EINVAL;
		goto out;
	}

	len = pgmap(&buf, arg_intv(data_len));
	if (!buf) {
		unvme_pr_err("failed to allocate buffer\n");
		ret = errno;
		goto out;
	}

	if (_write) {
		filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(input));
		if (unvme_read_file(filepath, buf, arg_intv(data_len))) {
			unvme_pr_err("failed to read file %s\n", filepath);
			ret = ENOENT;
			goto free;
		}
	}

	sqe.opcode = (uint8_t)arg_intv(opcode);
	sqe.flags = (uint8_t)arg_intv(flags);
	sqe.nsid = cpu_to_le32(arg_intv(nsid));
	sqe.cdw2 = cpu_to_le32(arg_intv(cdw2));
	sqe.cdw3 = cpu_to_le32(arg_intv(cdw3));

	/*
	 * Override prp1 and prp2 if they are given to inject specific values
	 */
	if (prp1)
		sqe.dptr.prp1 = strtoull(arg_strv(prp1), NULL, 0);
	if (prp2)
		sqe.dptr.prp2 = strtoull(arg_strv(prp2), NULL, 0);

	sqe.cdw10 = cpu_to_le32(arg_intv(cdw10));
	sqe.cdw11 = cpu_to_le32(arg_intv(cdw11));
	sqe.cdw12 = cpu_to_le32(arg_intv(cdw12));
	sqe.cdw13 = cpu_to_le32(arg_intv(cdw13));
	sqe.cdw14 = cpu_to_le32(arg_intv(cdw14));
	sqe.cdw15 = cpu_to_le32(arg_intv(cdw15));

	if (arg_boolv(show_cmd) || arg_boolv(dry_run)) {
		uint32_t *entry = (uint32_t *)&sqe;
		for (int dw = 0; dw < 16; dw++)
			unvme_pr("cdw%d\t\t: 0x%08x\n", dw, *(entry + dw));
	}
	if (arg_boolv(dry_run))
		return 0;

	if (arg_boolv(nodb))
		cmd_flags |= UNVMED_CMD_F_NODB;

	ret = unvmed_passthru(u, arg_intv(sqid), buf, len, &sqe,
			_read, cmd_flags);
	if (!ret && !arg_boolv(nodb)) {
		if (_read)
			unvme_cmd_pr_raw(buf, arg_intv(data_len));
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);

free:
	if (ret || (!ret && !(cmd_flags & UNVMED_CMD_F_NODB)))
		pgunmap(buf, len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_update_sqdb(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_dbl *sqid;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Update submission queue tail doorbell to issue all the pending written\n"
		"submission queue entries by `--nodb` options.  This command will wait for\n"
		"the pending commands in the submission queue to complete.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		sqid = arg_dbl1("q", "sqid", "<n>", "[M] Submission queue ID"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	__unvme_free struct nvme_cqe *cqes = NULL;
	int nr_sqes;
	int ret = 0;

	/* Set default argument values prior to parsing */
	arg_dblv(sqid) = UINT64_MAX;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (!unvmed_get_sq(u, arg_dblv(sqid))) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	nr_sqes = unvmed_sq_update_tail_and_wait(u, arg_dblv(sqid), &cqes);
	if (nr_sqes < 0) {
		unvme_pr_err("failed to update sq and wait cq\n");
		ret = errno;
		goto out;
	}

	if (!nr_sqes)
		return 0;

	for (int i = 0; i < nr_sqes; i++) {
		struct unvme_cmd *cmd = unvmed_get_cmd_from_cqe(u, &cqes[i]);

		if (cmd->vaddr)
			pgunmap(cmd->vaddr, cmd->len);

		unvmed_cmd_free(cmd);
	}

	for (int i = 0; i < nr_sqes; i++) {
		unvme_pr_cqe(&cqes[i]);
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_reset(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_lit *reinit;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Reset NVMe controller by setting CC.EN to 0 and wait for CSTS.RDY register\n"
		"to be 0 which represents reset completed.  To re-enable the controller,\n"
		"`enable` should be executed again.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		reinit = arg_lit0(NULL, "reinit", "[O] Re-initialize the controller with the current driver context (e.g., I/O queues)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	/*
	 * If --reinit is given, we should gather all the driver context here
	 * to restore them back when enabling the controller back again.
	 */
	if (arg_boolv(reinit))
		unvmed_ctx_init(u);

	unvmed_reset_ctrl(u);

	if (arg_boolv(reinit))
		unvmed_ctx_restore(u);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_perf(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *sqid;
	struct arg_int *nsid;
	struct arg_str *io_pattern;
	struct arg_lit *random;
	struct arg_int *io_depth;
	struct arg_int *sec_runtime;
	struct arg_int *sec_warmup;
	struct arg_int *update_interval;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit a Read or Write I/O command to the given submission queue of the\n"
		"target <device> while maintaining queue depth, configured by -d|--io-depth.\n"
		"To run this command, I/O queue MUST be created.  This is derieved from "
		"libvfn's example tool 'perf'.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		sqid = arg_int1("q", "sqid", "<n>", "[M] Submission Queue ID"),
		nsid = arg_int1("n", "namespace-id", "<n>", "[M] Namespace ID"),
		io_pattern = arg_str0("p", "io-pattern", "[read|write]", "[O] I/O pattern (defaults: read)"),
		random = arg_lit0("r", "random", "[O] Random I/O (defaults: false)"),
		io_depth = arg_int0("d", "io-depth", "<n>", "[O] I/O depth (defaults: 1)"),
		sec_runtime = arg_int0("t", "runtime", "<n>", "[O] Runtime in seconds (defaults: 10)"),
		sec_warmup = arg_int0("w", "warmup", "<n>", "[O] Warmup time in seconds (defaults: 0)"),
		update_interval = arg_int0("u", "update-interval", "<n>", "[O] Update stats interval in seconds (defaults: 1)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	/* Set default argument values prior to parsing */
	arg_strv(io_pattern) = "read";
	arg_intv(io_depth) = 1;
	arg_intv(sec_runtime) = 10;
	arg_intv(sec_warmup) = 0;
	arg_intv(update_interval) = 1;

	int qsize;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (!unvmed_get_sq(u, arg_intv(sqid))) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	qsize = unvmed_get_sq(u, arg_intv(sqid))->q->qsize;

	if (arg_intv(io_depth) < 1 || arg_intv(io_depth) > qsize - 1) {
		unvme_pr_err("invalid -d|--io-depth\n");
		ret = EINVAL;
		goto out;
	}

	if (!(streq(arg_strv(io_pattern), "read") ||
				streq(arg_strv(io_pattern), "write"))) {
		unvme_pr_err("invalid -p|--io-pattern\n");
		ret = EINVAL;
		goto out;
	}

	ret = unvmed_perf(u, arg_intv(sqid), arg_intv(nsid),
			arg_strv(io_pattern), arg_boolv(random),
			arg_intv(io_depth), arg_intv(sec_runtime),
			arg_intv(sec_warmup), arg_intv(update_interval));
	if (ret)
		unvme_pr_err("failed to run perf\n");
out:
	unvme_free_args(argtable);
	return ret;
}

#ifdef UNVME_FIO
extern int unvmed_run_fio(int argc, char *argv[], const char *libfio, const char *pwd);
int unvme_fio(int argc, char *argv[], struct unvme_msg *msg)
{
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Run fio libvfn ioengine with NVMe controller resources configured by unvme-cli.\n"
		"'unvme start --with-fio=<fio>' must be given first to load fio shared object to unvmed.\n"
		"And users should enable and create I/O queues before running fio through this command";

	void *argtable[] = {
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	const char *libfio;
	int ret;

	/*
	 * We don't care the failure of the parameter parsing since we will
	 * have fio arguments in this command.
	 */
	arg_parse(argc, argv, argtable);

	if (arg_boolv(help))
		unvme_print_help(__stdout, argv[1], desc, argtable);

	libfio = unvmed_get_libfio();
	if (!libfio) {
		/*
		 * If user does not give --with-fio=<path> option to 'unvme
		 * start' command, it will find out available 'fio.so' shared
		 * object in the current system by default.
		 */
		libfio = strdup("fio.so");
	}

	ret = unvmed_run_fio(argc - 1, &argv[1], libfio, unvme_msg_pwd(msg));

	unvme_free_args(argtable);
	return ret;
}
#endif
