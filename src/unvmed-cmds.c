// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <setjmp.h>
#include <sys/msg.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>

#include <ccan/str/str.h>
#include <nvme/types.h>
#include <vfn/pci.h>
#include <vfn/nvme.h>
#include <vfn/pci/util.h>

#include "libunvmed.h"
#include "unvme.h"
#include "unvmed.h"
#include "app/perf/perf.h"

#include <argtable3.h>

static pthread_spinlock_t __arglock;

static void __attribute__((constructor)) unvmed_cmds_init(void)
{
	pthread_spin_init(&__arglock, 0);
}

#define unvme_parse_args_locked(argc, argv, argtable, help, end, desc)			\
	do {										\
		int nerror;								\
											\
		pthread_spin_lock(&__arglock);						\
		nerror = arg_parse(argc - 1, &argv[1], argtable);			\
		pthread_spin_unlock(&__arglock);					\
											\
		if (arg_boolv(help)) {							\
			unvme_print_help(__stdout, argv[1], desc, argtable);		\
											\
			arg_freetable(argtable, sizeof(argtable) / sizeof(*argtable));	\
			return 0;							\
		}									\
											\
		if (nerror > 0) {							\
			arg_print_errors(__stdout, end, "unvme");                       \
			unvme_print_help(__stdout, argv[1], desc, argtable);		\
											\
			arg_freetable(argtable, sizeof(argtable) / sizeof(*argtable));	\
			return EINVAL;							\
		}									\
											\
	} while (0)

extern __thread struct unvme_msg *__msg;
__thread jmp_buf *__jump = NULL;

/*
 * Overrided exit() function which should be called by the external apps.
 */
void exit(int status)
{
	if (__msg) {
		unvmed_log_err("job (pid=%d) has been terminated (err=%d)",
				unvme_msg_pid(__msg), status);
	}

	if (__jump)
		longjmp(*__jump, EINTR);

	unvme_exit_job(status);
	pthread_exit(NULL);
}

static void unvme_pr_cqe(struct nvme_cqe *cqe)
{
	uint32_t sct, sc;

	sct = (cqe->sfp >> 9) & 0x7;
	sc = (cqe->sfp >> 1) & 0xff;

	unvme_pr_err("CQ entry: sqid=%#x, sqhd=%#x, cid=%#x, dw0=%#x, dw1=%#x, sct=%#x, sc=%#x\n",
			cqe->sqid, cqe->sqhd, cqe->cid, cqe->dw0, cqe->dw1, sct, sc);
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

static int unvmed_pci_bind(const char *bdf, const char *target)
{
	char *path = "/sys/module/vfio_pci";
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

static bool unvmed_sriov_supported(const char *bdf)
{
	char *pf_path = NULL;
	bool ret;

	assert(asprintf(&pf_path, "/sys/bus/pci/devices/%s/sriov_numvfs", bdf));

	if ((access(pf_path, F_OK) == 0) | pci_is_vf(bdf))
		ret = true;
	else
		ret = false;

	free(pf_path);
	return ret;
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

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

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
	struct arg_str *vf_token;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Register a given target <device> to unvmed service by binding\n"
		"it to 'vfio-pci' kernel driver to support user-space I/O.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nrioqs = arg_int0("q", "nr-ioqs", "<n>", "[O] Maximum number of "
			"I/O queues to create (defaults: # of cpu)"),
		vf_token = arg_str0("v", "vf-token", "<n>", "[O] VF token(UUID) to override"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	/* Set default argument values prior to parsing */
	arg_intv(nrioqs) = get_nprocs();
	arg_strv(vf_token) = UNVME_DEFAULT_UUID;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (u)
		goto out;

	if (arg_intv(nrioqs) < 1) {
		unvme_pr_err("'--nr-ioqs=' should be greater than 0\n");
		ret = EINVAL;
		goto out;
	}

	if(!pci_get_iommu_group(arg_strv(dev))){
		unvme_pr_err("failed to find iommu group\n");
		ret = EINVAL;
		goto out;
	}

	if (unvmed_pci_bind(arg_strv(dev), "vfio-pci")) {
		unvme_pr_err("failed to bind PCI device to vfio-pci driver\n");
		ret = errno;
		goto out;
	}

	/* VFTOKEN is an environmental variable used in libvfn for SR-IOV */
	if (unvmed_sriov_supported(arg_strv(dev)))
		setenv("VFTOKEN", arg_strv(vf_token), 1);
	else
		unsetenv("VFTOKEN");

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
	struct arg_lit *nvme;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Delete a given target <device> from unvmed service by unbinding\n"
		"it from 'vfio-pci' kernel driver";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nvme = arg_lit0("n", "nvme", "Bind back to nvme kernel driver from vfio-pci driver"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (u)
		unvmed_free_ctrl(u);

	if (unvmed_pci_unbind(arg_strv(dev))) {
		unvme_pr_err("failed to unbind PCI device from vfio-pci driver\n");
		ret = errno;
	}

	/*
	 * If --nvme is not given, keep the device being binded to vfio-pci
	 * kernel driver, otherwise, bind it to nvme kernel drive back.
	 */
	if (arg_boolv(nvme)) {
		if (unvmed_pci_bind(arg_strv(dev), "nvme")) {
			unvme_pr_err("failed to bind PCI device to nvme driver\n");
			ret = errno;
		}
	}

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

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

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

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

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

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

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

int unvme_cmb(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_lit *enable;
	struct arg_lit *disable;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Enable CMB (controller memory buffer) in the controller.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		enable = arg_lit0("e", "enable", "Enable CMB"),
		disable = arg_lit0("d", "disable", "Disable CMB"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	if (arg_boolv(enable) && arg_boolv(disable)) {
		unvme_pr_err("invalid, given --enable and --disable both\n");
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_boolv(enable)) {
		if (unvmed_cmb_init(u)) {
			unvme_pr_err("failed to initialize CMB\n");
			ret = EINVAL;
			goto out;
		}
	} else if (arg_boolv(disable)) {
		unvmed_cmb_free(u);
	} else {
		unvme_pr_err("either --enable or --disable should be given\n");
		ret = EINVAL;
		goto out;
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
	struct unvme_sq *usq;
	int ret = 0;

	/* Set default argument values prior to parsing */
	arg_intv(vector) = -1;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, 0);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(vector) < 0)
		arg_intv(vector) = -1;

	if (unvmed_cq_enabled(u, arg_intv(qid))) {
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
	struct unvme_sq *usq;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, 0);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (!unvmed_cq_enabled(u, arg_intv(qid))) {
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
	struct unvme_sq *usq, *targetq;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, 0);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	targetq = unvmed_sq_find(u, arg_intv(qid));
	if (unvmed_sq_enabled(targetq)) {
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
	struct unvme_sq *usq, *targetq;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, 0);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	targetq = unvmed_sq_find(u, arg_intv(qid));
	if (unvmed_sq_enabled(targetq)) {
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
	struct arg_dbl *nsid;
	struct arg_int *prp1_offset;
	struct arg_str *format;
	struct arg_lit *nodb;
	struct arg_lit *help;
	struct arg_end *end;
	const char *desc =
		"Submit an Identify Namespace admin command to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nsid = arg_dbl1("n", "nsid", "<n>", "[M] Namespace ID"),
		prp1_offset = arg_int0(NULL, "prp1-offset", "<n>", "[O] PRP1 offset < CC.MPS (default: 0x0)"),
		format = arg_str0("o", "output-format", "[normal|binary]", "[O] Output format: [normal|binary] (defaults: normal)"),
		nodb = arg_lit0("N", "nodb", "[O] Don't update tail doorbell of the submission queue"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	const size_t size = NVME_IDENTIFY_DATA_SIZE;
	const uint16_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	ssize_t len;
	void *buf = NULL;
	unsigned long flags = 0;
	struct iovec iov;
	int ret;

	/* Set default argument values prior to parsing */
	arg_strv(format) = "normal";
	arg_intv(prp1_offset) = 0x0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(prp1_offset) >= getpagesize()) {
		unvme_pr_err("invalid --prp1-offset\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_boolv(nodb))
		flags |= UNVMED_CMD_F_NODB;

	/* allocate a buffer with a consieration of --prp1-offset=<n> */
	len = pgmap(&buf, size + (getpagesize() - arg_intv(prp1_offset)));
	if (len < 0) {
		unvme_pr_err("failed to allocate user data buffer\n");
		ret = errno;
		goto out;
	}

	cmd = unvmed_alloc_cmd(u, usq, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		pgunmap(buf, len);
		ret = errno;
		goto out;
	}

	buf += arg_intv(prp1_offset);

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	ret = unvmed_id_ns(u, cmd, arg_dblv(nsid), &iov, 1, flags);

	if (arg_boolv(nodb)) {
		cmd->buf.flags = UNVME_CMD_BUF_F_VA_UNMAP |
			UNVME_CMD_BUF_F_IOVA_UNMAP;
		goto out;
	}

	if (!ret) {
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_ns);

		if (unvmed_init_ns(u, arg_dblv(nsid), buf)) {
			unvme_pr_err("failed to initialize ns instance\n");
			ret = errno;
		}
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else
		unvme_pr_err("failed to identify namespace\n");

	unvmed_cmd_free(cmd);
	pgunmap(buf - arg_intv(prp1_offset), len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_id_ctrl(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Submit an Identify Controller admin command to the target <device>.";

	struct unvme *u;
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_int *prp1_offset = arg_int0(NULL, "prp1-offset", "<n>", "[O] PRP1 offset < CC.MPS (default: 0x0)");
	struct arg_lit *vendor_specific = arg_lit0("V", "vendor-specific", "[O] Dump binary vendor field");
	struct arg_lit *binary = arg_lit0("b", "raw-binary", "[O] Show identify in binary format");
	struct arg_lit *nodb = arg_lit0("N", "nodb", "[O] Don't update tail doorbell of the submission queue");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, prp1_offset, vendor_specific, binary, nodb, help, end};

	const size_t size = NVME_IDENTIFY_DATA_SIZE;
	const uint16_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	ssize_t len;
	void *buf = NULL;
	unsigned long flags = 0;
	struct iovec iov;
	int ret;

	/* Set default argument values prior to parsing */
	arg_intv(prp1_offset) = 0x0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(prp1_offset) >= getpagesize()) {
		unvme_pr_err("invalid --prp1-offset\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_boolv(nodb))
		flags |= UNVMED_CMD_F_NODB;

	/* allocate a buffer with a consieration of --prp1-offset=<n> */
	len = pgmap(&buf, size + (getpagesize() - arg_intv(prp1_offset)));
	if (len < 0) {
		unvme_pr_err("failed to allocate user data buffer\n");
		ret = errno;
		goto out;
	}

	cmd = unvmed_alloc_cmd(u, usq, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		pgunmap(buf, len);
		ret = errno;
		goto out;
	}

	buf += arg_intv(prp1_offset);

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	ret = unvmed_id_ctrl(u, cmd, &iov, 1, flags);

	if (arg_boolv(nodb)) {
		cmd->buf.flags = UNVME_CMD_BUF_F_VA_UNMAP |
			UNVME_CMD_BUF_F_IOVA_UNMAP;
		goto out;
	}

	if (!ret) {
		unvmed_init_id_ctrl(u, buf);
		__unvme_cmd_pr(arg_boolv(binary) ? "binary" : "normal", buf, size, unvme_pr_id_ctrl);
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else
		unvme_pr_err("failed to identify namespace\n");

	unvmed_cmd_free(cmd);
	pgunmap(buf - arg_intv(prp1_offset), len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_id_active_nslist(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_dbl *nsid;
	struct arg_int *prp1_offset;
	struct arg_str *format;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit an Identify Active Namespace List admin command to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nsid = arg_dbl0("n", "nsid", "<n>", "[O] Starting NSID for retrieving active NS with NSID greater than this (default: 0)"),
		prp1_offset = arg_int0(NULL, "prp1-offset", "<n>", "[O] PRP1 offset < CC.MPS (default: 0x0)"),
		format = arg_str0("o", "output-format", "[normal|binary]", "[O] Output format: [normal|binary] (defaults: normal)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	const size_t size = NVME_IDENTIFY_DATA_SIZE;
	const uint16_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	struct iovec iov;
	ssize_t len;
	void *buf = NULL;
	int ret;

	/* Set default argument values prior to parsing */
	arg_dblv(nsid) = 0;
	arg_strv(format) = "normal";
	arg_intv(prp1_offset) = 0x0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(prp1_offset) >= getpagesize()) {
		unvme_pr_err("invalid --prp1-offset\n");
		ret = EINVAL;
		goto out;
	}

	len = pgmap(&buf, size + (getpagesize() - arg_intv(prp1_offset)));
	if (len < 0) {
		unvme_pr_err("failed to allocate buffer\n");
		ret = errno;
		goto out;
	}

	cmd = unvmed_alloc_cmd(u, usq, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		pgunmap(buf, len);
		ret = errno;
		goto out;
	}

	buf += arg_intv(prp1_offset);

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	ret = unvmed_id_active_nslist(u, cmd, arg_dblv(nsid), &iov, 1);
	if (!ret)
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_active_nslist);
	else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else
		unvme_pr_err("failed to identify active namespace list\n");

	unvmed_cmd_free(cmd);
	pgunmap(buf - arg_intv(prp1_offset), len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_nvm_id_ns(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_dbl *nsid;
	struct arg_int *prp1_offset;
	struct arg_str *format;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit an Identify Namespace NVM Command Set command to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nsid = arg_dbl1("n", "nsid", "<n>", "[M] Namespace ID"),
		prp1_offset = arg_int0(NULL, "prp1-offset", "<n>", "[O] PRP1 offset < CC.MPS (default: 0x0)"),
		format = arg_str0("o", "output-format", "[normal|binary]", "[O] Output format: [normal|binary] (defaults: normal)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	const size_t size = NVME_IDENTIFY_DATA_SIZE;
	const uint16_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	struct iovec iov;
	ssize_t len;
	void *buf = NULL;
	int ret;

	/* Set default argument values prior to parsing */
	arg_strv(format) = "normal";
	arg_intv(prp1_offset) = 0x0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (!unvmed_ns_find(u, arg_dblv(nsid))) {
		unvme_pr_err("failed to get namespace instance. Do `unvme id-ns` first\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_intv(prp1_offset) >= getpagesize()) {
		unvme_pr_err("invalid --prp1-offset\n");
		ret = EINVAL;
		goto out;
	}

	len = pgmap(&buf, size + (getpagesize() - arg_intv(prp1_offset)));
	if (len < 0) {
		unvme_pr_err("failed to allocate buffer\n");
		ret = errno;
		goto out;
	}

	cmd = unvmed_alloc_cmd(u, usq, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		pgunmap(buf, len);
		ret = errno;
		goto out;
	}

	buf += arg_intv(prp1_offset);

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	ret = unvmed_nvm_id_ns(u, cmd, arg_dblv(nsid), &iov, 1);
	if (!ret) {
		if (unvmed_init_meta_ns(u, arg_dblv(nsid), buf)) {
			unvme_pr_err("failed to initialize meta info");

			unvmed_cmd_free(cmd);
			pgunmap(buf, len);
			ret = errno;
			goto out;
		}
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_nvm_id_ns);
	}
	else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else
		unvme_pr_err("failed to NVM identify namespace\n");

	unvmed_cmd_free(cmd);
	pgunmap(buf - arg_intv(prp1_offset), len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_set_features(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Submit a Set Features admin command to the given <device> NVMe controller";

	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_dbl *nsid = arg_dbl0("n", "namespace-id", "<n>",	"[O] Namespace ID");
	struct arg_int *fid = arg_int1("f", "feature-id", "<n>",	"[M] Feature Identifier");
	struct arg_lit *save = arg_lit0("s", "save",			"[O] Save the attribute to make it persistent");
	struct arg_dbl *cdw11 = arg_dbl1(NULL, "cdw11", "<n>",		"[M] CDW11 value");
	struct arg_dbl *cdw12 = arg_dbl0(NULL, "cdw12", "<n>",		"[O] CDW12 value");
	struct arg_file *data = arg_file0("d", "data", "<file>",	"[O] Write data");
	struct arg_int *data_size = arg_int0("z", "data-size", "<n>",	"[O] Write data size in bytes");
	struct arg_lit *help = arg_lit0("h", "help",			"Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, nsid, fid, save, cdw11, cdw12, data, data_size, help, end};

	__unvme_free char *filepath = NULL;
	const uint32_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	struct nvme_cqe cqe;
	struct iovec iov;
	struct unvme *u;
	void *buf = NULL;
	ssize_t len = 0;
	int ret;

	arg_dblv(nsid) = 0;
	arg_dblv(cdw12) = 0;
	arg_intv(data_size) = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_boolv(data)) {
		if (!arg_boolv(data_size) || !arg_intv(data_size)) {
			unvme_pr_err("invalid -z|--data-size\n");
			ret = EINVAL;
			goto out;
		}

		len = pgmap(&buf, arg_intv(data_size));
		if (len < 0) {
			unvme_pr_err("failed to allocate buffer\n");
			ret = errno;
			goto out;
		}

		filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(data));
		if (unvme_read_file(filepath, buf, arg_intv(data_size))) {
			unvme_pr_err("failed to read file %s\n", filepath);

			pgunmap(buf, len);
			ret = ENOENT;
			goto out;
		}
		cmd = unvmed_alloc_cmd(u, usq, buf, len);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");

			if (buf)
				pgunmap(buf, len);
			ret = errno;
			goto out;
		}

		iov = (struct iovec) {
			.iov_base = buf,
			.iov_len = arg_intv(data_size),
		};

	} else {
		cmd = unvmed_alloc_cmd_nodata(u, usq);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");
			ret = errno;
			goto out;
		}
	}

	ret = unvmed_set_features(u, cmd, arg_dblv(nsid), arg_intv(fid),
			arg_boolv(save), arg_dblv(cdw11), arg_dblv(cdw12),
			&iov, arg_intv(data_size) > 0 ? 1 : 0, &cqe);
	if (!ret) {
		unvme_pr("dw0: %#x\n", le32_to_cpu(cqe.dw0));
		unvme_pr("dw1: %#x\n", le32_to_cpu(cqe.dw1));
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else if (ret < 0)
		unvme_pr_err("failed to set-features\n");

	unvmed_cmd_free(cmd);
	if (buf && len)
		pgunmap(buf, len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_set_features_noq(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Submit a Set Features admin command to the given <device> NVMe controller";

	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_int *nsqr = arg_int1("s", "nsqr", "<n>", "[M] Number of I/O Submission Queue Requested");
	struct arg_int *ncqr = arg_int1("c", "ncqr", "<n>", "[M] Number of I/O Completion Queue Requested");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, nsqr, ncqr, help, end};

	const uint32_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	struct nvme_cqe cqe;
	struct unvme *u;
	uint32_t cdw11;
	int ret;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");
		ret = errno;
		goto out;
	}

	cdw11 = arg_intv(ncqr) << 16 | arg_intv(nsqr);

	ret = unvmed_set_features(u, cmd, 0 /* nsid */, NVME_FEAT_FID_NUM_QUEUES,
			0 /* save */, cdw11, 0 /* cdw12 */, NULL /* iov */,
			0 /* nr_iov */, &cqe);
	if (!ret)
		unvme_pr_get_features_noq(le32_to_cpu(cqe.dw0));
	else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else if (ret < 0)
		unvme_pr_err("failed to set-features-noq\n");

	unvmed_cmd_free(cmd);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_set_features_hmb(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Submit a Set Features admin command to the given <device> NVMe controller\n"
		"to enable Host Memory Buffer.\n"
		"\n"
		"-s|--size argument will be ignored in case --disable is given.";

	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_lit *enable = arg_lit0(NULL, "enable", "[O] Enable HMB (EHM=1)");
	struct arg_lit *disable = arg_lit0(NULL, "disable", "[O] Disable HMB (EHM=0)");
	struct arg_int *size = arg_intn("s", "size", "<n>", 0, 256, "[M] Number of contiguous memory page size(CC.MPS) for a single HMB descriptor.  Multiple sizes can be given.");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, enable, disable, size, help, end};

	struct unvme_sq *usq;
	struct unvme *u;
	struct nvme_cqe cqe = {0, };
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	if ((!arg_boolv(enable) && !arg_boolv(disable)) ||
			(arg_boolv(enable) && arg_boolv(disable))) {
		unvme_pr_err("either --enable or --disable should be given\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_boolv(enable) && !arg_boolv(size)) {
		unvme_pr_err("-s|--size should be given\n");
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, 0);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_boolv(enable)) {
		ret = unvmed_set_features_hmb(u, true, (uint32_t *)size->ival,
				size->count, &cqe);
	} else
		ret = unvmed_set_features_hmb(u, false, NULL, 0, &cqe);

	if (!ret)
		unvme_pr_err("dw0: %#x\n", le32_to_cpu(cqe.dw0));
	else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else if (ret < 0)
		unvme_pr_err("failed to set-features\n");
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_get_features(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Submit a Get Features admin command to the given <device> NVMe controller";

	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_dbl *nsid = arg_dbl0("n", "namespace-id", "<n>",	"[O] Namespace ID");
	struct arg_int *fid = arg_int1("f", "feature-id", "<n>",	"[M] Feature Identifier");
	struct arg_int *sel = arg_int0("s", "sel", "n",			"[O] Select [0-3,8]: current/default/saved/supported/changed");
	struct arg_file *data = arg_file0("d", "data", "<file>",	"[O] File to write dptr data");
	struct arg_int *data_size = arg_int0("z", "data-size", "<n>",	"[O] Data size in bytes");
	struct arg_dbl *cdw11 = arg_dbl0(NULL, "cdw11", "<n>",		"[O] CDW11 value");
	struct arg_dbl *cdw14 = arg_dbl0(NULL, "cdw14", "<n>",		"[O] CDW14 value");
	struct arg_lit *help = arg_lit0("h", "help",			"Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, nsid, fid, sel, data, data_size, cdw11, cdw14, help, end};

	__unvme_free char *filepath = NULL;
	const uint32_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	struct nvme_cqe cqe;
	struct iovec iov;
	struct unvme *u;
	void *buf = NULL;
	ssize_t len = 0;
	int ret;

	arg_dblv(nsid) = 0;
	arg_intv(sel) = 0;
	arg_intv(data_size) = 0;
	arg_dblv(cdw11) = 0;
	arg_dblv(cdw14) = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_boolv(data_size)) {
		len = pgmap(&buf, arg_intv(data_size));
		if (len < 0) {
			unvme_pr_err("failed to allocate buffer\n");
			ret = errno;
			goto out;
		}

		cmd = unvmed_alloc_cmd(u, usq, buf, len);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");

			if (buf)
				pgunmap(buf, len);
			ret = errno;
			goto out;
		}

		iov = (struct iovec) {
			.iov_base = buf,
			.iov_len = arg_intv(data_size),
		};

	} else {
		cmd = unvmed_alloc_cmd_nodata(u, usq);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");
			ret = errno;
			goto out;
		}
	}

	ret = unvmed_get_features(u, cmd, arg_dblv(nsid), arg_intv(fid),
			arg_boolv(sel), arg_dblv(cdw11), arg_dblv(cdw14), &iov,
			arg_intv(data_size) > 0 ? 1 : 0, &cqe);

	if (!ret) {
		unvme_pr_err("dw0: %#x\n", le32_to_cpu(cqe.dw0));
		unvme_pr_err("dw1: %#x\n", le32_to_cpu(cqe.dw1));

		if (arg_boolv(data_size)) {
			if (arg_boolv(data)) {
				filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(data));
				unvme_write_file(filepath, buf, arg_intv(data_size));
			} else
				unvme_cmd_pr_raw(buf, arg_intv(data_size));
		}
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else if (ret < 0)
		unvme_pr_err("failed to get-features\n");

	unvmed_cmd_free(cmd);

	if (buf && len)
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
	struct arg_dbl *nsid;
	struct arg_dbl *slba;
	struct arg_int *nlb;
	struct arg_int *data_size;
	struct arg_file *data;
	/* metadata */
	struct arg_int *metadata_size;
	struct arg_file *metadata;
	struct arg_int *prinfo;
	struct arg_int *atag_mask;
	struct arg_int *atag;
	struct arg_int *rtag;
	struct arg_int *stag;
	struct arg_lit *stag_check;
	struct arg_int *prp1_offset;
	struct arg_lit *sgl;
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
                nsid = arg_dbl1("n", "namespace-id", "<n>", "[M] Namespace ID"),
                slba = arg_dbl1("s", "start-block", "<n>", "[M] Start LBA"),
		nlb = arg_int1("c", "block-count", "<n>", "[M] Number of logical block (0-based)"),
		data_size = arg_int1("z", "data-size", "<n>", "[M] Read data buffer size in bytes"),
		data = arg_file0("d", "data", "<output>", "[O] File to write read data"),
		metadata_size = arg_int0("y", "metadata-size", "<n>", "[O] Metadata block size in bytes"),
		metadata = arg_file0("M", "metadata", "<input>", "[O] File to write as metadata"),
		prinfo = arg_int0("p", "prinfo", "<n>", "[O] PI and check field"),
		atag_mask = arg_int0("m", "app-tag-mask", "<n>", "[O] App tag mask for end-to-end PI"),
		atag = arg_int0("a", "app-tag", "<n>", "[O] App tag for end-to-end PI"),
		rtag = arg_int0("r", "ref-tag", "<n>", "[O] Reference tag for end-to-end PI"),
		stag = arg_int0("g", "storage-tag", "<n>", "[O] Storage tag for end-to-end PI"),
		stag_check = arg_lit0("C", "storage-tag-check", "[O] Enable to check storage tag"),
		prp1_offset = arg_int0(NULL, "prp1-offset", "<n>", "[O] PRP1 offset < CC.MPS (default: 0x0)"),
		sgl = arg_lit0("S", "sgl", "[O] Map data buffer with SGL (default: PRP)"),
		nodb = arg_lit0("N", "nodb", "[O] Don't update tail doorbell of the submission queue"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	__unvme_free char *filepath = NULL;
	__unvme_free char *mfilepath = NULL;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	struct unvme_ns *ns = NULL;
	struct iovec iov;
	void *buf = NULL;
	void *mbuf = NULL;
	void *rdata;
	void *rmdata;
	unsigned long flags = 0;
	ssize_t size;
	ssize_t len;
	ssize_t mlen = 0;
	int ret;

	arg_intv(metadata_size) = 0;
	arg_intv(prinfo) = 0;
	arg_intv(atag) = 0;
	arg_intv(atag_mask) = 0;
	arg_intv(rtag) = 0;
	arg_intv(stag) = 0;
	arg_intv(prp1_offset) = 0x0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_intv(metadata_size)) {
		ns = unvmed_ns_get(u, arg_dblv(nsid));
		if (!ns) {
			unvme_pr_err("failed to get namespace\n");
			ret = EINVAL;
			goto out;
		}

		if (!ns->ms) {
			unvme_pr_err("metadata is not supported by ns\n");
			ret = ENOTSUP;
			goto out;
		}
	}

	usq = unvmed_sq_find(u, arg_intv(sqid));
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(prp1_offset) >= getpagesize()) {
		unvme_pr_err("invalid --prp1-offset\n");
		ret = EINVAL;
		goto out;
	}

	/*
	 * XXX: Users can be confused because of printing metadata with
	 * data.  So, if there is metadata, the output file for metadata
	 * have to be given by users, so that we can seperate it from
	 * data.
	 */
	if (arg_intv(metadata_size) && !arg_boolv(metadata)) {
		unvme_pr_err("-M <output> is needed for metadata\n");
		ret = EINVAL;
		goto out;
	}

	size = arg_intv(data_size);
	if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_EXTENDED)
		size += arg_intv(metadata_size);

	len = pgmap(&buf, size + (getpagesize() - arg_intv(prp1_offset)));
	if (len < 0) {
		unvme_pr_err("failed to allocate buffer\n");
		ret = errno;
		goto out;
	}

	if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_SEPARATE) {
		mlen = pgmap(&mbuf, arg_intv(metadata_size));
		if (mlen < 0) {
			unvme_pr_err("failed to allocate meta buffer\n");
			ret = errno;
			goto unmap;
		}
	}

	if (arg_boolv(sgl))
		flags |= UNVMED_CMD_F_SGL;
	if (arg_boolv(nodb))
		flags |= UNVMED_CMD_F_NODB;

	if (arg_boolv(data))
		filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(data));
	if (arg_boolv(metadata))
		mfilepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(metadata));

	cmd = unvmed_alloc_cmd_meta(u, usq, buf, len, mbuf, mlen);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");
		ret = errno;
		goto unmap;
	}

	buf += arg_intv(prp1_offset);

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_SEPARATE)
		mbuf += arg_intv(prp1_offset);

	ret = unvmed_read(u, cmd, arg_dblv(nsid), arg_dblv(slba), arg_intv(nlb),
			arg_intv(prinfo), arg_intv(atag), arg_intv(atag_mask),
			arg_intv(rtag), arg_intv(stag), arg_boolv(stag_check),
			&iov, 1, mbuf, flags, NULL);

	if (arg_boolv(nodb)) {
		cmd->buf.flags = UNVME_CMD_BUF_F_VA_UNMAP |
			UNVME_CMD_BUF_F_IOVA_UNMAP;
		if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_SEPARATE) {
			cmd->mbuf.flags = UNVME_CMD_BUF_F_VA_UNMAP |
				UNVME_CMD_BUF_F_IOVA_UNMAP;
		}
		goto out;
	}


	if (!ret) {
		rdata = malloc(arg_intv(data_size));
		if (!arg_intv(metadata_size))
			memcpy(rdata, buf, arg_intv(data_size));
		else {
			rmdata = malloc(arg_intv(metadata_size));
			if (arg_intv(nlb) + 1 != arg_intv(metadata_size) / ns->ms)
				unvme_pr_err("warning: # of lba is not fit with # of metadata\n");

			if (ns->mset == NVME_FORMAT_MSET_SEPARATE) {
				memcpy(rdata, buf, arg_intv(data_size));
				memcpy(rmdata, mbuf, arg_intv(metadata_size));
			} else {
				uint64_t offset = 0;

				for (int i = 0; i < arg_intv(nlb) + 1; i++) {
					memcpy(rdata + (i * ns->lba_size), buf + offset, ns->lba_size);
					offset += ns->lba_size;
					memcpy(rmdata + (i * ns->ms), buf + offset, ns->ms);
					offset += ns->ms;
				}
			}
			unvme_write_file(mfilepath, rmdata, arg_intv(metadata_size));
			free(rmdata);
		}

		if (!filepath)
			unvme_cmd_pr_raw(rdata, arg_intv(data_size));
		else
			unvme_write_file(filepath, rdata, arg_intv(data_size));

		free(rdata);
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else
		unvme_pr_err("failed to read\n");

	unvmed_cmd_free(cmd);
unmap:
	pgunmap(buf - arg_intv(prp1_offset), len);
	if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_SEPARATE)
		pgunmap(mbuf - arg_intv(prp1_offset), mlen);
out:
	if (ns)
		unvmed_ns_put(u, ns);
	unvme_free_args(argtable);
	return ret;
}

int unvme_write(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *sqid;
	struct arg_dbl *nsid;
	struct arg_dbl *slba;
	struct arg_int *nlb;
	struct arg_int *data_size;
	struct arg_file *data;
	/* metadata */
	struct arg_int *metadata_size;
	struct arg_file *metadata;
	struct arg_int *prinfo;
	struct arg_int *atag_mask;
	struct arg_int *atag;
	struct arg_int *rtag;
	struct arg_int *stag;
	struct arg_lit *stag_check;
	struct arg_int *prp1_offset;
	struct arg_lit *sgl;
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
                nsid = arg_dbl1("n", "namespace-id", "<n>", "[M] Namespace ID"),
                slba = arg_dbl1("s", "start-block", "<n>", "[M] Start LBA"),
		nlb = arg_int1("c", "block-count", "<n>", "[M] Number of logical block (0-based)"),
		data_size = arg_int1("z", "data-size", "<n>", "[O] Logical block size in bytes"),
		data = arg_file1("d", "data", "<input>", "[M] File to write as write data"),
		metadata_size = arg_int0("y", "metadata-size", "<n>", "[O] Metadata block size in bytes"),
		metadata = arg_file0("M", "metadata", "<input>", "[O] File to write as metadata"),
		prinfo = arg_int0("p", "prinfo", "<n>", "[O] PI and check field"),
		atag_mask = arg_int0("m", "app-tag-mask", "<n>", "[O] App tag mask for end-to-end PI"),
		atag = arg_int0("a", "app-tag", "<n>", "[O] App tag for end-to-end PI"),
		rtag = arg_int0("r", "ref-tag", "<n>", "[O] Reference tag for end-to-end PI"),
		stag = arg_int0("g", "storage-tag", "<n>", "[O] Storage tag for end-to-end PI"),
		stag_check = arg_lit0("C", "storage-tag-check", "[O] Enable to check storage tag"),
		prp1_offset = arg_int0(NULL, "prp1-offset", "<n>", "[O] PRP1 offset < CC.MPS (default: 0x0)"),
		sgl = arg_lit0("S", "sgl", "[O] Map data buffer with SGL (default: PRP)"),
		nodb = arg_lit0("N", "nodb", "[O] Don't update tail doorbell of the submission queue"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	__unvme_free char *filepath = NULL;
	__unvme_free char *mfilepath = NULL;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	struct unvme_ns *ns = NULL;
	struct iovec iov;
	void *buf = NULL;
	void *mbuf = NULL;
	void *__buf;
	void *__mbuf = NULL;
	void *wdata;
	void *wmdata = NULL;
	unsigned long flags = 0;
	ssize_t size;
	ssize_t len;
	ssize_t mlen = 0;
	int ret;

	arg_intv(metadata_size) = 0;
	arg_intv(prinfo) = 0;
	arg_intv(atag) = 0;
	arg_intv(atag_mask) = 0;
	arg_intv(rtag) = 0;
	arg_intv(stag) = 0;
	arg_intv(prp1_offset) = 0x0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_intv(metadata_size)) {
		ns = unvmed_ns_get(u, arg_dblv(nsid));
		if (!ns) {
			unvme_pr_err("failed to get ns\n");
			ret = ENODEV;
			goto out;
		}

		if (!ns->ms) {
			unvme_pr_err("metadata is not supported by ns\n");
			ret = ENOTSUP;
			goto out;
		}
	}

	usq = unvmed_sq_find(u, arg_intv(sqid));
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(prp1_offset) >= getpagesize()) {
		unvme_pr_err("invalid --prp1-offset\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_intv(metadata_size) && !arg_boolv(metadata)) {
		unvme_pr_err("-M <input> is needed for metadata\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_boolv(sgl))
		flags |= UNVMED_CMD_F_SGL;
	if (arg_boolv(nodb))
		flags |= UNVMED_CMD_F_NODB;

	if (arg_boolv(data))
		filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(data));
	if (arg_boolv(metadata))
		mfilepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(metadata));

	size = arg_intv(data_size);
	if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_EXTENDED)
		size += arg_intv(metadata_size);

	len = pgmap(&buf, size + (getpagesize() - arg_intv(prp1_offset)));
	if (len < 0) {
		unvme_pr_err("failed to allocate buffer\n");
		ret = errno;
		goto out;
	}

	__buf = buf + arg_intv(prp1_offset);

	wdata = malloc(arg_intv(data_size));

	if (unvme_read_file(filepath, wdata, arg_intv(data_size))) {
		unvme_pr_err("failed to read file %s\n", filepath);
		ret = ENOENT;
		goto unmap;
	}

	if (!arg_intv(metadata_size))
		memcpy(__buf, wdata, arg_intv(data_size));
	else {
		if (arg_intv(nlb) + 1 != arg_intv(metadata_size) / ns->ms)
			unvme_pr_err("Warning: # of lba is not fit with # of metadata\n");

		wmdata = malloc(arg_intv(metadata_size));
		if (unvme_read_file(mfilepath, wmdata, arg_intv(metadata_size))) {
			unvme_pr_err("failed to read file %s\n", mfilepath);
			ret = ENOENT;
			goto unmap;
		}

		if (ns->mset == NVME_FORMAT_MSET_SEPARATE) {
			mlen = pgmap(&mbuf, arg_intv(metadata_size) +
					(getpagesize() - arg_intv(prp1_offset)));
			if (mlen < 0) {
				unvme_pr_err("failed to allocate meta buffer\n");
				ret = errno;
				goto unmap;
			}
			__mbuf = mbuf + arg_intv(prp1_offset);
			memcpy(__buf, wdata, arg_intv(data_size));
			memcpy(__mbuf, wmdata, arg_intv(metadata_size));
		} else {
			uint64_t offset = 0;

			for (int i = 0; i < arg_intv(nlb) + 1; i++) {
				memcpy(__buf + offset, wdata + (i * ns->lba_size), ns->lba_size);
				offset += ns->lba_size;
				memcpy(__buf + offset, wmdata + (i * ns->ms), ns->ms);
				offset += ns->ms;
			}
		}
	}

	cmd = unvmed_alloc_cmd_meta(u, usq, buf, len, mbuf, mlen);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");
		ret = errno;
		goto unmap;
	}

	iov = (struct iovec) {
		.iov_base = __buf,
		.iov_len = size,
	};

	ret = unvmed_write(u, cmd, arg_dblv(nsid), arg_dblv(slba), arg_intv(nlb),
			arg_intv(prinfo), arg_intv(atag), arg_intv(atag_mask),
			arg_intv(rtag), arg_intv(stag), arg_boolv(stag_check),
			&iov, 1, __mbuf, flags, NULL);

	if (arg_boolv(nodb)) {
		cmd->buf.flags = UNVME_CMD_BUF_F_VA_UNMAP |
			UNVME_CMD_BUF_F_IOVA_UNMAP;
		if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_SEPARATE) {
			cmd->mbuf.flags = UNVME_CMD_BUF_F_VA_UNMAP |
				UNVME_CMD_BUF_F_IOVA_UNMAP;
		}
		goto out;
	}

	if (ret > 0)
		unvme_pr_cqe_status(ret);
	else if (ret < 0)
		unvme_pr_err("failed to write\n");

	unvmed_cmd_free(cmd);
unmap:
	pgunmap(buf - arg_intv(prp1_offset), len);

	if (arg_intv(metadata_size)) {
		free(wmdata);
		if (ns->mset == NVME_FORMAT_MSET_SEPARATE)
			pgunmap(mbuf - arg_intv(prp1_offset), mlen);
	}
	free(wdata);
out:
	if (ns)
		unvmed_ns_put(u, ns);
	unvme_free_args(argtable);
	return ret;
}

int unvme_passthru(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *sqid;
	struct arg_dbl *nsid;
	struct arg_int *opcode;
	struct arg_int *flags;
	struct arg_int *rsvd;
	struct arg_int *data_len;
	struct arg_dbl *cdw2;
	struct arg_dbl *cdw3;
	/* To figure out whether --prp1=, --prp2= are given or not */
	struct arg_dbl *prp1;
	struct arg_dbl *prp2;
	struct arg_dbl *cdw10;
	struct arg_dbl *cdw11;
	struct arg_dbl *cdw12;
	struct arg_dbl *cdw13;
	struct arg_dbl *cdw14;
	struct arg_dbl *cdw15;
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
                sqid = arg_int1("q", "sqid", "<n>", "[M] Submission queue ID"),
                nsid = arg_dbl0("n", "namespace-id", "<n>", "[O] Namespace ID, Mandatory if --sqid > 0"),
		opcode = arg_int1("o", "opcode", "<int>", "[M] Operation code"),
		flags = arg_int0("f", "flags", "<n>", "[O] Command flags in CDW0[15:8]"),
		rsvd = arg_int0("R", "rsvd", "<n>", "[O] Reserved field"),
		data_len = arg_int0("l", "data-len", "<n>", "[O] Data length in bytes"),
		cdw2 = arg_dbl0("2", "cdw2", "<n>", "[O] Command dword 2"),
		cdw3 = arg_dbl0("3", "cdw3", "<n>", "[O] Command dword 3"),
		prp1 = arg_dbl0(NULL, "prp1", "<ptr>", "[O] PRP1 in DPTR (for injection)"),
		prp2 = arg_dbl0(NULL, "prp2", "<ptr>", "[O] PRP2 in DPTR (for injection)"),
		cdw10 = arg_dbl0("4", "cdw10", "<n>", "[O] Command dword 10"),
		cdw11 = arg_dbl0("5", "cdw11", "<n>", "[O] Command dword 11"),
		cdw12 = arg_dbl0("6", "cdw12", "<n>", "[O] Command dword 12"),
		cdw13 = arg_dbl0("7", "cdw13", "<n>", "[O] Command dword 13"),
		cdw14 = arg_dbl0("8", "cdw14", "<n>", "[O] Command dword 14"),
		cdw15 = arg_dbl0("9", "cdw15", "<n>", "[O] Command dword 15"),
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
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	struct iovec iov;
	void *buf = NULL;
	ssize_t len = 0;
	unsigned long cmd_flags = 0;
	bool _write = false;
	bool _read = false;
	union nvme_cmd sqe = {0, };
	int ret;

	arg_dblv(nsid) = 0;
	arg_intv(flags) = 0;
	arg_intv(rsvd) = 0;
	arg_intv(data_len) = 0;
	arg_dblv(cdw2) = 0;
	arg_dblv(cdw3) = 0;
	arg_dblv(prp1) = 0;
	arg_dblv(prp2) = 0;
	arg_dblv(cdw10) = 0;
	arg_dblv(cdw11) = 0;
	arg_dblv(cdw12) = 0;
	arg_dblv(cdw13) = 0;
	arg_dblv(cdw14) = 0;
	arg_dblv(cdw15) = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_boolv(read) && arg_boolv(write)) {
		unvme_pr_err("invalid -r|--read and -w|--write\n");
		ret = EINVAL;
		goto out;
	}

	usq = unvmed_sq_find(u, arg_intv(sqid));
	if (!usq || !unvmed_sq_enabled(usq)) {
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

	if (arg_intv(data_len)) {
		len = pgmap(&buf, arg_intv(data_len));
		if (len < 0) {
			unvme_pr_err("failed to allocate buffer\n");
			ret = errno;
			goto out;
		}

		cmd = unvmed_alloc_cmd(u, usq, buf, len);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");

			pgunmap(buf, len);
			ret = errno;
			goto out;
		}

		if (_write) {
			filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(input));
			if (unvme_read_file(filepath, buf, arg_intv(data_len))) {
				unvme_pr_err("failed to read file %s\n", filepath);

				unvmed_cmd_free(cmd);
				pgunmap(buf, len);
				ret = ENOENT;
				goto out;
			}
		}

		iov = (struct iovec) {
			.iov_base = buf,
			.iov_len = arg_intv(data_len),
		};

	} else {
		cmd = unvmed_alloc_cmd_nodata(u, usq);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");

			ret = errno;
			goto out;
		}
	}

	sqe.opcode = (uint8_t)arg_intv(opcode);
	sqe.flags = (uint8_t)arg_intv(flags);
	sqe.nsid = cpu_to_le32(arg_dblv(nsid));
	sqe.cdw2 = cpu_to_le32(arg_dblv(cdw2));
	sqe.cdw3 = cpu_to_le32(arg_dblv(cdw3));

	/*
	 * Override prp1 and prp2 if they are given to inject specific values
	 */
	if (arg_boolv(prp1))
		sqe.dptr.prp1 = cpu_to_le64((uint64_t)arg_dblv(prp1));
	if (arg_boolv(prp2))
		sqe.dptr.prp2 = cpu_to_le64((uint64_t)arg_dblv(prp2));

	sqe.cdw10 = cpu_to_le32(arg_dblv(cdw10));
	sqe.cdw11 = cpu_to_le32(arg_dblv(cdw11));
	sqe.cdw12 = cpu_to_le32(arg_dblv(cdw12));
	sqe.cdw13 = cpu_to_le32(arg_dblv(cdw13));
	sqe.cdw14 = cpu_to_le32(arg_dblv(cdw14));
	sqe.cdw15 = cpu_to_le32(arg_dblv(cdw15));

	if (arg_boolv(show_cmd) || arg_boolv(dry_run)) {
		uint32_t *entry = (uint32_t *)&sqe;
		for (int dw = 0; dw < 16; dw++)
			unvme_pr("cdw%d\t\t: 0x%08x\n", dw, *(entry + dw));
	}

	if (arg_boolv(dry_run)) {
		unvmed_cmd_free(cmd);
		pgunmap(buf, len);
		ret = 0;
		goto out;
	}

	if (arg_boolv(nodb))
		cmd_flags |= UNVMED_CMD_F_NODB;

	ret = unvmed_passthru(u, cmd, &sqe, _read, &iov,
			      arg_intv(data_len) > 0 ? 1 : 0, cmd_flags);

	if (arg_boolv(nodb)) {
		if (buf) {
			cmd->buf.flags = UNVME_CMD_BUF_F_VA_UNMAP |
				UNVME_CMD_BUF_F_IOVA_UNMAP;
		}
		goto out;
	}

	if (!ret) {
		if (arg_boolv(data_len) && _read)
			unvme_cmd_pr_raw(buf, arg_intv(data_len));
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else
		unvme_pr_err("failed to passthru\n");

	unvmed_cmd_free(cmd);

	if (buf && len)
		pgunmap(buf, len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_update_sqdb(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *sqid;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Update submission queue tail doorbell to issue all the pending written\n"
		"submission queue entries by `--nodb` options.  This command will wait for\n"
		"the pending commands in the submission queue to complete.\n"
		"\n"
		"Note that this command should not be executed while other app (e.g., fio) is running.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		sqid = arg_int1("q", "sqid", "<n>", "[M] Submission queue ID"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	__unvme_free struct nvme_cqe *cqes = NULL;
	struct unvme_sq *usq;
	int nr_sqes;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, arg_intv(sqid));
	if (!usq) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	unvmed_sq_enter(usq);
	nr_sqes = unvmed_sq_update_tail(u, usq);
	if (!nr_sqes) {
		unvmed_sq_exit(usq);
		goto out;
	}

	unvme_pr("Updated SQ%d doorbell for %d entries\n", arg_intv(sqid), nr_sqes);

	cqes = malloc(sizeof(struct nvme_cqe) * nr_sqes);
	if (!cqes) {
		unvmed_sq_exit(usq);
		unvme_pr_err("failed to allocate memory for cq entreis\n");
		goto out;
	}

	unvme_pr("Reaping for %d CQ entries..\n", nr_sqes);
	if (unvmed_cq_run_n(u, usq->ucq, cqes, nr_sqes, nr_sqes) < 0) {
		unvmed_sq_exit(usq);
		unvme_pr_err("failed to fetch CQ entries\n");
		goto out;
	}
	unvmed_sq_exit(usq);

	for (int i = 0; i < nr_sqes; i++) {
		struct unvme_cmd *cmd = unvmed_get_cmd_from_cqe(u, &cqes[i]);

		unvmed_cmd_free(cmd);
	}

	for (int i = 0; i < nr_sqes; i++) {
		unvme_pr_cqe(&cqes[i]);
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_format(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Submit a Format NVM admin command to the given <device>.  After Format NVM command,\n"
		"Identify Namespace (CNS 0h) admin command will be issued.\n";

	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_dbl *nsid = arg_dbl1("n", "nsid", "<n>", "[M] Namespace ID");
	struct arg_int *lbaf = arg_int0("l", "lbaf", "<n>", "[O] LBA Format index");
	struct arg_int *ses = arg_int0("s", "ses", "<n>", "[O] Secure Erase Setting (*0: No secure, 1: User data erase, 2: Cryptographic erase)");
	struct arg_int *pil = arg_int0("p", "pil", "<n>", "[O] Protection Info Location (*0: First bytes of metadata, 1: Last bytes of metadata)");
	struct arg_int *pi = arg_int0("i", "pi", "<n>", "[O] Protection Info (*0: PI disabled, 1: Type 1, 2: Type 2, 3: Type 3)");
	struct arg_int *mset = arg_int0("m", "mset", "<n>", "[O] Metadata Settings (*0: Metadata as separate buffer, 1: Metadata as extended buffer)");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, nsid, lbaf, ses, pil, pi, mset, help, end};

	struct unvme *u;
	const int sqid = 0;
	struct unvme_sq *usq;
	struct unvme_cmd *cmd;
	int ret;

	/* Set default argument values prior to parsing */
	arg_intv(ses) = 0;
	arg_intv(pil) = 0;
	arg_intv(pi) = 0;
	arg_intv(mset) = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		ret = errno;
		goto out;
	}

	if (!arg_boolv(lbaf)) {
		struct unvme_ns *ns = unvmed_ns_get(u, arg_dblv(nsid));
		if (ns) {
			arg_intv(lbaf) = ns->format_idx;
			unvmed_ns_put(u, ns);
		} else {
			unvme_pr_err("failed to get a namespace instance\n");
			ret = -EINVAL;
			goto out;
		}
	}

	ret = unvmed_format(u, cmd, arg_dblv(nsid), arg_intv(lbaf),
			arg_intv(ses), arg_intv(pil), arg_intv(pi),
			arg_intv(mset));

	if (!ret) {
		/*
		 * Re-enumerate &struct unvme_ns instance by issuing an
		 * Identify Namespace (CNS 0h) admin command to the controller
		 * and update the either pre-existing or non-existing @ns
		 * instance.
		 */
		ret = unvmed_init_ns(u, arg_dblv(nsid), NULL);
		if (ret)
			unvme_pr_err("failed to identify formatted namespace\n");
		ret = unvmed_init_meta_ns(u, arg_dblv(nsid), NULL);
		if (ret)
			unvme_pr_err("failed to identify formatted namespace\n");
	} else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else
		unvme_pr_err("failed to format NVM\n");

	unvmed_cmd_free(cmd);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_reset(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_lit *graceful;
	struct arg_lit *reinit;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Reset NVMe controller by setting CC.EN to 0 and wait for CSTS.RDY register\n"
		"to be 0 which represents reset completed.  To re-enable the controller,\n"
		"`enable` should be executed again.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		graceful = arg_lit0(NULL, "graceful", "[O] Perform a graceful reset, meaning deleting I/O queues before controller reset"),
		reinit = arg_lit0(NULL, "reinit", "[O] Re-initialize the controller with the current driver context (e.g., I/O queues)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

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
	if (arg_boolv(reinit) && unvmed_ctx_init(u)) {
		unvme_pr_err("failed to save the current driver context\n");
		ret = errno;
		goto out;
	}

	if (arg_boolv(graceful))
		unvmed_reset_ctrl_graceful(u);
	else
		unvmed_reset_ctrl(u);

	if (arg_boolv(reinit) && unvmed_ctx_restore(u)) {
		unvme_pr_err("failed to restore the previous driver context\n");
		ret = errno;
		goto out;
	}
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_subsystem_reset(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Reset NVMe Subsystem by setting NSSR to 0x4E564D65.  This will make\n"
		"link down, so user cannot even access to the device register.  To\n"
		"re-enable the device, follow the steps.\n\n"
		"1. restore the previous config to /sys/bus/pci/device/<bdf>/config\n"
		"2. set 1 to CSTS.NSSRO\n"
		"3. reset the controller";

	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_lit *reinit = arg_lit0(NULL, "reinit", "[O] Re-initialize the controller with the current driver context (e.g., I/O queues)");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, reinit, help, end};

	struct unvme *u;
	int ret;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

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
	if (arg_boolv(reinit) && unvmed_ctx_init(u)) {
		unvme_pr_err("failed to save the current driver context\n");
		ret = errno;
		goto out;
	}

	ret = unvmed_subsystem_reset(u);
	if (ret) {
		unvme_pr_err("failed to nvm subsystem reset\n");
		ret = errno;
		goto out;
	}

	if (arg_boolv(reinit) && unvmed_ctx_restore(u)) {
		unvme_pr_err("failed to restore the previous driver context\n");
		ret = EINVAL;
		goto out;
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_flr(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc = "Issue FLR";

	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_lit *reinit = arg_lit0(NULL, "reinit", "[O] Re-initialize the controller with the current driver context (e.g., I/O queues)");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, reinit, help, end};

	struct unvme *u;
	int ret;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_boolv(reinit) && unvmed_ctx_init(u)) {
		unvme_pr_err("failed to save the current driver context\n");
		ret = errno;
		goto out;
	}

	ret = unvmed_flr(u);
	if (ret)
		unvme_pr_err("failed to flr\n");

	if (arg_boolv(reinit) && unvmed_ctx_restore(u)) {
		unvme_pr_err("failed to restore the previous driver context\n");
		ret = EINVAL;
		goto out;
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_hot_reset(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc = "Trigger Hot Reset to corresponding downstream port of \n"
			"the given endpoint device.";

	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_lit *reinit = arg_lit0(NULL, "reinit", "[O] Re-initialize the controller with the current driver context (e.g., I/O queues)");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, reinit, help, end};

	struct unvme *u;
	int ret;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_boolv(reinit) && unvmed_ctx_init(u)) {
		unvme_pr_err("failed to save the current driver context\n");
		ret = errno;
		goto out;
	}

	ret = unvmed_hot_reset(u);
	if (ret)
		unvme_pr_err("failed to hot reset\n");

	if (arg_boolv(reinit) && unvmed_ctx_restore(u)) {
		unvme_pr_err("failed to restore the previous driver context\n");
		ret = EINVAL;
		goto out;
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_link_disable(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc = "Trigger Link Disable to corresponding downstream port of \n"
			"the given endpoint device.";

	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_lit *reinit = arg_lit0(NULL, "reinit", "[O] Re-initialize the controller with the current driver context (e.g., I/O queues)");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, reinit, help, end};

	struct unvme *u;
	int ret;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_boolv(reinit) && unvmed_ctx_init(u)) {
		unvme_pr_err("failed to save the current driver context\n");
		ret = errno;
		goto out;
	}

	ret = unvmed_link_disable(u);
	if (ret)
		unvme_pr_err("failed to link disable\n");

	if (arg_boolv(reinit) && unvmed_ctx_restore(u)) {
		unvme_pr_err("failed to restore the previous driver context\n");
		ret = EINVAL;
		goto out;
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_perf(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *sqid;
	struct arg_dbl *nsid;
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
		nsid = arg_dbl1("n", "namespace-id", "<n>", "[M] Namespace ID"),
		io_pattern = arg_str0("p", "io-pattern", "[read|write]", "[O] I/O pattern (defaults: read)"),
		random = arg_lit0("r", "random", "[O] Random I/O (defaults: false)"),
		io_depth = arg_int0("d", "io-depth", "<n>", "[O] I/O depth (defaults: 1)"),
		sec_runtime = arg_int0("t", "runtime", "<n>", "[O] Runtime in seconds (defaults: 10)"),
		sec_warmup = arg_int0("w", "warmup", "<n>", "[O] Warmup time in seconds (defaults: 0)"),
		update_interval = arg_int0("u", "update-interval", "<n>", "[O] Update stats interval in seconds (defaults: 1)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	struct unvme_sq *usq = NULL;
	int ret = 0;

	/* Set default argument values prior to parsing */
	arg_strv(io_pattern) = "read";
	arg_intv(io_depth) = 1;
	arg_intv(sec_runtime) = 10;
	arg_intv(sec_warmup) = 0;
	arg_intv(update_interval) = 1;

	int qsize;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, arg_intv(sqid));
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	qsize = unvmed_sq_find(u, arg_intv(sqid))->q->qsize;

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

	ret = unvmed_perf(u, arg_intv(sqid), arg_dblv(nsid),
			arg_strv(io_pattern), arg_boolv(random),
			arg_intv(io_depth), arg_intv(sec_runtime),
			arg_intv(sec_warmup), arg_intv(update_interval));
	if (ret)
		unvme_pr_err("failed to run perf\n");
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_virt_mgmt(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc = "Submit a Virtualization management command, which is"
		" supported by primary controller that support the Virtualization"
		" Enhancements capability";

	struct unvme *u;
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_int *cntlid = arg_int1("c", "cntlid", "<n>", "[M] Controller Identifier");
	struct arg_int *rt = arg_int0("r", "rt", "<n>", "[O] Resource Type (*0: VQ Resource, 1: VI Resource)");
	struct arg_int *act = arg_int1("a", "act", "<n>", "[M] Action (*1: Primary Flexible, 7: Secondary Offline, 8:Secondary Assign, 9:Secondary Online)");
	struct arg_int *nr = arg_int0("n", "nr", "<n>", "[O] Number of Controller Resources");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);

	void *argtable[] = {dev, cntlid, rt, act, nr, help, end};

	struct unvme_sq *usq = NULL;
	struct unvme_cmd *cmd;
	int sqid = 0;
	int ret = 0;

	/* Set default argument values prior to parsing */
	arg_intv(rt) = 0;
	arg_intv(nr) = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");
		ret = errno;
		goto out;
	}

	ret = unvmed_virt_mgmt(u, cmd, arg_intv(cntlid), arg_intv(rt),
			arg_intv(act), arg_intv(nr));

	if (ret > 0)
		unvme_pr_cqe_status(ret);
	else if (ret < 0)
		unvme_pr_err("failed to submit virt-mgmt command\n");

	unvmed_cmd_free(cmd);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_id_primary_ctrl_caps(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Submit an Identify Primary Controller Capabilities admin command to the target <device>.";

	struct unvme *u;
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_int *cntlid = arg_int1("c", "cntlid", "<n>", "[M] Controller Identifier");
	struct arg_str *format = arg_str0("o", "output-format", "[normal|binary]", "[O] Output format: [normal|binary] (defaults: normal)");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, cntlid, format, help, end};

	const size_t size = NVME_IDENTIFY_DATA_SIZE;
	const uint16_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	ssize_t len;
	void *buf = NULL;
	struct iovec iov;
	int ret;

	/* Set default argument values prior to parsing */
	arg_strv(format) = "normal";

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	len = pgmap(&buf, size + getpagesize());
	if (len < 0) {
		unvme_pr_err("failed to allocate user data buffer\n");
		ret = errno;
		goto out;
	}

	cmd = unvmed_alloc_cmd(u, usq, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		pgunmap(buf, len);
		ret = errno;
		goto out;
	}

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	ret = unvmed_id_primary_ctrl_caps(u, cmd, &iov, 1, arg_intv(cntlid));

	if (!ret)
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_primary_ctrl_caps);
	else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else
		unvme_pr_err("failed to identify primary controller capabilities\n");

	unvmed_cmd_free(cmd);
	pgunmap(buf, len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_id_secondary_ctrl_list(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Submit an Identify Secondary Controller List admin command to the target <device>.";

	struct unvme *u;
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_int *cntlid = arg_int1("c", "cntlid", "<n>", "[M] Lowest Controller Identifier");
	struct arg_str *format = arg_str0("o", "output-format", "[normal|binary]", "[O] Output format: [normal|binary] (defaults: normal)");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, cntlid, format, help, end};

	const size_t size = NVME_IDENTIFY_DATA_SIZE;
	const uint16_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	ssize_t len;
	void *buf = NULL;
	struct iovec iov;
	int ret;

	/* Set default argument values prior to parsing */
	arg_strv(format) = "normal";

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_find(u, sqid);
	if (!usq || !unvmed_sq_enabled(usq)) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	len = pgmap(&buf, size + getpagesize());
	if (len < 0) {
		unvme_pr_err("failed to allocate user data buffer\n");
		ret = errno;
		goto out;
	}

	cmd = unvmed_alloc_cmd(u, usq, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		pgunmap(buf, len);
		ret = errno;
		goto out;
	}

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	ret = unvmed_id_secondary_ctrl_list(u, cmd, &iov, 1, arg_intv(cntlid));

	if (!ret)
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_secondary_ctrl_list);
	else if (ret > 0)
		unvme_pr_cqe_status(ret);
	else
		unvme_pr_err("failed to identify secondary controller list\n");

	unvmed_cmd_free(cmd);
	pgunmap(buf, len);
out:
	unvme_free_args(argtable);
	return ret;
}

#ifdef UNVME_FIO
extern int unvmed_run_fio(int argc, char *argv[], const char *libfio, const char *pwd);
int unvme_fio(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *libfio;

	libfio = unvmed_get_libfio();
	if (!libfio) {
		/*
		 * If user does not give --with-fio=<path> option to 'unvme
		 * start' command, it will find out available 'fio.so' shared
		 * object in the current system by default.
		 */
		libfio = strdup("fio.so");
	}

	return unvmed_run_fio(argc - 1, &argv[1], libfio, unvme_msg_pwd(msg));
}
#endif
