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

static inline int arg_validate_format(const char *format, int nr_formats, ...)
{
	va_list args;

	if (!format)
		return -1;

	va_start(args, nr_formats);

	for (int i = 0; i < nr_formats; i++) {
		const char *valid = va_arg(args, const char *);

		if (valid && streq(format, valid)) {
			va_end(args);
			return 0;
		}
	}

	va_end(args);
	return -1;
}

static inline void __unvme_cmd_pr(const char *format, void *buf, size_t len,
			   void (*pr)(const char *format, void *vaddr))
{
	if (streq(format, "binary"))
		unvme_pr_raw(buf, len);
	else if (streq(format, "normal") || streq(format, "json"))
		pr(format, buf);
	else
		assert(false);
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

int unvme_log_level(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Get or set log level of unvmed process. If `level` is given,\n"
		"the log level will be set by the given value. If not, print\n"
		"the current log level.  It defaults to INFO in release build\n"
		"and to DEBUG in debug build.";

	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_int *level = arg_int0(NULL, NULL, "<n>", "level (0:ERROR,1:INFO,2:DEBUG)");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);


	void *argtable[] = { help, level, end };

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	if (arg_boolv(level)) {
		int prev = atomic_load_acquire(&__log_level);
		atomic_store_release(&__log_level, arg_intv(level));
		unvme_pr("Log level changed to %s (prev: %s)\n",
			 loglv_to_str(atomic_load_acquire(&__log_level)),
			 loglv_to_str(prev));
	} else {
		unvme_pr("Current log level: %s\n",
			 loglv_to_str(atomic_load_acquire(&__log_level)));
	}

	unvme_free_args(argtable);
	return 0;
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

	u = unvmed_init_ctrl(arg_strv(dev), arg_intv(nrioqs));
	if (!u) {
		unvme_pr_err("failed to initialize unvme\n");
		ret = errno;
		goto out;
	}

	/*
	 * Check whether the device controller has already been enabled even if
	 * we just created the @u instance successfully here.  To ensure that
	 * state machines between the two (@u->state and actual device) are
	 * matched each other, we should check if they are not consistent,
	 * reset the controller here with an warning.
	 */
	if (NVME_CSTS_RDY(unvmed_read32(u, NVME_REG_CSTS))) {
		unvme_pr_err("controller %s has already been enabled.  Resetting...\n",
				arg_strv(dev));
		unvmed_reset_ctrl(u);
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
	struct arg_str *format;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Show NVMe controller properties (registers in MMIO space).";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		format = arg_str0("o", "output-format", "[normal|json|binary]", "[O] Output format: [normal|json|binary] (defaults: normal)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	arg_strv(format) = "normal";

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	if (arg_validate_format(arg_strv(format), 3, "normal", "json", "binary")) {
		unvme_pr_err("invalid -o|--output-format=%s\n", arg_strv(format));
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	unvme_pr_show_regs(arg_strv(format), u);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_status(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_str *format;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Show status of a given target <device> in unvmed.\n"
		"The status includes CC, CSTS and Submission/Completion Queue.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		format = arg_str0("o", "output-format", "[normal|json]", "[O] Output format: [normal|json] (defaults: normal)"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	arg_strv(format) = "normal";

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	if (arg_validate_format(arg_strv(format), 2, "normal", "json")) {
		unvme_pr_err("invalid -o|--output-format=%s\n", arg_strv(format));
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	unvme_pr_status(arg_strv(format), u);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_hmb(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_lit *allocate;
	struct arg_lit *deallocate;
	struct arg_int *size;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Allocate or de-allocate Host Memory Buffer in the unvmed context.\n"
		"Once the HMB is allocated, `set-features-hmb` command should proceed.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		allocate = arg_lit0("a", "allocate", "Allocate HMB"),
		deallocate = arg_lit0("d", "deallocate", "Deallocate HMB"),
		size = arg_intn("s", "size", "<n>", 0, 256, "[M] Number of contiguous memory page size(CC.MPS) for a single HMB descriptor.  Multiple sizes can be given."),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	if ((arg_boolv(allocate) && arg_boolv(deallocate)) ||
			(!arg_boolv(allocate) && !arg_boolv(deallocate))) {
		unvme_pr_err("either --allocate or --deallocate should be given\n");
		ret = EINVAL;
		goto out;
	}

	if (arg_boolv(allocate) && !arg_boolv(size)) {
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

	if (arg_boolv(allocate)) {
		ret = unvmed_hmb_init(u, (uint32_t *)size->ival, size->count);
		if (ret < 0) {
			if (errno == EEXIST) {
				unvme_pr_err("HMB has already been allocated\n");
				errno = 0;
			} else
				unvme_pr_err("failed to initialize Host Memory Buffer\n");
		}
	} else if (arg_boolv(deallocate)) {
		ret = unvmed_hmb_free(u);
		if (ret < 0)
			unvme_pr_err("failed to uninitialize Host Memory Buffer\n");
	}
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_create_adminq(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_lit *noint;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Create admin submission and completion queues for the NVMe controller.\n"
		"This command should be run before enabling the controller.\n"
		"Use --noint to skip IRQ initialization.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		noint = arg_lit0(NULL, "noint", "[O] Skip IRQ initialization"),
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

	if (unvmed_ctrl_enabled(u)) {
		unvme_pr_err("%s is already enabled\n", arg_strv(dev));
		ret = EALREADY;
		goto out;
	}

	if (unvmed_create_adminq(u, !arg_boolv(noint))) {
		unvme_pr_err("failed to create adminq\n");
		ret = errno;
		goto out;
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_enable(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *iosqes;
	struct arg_int *iocqes;
	struct arg_int *mps;
	struct arg_int *css;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Enable NVMe controller.\n"
		"It will wait for CSTS.RDY to be 1 after setting CC.EN to 1.\n"
		"Note: Admin queues must be created before enabling the controller.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
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

	if (unvmed_enable_ctrl(u, arg_intv(iosqes), arg_intv(iocqes), arg_intv(mps), arg_intv(css))) {
		unvme_pr_err("failed to enable controller\n");
		ret = errno;
		goto out;
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
	struct arg_lit *verbose;
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
		verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	struct unvme_sq *usq;
	struct unvme_cq *ucq;
	struct unvme_cmd *cmd;
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

	usq = unvmed_sq_get(u, 0);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(vector) < 0)
		arg_intv(vector) = -1;

	if (unvmed_cq_enabled(u, arg_intv(qid))) {
		unvme_pr_err("failed to create cq (qid=%u) (exists)\n", arg_intv(qid));
		ret = EEXIST;
		goto usq;
	}

	ucq = unvmed_init_cq(u, arg_intv(qid), arg_intv(qsize), arg_intv(vector));
	if (!ucq) {
		unvme_pr_err("failed to configure and initialize I/O CQ\n");
		ret = errno;
		goto usq;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto ucq;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto ucq;
	}

	if (unvmed_cmd_prep_create_cq(cmd, u, arg_intv(qid), arg_intv(qsize),
				      arg_intv(vector)) < 0) {
		unvme_pr_err("failed to prepare Create I/O Completion Queue command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (ret || !nvme_cqe_ok(&cmd->cqe)) {
		unvme_pr_err("failed to create iocq\n");
		ret = EINVAL;
		goto cmd;
	}

	unvmed_enable_cq(ucq);

cmd:
	unvmed_cmd_put(cmd);
ucq:
	if (ret)
		unvmed_free_cq(u, arg_intv(qid));
usq:
	unvmed_sq_put(u, usq);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_delete_iocq(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *qid;
	struct arg_lit *verbose;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit a Delete I/O Completion Queue admin command to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		qid = arg_int1("q", "qid", "<n>", "[M] Completion Queue ID to delete"),
		verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	struct unvme_sq *usq;
	struct unvme_cq *ucq;
	struct unvme_cmd *cmd;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_get(u, 0);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	ucq = unvmed_cq_get(u, arg_intv(qid));
	if (!ucq) {
		unvme_pr_err("failed to get target cq %d\n", arg_intv(qid));

		ret = ENOMEDIUM;
		goto usq;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto ucq;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto ucq;
	}

	if (unvmed_cmd_prep_delete_cq(cmd, arg_intv(qid)) < 0) {
		unvme_pr_err("failed to prepare Delete I/O Completion Queue command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!nvme_cqe_ok(&cmd->cqe)) {
		unvme_pr_err("failed to delete iocq\n");
		ret = EINVAL;
	} else {
		if (unvmed_free_cq(u, arg_intv(qid))) {
			unvme_pr_err("failed to delete iocq in libunvmed\n");
			ret = errno;
		}
	}

cmd:
	unvmed_cmd_put(cmd);
ucq:
	unvmed_cq_put(u, ucq);
usq:
	unvmed_sq_put(u, usq);
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
	struct arg_lit *verbose;
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
		verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	struct unvme_sq *usq, *targetq;
	struct unvme_cq *ucq;
	struct unvme_cmd *cmd;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_get(u, 0);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	targetq = unvmed_sq_get(u, arg_intv(qid));
	if (unvmed_sq_enabled(targetq)) {
		unvme_pr_err("failed to create iosq (qid=%u) (exists)\n", arg_intv(qid));
		unvmed_sq_put(u, targetq);
		ret = EEXIST;
		goto usq;
	}

	ucq = unvmed_cq_get(u, arg_intv(cqid));
	if (!ucq) {
		unvme_pr_err("failed to find cq (cqid=%u)\n", arg_intv(cqid));
		ret = ENODEV;
		goto usq;
	}

	targetq = unvmed_init_sq(u, arg_intv(qid), arg_intv(qsize), arg_intv(cqid));
	if (!targetq) {
		unvme_pr_err("failed to configure and initialize io submission queue\n");
		ret = errno;
		goto ucq;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto ucq;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto free;
	}

	cmd->flags = UNVMED_CMD_F_WAKEUP_ON_CQE;

	if (unvmed_cmd_prep_create_sq(cmd, u, arg_intv(qid), arg_intv(qsize),
				      arg_intv(cqid)) < 0) {
		unvme_pr_err("failed to prepare Create I/O Submission Queue command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!nvme_cqe_ok(&cmd->cqe)) {
		unvme_pr_err("failed to create iosq\n");
		ret = EINVAL;
		goto cmd;
	}

	unvmed_enable_sq(targetq);

cmd:
	unvmed_cmd_put(cmd);
free:
	if (ret)
		unvmed_free_sq(u, arg_intv(qid));
ucq:
	unvmed_cq_put(u, ucq);
usq:
	unvmed_sq_put(u, usq);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_delete_iosq(int argc, char *argv[], struct unvme_msg *msg)
{
	struct unvme *u;
	struct arg_rex *dev;
	struct arg_int *qid;
	struct arg_lit *verbose;
	struct arg_lit *nodb;
	struct arg_lit *help;
	struct arg_end *end;
	const char *desc =
		"Submit a Delete I/O Submission Queue admin command\n"
		"to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		qid = arg_int1("q", "qid", "<n>", "[M] Submission Queue ID to delete"),
		verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion"),
		nodb = arg_lit0("N", "nodb", "[O] Don't update tail doorbell of the submission queue"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};
	struct unvme_sq *usq, *targetq;
	struct unvme_cmd *cmd;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_get(u, 0);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	targetq = unvmed_sq_get(u, arg_intv(qid));
	if (!targetq) {
		unvme_pr_err("failed to delete iosq (qid=%u) (not exists)\n", arg_intv(qid));
		ret = ENOMEDIUM;
		goto usq;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto targetq;
	}

	cmd->flags = UNVMED_CMD_F_WAKEUP_ON_CQE;

	if (arg_boolv(nodb))
		cmd->flags |= UNVMED_CMD_F_NODB;

	if (unvmed_cmd_prep_delete_sq(cmd, arg_intv(qid)) < 0) {
		unvme_pr_err("failed to prepare Delete I/O Submission Queue command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!nvme_cqe_ok(&cmd->cqe)) {
		unvme_pr_err("failed to delete iosq\n");
		ret = EINVAL;
	} else {
		if (unvmed_free_sq(u, arg_intv(qid))) {
			unvme_pr_err("failed to delete iosq in libunvmed\n");
			ret = errno;
		}
	}

cmd:
	unvmed_cmd_put(cmd);
targetq:
	unvmed_sq_put(u, targetq);
usq:
	unvmed_sq_put(u, usq);
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
	struct arg_lit *verbose;
	struct arg_lit *nodb;
	struct arg_lit *help;
	struct arg_end *end;
	const char *desc =
		"Submit an Identify Namespace admin command to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nsid = arg_dbl1("n", "nsid", "<n>", "[M] Namespace ID"),
		prp1_offset = arg_int0(NULL, "prp1-offset", "<n>", "[O] PRP1 offset < CC.MPS (default: 0x0)"),
		format = arg_str0("o", "output-format", "[normal|json|binary]", "[O] Output format: [normal|json|binary] (defaults: normal)"),
		verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion"),
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
	struct iovec iov;
	int ret;

	/* Set default argument values prior to parsing */
	arg_strv(format) = "normal";
	arg_intv(prp1_offset) = 0x0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	if (arg_validate_format(arg_strv(format), 3, "normal", "json", "binary")) {
		unvme_pr_err("invalid -o|--output-format=%s\n", arg_strv(format));
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_intv(prp1_offset) >= getpagesize()) {
		unvme_pr_err("invalid --prp1-offset\n");
		ret = EINVAL;
		goto out;
	}

	/* allocate a buffer with a consieration of --prp1-offset=<n> */
	len = pgmap(&buf, size + (getpagesize() - arg_intv(prp1_offset)));
	if (len < 0) {
		unvme_pr_err("failed to allocate user data buffer\n");
		ret = errno;
		goto out;
	}

	buf += arg_intv(prp1_offset);

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto buf;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	if (arg_boolv(nodb))
		cmd->flags |= UNVMED_CMD_F_NODB;

	if (unvmed_cmd_prep_id_ns(cmd, arg_dblv(nsid), &iov, 1) < 0) {
		unvme_pr_err("failed to prepare Identify Namespace command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret) {
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_ns);

		if (unvmed_init_ns(u, arg_dblv(nsid), buf)) {
			unvme_pr_err("failed to initialize ns instance\n");
			ret = errno;
		}
	} else if (ret < 0)
		unvme_pr_err("failed to identify namespace\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
buf:
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
	struct arg_str *format = arg_str0("o", "output-format", "[normal|json|binary]", "[O] Output format: [normal|json|binary] (defaults: normal)");
	struct arg_lit *verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion");
	struct arg_lit *nodb = arg_lit0("N", "nodb", "[O] Don't update tail doorbell of the submission queue");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, prp1_offset, vendor_specific, format, verbose, nodb, help, end};

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
	arg_intv(prp1_offset) = 0x0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	if (arg_validate_format(arg_strv(format), 3, "normal", "json", "binary")) {
		unvme_pr_err("invalid -o|--output-format=%s\n", arg_strv(format));
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_intv(prp1_offset) >= getpagesize()) {
		unvme_pr_err("invalid --prp1-offset\n");
		ret = EINVAL;
		goto out;
	}

	/* allocate a buffer with a consieration of --prp1-offset=<n> */
	len = pgmap(&buf, size + (getpagesize() - arg_intv(prp1_offset)));
	if (len < 0) {
		unvme_pr_err("failed to allocate user data buffer\n");
		ret = errno;
		goto out;
	}

	buf += arg_intv(prp1_offset);

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto buf;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	if (arg_boolv(nodb))
		cmd->flags |= UNVMED_CMD_F_NODB;

	if (unvmed_cmd_prep_id_ctrl(cmd, &iov, 1) < 0) {
		unvme_pr_err("failed to prepare Identify Controller command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret) {
		unvmed_init_id_ctrl(u, buf);
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_ctrl);
	} else if (ret < 0)
		unvme_pr_err("failed to identify namespace\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
buf:
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
	struct arg_lit *verbose;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit an Identify Active Namespace List admin command to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nsid = arg_dbl0("n", "nsid", "<n>", "[O] Starting NSID for retrieving active NS with NSID greater than this (default: 0)"),
		prp1_offset = arg_int0(NULL, "prp1-offset", "<n>", "[O] PRP1 offset < CC.MPS (default: 0x0)"),
		format = arg_str0("o", "output-format", "[normal|json|binary]", "[O] Output format: [normal|json|binary] (defaults: normal)"),
		verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion"),
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

	if (arg_validate_format(arg_strv(format), 3, "normal", "json", "binary")) {
		unvme_pr_err("invalid -o|--output-format=%s\n", arg_strv(format));
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
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

	buf += arg_intv(prp1_offset);

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto buf;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	if (unvmed_cmd_prep_id_active_nslist(cmd, arg_dblv(nsid), &iov, 1) < 0) {
		unvme_pr_err("failed to prepare Identify Active NS List command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret)
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_active_nslist);
	else if (ret < 0)
		unvme_pr_err("failed to identify active namespace list\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
buf:
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
	struct arg_lit *verbose;
	struct arg_lit *help;
	struct arg_end *end;

	const char *desc =
		"Submit an Identify Namespace NVM Command Set command to the target <device>.";

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		nsid = arg_dbl1("n", "nsid", "<n>", "[M] Namespace ID"),
		prp1_offset = arg_int0(NULL, "prp1-offset", "<n>", "[O] PRP1 offset < CC.MPS (default: 0x0)"),
		format = arg_str0("o", "output-format", "[normal|json|binary]", "[O] Output format: [normal|json|binary] (defaults: normal)"),
		verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion"),
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

	if (arg_validate_format(arg_strv(format), 3, "normal", "json", "binary")) {
		unvme_pr_err("invalid -o|--output-format=%s\n", arg_strv(format));
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
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

	buf += arg_intv(prp1_offset);

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto buf;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	if (unvmed_cmd_prep_nvm_id_ns(cmd, arg_dblv(nsid), &iov, 1) < 0) {
		unvme_pr_err("failed to prepare NVM Identify Namespace command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret) {
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_nvm_id_ns);

		if (unvmed_init_meta_ns(u, arg_dblv(nsid), buf)) {
			unvme_pr_err("failed to initialize meta info");
			ret = errno;
		}
	} else if (ret < 0)
		unvme_pr_err("failed to NVM identify namespace\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
buf:
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
	struct arg_lit *verbose = arg_lit0("v", "verbose",		"[O] Print command instance verbosely in stderr after completion");
	struct arg_lit *help = arg_lit0("h", "help",			"Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, nsid, fid, save, cdw11, cdw12, data, data_size, verbose, help, end};

	__unvme_free char *filepath = NULL;
	const uint32_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
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

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	if (arg_boolv(data)) {
		if (!arg_boolv(data_size) || !arg_intv(data_size)) {
			unvme_pr_err("invalid -z|--data-size\n");
			unvmed_sq_exit(usq);
			ret = EINVAL;
			goto usq;
		}

		len = pgmap(&buf, arg_intv(data_size));
		if (len < 0) {
			unvme_pr_err("failed to allocate buffer\n");
			unvmed_sq_exit(usq);
			ret = errno;
			goto usq;
		}

		filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(data));
		if (unvme_read_file(filepath, buf, arg_intv(data_size))) {
			unvme_pr_err("failed to read file %s\n", filepath);

			pgunmap(buf, len);
			unvmed_sq_exit(usq);
			ret = ENOENT;
			goto usq;
		}

		cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");

			pgunmap(buf, len);
			unvmed_sq_exit(usq);
			ret = errno;
			goto usq;
		}

		iov = (struct iovec) {
			.iov_base = buf,
			.iov_len = arg_intv(data_size),
		};

	} else {
		cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");
			unvmed_sq_exit(usq);
			ret = errno;
			goto usq;
		}
	}

	if (unvmed_cmd_prep_set_features(cmd, arg_dblv(nsid), arg_intv(fid),
			arg_boolv(save), arg_dblv(cdw11), arg_dblv(cdw12),
			&iov, arg_intv(data_size) > 0 ? 1 : 0) < 0) {
		unvme_pr_err("failed to prepare Set Features command\n");

		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret) {
		unvme_pr("dw0: %#x\n", le32_to_cpu(cmd->cqe.dw0));
		unvme_pr("dw1: %#x\n", le32_to_cpu(cmd->cqe.dw1));
	} else if (ret < 0)
		unvme_pr_err("failed to set-features\n");

cmd:
	unvmed_cmd_put(cmd);
	if (buf && len)
		pgunmap(buf, len);
usq:
	unvmed_sq_put(u, usq);
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
	struct arg_str *format = arg_str0("o", "output-format", "[normal|json]", "[O] Output format: [normal|json] (defaults: normal)");
	struct arg_lit *verbose = arg_lit0("v", "verbose",		"[O] Print command instance verbosely in stderr after completion");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, nsqr, ncqr, format, verbose, help, end};

	const uint32_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
	struct unvme *u;
	uint32_t cdw11;
	int ret;

	arg_strv(format) = "normal";

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	if (arg_validate_format(arg_strv(format), 2, "normal", "json")) {
		unvme_pr_err("invalid -o|--output-format=%s\n", arg_strv(format));
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	cdw11 = arg_intv(ncqr) << 16 | arg_intv(nsqr);

	if (unvmed_cmd_prep_set_features(cmd, 0 /* nsid */, NVME_FEAT_FID_NUM_QUEUES,
			0 /* save */, cdw11, 0 /* cdw12 */, NULL /* iov */,
			0 /* nr_iov */) < 0) {
		unvme_pr_err("failed to prepare Set Features command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret)
		unvme_pr_get_features_noq(arg_strv(format), le32_to_cpu(cmd->cqe.dw0));
	else if (ret < 0)
		unvme_pr_err("failed to set-features-noq\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_set_features_hmb(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Submit a Set Features admin command to the given <device> NVMe controller\n"
		"to enable Host Memory Buffer.";

	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_lit *enable = arg_lit0(NULL, "enable", "[O] Enable HMB (EHM=1)");
	struct arg_lit *disable = arg_lit0(NULL, "disable", "[O] Disable HMB (EHM=0)");
	struct arg_int *hsize = arg_int1("h", "hsize", "<n>", "[M] Host Memory Buffer size in MPS unit");
	struct arg_dbl *descs = arg_dbl1("d", "desc", "<n>", "[M] Host Memory Buffer descriptor list address");
	struct arg_int *nr_descs = arg_int1("n", "nr-descs", "<n>", "[M] Number of HMB descriptor list entries");
	struct arg_lit *mr = arg_lit0("m", "mr", "[O] MR(Memory Return)");
	struct arg_lit *verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, enable, disable, hsize, descs, nr_descs, mr, verbose, help, end};

	struct unvme_cmd *cmd;
	struct unvme_sq *usq;
	struct unvme *u;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	if ((!arg_boolv(enable) && !arg_boolv(disable)) ||
			(arg_boolv(enable) && arg_boolv(disable))) {
		unvme_pr_err("either --enable or --disable should be given\n");
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (arg_boolv(enable) && !unvmed_hmb_allocated(u)) {
		unvme_pr_err("Host Memory Buffer has not been allocated yet\n");
		ret = EINVAL;
		goto out;
	}

	usq = unvmed_sq_get(u, 0);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	if (unvmed_cmd_prep_set_features_hmb(cmd, arg_intv(hsize),
				arg_dblv(descs), arg_intv(nr_descs),
				arg_boolv(mr), arg_boolv(enable)) < 0) {
		unvme_pr_err("failed to prepare Set Features HMB command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret)
		unvme_pr("dw0: %#x\n", le32_to_cpu(cmd->cqe.dw0));
	else if (ret < 0)
		unvme_pr_err("failed to set-features\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
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
	struct arg_lit *verbose = arg_lit0("v", "verbose",		"[O] Print command instance verbosely in stderr after completion");
	struct arg_lit *help = arg_lit0("h", "help",			"Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, nsid, fid, sel, data, data_size, cdw11, cdw14, verbose, help, end};

	__unvme_free char *filepath = NULL;
	const uint32_t sqid = 0;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq = NULL;
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

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	if (arg_boolv(data_size)) {
		len = pgmap(&buf, arg_intv(data_size));
		if (len < 0) {
			unvme_pr_err("failed to allocate buffer\n");

			unvmed_sq_exit(usq);
			ret = errno;
			goto usq;
		}

		cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");

			pgunmap(buf, len);
			unvmed_sq_exit(usq);
			ret = errno;
			goto usq;
		}

		iov = (struct iovec) {
			.iov_base = buf,
			.iov_len = arg_intv(data_size),
		};

	} else {
		cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");

			unvmed_sq_exit(usq);
			ret = errno;
			goto usq;
		}
	}

	if (unvmed_cmd_prep_get_features(cmd, arg_dblv(nsid), arg_intv(fid),
			arg_boolv(sel), arg_dblv(cdw11), arg_dblv(cdw14), &iov,
			arg_intv(data_size) > 0 ? 1 : 0) < 0) {
		unvme_pr_err("failed to prepare Get Features command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret) {
		unvme_pr("dw0: %#x\n", le32_to_cpu(cmd->cqe.dw0));
		unvme_pr("dw1: %#x\n", le32_to_cpu(cmd->cqe.dw1));

		if (arg_boolv(data_size)) {
			if (arg_boolv(data)) {
				filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(data));
				unvme_write_file(filepath, buf, arg_intv(data_size));
			} else
				unvme_pr_raw(buf, arg_intv(data_size));
		}
	} else if (ret < 0)
		unvme_pr_err("failed to get-features\n");

cmd:
	unvmed_cmd_put(cmd);
	if (buf && len)
		pgunmap(buf, len);
usq:
	unvmed_sq_put(u, usq);
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
	struct arg_lit *verbose;
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
		verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion"),
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

	usq = unvmed_sq_get(u, arg_intv(sqid));
	if (!usq) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(prp1_offset) >= getpagesize()) {
		unvme_pr_err("invalid --prp1-offset\n");
		ret = EINVAL;
		goto usq;
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
		goto usq;
	}

	size = arg_intv(data_size);
	if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_EXTENDED)
		size += arg_intv(metadata_size);

	len = pgmap(&buf, size + (getpagesize() - arg_intv(prp1_offset)));
	if (len < 0) {
		unvme_pr_err("failed to allocate buffer\n");
		ret = errno;
		goto usq;
	}

	if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_SEPARATE) {
		mlen = pgmap(&mbuf, arg_intv(metadata_size));
		if (mlen < 0) {
			unvme_pr_err("failed to allocate meta buffer\n");
			ret = errno;
			goto buf;
		}
	}

	if (arg_boolv(data))
		filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(data));
	if (arg_boolv(metadata))
		mfilepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(metadata));

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto mbuf;
	}

	cmd = unvmed_alloc_cmd_meta(u, usq, NULL, buf, len, mbuf, mlen);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto mbuf;
	}

	if (arg_boolv(sgl))
		cmd->flags |= UNVMED_CMD_F_SGL;
	if (arg_boolv(nodb))
		cmd->flags |= UNVMED_CMD_F_NODB;

	buf += arg_intv(prp1_offset);

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_SEPARATE)
		mbuf += arg_intv(prp1_offset);

	if (unvmed_cmd_prep_read(cmd, arg_dblv(nsid), arg_dblv(slba), arg_intv(nlb),
			arg_intv(prinfo), arg_intv(atag), arg_intv(atag_mask),
			arg_intv(rtag), arg_intv(stag), arg_boolv(stag_check),
			&iov, 1, mbuf, NULL) < 0) {
		unvme_pr_err("failed to prepare Read Namespace command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

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
			unvme_pr_raw(rdata, arg_intv(data_size));
		else
			unvme_write_file(filepath, rdata, arg_intv(data_size));

		free(rdata);
	} else if (ret < 0)
		unvme_pr_err("failed to read\n");

cmd:
	unvmed_cmd_put(cmd);
mbuf:
	if (arg_intv(metadata_size) && ns->mset == NVME_FORMAT_MSET_SEPARATE)
		pgunmap(mbuf - arg_intv(prp1_offset), mlen);
buf:
	pgunmap(buf - arg_intv(prp1_offset), len);
usq:
	unvmed_sq_put(u, usq);
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
	struct arg_lit *verbose;
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
		verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion"),
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

	usq = unvmed_sq_get(u, arg_intv(sqid));
	if (!usq) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	if (arg_intv(prp1_offset) >= getpagesize()) {
		unvme_pr_err("invalid --prp1-offset\n");
		ret = EINVAL;
		goto usq;
	}

	if (arg_intv(metadata_size) && !arg_boolv(metadata)) {
		unvme_pr_err("-M <input> is needed for metadata\n");
		ret = EINVAL;
		goto usq;
	}

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
		goto usq;
	}

	__buf = buf + arg_intv(prp1_offset);

	wdata = malloc(arg_intv(data_size));

	if (unvme_read_file(filepath, wdata, arg_intv(data_size))) {
		unvme_pr_err("failed to read file %s\n", filepath);
		ret = ENOENT;
		goto buf;
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
			goto buf;
		}

		if (ns->mset == NVME_FORMAT_MSET_SEPARATE) {
			mlen = pgmap(&mbuf, arg_intv(metadata_size) +
					(getpagesize() - arg_intv(prp1_offset)));
			if (mlen < 0) {
				unvme_pr_err("failed to allocate meta buffer\n");
				ret = errno;
				goto buf;
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

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto mbuf;
	}

	cmd = unvmed_alloc_cmd_meta(u, usq, NULL, buf, len, mbuf, mlen);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto mbuf;
	}

	if (arg_boolv(sgl))
		cmd->flags |= UNVMED_CMD_F_SGL;
	if (arg_boolv(nodb))
		cmd->flags |= UNVMED_CMD_F_NODB;

	iov = (struct iovec) {
		.iov_base = __buf,
		.iov_len = size,
	};

	if (unvmed_cmd_prep_write(cmd, arg_dblv(nsid), arg_dblv(slba), arg_intv(nlb),
			arg_intv(prinfo), arg_intv(atag), arg_intv(atag_mask),
			arg_intv(rtag), arg_intv(stag), arg_boolv(stag_check),
			&iov, 1, __mbuf, NULL) < 0) {
		unvme_pr_err("failed to prepare Identify Namespace command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (ret < 0)
		unvme_pr_err("failed to write\n");

cmd:
	unvmed_cmd_put(cmd);
mbuf:

	if (arg_intv(metadata_size)) {
		free(wmdata);
		if (ns->mset == NVME_FORMAT_MSET_SEPARATE)
			pgunmap(mbuf - arg_intv(prp1_offset), mlen);
	}
buf:
	pgunmap(buf - arg_intv(prp1_offset), len);
	free(wdata);
usq:
	unvmed_sq_put(u, usq);
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
	struct arg_int *cid;
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
	struct arg_lit *verbose;
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
		cid = arg_int0("c", "cid", "<n>", "[O] Command ID (default: automatically allocated)"),
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
		verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion"),
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
	bool _write = false;
	bool _read = false;
	union nvme_cmd sqe = {0, };
	uint16_t __cid;
	uint16_t *__cidp = NULL;
	int ret;

	arg_intv(cid) = 0;
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

	usq = unvmed_sq_get(u, arg_intv(sqid));
	if (!usq) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	/*
	 * If --data-len= argument is given with either --prp1= or --prp2=,
	 * return error since --data-len= value is just to read or write the
	 * DMA buffer data within libunvmed, not user-defined DMA buffers.
	 *
	 * If user wants to fill up or write the data, --data-len=0 should be
	 * given with user-defined memory buffers to --prp1= and --prp2=.
	 */
	if ((arg_boolv(prp1) || arg_boolv(prp2)) && arg_intv(data_len) > 0) {
		unvme_pr_err("If either --prp1= or --prp2= is given, --data-len= "
				"should not be given\n");
		ret = EINVAL;
		goto usq;
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

	/*
	 * If @cid is given, put the proper pointer to @__cidp to let libunvmed
	 * knows that a specific CID has been given by user, otherwise NULL
	 * will be given.
	 */
	if (arg_boolv(cid)) {
		__cid = arg_intv(cid);
		__cidp = &__cid;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	/*
	 * If --prp1 and --prp2 both are not given, libunvmed will take care of
	 * the DMA buffers.
	 */
	if ((!arg_boolv(prp1) && !arg_boolv(prp2)) && arg_intv(data_len) > 0) {
		len = pgmap(&buf, arg_intv(data_len));
		if (len < 0) {
			unvme_pr_err("failed to allocate buffer\n");

			unvmed_sq_exit(usq);
			ret = errno;
			goto usq;
		}

		cmd = unvmed_alloc_cmd(u, usq, __cidp, buf, len);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");

			unvmed_sq_exit(usq);
			ret = errno;
			goto buf;
		}

		if (_write) {
			filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(input));
			if (unvme_read_file(filepath, buf, arg_intv(data_len))) {
				unvme_pr_err("failed to read file %s\n", filepath);

				unvmed_sq_exit(usq);
				ret = ENOENT;
				goto cmd;
			}
		}

		iov = (struct iovec) {
			.iov_base = buf,
			.iov_len = arg_intv(data_len),
		};

	} else {
		cmd = unvmed_alloc_cmd_nodata(u, usq, __cidp);
		if (!cmd) {
			unvme_pr_err("failed to allocate a command instance\n");

			unvmed_sq_exit(usq);
			ret = errno;
			goto usq;
		}
	}

	sqe.cid = cmd->cid;
	sqe.opcode = (uint8_t)arg_intv(opcode);
	sqe.flags = (uint8_t)arg_intv(flags);
	sqe.nsid = cpu_to_le32(arg_dblv(nsid));
	sqe.cdw2 = cpu_to_le32(arg_dblv(cdw2));
	sqe.cdw3 = cpu_to_le32(arg_dblv(cdw3));

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
		unvmed_sq_exit(usq);
		ret = 0;
		goto cmd;
	}

	if (arg_boolv(nodb))
		cmd->flags |= UNVMED_CMD_F_NODB;

	if (unvmed_cmd_prep(cmd, &sqe, &iov, arg_intv(data_len) > 0 ? 1 : 0) < 0) {
		unvme_pr_err("failed to prepare a command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	/*
	 * Override prp1 and prp2 if they are given to inject specific values
	 */
	if (arg_boolv(prp1))
		cmd->sqe.dptr.prp1 = cpu_to_le64((uint64_t)arg_dblv(prp1));
	if (arg_boolv(prp2))
		cmd->sqe.dptr.prp2 = cpu_to_le64((uint64_t)arg_dblv(prp2));

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret) {
		if (arg_boolv(data_len) && _read)
			unvme_pr_raw(buf, arg_intv(data_len));
	} else if (ret < 0)
		unvme_pr_err("failed to passthru\n");

cmd:
	unvmed_cmd_put(cmd);
buf:
	if (buf && len)
		pgunmap(buf, len);
usq:
	unvmed_sq_put(u, usq);
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

	__unvme_free struct unvme_cmd **cmds = NULL;
	struct unvme_sq *usq;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_get(u, arg_intv(sqid));
	if (!usq) {
		unvme_pr_err("failed to get iosq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	unvmed_sq_update_tail(u, usq);
	unvmed_sq_exit(usq);
usq:
	unvmed_sq_put(u, usq);
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
	struct arg_lit *verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, nsid, lbaf, ses, pil, pi, mset, verbose, help, end};

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

	if (!arg_boolv(lbaf)) {
		struct unvme_ns *ns = unvmed_ns_get(u, arg_dblv(nsid));
		if (ns) {
			arg_intv(lbaf) = ns->format_idx;
			unvmed_ns_put(u, ns);
		} else {
			unvme_pr_err("failed to get a namespace instance\n");
			ret = EINVAL;
			goto out;
		}
	}

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	if (unvmed_cmd_prep_format(cmd, arg_dblv(nsid), arg_intv(lbaf),
			arg_intv(ses), arg_intv(pil), arg_intv(pi),
			arg_intv(mset)) < 0) {
		unvme_pr_err("failed to prepare Format command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

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
	} else if (ret < 0)
		unvme_pr_err("failed to format NVM\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
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

	if (!unvmed_ctrl_enabled(u)) {
		unvme_pr_err("%s is already disabled\n", arg_strv(dev));
		ret = 0;
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
	uint64_t cap;
	int ret;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	/* Check if subsystem reset is supported in CAP.NSSRS */
	cap = unvmed_read64(u, NVME_REG_CAP);
	if (!(NVME_CAP_NSSRC(cap))) {
		unvme_pr_err("NVM subsystem reset is not supported\n");
		ret = EINVAL;
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
	if (ret) {
		unvme_pr_err("failed to flr\n");
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
	if (ret) {
		unvme_pr_err("failed to hot reset\n");
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
	if (ret) {
		unvme_pr_err("failed to link disable\n");
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
	struct arg_lit *verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);

	void *argtable[] = {dev, cntlid, rt, act, nr, verbose, help, end};

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

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	if (unvmed_cmd_prep_virt_mgmt(cmd, arg_intv(cntlid), arg_intv(rt),
			arg_intv(act), arg_intv(nr)) < 0 ) {
		unvme_pr_err("failed to prepare Virtualization Mgmt. command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}


	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (ret < 0)
		unvme_pr_err("failed to submit virt-mgmt command\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
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
	struct arg_str *format = arg_str0("o", "output-format", "[normal|json|binary]", "[O] Output format: [normal|json|binary] (defaults: normal)");
	struct arg_lit *verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, cntlid, format, verbose, help, end};

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

	if (arg_validate_format(arg_strv(format), 3, "normal", "json", "binary")) {
		unvme_pr_err("invalid -o|--output-format=%s\n", arg_strv(format));
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	len = pgmap(&buf, size + getpagesize());
	if (len < 0) {
		unvme_pr_err("failed to allocate user data buffer\n");
		ret = errno;
		goto out;
	}

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto buf;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	if (unvmed_cmd_prep_id_primary_ctrl_caps(cmd, &iov, 1, arg_intv(cntlid)) < 0) {
		unvme_pr_err("failed to prepare Identify Primary Controller command\n");

		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret)
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_primary_ctrl_caps);
	else if (ret < 0)
		unvme_pr_err("failed to identify primary controller capabilities\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
buf:
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
	struct arg_str *format = arg_str0("o", "output-format", "[normal|json|binary]", "[O] Output format: [normal|json|binary] (defaults: normal)");
	struct arg_lit *verbose = arg_lit0("v", "verbose", "[O] Print command instance verbosely in stderr after completion");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = {dev, cntlid, format, verbose, help, end};

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

	if (arg_validate_format(arg_strv(format), 3, "normal", "json", "binary")) {
		unvme_pr_err("invalid -o|--output-format=%s\n", arg_strv(format));
		ret = EINVAL;
		goto out;
	}

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	len = pgmap(&buf, size + getpagesize());
	if (len < 0) {
		unvme_pr_err("failed to allocate user data buffer\n");
		ret = errno;
		goto out;
	}

	usq = unvmed_sq_get(u, sqid);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto buf;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	if (unvmed_cmd_prep_id_secondary_ctrl_list(cmd, &iov, 1, arg_intv(cntlid)) < 0) {
		unvme_pr_err("failed to prepare Identify Secondary Controller command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret)
		__unvme_cmd_pr(arg_strv(format), buf, size, unvme_pr_id_secondary_ctrl_list);
	else if (ret < 0)
		unvme_pr_err("failed to identify secondary controller list\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
buf:
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

int unvme_malloc(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc = "Allocate a I/O buffer for the given size";
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_int *size = arg_int1("s", "size", "<n>", "[M] Size in bytes to allocate");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = { dev, size, help, end };

	struct iommu_dmabuf *buf;
	struct unvme *u;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	buf = unvmed_mem_alloc(u, arg_intv(size));
	if (!buf) {
		unvme_pr_err("failed to allocate an I/O memory buffer\n");
		ret = errno;
		goto out;
	}

	unvme_pr_buf(buf);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_mfree(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc = "Free a I/O buffer for the given address";
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_dbl *iova = arg_dbl1("i", "iova", "<n>", "[M] I/O virtual address");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = { dev, iova, help, end };

	struct unvme *u;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	if (unvmed_mem_free(u, arg_dblv(iova)) < 0) {
		unvme_pr_err("failed to free an I/O memory buffer\n");
		ret = errno;
		goto out;
	}

out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_mread(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc = "Read I/O buffer of the given address";
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_dbl *iova = arg_dbl1("i", "iova", "<n>", "[M] I/O virtual address");
	struct arg_int *size = arg_int1("s", "size", "<n>", "[M] Size to read in bytes");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = { dev, iova, size, help, end };

	struct unvme *u;
	ssize_t len;
	void *buf;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	len = unvmed_to_vaddr(u, arg_dblv(iova), &buf);
	if (len < 0) {
		unvme_pr_err("failed to get I/O buffer\n");
		ret = errno;
		goto out;
	}

	if (arg_intv(size) > len) {
		unvme_pr_err("adjust --size=%d to %ld\n", arg_intv(size), len);
		arg_intv(size) = len;
	}

	unvme_pr_raw(buf, arg_intv(size));
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_mwrite(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc = "Write data to I/O buffer";
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");
	struct arg_dbl *iova = arg_dbl1("i", "iova", "<n>", "[M] I/O virtual address");
	struct arg_int *size = arg_int1("s", "size", "<n>", "[M] Size to read in bytes");
	struct arg_file *data = arg_file1("d", "data", "<file>", "[M] Write data file");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);
	void *argtable[] = { dev, iova, size, data, help, end };

	__unvme_free char *filepath = NULL;
	struct unvme *u;
	ssize_t len;
	void *fbuf;
	void *buf;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	len = unvmed_to_vaddr(u, arg_dblv(iova), &buf);
	if (len < 0) {
		unvme_pr_err("failed to get I/O buffer\n");
		ret = errno;
		goto out;
	}

	filepath = unvme_get_filepath(unvme_msg_pwd(msg), arg_filev(data));

	if (arg_intv(size) > len) {
		unvme_pr_err("adjust --size=%d to %ld\n",
				arg_intv(size), len);
		arg_intv(size) = len;
	}

	fbuf = malloc(arg_intv(size));
	if (!fbuf) {
		unvme_pr_err("failed to allocate memory buffer\n");
		ret = errno;
		goto out;
	}

	if (unvme_read_file(filepath, fbuf, arg_intv(size))) {
		unvme_pr_err("failed to read data from %s\n", filepath);
		ret = errno;
		goto free;
	}

	memcpy(buf, fbuf, arg_intv(size));
free:
	free(fbuf);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_create_ns(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Create a namespace with the specified parameters.";

	struct unvme *u;
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");

	struct arg_int *csi = arg_int0("y", "csi", "<NUM>", "[O] command set identifier (CSI)");

	/* Identify Namespace data structure */
	struct arg_dbl *nsze = arg_dbl1("s", "nsze", "<IONUM>", "[M] size of ns (NSZE)");
	struct arg_dbl *ncap = arg_dbl1("c", "ncap", "<IONUM>", "[M] capacity of ns (NCAP)");
	struct arg_int *flbas = arg_int1("f", "flbas", "<NUM>", "[M] Formatted LBA size (FLBAS)");
	struct arg_int *dps = arg_int0("d", "dps", "<NUM>", "[O] data protection settings (DPS)");
	struct arg_int *nmic = arg_int0("m", "nmic", "<NUM>", "[O] multipath and sharing capabilities (NMIC)");
	struct arg_int *anagrp_id = arg_int0("a", "anagrp-id", "<NUM>", "[O] ANA Group Identifier (ANAGRPID)");
	struct arg_int *nvmset_id = arg_int0("i", "nvmset-id", "<NUM>", "[O] NVM Set Identifier (NVMSETID)");
	struct arg_int *endg_id = arg_int0("e", "endg-id", "<NUM>", "[O] Endurance Group Identifier (ENDGID)");
	struct arg_dbl *lbstm = arg_dbl0("l", "lbstm", "<IONUM>", "[O] logical block storage tag mask (LBSTM)");

	/* FDP-related attributes */
	struct arg_int *phndls = arg_intn("p", "phndls", "<n>", 0, 128, "[O] Placement Handle Associated RUH, multiple -p|--phndls can be given");

	struct arg_lit *verbose = arg_lit0("v", "verbose", "[O] Print SQE and CQE in stderr");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);

	void *argtable[] = {dev, csi, nsze, ncap, flbas, dps, nmic, anagrp_id,
		nvmset_id, endg_id, lbstm, phndls, verbose, help,
		end};

	const size_t size = sizeof(struct nvme_ns_mgmt_host_sw_specified);
	struct unvme_cmd *cmd;
	struct unvme_sq *usq;
	ssize_t len;
	void *buf = NULL;
	struct iovec iov;
	uint16_t __phndls[128];
	int ret;

	arg_intv(csi) = 0;
	arg_intv(dps) = 0;
	arg_intv(nmic) = 0;
	arg_intv(anagrp_id) = 0;
	arg_intv(nvmset_id) = 0;
	arg_intv(endg_id) = 0;
	arg_dblv(lbstm) = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	len = pgmap(&buf, size);
	if (len < 0) {
		unvme_pr_err("failed to allocate data buffer\n");
		ret = errno;
		goto out;
	}

	usq = unvmed_sq_get(u, 0);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto buf;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	for (int i = 0; i < phndls->count; i++)
		__phndls[i] = (uint16_t)phndls->ival[i];

	if (unvmed_cmd_prep_create_ns(cmd, arg_dblv(nsze), arg_dblv(ncap),
				      arg_intv(flbas), arg_intv(dps),
				      arg_intv(nmic), arg_intv(anagrp_id),
				      arg_intv(nvmset_id), arg_intv(endg_id),
				      arg_intv(csi), arg_dblv(lbstm),
				      phndls->count, __phndls, &iov, 1) < 0) {
		unvme_pr_err("failed to prepare Create Namespace command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret) {
		unvme_pr("{ \"nsid\": %u }\n", le32_to_cpu(cmd->cqe.dw0));
		if (unvmed_init_ns(u, le32_to_cpu(cmd->cqe.dw0), NULL)) {
			unvme_pr_err("failed to initialize ns instance\n");
			ret = errno;
		}
	} else if (ret < 0)
		unvme_pr_err("failed to create namespace\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
buf:
	pgunmap(buf, len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_delete_ns(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Delete the given namespace by sending a namespace management command";

	struct unvme *u;
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");

	struct arg_dbl *nsid = arg_dbl1("n", "nsid", "<n>", "[M] Namespace ID");

	struct arg_lit *verbose = arg_lit0("v", "verbose", "[O] Print SQE and CQE in stderr");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);

	void *argtable[] = {dev, nsid, verbose, help, end};

	struct unvme_cmd *cmd;
	struct unvme_sq *usq;
	int ret;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	usq = unvmed_sq_get(u, 0);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto out;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd_nodata(u, usq, NULL);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	if (unvmed_cmd_prep_delete_ns(cmd, arg_dblv(nsid)) < 0) {
		unvme_pr_err("failed to prepare Delete Namespace command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret) {
		if (unvmed_init_ns(u, arg_dblv(nsid), NULL)) {
			unvme_pr_err("failed to initialize ns instance\n");
			ret = errno;
		}
	} else if (ret < 0)
		unvme_pr_err("failed to delete namespace\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_attach_ns(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Attach the given namespace to one or more given controller(s)";

	struct unvme *u;
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");

	struct arg_dbl *nsid = arg_dbl1("n", "nsid", "<n>", "[M] Namespace ID");
	struct arg_int *ctrlids = arg_intn("c", "controllers", "<n>", 0, 2047, "[O] One or more controller ids");

	struct arg_lit *verbose = arg_lit0("v", "verbose", "[O] Print SQE and CQE in stderr");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);

	void *argtable[] = {dev, verbose, nsid, ctrlids, help, end};

	const size_t size = 4096;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq;
	uint16_t __ctrlids[2048];
	struct iovec iov;
	void *buf = NULL;
	ssize_t len;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	len = pgmap(&buf, size);
	if (len < 0) {
		unvme_pr_err("failed to allocate data buffer\n");
		ret = errno;
		goto out;
	}

	usq = unvmed_sq_get(u, 0);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto buf;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	for (int i = 0; i < ctrlids->count; i++)
		__ctrlids[i] = (uint16_t)ctrlids->ival[i];

	if (unvmed_cmd_prep_attach_ns(cmd, arg_dblv(nsid), ctrlids->count,
				__ctrlids, &iov, 1) < 0) {
		unvme_pr_err("failed to prepare Attach Namespace command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret) {
		if (unvmed_init_ns(u, arg_dblv(nsid), NULL)) {
			unvme_pr_err("failed to initialize ns instance\n");
			ret = errno;
		}
	} else if (ret < 0)
		unvme_pr_err("failed to attach namespace\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
buf:
	pgunmap(buf, len);
out:
	unvme_free_args(argtable);
	return ret;
}

int unvme_detach_ns(int argc, char *argv[], struct unvme_msg *msg)
{
	const char *desc =
		"Deattach the given namespace from one or more given controller(s)";

	struct unvme *u;
	struct arg_rex *dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf");

	struct arg_dbl *nsid = arg_dbl1("n", "nsid", "<n>", "[M] Namespace ID");
	struct arg_int *ctrlids = arg_intn("c", "controllers", "<n>", 0, 2047, "[O] One or more controller ids");

	struct arg_lit *verbose = arg_lit0("v", "verbose", "[O] Print SQE and CQE in stderr");
	struct arg_lit *help = arg_lit0("h", "help", "Show help message");
	struct arg_end *end = arg_end(UNVME_ARG_MAX_ERROR);

	void *argtable[] = {dev, verbose, nsid, ctrlids, help, end};

	const size_t size = 4096;
	struct unvme_cmd *cmd;
	struct unvme_sq *usq;
	uint16_t __ctrlids[2048];
	struct iovec iov;
	void *buf = NULL;
	ssize_t len;
	int ret = 0;

	unvme_parse_args_locked(argc, argv, argtable, help, end, desc);

	u = unvmed_get(arg_strv(dev));
	if (!u) {
		unvme_pr_err("%s is not added to unvmed\n", arg_strv(dev));
		ret = ENODEV;
		goto out;
	}

	len = pgmap(&buf, size);
	if (len < 0) {
		unvme_pr_err("failed to allocate data buffer\n");
		ret = errno;
		goto out;
	}

	usq = unvmed_sq_get(u, 0);
	if (!usq) {
		unvme_pr_err("failed to get admin sq\n");
		ret = ENOMEDIUM;
		goto buf;
	}

	unvmed_sq_enter(usq);
	if (!unvmed_sq_enabled(usq)) {
		unvme_pr_err("usq(qid=%d) is not enabled", unvmed_sq_id(usq));

		unvmed_sq_exit(usq);
		errno = ENOMEDIUM;
		ret = errno;
		goto usq;
	}

	cmd = unvmed_alloc_cmd(u, usq, NULL, buf, len);
	if (!cmd) {
		unvme_pr_err("failed to allocate a command instance\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto usq;
	}

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = size,
	};

	for (int i = 0; i < ctrlids->count; i++)
		__ctrlids[i] = (uint16_t)ctrlids->ival[i];

	if (unvmed_cmd_prep_detach_ns(cmd, arg_dblv(nsid), ctrlids->count,
				__ctrlids, &iov, 1) < 0) {
		unvme_pr_err("failed to prepare Deattach Namespace command\n");

		unvmed_sq_exit(usq);
		ret = errno;
		goto cmd;
	}

	if (arg_boolv(verbose))
		unvme_pr_sqe(&cmd->sqe);

	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(usq);

	unvmed_cmd_wait(cmd);
	ret = unvmed_cqe_status(&cmd->cqe);

	if ((ret >= 0 && arg_boolv(verbose)) || ret > 0)
		unvme_pr_cqe(&cmd->cqe);

	if (!ret) {
		if (unvmed_init_ns(u, arg_dblv(nsid), NULL)) {
			unvme_pr_err("failed to initialize ns instance\n");
			ret = errno;
		}
	} else if (ret < 0)
		unvme_pr_err("failed to deattach namespace\n");

cmd:
	unvmed_cmd_put(cmd);
usq:
	unvmed_sq_put(u, usq);
buf:
	pgunmap(buf, len);
out:
	unvme_free_args(argtable);
	return ret;
}
