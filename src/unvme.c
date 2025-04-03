// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/ipc.h>

#include <vfn/nvme.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <ccan/build_assert/build_assert.h>

#include "libunvmed.h"
#include "unvme.h"
#include "config.h"

#include <argtable3.h>

/*
 * for async stdio print handlers
 */
static char *__stdout_fname;
static char *__stderr_fname;
static bool __stdio_stop;
static pthread_t __stdio_th[4];
static struct command *__cmd;

static int unvme_help(int argc, char *argv[], struct unvme_msg *msg);
static int unvme_version(int argc, char *argv[], struct unvme_msg *msg);
static struct command cmds[] = {
	{"help",		"Show usage help message",				UNVME_GENERIC_CMD | UNVME_CLIENT_CMD | UNVME_NODEV_CMD,	unvme_help},
	{"version", 		"Show unvme-cli version",				UNVME_GENERIC_CMD | UNVME_CLIENT_CMD | UNVME_NODEV_CMD,	unvme_version},
	{"start",		"Start unvmed daemon process",				UNVME_GENERIC_CMD | UNVME_CLIENT_CMD | UNVME_NODEV_CMD,	unvme_start},
	{"stop",		"Stop unvmed daemon process",				UNVME_GENERIC_CMD | UNVME_CLIENT_CMD | UNVME_NODEV_CMD,	unvme_stop},
	{"log",			"Show logs written by unvmed process",			UNVME_GENERIC_CMD | UNVME_CLIENT_CMD | UNVME_NODEV_CMD,	unvme_log},
	{"list",		"Show NVMe PCIe devices",				UNVME_GENERIC_CMD | UNVME_DAEMON_CMD | UNVME_NODEV_CMD,	unvme_list},
	{"add",			"Add NVMe PCI device to unvmed",			UNVME_GENERIC_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_add},
	{"del",			"Delete NVMe PCI device from unvmed",			UNVME_GENERIC_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_del},
	{"status",		"Show device resource status",				UNVME_DRIVER_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_status},
	{"show-regs",		"Show NVMe controller properties",			UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_show_regs},
	{"enable",		"Enable controller with adminq",			UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_enable},
	{"disable",		"Disable controller",					UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_reset},
	{"cmb",			"Enable controller memory buffer",			UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_cmb},
	{"create-iocq",		"Create I/O Completion Queue",				UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_create_iocq},
	{"delete-iocq",		"Delete I/O Completion Queue",				UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_delete_iocq},
	{"create-iosq",		"Create I/O Submission Queue",				UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_create_iosq},
	{"delete-iosq",		"Delete I/O Submission Queue",				UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_delete_iosq},
	{"id-ns",		"Identify Namespace (CNS 0h)",				UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_id_ns},
	{"id-ctrl",		"Identify Controller (CNS 1h)",				UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_id_ctrl},
	{"id-active-nslist",	"Identify Active Namespace List (CNS 2h)",		UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_id_active_nslist},
	{"nvm-id-ns",		"Identify Namespace NVM (CNS 5h)",			UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_nvm_id_ns},
	{"set-features",	"Set Features",						UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_set_features},
	{"set-features-noq",	"Set Features for Number of Queue (FID 7h)",		UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_set_features_noq},
	{"get-features",	"Get Features",						UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_get_features},
	{"read",		"NVM Read command",					UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_read},
	{"write",		"NVM Write command",					UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_write},
	{"passthru",		"Passthrough command",					UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_passthru},
	{"update-sqdb",		"Update SQ tail doorbell",				UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_update_sqdb},
	{"format",		"Format NVM",						UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_format},
	{"reset",		"Reset NVMe controller",				UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_reset},
	{"virt-mgmt",		"NVM Virtualization Management Command",		UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_virt_mgmt},
	{"primary-ctrl-caps",	"Identify Primary Controller Capability",		UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_id_primary_ctrl_caps},
	{"list-secondary",	"Identify Secondary Controller List",			UNVME_NVME_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_id_secondary_ctrl_list},
	{"perf",		"Microbenchmark for simple read/write with N QD",	UNVME_APP_CMD | UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_perf},
#ifdef UNVME_FIO
	{"fio",			"Run fio built as shared object",			UNVME_APP_CMD | UNVME_DAEMON_CMD | UNVME_NODEV_CMD,	unvme_fio},
#endif
	UNVME_CMDS_END
};

static int unvme_help(int argc, char *argv[], struct unvme_msg *msg)
{
	unvme_pr("Usage: unvme <command> [<device>] [<args>]\n");
	unvme_pr("\n");
	unvme_pr("Submit or trigger a given command to <device>. <device> is a bus-device-func\n"
		 "address of a PCI device (e.g., 0000:01:00.0).  <device> can be found from\n"
		 "'unvme list' command result.\n");

	unvme_pr("\nGeneric Commands:\n");
	for (int i = 0; i < ARRAY_SIZE(cmds) && cmds[i].name; i++) {
		if (cmds[i].ctype & UNVME_GENERIC_CMD)
			unvme_pr("\t%-16s\t%s\n", cmds[i].name, cmds[i].summary);
	}
	unvme_pr("\nNVMe Commands:\n");
	for (int i = 0; i < ARRAY_SIZE(cmds) && cmds[i].name; i++) {
		if (cmds[i].ctype & UNVME_NVME_CMD)
			unvme_pr("\t%-16s\t%s\n", cmds[i].name, cmds[i].summary);
	}
	unvme_pr("\nApp. Commands:\n");
	for (int i = 0; i < ARRAY_SIZE(cmds) && cmds[i].name; i++) {
		if (cmds[i].ctype & UNVME_APP_CMD)
			unvme_pr("\t%-16s\t%s\n", cmds[i].name, cmds[i].summary);
	}


	return 0;
}

static int unvme_version(int argc, char *argv[], struct unvme_msg *msg)
{
#ifdef UNVME_DEBUG
	const char *buildtype = "debug";
#else
	const char *buildtype = "release";
#endif

	unvme_pr("unvme (%s) version %s\n", buildtype, UNVME_VERSION);
	unvme_pr("Dependencies:\n");
	unvme_pr(" - libunvmed version %s\n", LIBUNVMED_VERSION);
#ifdef UNVME_FIO
	unvme_pr(" - libunvmed-ioengine version %s\n", LIBUNVMED_IOENGINE_VERSION);
#endif

	return 0;
}

struct command *unvme_cmds(void)
{
	return cmds;
}

static int unvme_send_msg(struct unvme_msg *msg)
{
	int msgq = unvme_msgq_get(UNVME_MSGQ);

	if (msgq < 0)
		unvme_pr_return(-1, "ERROR: failed to get msgq\n");

	if (unvme_msgq_send(msgq, msg) < 0) {
		if (errno == EIDRM)
			unvme_pr_err("ERROR: failed to send a msg to daemon, "
					"see 'unvme log' for details\n");
	}

	return 0;
}

static int unvme_recv_msg(struct unvme_msg *msg)
{
	int msgq = unvme_msgq_get(UNVME_MSGQ);

	if (msgq < 0)
		unvme_pr_return(-1, "ERROR: failed to get msgq\n");

	if (unvme_msgq_recv(msgq, msg, unvme_msg_pid(msg)) < 0) {
		if (errno == EIDRM)
			unvme_pr_err("ERROR: failed to receive a msg from daemon, "
					"see 'unvme log' for details\n");
	}

	return 0;
}

/*
 *
 */
static int unvme_check_args_devcmd(int argc, char *argv[], char *bdf)
{
	struct arg_rex *dev;
	struct arg_end *end;

	void *argtable[] = {
		dev = arg_rex1(NULL, NULL, UNVME_BDF_PATTERN, "<device>", 0, "[M] Device bdf"),
		end = arg_end(UNVME_ARG_MAX_ERROR),
	};

	const char *devstr;

	arg_parse(argc - 1, &argv[1], argtable);

	if (arg_boolv(dev)) {
		devstr = arg_strv(dev);

		if (unvmed_parse_bdf(devstr, bdf)) {
			unvme_pr_err("Invalid device format '%s'\n", argv[2]);
			return -EINVAL;
		}
		argv[2] = bdf;
	} else {
		/*
		 * We don't have to print help here since daemon will print the
		 * help message.
		 */
		;
	}

	return 0;
}

/*
 * Check the given arguments are valid.
 *
 * Returns: Normally it returns the number of arguments given as a user input
 * which is the same with 'argc', 0 to print out help message as a success
 * case, otherwise, < 0 on error cases.
 *
 */
static int unvme_check_args(int argc, char *argv[], char *bdf)
{
	struct command *cmd;
	int ret;

	if (argc == 1) {
		unvme_help(0, NULL, NULL);
		return 0;
	}

	cmd = unvme_get_cmd(argv[1]);
	if (!cmd)
		unvme_pr_err_return(-EINVAL, "Invalid command '%s'\n",
				argv[1]);

	/*
	 * Check the given <device> is a valid PCI BDF format.
	 */
	if (cmd->ctype & UNVME_DEV_CMD) {
		ret = unvme_check_args_devcmd(argc, argv, bdf);
		if (ret)
			return ret;

	}

	return argc;
}

int unvme_get_daemon_pid(void)
{
	char pid[8] = {};
	ssize_t ret;
	int fd;

	fd = open(UNVME_DAEMON_PID, O_RDONLY);
	if (fd < 0)
		return -EINVAL;

	ret = read(fd, pid, sizeof(pid));
	if (ret < 0)
		return -1;

	return atoi(pid);
}

bool unvme_is_daemon_running(void)
{
	pid_t pid = unvme_get_daemon_pid();

	if (pid < 0)
		return false;

	if (kill(pid, 0))
		return false;

	return true;
}

static void unvme_exit(void)
{
	exit(EXIT_FAILURE);
}

static void __unvme_stdio_init(char **fname, char *filefmt)
{
	pid_t pid = getpid();
	FILE *file;
	int ret;

	ret = asprintf(fname, filefmt, pid);
	if (ret < 0) {
		unvme_pr_err("failed to init stdio (ret=%d)\n", ret);
		goto err;
	}

	if (mkdir("/var/log/unvmed", 0755) < 0 && errno != EEXIST) {
		unvme_pr_err("failed to create /var/log/unvmed dir\n");
		goto err;
	}

	file = fopen(*fname, "w");
	if (!file) {
		unvme_pr_err("failed to create %s\n", *fname);
		goto err;
	}

	fclose(file);
	return;
err:
	if (*fname)
		free(*fname);
	unvme_exit();
}

static void __unvme_stdio_pr(const char *fname, int stdio, bool to_remove)
{
	char buf[256];
	int token = 1;
	ssize_t bytes;
	int fd;

	fd = open(fname, O_RDONLY, 0);
	if (fd < 0)
		return;

	while (token > 0) {
		if (__stdio_stop)
			token--;

		while ((bytes = read(fd, buf, 256)) > 0) {
			if (write(stdio, buf, bytes) < 0) {
				close(fd);
				return;
			}
		}
		usleep(1000);
	}

	close(fd);

	if (to_remove)
		remove(fname);
}

static void *unvme_stdout_handler(void *opaque)
{
	__unvme_stdio_pr(__stdout_fname, STDOUT_FILENO, true);
	pthread_exit(NULL);
}

static void *unvme_stderr_handler(void *opaque)
{
	__unvme_stdio_pr(__stderr_fname, STDERR_FILENO, true);
	pthread_exit(NULL);
}

static void *unvme_app_stdout_handler(void *opaque)
{
	__unvme_stdio_pr(UNVME_DAEMON_STDOUT, STDOUT_FILENO, false);

	if (truncate(UNVME_DAEMON_STDOUT, 0))
		unvme_pr_err("failed to truncate %s\n", UNVME_DAEMON_STDOUT);
	pthread_exit(NULL);
}

static void *unvme_app_stderr_handler(void *opaque)
{
	__unvme_stdio_pr(UNVME_DAEMON_STDERR, STDERR_FILENO, false);

	if (truncate(UNVME_DAEMON_STDERR, 0))
		unvme_pr_err("failed to truncate %s\n", UNVME_DAEMON_STDERR);
	pthread_exit(NULL);
}

static void unvme_stdio_init(bool app_stdio)
{
	__unvme_stdio_init(&__stdout_fname, UNVME_STDOUT);
	__unvme_stdio_init(&__stderr_fname, UNVME_STDERR);

	pthread_create(&__stdio_th[0], NULL, unvme_stdout_handler, NULL);
	pthread_create(&__stdio_th[1], NULL, unvme_stderr_handler, NULL);

	if (app_stdio) {
		pthread_create(&__stdio_th[2], NULL, unvme_app_stdout_handler, NULL);
		pthread_create(&__stdio_th[3], NULL, unvme_app_stderr_handler, NULL);
	}
}

static void unvme_stdio_finish(bool app_stdio)
{
	__stdio_stop = true;

	pthread_join(__stdio_th[0], NULL);
	pthread_join(__stdio_th[1], NULL);

	if (app_stdio) {
		pthread_join(__stdio_th[2], NULL);
		pthread_join(__stdio_th[3], NULL);
	}
}

static void unvme_sigint(int signum)
{
	struct unvme_msg msg = {0, };

	unvme_msg_to_daemon(&msg);
	unvme_msg_signum(&msg) = signum;

	unvme_send_msg(&msg);
	unvme_recv_msg(&msg);
}

static void unvme_cleanup(void)
{
	if (__cmd)
		unvme_stdio_finish(!!(__cmd->ctype & UNVME_APP_CMD));
}

static int unvme_check_ver(void)
{
	char ver[UNVME_VER_STR];
	int fd;

	fd = open(UNVME_DAEMON_VER, O_RDONLY, S_IRUSR);
	if (fd < 0)
		return -1;

	if (read(fd, ver, sizeof(ver)) < 0) {
		close(fd);
		return -1;
	}

	if (strcmp(ver, UNVME_VERSION)) {
		errno = EKEYREJECTED;
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

/*
 * XXX: unvmed-file.c can be used in unvmed and unvme both, until it's renamed
 * to unvme-file.c, declare it temporarily.
 */
int unvme_write_file(const char *abspath, void *buf, size_t len);

static int unvme_msg_init(struct unvme_msg *msg, int argc, char *argv[],
			  const char *bdf, int bdf_len)
{
	const char *dir = "/var/run/unvmed";
	pid_t pid = getpid();
	char buf[UNVME_ARGV_MAXLEN] = {0, };
	int ret;

	if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
		unvme_pr_err("failed to create %s dir\n", dir);
		return -1;
	}

	ret = sprintf(msg->msg.argv_file, "%s/argv-%d", dir, pid);
	if (ret < 0) {
		unvme_pr_err("failed to sprintf for argv file\n");
		return -1;
	}

	unvme_msg_to_daemon(msg);
	msg->msg.argc = argc;
	memcpy(msg->msg.bdf, bdf, bdf_len);
	if (!getcwd(msg->msg.pwd, UNVME_PWD_STRLEN)) {
		unvme_pr_err("failed to set current working dir\n");
		return -1;
	}

	for (int i = 0; i < msg->msg.argc; i++) {
		strcat(buf, argv[i]);
		strcat(buf, "\n");
	}

	if (unvme_write_file(msg->msg.argv_file, buf, sizeof(buf))) {
		unvme_pr_err("failed to write argv to %s\n", msg->msg.argv_file);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct unvme_msg msg = {0, };
	const char *name = argv[1];
	bool app_cmd;
	char bdf[UNVME_BDF_STRLEN];
	int ret;

	/* 'man msgsnd' says msg size should be <= 8192 bytes */
	BUILD_ASSERT(sizeof(msg) <= 8192);

	ret = unvme_check_args(argc, argv, bdf);
	if (ret <= 0) {
		if (ret == -EINVAL)
			unvme_help(0, NULL, NULL);

		return abs(ret);
	}

	__cmd = unvme_get_cmd(name);
	if (!__cmd)
		return 1;

	if (__cmd->ctype & UNVME_CLIENT_CMD)
		return __cmd->func(argc, argv, &msg);

	if (!unvme_is_daemon_running())
		unvme_pr_return(1, "ERROR: unvmed is not running, "
				"please run 'unvme start' first\n");

	/*
	 * Check whether unvmed version is exactly the same with the client's
	 * one.
	 */
	if (unvme_check_ver())
		unvme_pr_return(errno, "ERROR: Mismatch between unvmed and "
				"unvme versions.  Please restart unvmed.\n");

	if (unvme_msg_init(&msg, argc, argv, bdf, sizeof(bdf)))
		return -1;

	atexit(unvme_cleanup);
	signal(SIGINT, unvme_sigint);

	app_cmd = !!(__cmd->ctype & UNVME_APP_CMD);

	/*
	 * Prepare stderr file for the current process to receive from the
	 * daemon process.
	 */
	unvme_stdio_init(app_cmd);

	if (unvme_send_msg(&msg))
		return -1;
	if (unvme_recv_msg(&msg))
		return -1;

	unvme_cleanup();

	if (msg.msg.ret == -ENOTCONN) {
		unvme_pr_err("ERROR: unvmed has been terminated unexpectedly."
				" See details by `unvme log`\n");
	}

	return msg.msg.ret;
}
