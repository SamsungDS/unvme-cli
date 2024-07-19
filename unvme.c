#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/ipc.h>

#include <ccan/opt/opt.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>

#include "unvme.h"

static int unvme_help(int argc, char *argv[], struct unvme_msg *msg);
static struct command cmds[] = {
	{"help",		"Show usage help message",		UNVME_CLIENT_CMD | UNVME_NODEV_CMD,	unvme_help},
	{"start",		"Start unvmed daemon process",		UNVME_CLIENT_CMD | UNVME_NODEV_CMD,	unvme_start},
	{"stop",		"Stop unvmed daemon process",		UNVME_CLIENT_CMD | UNVME_NODEV_CMD,	unvme_stop},
	{"list",		"Show NVMe PCIe devices",		UNVME_DAEMON_CMD | UNVME_NODEV_CMD,	unvme_list},
	{"add",			"Add NVMe PCI device to unvmed",	UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_add},
	{"del",			"Delete NVMe PCI device from unvmed",	UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_del},
	{"show-regs",		"Show NVMe controller properties",	UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_show_regs},
	{"enable",		"Enable controller with adminq",	UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_enable},
	{"disable",		"Disable controller",			UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_reset},
	{"create-iocq",		"Create I/O Completion Queue",		UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_create_iocq},
	{"create-iosq",		"Create I/O Submission Queue",		UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_create_iosq},
	{"id-ns",		"Identify Namespace (CNS 0h)",		UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_id_ns},
	{"read",		"NVM Read command",			UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_read},
	{"write",		"NVM Write command",			UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_write},
	{"io-passthru",		"I/O passthrough command",		UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_io_passthru},
	{"update-sqdb",		"Update SQ tail doorbell",		UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_update_sqdb},
	{"reset",		"Reset NVMe controller",		UNVME_DAEMON_CMD | UNVME_DEV_CMD,	unvme_reset},
	UNVME_CMDS_END
};

struct command *unvme_cmds(void)
{
	return cmds;
}

int unvme_send_msg(struct unvme_msg *msg)
{
	int sqid = unvme_msgq_get(UNVME_MSGQ_SQ);

	if (sqid < 0)
		unvme_pr_return(-1, "ERROR: failed to get SQ\n");

	return unvme_msgq_send(sqid, msg);
}

int unvme_recv_msg(struct unvme_msg *msg)
{
	int cqid = unvme_msgq_get(UNVME_MSGQ_CQ);

	if (cqid < 0)
		unvme_pr_return(-1, "ERROR: failed to get CQ\n");

	return unvme_msgq_recv(cqid, msg);
}

static inline struct command *unvme_cmd(const char *cmd)
{
	for (int i = 0; i < ARRAY_SIZE(cmds) && cmds[i].name; i++) {
		if (streq(cmd, cmds[i].name))
			return &cmds[i];
	}

	return NULL;
}

void unvme_cmd_help(const char *name, const char *desc, struct opt_table *opts)
{
	struct command *cmd = unvme_cmd(name);

	if (!cmd)
		return;

	if (cmd->ctype & UNVME_DEV_CMD)
		unvme_pr("Usage: unvme %s <device> [<args>]\n", name);
	else
		unvme_pr("Usage: unvme %s [<args>]\n", name);

	unvme_pr("\n");

	unvme_pr("%s\n", desc);

	unvme_pr("\n");
	unvme_pr("<args>\n");

	while (opts->names) {
		unvme_pr("\t%-16s\t%s\n", opts->names, opts->desc);
		opts++;
	}
}

static inline bool unvme_is_daemon_cmd(const char *name)
{
	for (int i = 0; i < ARRAY_SIZE(cmds) && cmds[i].name; i++) {
		if (streq(name, cmds[i].name) &&
				cmds[i].ctype == UNVME_DAEMON_CMD)
			return true;
	}

	return false;
}

static int unvme_help(int argc, char *argv[], struct unvme_msg *msg)
{
	unvme_pr("Usage: unvme <command> [<device>] [<args>]\n");
	unvme_pr("\n");
	unvme_pr("Submit or trigger a given command to <device>. <device> is a bus-device-func\n"
		 "address of a PCI device (e.g., 0000:01:00.0).  <device> can be found from\n"
		 "'unvme list' command result.\n");
	unvme_pr("\n");
	unvme_pr("Supported commands:\n");

	for (int i = 0; i < ARRAY_SIZE(cmds) && cmds[i].name; i++)
		unvme_pr("\t%-16s\t%s\n", cmds[i].name, cmds[i].summary);

	return 0;
}

static int __unvme_help(void)
{
	return unvme_help(0, NULL, NULL);
}

static int unvme_parse_bdf(const char *input, char *bdf)
{
	unsigned int domain = 0, bus = 0, dev = 0, func = 0;
	int nr_dot = strcount(input, ".");
	int nr_col = strcount(input, ":");

	switch (nr_dot) {
	case 0:
		switch (nr_col) {
		case 1:
			if (sscanf(input, "%x:%x", &bus, &dev) != 2)
				return 1;
			break;
		case 2:
			if (sscanf(input, "%x:%x:%x",
					&domain, &bus, &dev) != 3)
				return 1;
			break;
		default:
			return 1;
		}
		break;
	case 1:
		switch (nr_col) {
		case 0:
			if (sscanf(input, "%x.%d", &dev, &func) != 2)
				return 1;
			break;
		case 1:
			if (sscanf(input, "%x:%x.%d", &bus, &dev, &func) != 3)
				return 1;
			break;
		case 2:
			if (sscanf(input, "%x:%x:%x.%d",
					&domain, &bus, &dev, &func) != 4)
				return 1;
			break;
		default:
			return 1;
		}
		break;
	default:
		return 1;
	}

	sprintf(bdf, "%04x:%02x:%02x.%1d", domain, bus, dev, func);
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

	if (argc == 1) {
		__unvme_help();
		return 0;
	}

	cmd = unvme_cmd(argv[1]);
	if (!cmd)
		unvme_pr_err_return(-EINVAL, "Invalid command '%s'\n",
				argv[1]);

	/*
	 * UNVME_DEV_CMD has to be given with the target <device> which is a BDF
	 * of a PCI device, but it's not given, so print help message.
	 */
	if (argc == 2 && cmd->ctype & UNVME_DEV_CMD)
		return cmd->func(argc, argv, NULL);

	for (int i = 2; i < argc; i++) {
		if (strstarts(argv[i], "-h") || strstarts(argv[i], "--help")) {
			/*
			 * -h|--help option will be parsed in the command
			 *  handler without doing actual command behavior.
			 */
			return cmd->func(argc, argv, NULL);
		}
	}

	/*
	 * Check the given <device> is a valid PCI BDF format.
	 */
	if (cmd->ctype & UNVME_DEV_CMD) {
		if (unvme_parse_bdf(argv[2], bdf))
			unvme_pr_err_return(-EINVAL, "Invalid device format "
					"'%s'\n", argv[2]);
	}

	return argc;
}

int main(int argc, char *argv[])
{
	struct unvme_msg msg = {0, };
	const char *cmd = argv[1];
	char *__stderr;
	char *__stdout;
	char bdf[13];
	int ret;

	ret = unvme_check_args(argc, argv, bdf);
	if (ret <= 0) {
		if (ret == -EINVAL)
			__unvme_help();

		return abs(ret);
	}

	msg.type = UNVME_MSG;
	msg.msg.argc = argc;
	for (int i = 0; i < msg.msg.argc; i++)
		strcpy(msg.msg.argv[i], argv[i]);
	strncpy(msg.msg.bdf, bdf, UNVME_BDF_STRLEN);
	getcwd(msg.msg.pwd, UNVME_PWD_STRLEN);

	for (int i = 0; i < ARRAY_SIZE(cmds) && cmds[i].name; i++) {
		if (streq(cmd, cmds[i].name) &&
				cmds[i].ctype & UNVME_CLIENT_CMD)
			return cmds[i].func(argc, argv, &msg);
	}

	if (!unvme_unvmed_running())
		unvme_pr_return(1, "ERROR: unvmed is not running, "
				"please run 'unvme start' first\n");

	/*
	 * Prepare shared memory which will be used as stdout from the unvmed.
	 * Reaching here means unvmed has already been running and shmem for
	 * stdout has already been created, so we just can simply open the
	 * shmem here.
	 */
	__stderr = unvme_stderr();
	__stdout = unvme_stdout();
	assert(__stderr != NULL && __stdout != NULL);

	if (unvme_send_msg(&msg))
		unvme_pr_return(-1, "ERROR: failed to send msg request\n");
	if (unvme_recv_msg(&msg))
		unvme_pr_return(-1, "ERROR: failed to receive msg request\n");

	fprintf(stderr, "%s", __stderr);
	if (!unvme_msg_dsize(&msg))
		fprintf(stdout, "%s", __stdout);
	else {
		for (int i = 0; i < unvme_msg_dsize(&msg); i++)
			fprintf(stdout, "%c", __stdout[i]);
	}

	return msg.msg.ret;
}
