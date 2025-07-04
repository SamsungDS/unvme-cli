// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <sys/signal.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ccan/str/str.h>

#include "unvme.h"

#include <argtable3.h>

static FILE *__stdout;
static FILE *__stderr;

static void __attribute__((constructor)) __unvme_cmd_init(void) {
	__stdout = stdout;
	__stderr = stderr;
}

#define unvme_parse_args(argc, argv, argtable, help, end, desc)				\
	do {										\
		int nerror = arg_parse(argc - 1, &argv[1], argtable);			\
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
	} while (0)

static void __unvme_stop(bool with_client);

int unvme_start(int argc, char *argv[], struct unvme_msg *msg)
{
	pid_t pid;
	int ret = 0;
	struct arg_str *with_fio;
	struct arg_lit *restart;
	struct arg_lit *help;
	struct arg_end *end;
	const char *desc = "Start unvmed daemon process.";

	void *argtable[] = {
		with_fio = arg_str0(NULL, "with-fio", "</path/to/fio>", "[O] fio shared object path to run"),
		restart = arg_lit0("r", "restart", "Stop the current running unvmed and re-run the daemon process"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(20),
	};

	arg_strv(with_fio) = NULL;

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	if (unvme_is_daemon_running()) {
		if (arg_boolv(restart))
			__unvme_stop(true);
		else {
			unvme_pr_err("unvmed is already running\n");
			goto out;
		}
	}

	if (arg_boolv(with_fio) && access(arg_strv(with_fio), F_OK))
		arg_strv(with_fio) = NULL;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		ret = errno;
	} else if (!pid)
		ret = unvmed(argv, arg_strv(with_fio));
	else {
		while (!unvme_is_daemon_running())
			;
	}

out:
	unvme_free_args(argtable);
	return ret;
}

static int __kill(const char *name)
{
	struct stat buffer;
	char pids[16];
	char *cmd = NULL;
	pid_t pid;
	FILE *fp;
	int ret;

	ret = asprintf(&cmd, "pgrep %s", name);
	if (ret < 0)
		return ret;

	fp = popen(cmd, "r");
	if (!fp) {
		unvme_pr_err("failed to popen '%s'\n", cmd);
		free(cmd);
		return -errno;
	}

	free(cmd);

	/*
	 * Find all the unvme* processes running in the current system and
	 * terminate them gracefully.  If they are not terminated successfully,
	 * kill them all here.
	 */
	while (fgets(pids, sizeof(pids) - 1, fp) != NULL) {
		pid = atoi(pids);
		if (pid == getpid())
			continue;

		kill(pid, SIGTERM);
	}

	/*
	 * Ensure that the daemon process is successfully terminated.
	 */
	while (!stat(UNVME_DAEMON_PID, &buffer))
		sleep(0.01);

	pclose(fp);
	return 0;
}

static void __unvme_stop(bool with_client)
{
	__kill("unvmed");
	/* To make sure that unvmed.pid file is removed from the system */
	remove(UNVME_DAEMON_VER);
	remove(UNVME_DAEMON_PID);

	if (with_client)
		__kill("unvme");
}

int unvme_stop(int argc, char *argv[], struct unvme_msg *msg)
{
	struct arg_lit *all;
	struct arg_lit *help;
	struct arg_end *end;
	const char *desc = "Stop unvmed daemon process";

	void *argtable[] = {
		all = arg_lit0("a", "all", "Stop all unvme-cli clients along with unvmed"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(20),
	};

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	__unvme_stop(arg_boolv(all));

	unvme_free_args(argtable);
	return 0;
}

int unvme_log(int argc, char *argv[], struct unvme_msg *msg)
{
	struct arg_lit *nvme;
	struct arg_lit *help;
	struct arg_end *end;
	const char *desc = "Show logs written by unvmed process.";

	void *argtable[] = {
		nvme = arg_lit0("n", "nvme", "Show NVMe command log only"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(20),
	};

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	char *line = NULL;
	size_t len;
	FILE *file;
	int ret;

	file = fopen(UNVME_DAEMON_LOG, "r");
	if (!file) {
		unvme_pr_err("failed to open unvme log file\n");
		ret = ENOENT;
		goto out;
	}

	while ((ret = getline(&line, &len, file)) != -1) {
		if (arg_boolv(nvme) > 0) {
			if (strstarts(line, "NVME"))
				unvme_pr("%s", line);
		} else
			unvme_pr("%s", line);
	}

	fclose(file);
	if (line)
		free(line);

	ret = 0;
out:
	unvme_free_args(argtable);
	return ret;
}
