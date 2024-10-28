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
#include <sys/wait.h>

#include <ccan/opt/opt.h>
#include <ccan/str/str.h>

#include "unvme.h"

int unvme_start(int argc, char *argv[], struct unvme_msg *msg)
{
	pid_t pid;
	int ret = 0;
	bool help = false;
	const char *desc = "Start unvmed daemon process.";
	char *with_fio = NULL;

	struct opt_table opts[] = {
#ifdef UNVME_FIO
		OPT_WITH_ARG("--with-fio", opt_set_charp, opt_show_charp, &with_fio, "[O] fio shared object path to run"),
#endif
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(2, argc, argv, opts, opt_log_stderr, help, desc);

	if (unvme_is_daemon_running())
		unvme_pr_return(1, "unvme: unvmed is already running\n");

	if (with_fio && access(with_fio, F_OK))
		with_fio = NULL;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		ret = errno;
	} else if (!pid)
		ret = unvmed(argv, with_fio);

	return ret;
}

int unvme_stop(int argc, char *argv[], struct unvme_msg *msg)
{
	pid_t pid;
	bool help = false;
	const char *desc = "Stop unvmed daemon process";

	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	FILE *fp;
	char pids[16];

	unvme_parse_args(2, argc, argv, opts, opt_log_stderr, help, desc);

	fp = popen("pgrep unvme", "r");
	if (!fp)
		unvme_pr_return(errno, "unvme: failed to pgrep unvme\n");

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
		if (waitpid(pid, NULL, 0) < 0) {
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
		}

		unvme_pr_err("pid %d terminated\n", pid);
	}

	/* To make sure that unvmed.pid file is removed from the system */
	remove(UNVME_DAEMON_PID);

	pclose(fp);
	return 0;
}

int unvme_log(int argc, char *argv[], struct unvme_msg *msg)
{
	bool nvme = false;
	bool help = false;
	const char *desc = "Show logs written by unvmed process.";

	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-n|--nvme", opt_set_bool, &nvme, "Show NVMe command log only"),
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(2, argc, argv, opts, opt_log_stderr, help, desc);

	char *line = NULL;
	ssize_t nread;
	size_t len;
	FILE *file;

	file = fopen(UNVME_DAEMON_LOG, "r");
	if (!file)
	        unvme_pr_return(errno, "failed to open unvme log file");

	while ((nread = getline(&line, &len, file)) != -1) {
		if (nvme) {
			if (strstarts(line, "NVME"))
				unvme_pr("%s", line);
		} else
			unvme_pr("%s", line);
	}

	fclose(file);
	if (line)
		free(line);
	return nread;
}
