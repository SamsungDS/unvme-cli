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

#include <ccan/str/str.h>

#include "unvme.h"

#include "argtable3/argtable3.h"

static FILE *__stdout;
static FILE *__stderr;

static void __attribute__((constructor)) __unvme_cmd_init(void) {
	__stdout = stdout;
	__stderr = stderr;
}

int unvme_start(int argc, char *argv[], struct unvme_msg *msg)
{
	pid_t pid;
	int ret = 0;
	struct arg_str *with_fio;
	struct arg_lit *help;
	struct arg_end *end;
	const char *desc = "Start unvmed daemon process.";

	void *argtable[] = {
		with_fio = arg_str0(NULL, "with-fio", "</path/to/fio>", "[O] fio shared object path to run"),
		help = arg_lit0("h", "help", "Show help message"),
		end = arg_end(20),
	};

	unvme_parse_args(argc, argv, argtable, help, end, desc);

	if (unvme_is_daemon_running())
		unvme_pr_return(1, "unvme: unvmed is already running\n");

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

	return ret;
}

static int __unvme_stop(const char *name)
{
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
		if (waitpid(pid, NULL, 0) < 0) {
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
		}
	}

	pclose(fp);
	return 0;
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

	__unvme_stop("unvmed");
	/* To make sure that unvmed.pid file is removed from the system */
	remove(UNVME_DAEMON_PID);

	if (arg_boolv(all))
		__unvme_stop("unvme");

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
	ssize_t nread;
	size_t len;
	FILE *file;

	file = fopen(UNVME_DAEMON_LOG, "r");
	if (!file)
	        unvme_pr_return(errno, "failed to open unvme log file");

	while ((nread = getline(&line, &len, file)) != -1) {
		if (arg_boolv(nvme) > 0) {
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
