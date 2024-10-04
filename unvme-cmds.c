// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/signal.h>
#include <sys/wait.h>

#include <ccan/opt/opt.h>

#include "unvme.h"

int unvme_start(int argc, char *argv[], struct unvme_msg *msg)
{
	pid_t pid;
	int ret = 0;
	bool help = false;
	const char *desc = "Start unvmed daemon process.";

	struct opt_table opts[] = {
		OPT_WITHOUT_ARG("-h|--help", opt_set_bool, &help, "Show help message"),
		OPT_ENDTABLE
	};

	unvme_parse_args(2, argc, argv, opts, opt_log_stderr, help, desc);

	if (unvme_is_daemon_running())
		unvme_pr_return(1, "unvme: unvmed is already running\n");

	pid = fork();
	if (pid < 0) {
		perror("fork");
		ret = errno;
	} else if (!pid)
		ret = unvmed(argv);

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

	unvme_parse_args(2, argc, argv, opts, opt_log_stderr, help, desc);

	if (!unvme_is_daemon_running())
		unvme_pr_return(1, "unvme: unvmed is not running\n");

	pid = unvme_get_daemon_pid();
	kill(pid, SIGTERM);

	return waitpid(pid, NULL, 0) > 0;
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

	int fd = open(UNVME_DAEMON_LOG, O_RDONLY);
	char buffer[512];
	ssize_t nread;

	if (fd < 0)
	        unvme_pr_return(fd, "failed to open unvme log file");

	while ((nread = read(fd, buffer, sizeof(buffer))) > 0) {
		if (nvme) {
			if (strstr(buffer, "nvme    |"))
				unvme_pr("%.*s", (int) nread, buffer);
		}
		else
			unvme_pr("%.*s", (int) nread, buffer);
	}

	if (nread < 0)
		perror("read");

	close(fd);
	return nread;
}
