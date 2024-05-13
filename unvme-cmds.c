#include <sys/signal.h>
#include <sys/wait.h>

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

	if (unvme_unvmed_running())
		unvme_pr_return(1, "unvme: unvmed is already running\n");

	pid = fork();
	if (pid < 0) {
		perror("fork");
		ret = errno;
	} else if (!pid)
		ret = unvmed();

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

	if (!unvme_unvmed_running())
		unvme_pr_return(1, "unvme: unvmed is not running\n");

	pid = unvme_unvmed_pid();
	kill(pid, SIGTERM);

	return waitpid(pid, NULL, 0) > 0;
}
