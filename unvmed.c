// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ccan/str/str.h>

#include <vfn/nvme.h>
#include <libunvmed.h>

#include "unvme.h"

/*
 * Shared memory buffer pointer pointing
 */
static char *__stderr;
static char *__stdout;
static int __msg_cq;
static int __log_fd;

void unvme_datetime(char *datetime, size_t str_len)
{
	struct timeval tv;
	struct tm *tm;
	char usec[16];

	assert(datetime != NULL);

	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);

	strftime(datetime, str_len, "%Y-%m-%d %H:%M:%S", tm);

	sprintf(usec, ".%06ld", tv.tv_usec);
	strcat(datetime, usec);
}

static int unvme_set_pid(void)
{
	pid_t pid = getpid();
	char spid[8] = {};
	int fd;

	fd = open(UNVME_DAEMON_PID, O_CREAT | O_WRONLY, S_IRUSR);
	if (fd < 0)
		return -EINVAL;

	if (sprintf(spid, "%d", pid) < 0) {
		close(fd);
		return -EINVAL;
	}

	write(fd, spid, sizeof(spid));
	close(fd);
	return 0;
}

static char __argv[UNVME_MAX_OPT * UNVME_MAX_STR];
static int unvme_handler(struct unvme_msg *msg)
{
	const struct command *cmds = unvme_cmds();
	char *oneline = __argv;
	char **argv;
	int argc = msg->msg.argc;
	int ret;
	int i = 0;

	argv = (char **)malloc(sizeof(char *) * (argc + 1));
	if (!argv)
		unvme_pr_return(-ENOMEM, "ERROR: failed to allocate memory\n");

	for (i = 0; i < argc; i++) {
		argv[i] = malloc(sizeof(char) * strlen(msg->msg.argv[i]));
		if (!argv[i])
			unvme_pr_return(-ENOMEM, "ERROR: failed to allocate memory\n");
		strcpy(argv[i], msg->msg.argv[i]);
		oneline += sprintf(oneline, "%s%s", (i == 0) ? "":" ", argv[i]);
	}
	argv[i] = NULL;

	log_info("msg: start: '%s'", __argv);

	/*
	 * If the message represents termination, simple return here.
	 */
	if (streq(argv[1], "stop")) {
		ret = -ECANCELED;
		goto out;
	}

	ret = -EINVAL;
	for (i = 0; cmds[i].name != NULL; i++) {
		if (streq(argv[1], cmds[i].name) &&
				cmds[i].ctype & UNVME_DAEMON_CMD) {
			ret = cmds[i].func(argc, argv, msg);
			break;
		}
	}

out:
	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);

	log_info("msg: compl: '%s' (ret=%d, type='%s')",
			__argv, ret, strerror(abs(ret)));
	return ret;
}

static void unvme_release(int signum)
{
	unvme_msgq_delete(UNVME_MSGQ_SQ);
	unvme_msgq_delete(UNVME_MSGQ_CQ);

	unvmed_free_ctrl_all();

	remove(UNVME_DAEMON_PID);

	log_info("unvmed(pid=%d) terminated (signum=%d, sigtype='%s')",
			getpid(), signum, strsignal(signum));
	exit(ECANCELED);
}

static void unvme_error(int signum)
{
	struct unvme_msg msg = {
		.type = UNVME_MSG,
		.msg = {
			.ret = -ENOTCONN,
		},
	};

	log_err("signal trapped (signum=%d, type='%s')",
			signum, strsignal(signum));

	if (__msg_cq)
		unvme_msgq_send(__msg_cq, &msg);

	unvme_release(signum);
}

static void unvme_std_init(void)
{
	if (!__stderr) {
		__stderr = (char *)unvme_stderr();
		assert(__stderr != NULL);
	}

	if (!__stdout) {
		__stdout = (char *)unvme_stdout();
		assert(__stdout!= NULL);
	}

	/*
	 * Redirect stderr to the buffer in the message packet
	 */
	stderr = fmemopen((char *)__stderr, UNVME_STDERR_SIZE, "w");
	setbuf(stderr, NULL);
	stdout = fmemopen((char *)__stdout, UNVME_STDERR_SIZE, "w");
	setbuf(stdout, NULL);

	__stderr[0] = '\0';
	__stdout[0] = '\0';
}

static inline int unvme_cmdline_strlen(void)
{
	char buf[16];
	ssize_t len;
	int fd;

	fd = open("/proc/self/cmdline", O_RDONLY);
	assert(fd > 0);

	len = read(fd, buf, sizeof(buf));

	close(fd);
	return len;
}

static int unvme_create_logfile(void)
{
	int fd;

	if(mkdir("/var/log", 0755) < 0 && errno != EEXIST)
		return -errno;

	fd = creat(UNVME_DAEMON_LOG, 0644);
	if (fd < 0)
		return -EINVAL;

	return fd;
}

int unvme_get_log_fd(void)
{
	return __log_fd;
}

int unvmed(char *argv[])
{
	struct unvme_msg msg;
	int sqid;

	/*
	 * Convert the current process to a daemon process
	 */
	if (setsid() < 0)
		unvme_pr_return(-1, "ERROR: failed to create new session\n");

	prctl(PR_SET_NAME, (unsigned long)"unvmed", 0, 0, 0);

	memset(argv[0], 0, unvme_cmdline_strlen());
	strcpy(argv[0], "unvmed");
	argv[0][strlen("unvmed")] = '\0';

	umask(0);
	chdir("/");

	__log_fd = unvme_create_logfile();
	assert(__log_fd >= 0);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	sqid = unvme_msgq_create(UNVME_MSGQ_SQ);
	__msg_cq = unvme_msgq_create(UNVME_MSGQ_CQ);

	log_info("unvmed daemon process is sucessfully created "
			"(pid=%d, msgq_sq=%d, msgq_cq=%d)",
			getpid(), sqid, __msg_cq);

	signal(SIGTERM, unvme_release);
	signal(SIGSEGV, unvme_error);
	signal(SIGABRT, unvme_error);
	unvme_set_pid();

	log_info("ready to receive messages from client ...");

	while (true) {
		unvme_msgq_recv(sqid, &msg);
		unvme_std_init();

		/*
		 * Provide error return value from the current daemon process to
		 * the requester unvme-cli client process.
		 */
		msg.msg.ret = unvme_handler(&msg);
		unvme_msgq_send(__msg_cq, &msg);
	}

	/*
	 * Should not reach here.
	 */
	return 0;
}
