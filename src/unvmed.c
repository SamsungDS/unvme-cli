// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <ccan/str/str.h>
#include <ccan/list/list.h>

#include <vfn/nvme.h>
#include <execinfo.h>

#include "libunvmed.h"
#include "unvme.h"
#include "unvmed.h"

struct unvme_job {
	int client_pid;
	pthread_t thread;

	struct list_node list;
};

__thread FILE *__stdout = NULL;
__thread FILE *__stderr = NULL;
static char *__libfio;
static pthread_mutex_t __app_mutex;

static LIST_HEAD(__jobs);
static pthread_mutex_t __job_mutex;

__thread struct unvme_msg *__msg;

static void unvme_callstack_dump(void)
{
	void *callstack[128];
	int i, nr_frames;
	char **strs;

	nr_frames = backtrace(callstack, sizeof(callstack) / sizeof(void *));
	strs = backtrace_symbols(callstack, nr_frames);

	for (i = 0; i < nr_frames; i++)
		unvmed_log_err("%s", strs[i]);

	free(strs);
}

static inline struct unvme_job *unvme_add_job(int client_pid)
{
	struct unvme_job *job = calloc(1, sizeof(*job));

	job->client_pid = client_pid;

	assert(job != NULL);

	pthread_mutex_lock(&__job_mutex);
	list_add_tail(&__jobs, &job->list);
	pthread_mutex_unlock(&__job_mutex);

	return job;
}

static inline struct unvme_job *unvme_get_job(int client_pid)
{
	struct unvme_job *job;

	pthread_mutex_lock(&__job_mutex);
	list_for_each(&__jobs, job, list) {
		if (job->client_pid == client_pid) {
			pthread_mutex_unlock(&__job_mutex);
			return job;
		}
	}
	pthread_mutex_unlock(&__job_mutex);

	return NULL;
}

static inline void unvme_del_job(int client_pid)
{
	struct unvme_job *job = unvme_get_job(client_pid);

	if (!job)
		return;

	pthread_mutex_lock(&__job_mutex);
	list_del(&job->list);
	pthread_mutex_unlock(&__job_mutex);
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

	if (write(fd, spid, sizeof(spid)) < 0)
		return -1;

	close(fd);
	return 0;
}

static int unvme_set_ver(void)
{
	char ver[UNVME_VER_STR];
	int fd;

	fd = open(UNVME_DAEMON_VER, O_CREAT | O_WRONLY, S_IRUSR);
	if (fd < 0)
		return -1;

	if (sprintf(ver, "%s", UNVME_VERSION) < 0) {
		close(fd);
		return -1;
	}

	if (write(fd, ver, strlen(ver) + 1) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static __thread char __argv[UNVME_MAX_OPT * UNVME_MAX_STR];
static int unvme_msg_init(struct unvme_msg *msg, int argc, char **argv)
{
	char *oneline = __argv;
	FILE *file;
	char buf[128];
	char *basename;
	int i = 0;

	file = fopen(msg->msg.argv_file, "r");
	if (!file) {
		unvme_pr_err("ERROR: failed to open %s\n", msg->msg.argv_file);
		return -1;
	}

	while (fgets(buf, sizeof(buf), file) != NULL) {
		if (!strlen(buf))
			break;
		argv[i] = calloc(1, strlen(buf));
		if (!argv[i]) {
			unvme_pr_err("ERROR: failed to malloc\n");
			goto err;
		}

		/* remove \n newline character */
		buf[strcspn(buf, "\n")] = '\0';
		if (i == 0 && (basename = strrchr(buf, '/'))) {
			strcpy(argv[i], basename + 1);
		} else
			strcpy(argv[i], buf);
		oneline += sprintf(oneline, "%s%s", (i == 0) ? "":" ", argv[i]);
		i++;
	}
	argv[i] = NULL;

	fclose(file);
	remove(msg->msg.argv_file);
	unvmed_log_info("msg (pid=%d): start: '%s'", unvme_msg_pid(msg), __argv);
	return 0;

err:
	for (i = 0; i < argc; i++) {
		if (argv[i])
			free(argv[i]);
	}

	if (file)
		fclose(file);
	remove(msg->msg.argv_file);
	return -1;
}

static int __unvme_handler(struct unvme_msg *msg)
{
	struct command *cmd;
	char **argv;
	int argc = msg->msg.argc;
	int ret;

	argv = (char **)calloc(argc + 1, sizeof(char *));
	if (!argv)
		unvme_pr_return(-ENOMEM, "ERROR: failed to allocate memory\n");

	if (unvme_msg_init(msg, argc, argv))
		unvme_pr_return(-errno, "ERROR: failed to parse msg\n");

	/*
	 * If the message represents termination, simple return here.
	 */
	if (streq(argv[1], "stop")) {
		ret = -ECANCELED;
		goto out;
	}

	ret = -EINVAL;

	cmd = unvme_get_cmd(argv[1]);
	if (cmd && cmd->ctype & UNVME_DAEMON_CMD) {
		/*
		 * We should truncate the stdout and stderr file which will be
		 * written by the application thread per every running.
		 */
		if (cmd->ctype & UNVME_APP_CMD)
			pthread_mutex_lock(&__app_mutex);

		ret = cmd->func(argc, argv, msg);

		if (cmd->ctype & UNVME_APP_CMD)
			pthread_mutex_unlock(&__app_mutex);
	}

out:
	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);

	unvmed_log_info("msg (pid=%d): compl: '%s' (ret=%d, type='%s')",
			unvme_msg_pid(msg), __argv, ret, strerror(abs(ret)));
	return ret;
}

static int unvme_msgq_delete(const char *keyfile)
{
	key_t key;
	int msg_id;

	key = ftok(keyfile, 0x0);
	if (key < 0)
		return -1;

	msg_id = msgget(key, 0666);
	if (msg_id < 0)
		return -1;

	if (msgctl(msg_id, IPC_RMID, NULL) < 0)
		return -1;

	if (remove(keyfile))
		return -1;

	return 0;
}

static int unvme_msgq_create(const char *keyfile)
{
	int msg_id;
	key_t key;
	int fd;

retry:
	fd = open(keyfile, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		if (errno == EEXIST) {
			if (!remove(keyfile))
				goto retry;
		}
		unvme_pr_return(-1, "failed to create msgq keyfile %s\n",
				keyfile);
	}
	close(fd);

	key = ftok(keyfile, 0x0);
	if (key < 0)
		unvme_pr_return(-1, "ERROR: failed to get a key\n");

	/*
	 * If the message queue already exists, remove it and re-create.
	 */
	msg_id = msgget(key, 0666);
	if (msg_id >= 0) {
		if (msgctl(msg_id, IPC_RMID, NULL) < 0)
			unvme_pr_return(-1, "ERROR: failed to remove a msgq\n");
	}

	msg_id = msgget(key, IPC_CREAT | 0666);
	if (msg_id < 0)
		unvme_pr_return(-1, "ERROR: failed to get a msgq\n");

	return msg_id;
}

static void unvme_release(int signum)
{
	if (__libfio) {
		free(__libfio);
		__libfio = NULL;
	}

	unvme_msgq_delete(UNVME_MSGQ);

	unvmed_free_ctrl_all();

	remove(UNVME_DAEMON_VER);
	remove(UNVME_DAEMON_PID);

	unvmed_log_info("unvmed(pid=%d) terminated (signum=%d, sigtype='%s')",
			getpid(), signum, strsignal(signum));

	unvme_callstack_dump();

	if (signum == SIGTERM)
		exit(EXIT_SUCCESS);
	exit(EXIT_FAILURE);
}

static void unvme_error(int signum)
{
	unvmed_log_err("signal trapped (signum=%d, type='%s')",
			signum, strsignal(signum));

	unvme_release(signum);
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

static int unvme_recv_msg(struct unvme_msg *msg)
{
	int msgq = unvme_msgq_get(UNVME_MSGQ);

	return unvme_msgq_recv(msgq, msg, getpid());
}

static int unvme_send_msg(struct unvme_msg *msg)
{
	int msgq = unvme_msgq_get(UNVME_MSGQ);

	return unvme_msgq_send(msgq, msg);
}

static void __unvme_get_stdio(pid_t pid, char *filefmt, FILE **stdio)
{
	char *filename = NULL;
	FILE *file;
	int ret;

	ret = asprintf(&filename, filefmt, pid);
	if (ret < 0) {
		unvmed_log_err("failed to init stdio (ret=%d)", ret);
		goto err;
	}

	file = fopen(filename, "w");
	if (!file) {
		unvmed_log_err("failed to open %s", filename);
		goto err;
	}

	*stdio = file;
	setbuf(*stdio, NULL);

	free(filename);
	return;
err:
	if (filename)
		free(filename);

	unvme_release(0);
}

static void unvme_get_stdio(pid_t pid)
{
	__unvme_get_stdio(pid, UNVME_STDOUT, &__stdout);
	__unvme_get_stdio(pid, UNVME_STDERR, &__stderr);
}

void unvme_exit_job(int ret)
{
	if (!__msg)
		return;

	unvme_msg_to_client(__msg, unvme_msg_pid(__msg), ret);
	unvme_send_msg(__msg);

	fclose(__stdout);
	fclose(__stderr);

	unvme_del_job(unvme_msg_pid(__msg));

	pthread_mutex_unlock(&__app_mutex);

	free(__msg);
	__msg = NULL;
}

static void *unvme_handler(void *opaque)
{
	struct unvme_msg *msg = (struct unvme_msg *)opaque;
	pid_t pid = unvme_msg_pid(msg);
	int ret;

	__msg = msg;

	unvme_get_stdio(pid);
	ret = __unvme_handler(msg);

	unvme_exit_job(ret);
	pthread_exit(NULL);
}

static inline struct unvme_msg *unvme_alloc_msg(void)
{
	struct unvme_msg *msg = calloc(1, sizeof(struct unvme_msg));

	if (!msg) {
		unvmed_log_err("failed to alloc unvme_msg");
		unvme_release(0);
	}

	return msg;
}

const char *unvmed_get_libfio(void)
{
	return __libfio;
}

static void unvme_run_job(struct unvme_msg *msg)
{
	struct unvme_job *job = unvme_add_job(unvme_msg_pid(msg));

	pthread_create(&job->thread, NULL, unvme_handler, (void *)msg);
}

static void unvme_signal_job(struct unvme_msg *msg)
{
	struct unvme_job *job;

	job = unvme_get_job(unvme_msg_pid(msg));
	/* 
	 * When sig occurs more than twice, the unvmed can't find a job.
	 * client continues to wait to receive msg. unvmed should send msg
	 */
	if (!job) {
		unvme_msg_to_client(msg, unvme_msg_pid(msg), 0);
		unvme_send_msg(msg);
		return;
	}

	if (unvme_msg_signum(msg) == SIGINT || unvme_msg_signum(msg) == SIGTERM)
		unvme_del_job(unvme_msg_pid(msg));

	pthread_kill(job->thread, unvme_msg_signum(msg));
	pthread_join(job->thread, NULL);
}

int unvmed(char *argv[], const char *fio)
{
	struct unvme_msg *msg;

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
	if (chdir("/"))
		unvme_pr_return(-1, "ERROR: failed to change directory\n");

	unvmed_init(UNVME_DAEMON_LOG);

	close(STDIN_FILENO);
	if (!freopen(UNVME_DAEMON_STDOUT, "w", stdout))
		unvmed_log_err("failed to redirect stdout to %s", UNVME_DAEMON_STDOUT);
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!freopen(UNVME_DAEMON_STDERR, "w", stderr))
		unvmed_log_err("failed to redirect stdout to %s", UNVME_DAEMON_STDERR);
	setvbuf(stderr, NULL, _IOLBF, 0);

	unvme_msgq_create(UNVME_MSGQ);

	unvmed_log_info("unvmed daemon process is sucessfully created "
			"(pid=%d, ver='%s')", getpid(), UNVME_VERSION);

	signal(SIGTERM, unvme_release);
	signal(SIGSEGV, unvme_error);
	signal(SIGABRT, unvme_error);

	unvme_set_pid();
	if (unvme_set_ver())
		unvme_pr_return(-1, "ERROR: failed to set unvme-cli version\n");

	pthread_mutex_init(&__app_mutex, NULL);
	pthread_mutex_init(&__job_mutex, NULL);

	unvmed_log_info("ready to receive messages from client ...");
	if (fio)
		__libfio = strdup(fio);

	while (true) {
		msg = unvme_alloc_msg();

		if (unvme_recv_msg(msg) < 0)
			return -1;

		if (unvme_msg_is_normal(msg))
			unvme_run_job(msg);
		else
			unvme_signal_job(msg);

	}

	/*
	 * Should not reach here.
	 */
	return 0;
}
