#include <stdio.h>
#include <sys/signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ccan/str/str.h>

#include "unvme.h"

/*
 * Shared memory buffer pointer pointing
 */
static char *__stderr;
static char *__stdout;
static struct list_head ctrls;

struct unvme *unvmed_ctrl(const char *bdf)
{
	struct unvme *ctrl;

	if (!ctrls.n.next || !ctrls.n.prev)
		return NULL;

	list_for_each(&ctrls, ctrl, list) {
		if (streq(ctrl->bdf, bdf))
			return ctrl;
	}

	return NULL;
}

int unvmed_alloc(const char *bdf)
{
	struct unvme *unvme;

	if (unvmed_ctrl(bdf))
		return 0;

	unvme = (struct unvme *)malloc(sizeof(struct unvme));
	if (!unvme)
		return -ENOMEM;

	strncpy(unvme->bdf, bdf, sizeof(unvme->bdf));

	list_head_init(&unvme->cmd_list);
	list_add(&ctrls, &unvme->list);
	return 0;
}

int unvmed_free(const char *bdf)
{
	struct unvme *unvme = unvmed_ctrl(bdf);

	if (!unvme)
		return -EINVAL;

	list_del(&unvme->list);
	return 0;
}

static int unvmed_set_pid(void)
{
	pid_t pid = getpid();
	char spid[8] = {};
	int fd;

	fd = open(UNVME_UNVMED_PID, O_CREAT | O_WRONLY, S_IRUSR);
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

static int unvmed_handler(struct unvme_msg *msg)
{
	const struct command *cmds = unvme_cmds();
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
	}
	argv[i] = NULL;

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

	return ret;
}

static void unvmed_release(int signum)
{
	struct unvme *ctrl, *next;

	unvme_msgq_delete(UNVME_MSGQ_SQ);
	unvme_msgq_delete(UNVME_MSGQ_CQ);

	list_for_each_safe(&ctrls, ctrl, next, list) {
		nvme_close(&ctrl->ctrl);
		free(ctrl);
	}

	remove(UNVME_UNVMED_PID);

	exit(ECANCELED);
}

static void unvmed_std_init(void)
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

int unvmed(void)
{
	struct unvme_msg msg;
	int sqid;
	int cqid;

	/*
	 * Convert the current process to a daemon process
	 */
	if (setsid() < 0)
		unvme_pr_return(-1, "ERROR: failed to create new session\n");

	prctl(PR_SET_NAME, (unsigned long)"unvmed", 0, 0, 0);

	umask(0);
	chdir("/");

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	sqid = unvme_msgq_create(UNVME_MSGQ_SQ);
	cqid = unvme_msgq_create(UNVME_MSGQ_CQ);

	list_head_init(&ctrls);

	signal(SIGTERM, unvmed_release);
	unvmed_set_pid();

	while (true) {
		unvme_msgq_recv(sqid, &msg);
		unvmed_std_init();

		/*
		 * Provide error return value from the current daemon process to
		 * the requester unvme-cli client process.
		 */
		msg.msg.ret = unvmed_handler(&msg);
		unvme_msgq_send(cqid, &msg);
	}

	/*
	 * Should not reach here.
	 */
	return 0;
}
