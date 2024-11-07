/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UNVME_H
#define UNVME_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <ccan/list/list.h>

#include <argtable3/argtable3.h>

#define UNVME_MAX_OPT		64
#define UNVME_MAX_STR		32
#define UNVME_BDF_STRLEN	13
#define UNVME_PWD_STRLEN	256

/*
 * argtable3-related helper macros
 */
#define arg_boolv(a)		(!!(a)->count)
#define arg_intv(a)		((a)->ival[0])
#define arg_dblv(a)		((a)->dval[0])
#define arg_strv(a)		((a)->sval[0])
#define arg_filev(a)		((a)->filename[0])

struct unvme_msg {
	/* msgq message type used to represent client pid */
	long type;

	struct {
		/*
		 * Request message from client to daemon
		 */
		int argc;
		char argv[UNVME_MAX_OPT][UNVME_MAX_STR];
		char bdf[UNVME_BDF_STRLEN];
		char pwd[UNVME_PWD_STRLEN];
		int pid;  /* client pid */

		union {
			/*
			 * Signal request to daemon from client
			 */
			int signum;
			/*
			 * Response message from daemon to client
			 */
			int ret;
		};
	} msg;
};

#define unvme_msg_pid(p)	((p)->msg.pid)
#define unvme_msg_pwd(p)	((p)->msg.pwd)
#define unvme_msg_signum(p)	((p)->msg.signum)

static inline bool unvme_msg_is_normal(struct unvme_msg *msg)
{
	return unvme_msg_signum(msg) == 0;
}

int unvme_get_daemon_pid(void);
bool unvme_is_daemon_running(void);

static inline void unvme_msg_to_daemon(struct unvme_msg *msg)
{
	pid_t client_pid = getpid();
	pid_t daemon_pid = unvme_get_daemon_pid();

	assert(client_pid != daemon_pid);

	msg->type = daemon_pid;
	msg->msg.pid = client_pid;
}

static inline void unvme_msg_to_client(struct unvme_msg *msg, pid_t pid, int ret)
{
	msg->type = pid;
	msg->msg.ret = ret;
}

enum command_type {
	UNVME_CLIENT_CMD	= 1 << 0,
	UNVME_DAEMON_CMD	= 1 << 1,
	UNVME_DEV_CMD		= 1 << 2,
	UNVME_NODEV_CMD		= 1 << 3,
	UNVME_APP_CMD		= 1 << 4,
};

struct command {
	char *name;
	char *summary;
	enum command_type ctype;
	int (*func)(int argc, char *argv[], struct unvme_msg *msg);
#define UNVME_CMDS_END	{NULL, NULL, 0, NULL}
};
struct command *unvme_cmds(void);

static inline struct command *unvme_get_cmd(const char *name)
{
	struct command *cmds = unvme_cmds();

	for (int i = 0; cmds[i].name != NULL; i++) {
		if (!strcmp(name, cmds[i].name))
			return &cmds[i];
	}

	return NULL;
}

#define UNVME_DAEMON_LOG	"/var/log/unvmed.log"
/* application (e.g., fio) will print stdout/stderr to the file */
#define UNVME_DAEMON_STDOUT	"/var/log/unvmed.stdout"
#define UNVME_DAEMON_STDERR	"/var/log/unvmed.stderr"
#define UNVME_STDOUT		"/var/log/unvmed/stdout-%d"
#define UNVME_STDERR		"/var/log/unvmed/stderr-%d"

#define UNVME_MSGQ		"/dev/mqueue/unvmed"

static inline int unvme_msgq_send(int msg_id, struct unvme_msg *msg)
{
	return msgsnd(msg_id, msg, sizeof(msg->msg), 0);
}

static inline int unvme_msgq_recv(int msg_id, struct unvme_msg *msg, long type)
{
	return msgrcv(msg_id, msg, sizeof(msg->msg), type, 0);
}

static inline int unvme_msgq_get(const char *keyfile)
{
	int msg_id;
	key_t key;

	key = ftok(keyfile, 0x0);
	if (key < 0)
		return -1;

	msg_id = msgget(key, 0666);
	if (msg_id < 0)
		return -1;

	return msg_id;
}

#define UNVME_DAEMON_PID	"/var/run/unvmed.pid"

static inline void unvme_print_help(FILE *fp, char *cmd, const char *desc, void *argtable[]) {
	fprintf(fp, "\nUsage: unvme %s", cmd);
	arg_print_syntax(fp, argtable, "\n");

	fprintf(fp, "\n%s\n\n", desc);

	arg_print_glossary(fp, argtable, "\t%-30s\t%s\n");
}

#define unvme_pr(fmt, ...)				\
	do {						\
		fprintf(stdout, fmt, ##__VA_ARGS__);	\
	} while(0)

#define unvme_pr_err(fmt, ...)				\
	do {						\
		fprintf(stderr, fmt, ##__VA_ARGS__);	\
	} while(0)

#define unvme_pr_return(ret, fmt, ...)			\
	do {						\
		unvme_pr_err(fmt, ##__VA_ARGS__);	\
		return ret;				\
	} while(0)

#define unvme_free_args(argtable)	\
	arg_freetable(argtable, sizeof(argtable) / sizeof(*argtable))

#define UNVME_ARG_MAX_ERROR	20
#define UNVME_BDF_PATTERN	"^[0-9]+:[0-9]+(:[0-9]+)?(.[0-9]+)?|[0-9]+.[0-9]+"

/*
 * Command handlers
 */
int unvme_list(int argc, char *argv[], struct unvme_msg *msg);
int unvme_start(int argc, char *argv[], struct unvme_msg *msg);
int unvme_stop(int argc, char *argv[], struct unvme_msg *msg);
int unvme_log(int argc, char *argv[], struct unvme_msg *msg);

int unvme_add(int argc, char *argv[], struct unvme_msg *msg);
int unvme_del(int argc, char *argv[], struct unvme_msg *msg);
int unvme_show_regs(int argc, char *argv[], struct unvme_msg *msg);
int unvme_status(int argc, char *argv[], struct unvme_msg *msg);
int unvme_enable(int argc, char *argv[], struct unvme_msg *msg);
int unvme_create_iocq(int argc, char *argv[], struct unvme_msg *msg);
int unvme_delete_iocq(int argc, char *argv[], struct unvme_msg *msg);
int unvme_create_iosq(int argc, char *argv[], struct unvme_msg *msg);
int unvme_delete_iosq(int argc, char *argv[], struct unvme_msg *msg);
int unvme_id_ns(int argc, char *argv[], struct unvme_msg *msg);
int unvme_id_active_nslist(int argc, char *argv[], struct unvme_msg *msg);
int unvme_nvm_id_ns(int argc, char *argv[], struct unvme_msg *msg);
int unvme_read(int argc, char *argv[], struct unvme_msg *msg);
int unvme_write(int argc, char *argv[], struct unvme_msg *msg);
int unvme_passthru(int argc, char *argv[], struct unvme_msg *msg);
int unvme_update_sqdb(int argc, char *argv[], struct unvme_msg *msg);
int unvme_reset(int argc, char *argv[], struct unvme_msg *msg);
int unvme_perf(int argc, char *argv[], struct unvme_msg *msg);
int unvme_fio(int argc, char *argv[], struct unvme_msg *msg);

/*
 * unvmed.c
 */
int unvmed(char *argv[], const char *fio);

/*
 * unvme.c
 */
#define unvme_pr_err_return(ret, fmt, ...)			\
	do {							\
		unvme_pr_err("Error: "fmt, ##__VA_ARGS__);	\
		return ret;					\
	} while(0)

#endif
