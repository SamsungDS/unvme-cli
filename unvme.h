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

#define UNVME_MAX_OPT		64
#define UNVME_MAX_STR		32
#define UNVME_BDF_STRLEN	13
#define UNVME_PWD_STRLEN	256

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

		/*
		 * Response message from daemon to client
		 */
		int ret;
	} msg;
};

#define unvme_msg_pid(p)	((p)->msg.pid)
#define unvme_msg_bdf(p)	((p)->msg.bdf)
#define unvme_msg_pwd(p)	((p)->msg.pwd)

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
};

struct command {
	char *name;
	char *summary;
	enum command_type ctype;
	int (*func)(int argc, char *argv[], struct unvme_msg *msg);
#define UNVME_CMDS_END	{NULL, NULL, 0, NULL}
};
struct command *unvme_cmds(void);

#define UNVME_DAEMON_LOG	"/var/log/unvmed.log"
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

struct opt_table;
void unvme_cmd_help(const char *name, const char *desc, struct opt_table *opts);

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

#define unvme_help_err(fmt, ...)					\
	do {								\
		fprintf(stderr, fmt"\n", ##__VA_ARGS__);		\
		unvme_cmd_help(argv[1], desc, opts);			\
		opt_free_table();					\
		return -EINVAL;						\
	} while(0)


#define unvme_help_return(fmt, ...)				\
	do {								\
		fprintf(stderr, fmt"\n", ##__VA_ARGS__);		\
		unvme_cmd_help(argv[1], desc, opts);			\
		opt_free_table();					\
		return -ENOEXEC;					\
	} while(0)

#define unvme_parse_args(exp_argc, argc, argv, opts, log_func, help, desc)	\
	do {									\
		if (!argc)							\
			unvme_help_return();					\
		opt_register_table(opts, NULL);					\
		if (!opt_parse(&(argc), argv, log_func))			\
			unvme_help_err();					\
		if (help)							\
			unvme_help_return();					\
										\
		if (argc < exp_argc)						\
			unvme_help_return();					\
		opt_free_table();						\
	} while (0)

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
int unvme_read(int argc, char *argv[], struct unvme_msg *msg);
int unvme_write(int argc, char *argv[], struct unvme_msg *msg);
int unvme_passthru(int argc, char *argv[], struct unvme_msg *msg);
int unvme_update_sqdb(int argc, char *argv[], struct unvme_msg *msg);
int unvme_reset(int argc, char *argv[], struct unvme_msg *msg);

/*
 * unvmed.c
 */
int unvmed(char *argv[]);

/*
 * unvme.c
 */
#define unvme_pr_err_return(ret, fmt, ...)			\
	do {							\
		unvme_pr_err("Error: "fmt, ##__VA_ARGS__);	\
		return ret;					\
	} while(0)

#endif
