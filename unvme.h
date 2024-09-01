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

#ifndef UNVME_H
#define UNVME_H

struct opt_table;

#define UNVME_MAX_OPT		64
#define UNVME_MAX_STR		32
#define UNVME_BDF_STRLEN	13
#define UNVME_PWD_STRLEN	256

struct nvme_ctrl;
union nvme_cmd;
struct nvme_cqe;

enum unvme_msg_type {
	UNVME_MSG = 1,
};

struct unvme_msg {
	long type;

	struct {
		/*
		 * Request message from client to daemon
		 */
		int argc;
		char argv[UNVME_MAX_OPT][UNVME_MAX_STR];
		char bdf[UNVME_BDF_STRLEN];
		char pwd[UNVME_PWD_STRLEN];

		/*
		 * Response message from daemon to client
		 */
		int ret;
		size_t dsize; /* data size in bytes in case type is binary */
	} msg;
};

#define unvme_msg_bdf(p)	((p)->msg.bdf)
#define unvme_msg_pwd(p)	((p)->msg.pwd)
#define unvme_msg_dsize(p)	((p)->msg.dsize)

static inline void unvme_msg_update_len(struct unvme_msg *msg, size_t len)
{
	msg->msg.dsize = len;
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
void unvme_cmd_help(const char *name, const char *desc, struct opt_table *opts);
int unvme_send_msg(struct unvme_msg *msg);
int unvme_recv_msg(struct unvme_msg *msg);

#define UNVME_DAEMON_PID	"/var/run/unvmed.pid"
int unvmed(char *argv[]);
void unvme_datetime(char *datetime, size_t str_len);

static inline int unvme_get_daemon_pid(void)
{
	char pid[8] = {};
	int fd;

	fd = open(UNVME_DAEMON_PID, O_RDONLY);
	if (fd < 0)
		return -EINVAL;

	read(fd, pid, sizeof(pid));
	return atoi(pid);
}

static inline bool unvme_is_daemon_running(void)
{
	pid_t pid = unvme_get_daemon_pid();

	if (pid < 0)
		return false;

	if (kill(pid, 0))
		return false;

	return true;
}

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
int unvme_create_iosq(int argc, char *argv[], struct unvme_msg *msg);
int unvme_id_ns(int argc, char *argv[], struct unvme_msg *msg);
int unvme_read(int argc, char *argv[], struct unvme_msg *msg);
int unvme_write(int argc, char *argv[], struct unvme_msg *msg);
int unvme_passthru(int argc, char *argv[], struct unvme_msg *msg);
int unvme_update_sqdb(int argc, char *argv[], struct unvme_msg *msg);
int unvme_reset(int argc, char *argv[], struct unvme_msg *msg);

struct unvme_list {
	char bdf[UNVME_BDF_STRLEN];
};

int unvme_write_file(struct unvme_msg *msg, const char *filename, void *buf, size_t len);
int unvme_read_file(struct unvme_msg *msg, const char *filename, void *buf, size_t len);

static inline void unvme_free(void *p)
{
	void **ptr = (void **)p;
	if (*ptr) {
		free(*ptr);
		*ptr = NULL;
	}
}
#define UNVME_FREE __attribute__((cleanup(unvme_free)))

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

#define unvme_pr_err_return(ret, fmt, ...)			\
	do {							\
		unvme_pr_err("Error: "fmt, ##__VA_ARGS__);	\
		return ret;					\
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

#define UNVME_MSGQ_SQ		"/dev/mqueue/unvmed-sq"
#define UNVME_MSGQ_CQ		"/dev/mqueue/unvmed-cq"
#define UNVME_SHMEM_STDERR	"/unvmed-stderr"
#define UNVME_SHMEM_STDOUT	"/unvmed-stdout"

static inline int unvme_msgq_delete(const char *keyfile)
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

static inline int unvme_msgq_create(const char *keyfile)
{
	int msg_id;
	key_t key;
	int fd;

	fd = open(keyfile, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0)
		unvme_pr_return(-1, "failed to create msgq keyfile %s\n",
				keyfile);
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

static inline int unvme_msgq_send(int msg_id, struct unvme_msg *msg)
{
	if (msgsnd(msg_id, msg, sizeof(msg->msg), 0) < 0)
		unvme_pr_return(-1, "ERROR: failed to send a message\n");

	return 0;
}

static inline int unvme_msgq_recv(int msg_id, struct unvme_msg *msg)
{
	if (msgrcv(msg_id, msg, sizeof(msg->msg), 0, 0) < 0)
		unvme_pr_return(-1, "ERROR: failed to receive a message\n");

	return 0;
}

#define UNVME_DAEMON_LOG	"/var/log/unvmed.log"
int unvme_get_log_fd(void);

#define __log(type, fmt, ...)								\
	do { 										\
		char buf[550];								\
		char datetime[32];							\
											\
		unvme_datetime(datetime, sizeof(datetime));				\
		int len = snprintf(buf, sizeof(buf),					\
				   "%-8s| %s | %s: %d: " fmt "\n",			\
				   type, datetime, __func__, __LINE__, ##__VA_ARGS__);	\
		write(unvme_get_log_fd(), buf, len);					\
	} while(0)

#ifdef log_info
#undef log_info
#endif

#define log_info(fmt, ...)	__log("INFO", fmt, ##__VA_ARGS__)
#define log_err(fmt, ...)	__log("ERROR", fmt, ##__VA_ARGS__)
#define log_nvme(fmt, ...)	__log("NVME", fmt, ##__VA_ARGS__)

/*
 * XXX: It would be better if we can have stderr and stdout with dynamic size
 * during the runtime.
 */
#define UNVME_STDERR_SIZE	(4 * 1024 * 1024)

static inline void *__shmem(const char *name, size_t size)
{
	void *vaddr;
	int fd;

	fd = shm_open(name, O_CREAT | O_RDWR, 0666);
	if (fd < 0)
		return NULL;

	if (ftruncate(fd, size) < 0) {
		close(fd);
		return NULL;
	}

	vaddr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (vaddr == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	close(fd);
	return vaddr;
}

static inline void *unvme_stderr(void)
{
	return __shmem(UNVME_SHMEM_STDERR, UNVME_STDERR_SIZE);
}

static inline void *unvme_stdout(void)
{
	return __shmem(UNVME_SHMEM_STDOUT, UNVME_STDERR_SIZE);
}

struct unvme;

/*
 * unvmed-print.c
 */
void unvme_pr_raw(void *vaddr, size_t len);
void unvme_pr_id_ns(void *vaddr);
void unvme_pr_show_regs(struct unvme *u);
void unvme_pr_status(struct unvme *u);

/*
 * unvmed-logs.c
 */
void unvme_log_cmd_post(const char *bdf, uint32_t sqid, union nvme_cmd *sqe);
void unvme_log_cmd_cmpl(const char *bdf, struct nvme_cqe *cqe);

#endif
