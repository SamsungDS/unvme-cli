#include <sys/msg.h>
#include <sys/signal.h>
#include <vfn/nvme.h>
#include <ccan/str/str.h>
#include <ccan/opt/opt.h>
#include <ccan/list/list.h>

#define UNVME_MAX_OPT		64
#define UNVME_MAX_STR		32
#define UNVME_BDF_STRLEN	13
#define UNVME_PWD_STRLEN	256

/*
 * unvme handle
 */
struct unvme {
	struct nvme_ctrl ctrl;
	char bdf[UNVME_BDF_STRLEN];
	bool init;

	struct list_head sq_list;
	struct list_head cq_list;
	struct list_head cmd_list;

	struct list_node list;
};

struct unvme_sq {
	struct nvme_sq *sq;
	struct list_node list;
};

struct unvme_cq {
	struct nvme_cq *cq;
	struct list_node list;
};

struct unvme_cmd {
	struct unvme *unvme;

	struct nvme_rq *rq;
	union nvme_cmd sqe;
	struct nvme_cqe cqe;

	/* Data buffer for the corresponding NVMe command */
	void *vaddr;
	size_t len;
	uint64_t iova;

	bool should_free;
	struct list_node list;
};

static inline struct nvme_sq *unvme_sq(struct unvme *unvme, unsigned int qid)
{
	if (!unvme->ctrl.sq)
		return NULL;

	return (struct nvme_sq *)&unvme->ctrl.sq[qid];
}

static inline bool unvme_sq_exists(struct unvme *unvme, unsigned int qid)
{
	struct unvme_sq* usq;

	list_for_each(&unvme->sq_list, usq, list) {
		if(usq->sq->id == qid)
			return true;
	}

	return false;
}

static inline int unvme_map_vaddr(struct unvme *unvme, void *buf, size_t len,
				  uint64_t *iova, unsigned long flags)
{
	struct nvme_ctrl *ctrl = &unvme->ctrl;
	struct iommu_ctx *ctx = __iommu_ctx(ctrl);

	if (iommu_map_vaddr(ctx, buf, len, iova, flags))
		return -1;

	return 0;
}

static inline int unvme_map_vaddr_to_iova(struct unvme *unvme, void *buf,
					  size_t len, uint64_t *iova)
{
	return unvme_map_vaddr(unvme, buf, len, iova, IOMMU_MAP_FIXED_IOVA);
}

static inline int unvme_unmap_vaddr(struct unvme *unvme, void *buf)
{
	struct nvme_ctrl *ctrl = &unvme->ctrl;
	struct iommu_ctx *ctx = __iommu_ctx(ctrl);

	return iommu_unmap_vaddr(ctx, buf, NULL);
}

static inline struct unvme_cmd *unvme_cmd_alloc(struct unvme *unvme, int sqid,
						size_t data_len)
{
	struct unvme_cmd *cmd;
	struct nvme_sq *sq;
	struct nvme_rq *rq;
	uint64_t iova;

	if (!unvme_sq_exists(unvme, sqid))
		return NULL;

	sq = unvme_sq(unvme, sqid);

	rq = nvme_rq_acquire(sq);
	if (!rq)
		return NULL;

	cmd = zmalloc(sizeof(*cmd));
	if (!cmd)
		goto free_rq;

	cmd->unvme = unvme;
	cmd->rq = rq;

	if (data_len) {
		if (pgmap(&cmd->vaddr, data_len) != data_len)
			goto free_cmd;
		cmd->len = data_len;

		if (unvme_map_vaddr(unvme, cmd->vaddr, cmd->len, &iova, 0x0))
			goto free_buf;
	}

	cmd->iova = iova;
	cmd->should_free = true;

	list_add(&unvme->cmd_list, &cmd->list);

	return cmd;

free_buf:
	pgunmap(cmd->vaddr, cmd->len);
free_cmd:
	free(cmd);
free_rq:
	nvme_rq_release(rq);
	return NULL;
}

void unvmed_log_cmd_post(struct unvme_cmd *cmd);
void unvmed_log_cmd_cmpl(struct unvme_cmd *cmd);

static inline void unvme_cmd_post(struct unvme_cmd *cmd, bool update_sqdb)
{
	nvme_rq_post(cmd->rq, (union nvme_cmd *)&cmd->sqe);
	if (update_sqdb)
		nvme_sq_update_tail(cmd->rq->sq);
	unvmed_log_cmd_post(cmd);
}

static inline int unvme_cmd_cmpl(struct unvme_cmd *cmd)
{
	nvme_rq_spin(cmd->rq, &cmd->cqe);
	unvmed_log_cmd_cmpl(cmd);

	return nvme_cqe_ok(&cmd->cqe) ? 0 : 1;
}

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

#define UNVME_UNVMED_PID	"/var/run/unvmed.pid"
int unvmed(char *argv[]);
struct unvme *unvmed_ctrl(const char *bdf);
struct unvme *unvmed_alloc(const char *bdf);
int unvmed_free(const char *bdf);

static inline int unvme_unvmed_pid(void)
{
	char pid[8] = {};
	int fd;

	fd = open(UNVME_UNVMED_PID, O_RDONLY);
	if (fd < 0)
		return -EINVAL;

	read(fd, pid, sizeof(pid));
	return atoi(pid);
}

static inline bool unvme_unvmed_running(void)
{
	pid_t pid = unvme_unvmed_pid();

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

static inline void unvme_cmd_free(void *p)
{
	struct unvme_cmd *cmd = *(struct unvme_cmd **)p;

	if (cmd && cmd->should_free) {
		if (cmd->len) {
			unvme_unmap_vaddr(cmd->unvme, cmd->vaddr);
			pgunmap(cmd->vaddr, cmd->len);
		}
		nvme_rq_release(cmd->rq);
		list_del(&cmd->list);
	}
}
#define UNVME_FREE_CMD __attribute__((cleanup(unvme_cmd_free)))

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

#define UNVME_UNVMED_LOG	"/var/log/unvmed.log"
int unvmed_get_log_fd(void);

#define __log(type, fmt, ...)								\
	do { 										\
		char buf[550];								\
		int len = snprintf(buf, sizeof(buf),					\
				   "%-8s| %s: %d: " fmt "\n",				\
				   type, __func__, __LINE__, ##__VA_ARGS__);		\
		write(unvmed_get_log_fd(), buf, len);					\
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

/*
 * unvmed-print.c
 */
void unvmed_pr_raw(void *vaddr, size_t len);
void unvmed_pr_id_ns(void *vaddr);
void unvmed_pr_show_regs(void *vaddr);
void unvmed_pr_status(struct unvme *unvme);
