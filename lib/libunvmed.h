/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */

#ifndef LIBUNVMED_H
#define LIBUNVMED_H

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/uio.h>
#include <sys/time.h>

#include "libunvmed-logs.h"

/*
 * `libunvmed`-specific structures
 */
struct unvme;
struct unvme_cmd;

/*
 * NVMe spec-based data structures defined in `libvfn`
 */
union nvme_cmd;
struct nvme_cqe;

/*
 * `libvfn`-specific structures
 */
struct nvme_sq;
struct nvme_cq;
struct nvme_rq;

/*
 * struct unvme_ns - Namespace instance
 * @u: unvme controller instance
 * @refcnt: reference count
 * @enabled: ``true`` if the unvme instance is in enabled state
 * @nsid: namespace identifier
 * @format_idx: LBA format index in Identify Namespace data structure
 * @lba_size: LBA size in bytes
 * @nr_lbas: number of logical blocks
 * @ms: metadata size in bytes
 * @mset: metadata setting (1: metadata is transferred as part of an extended
 *        data LBA.  Otherwise, metadata is transferred as part of separate
 *        buffer.
 * @pif: protection information format (00b: 16b, 01b: 32b, 10b: 64b guard)
 * @sts: stroage tag size
 * @lbstm: logical block storage tag mask
 */
#define unvme_declare_ns(name)	\
struct name {			\
	struct unvme *u;	\
				\
	int refcnt;		\
	bool enabled;		\
				\
	uint32_t nsid;		\
	uint8_t format_idx;	\
	unsigned int lba_size;	\
	unsigned long nr_lbas;	\
				\
	uint16_t ms;		\
	uint8_t mset;		\
	uint8_t pif;		\
	uint8_t dps;		\
	uint8_t sts;		\
	uint64_t lbstm;		\
}

/*
 * struct unvme_sq - Submission queue instance
 * @q: submission queue instance provided by libvfn
 * @ucq: unvme completion queue instance
 * @cmds: command instance array for @nr_cmds
 * @nr_cmds: number of command instances in the array @cmds
 * @lock: spinlock to protect the current unvme SQ instance
 * @enabled: ``true`` if the queue is enabled
 * @refcnt: reference count
 */
#define unvme_declare_sq(name)	\
struct name {			\
	struct nvme_sq *q;	\
	struct unvme_cq *ucq;	\
	struct unvme_cmd *cmds; \
	int nr_cmds;		\
	pthread_spinlock_t lock;\
	bool enabled;		\
	int refcnt;		\
}

/*
 * struct unvme_cq - Completion queue instance
 * @u: unvme controller instance
 * @q: completion queue instance provided by libvfn
 * @lock: spinlock to protect the current unvme CQ instance
 * @enabled: ``true`` if the queue is enabled
 * @refcnt: reference count
 */
#define unvme_declare_cq(name)	\
struct name {			\
	struct unvme *u;	\
	struct nvme_cq *q;	\
	struct unvme_sq *usq;	\
	pthread_spinlock_t lock;\
	bool enabled;		\
	int refcnt;		\
}

#define unvmed_cq_id(ucq)	((ucq)->q->id)
#define unvmed_cq_size(ucq)	((ucq)->q->qsize)
#define unvmed_cq_iv(ucq)	((ucq)->q->vector)
#define unvmed_sq_id(usq)	((usq)->q->id)
#define unvmed_sq_size(usq)	((usq)->q->qsize)
#define unvmed_sq_cqid(usq)	(unvmed_cq_id((usq)->ucq))

unvme_declare_ns(unvme_ns);
unvme_declare_cq(unvme_cq);
unvme_declare_sq(unvme_sq);

enum unvme_cmd_state {
	UNVME_CMD_S_INIT		= 0,
	UNVME_CMD_S_SUBMITTED,
	UNVME_CMD_S_COMPLETED,
	UNVME_CMD_S_TO_BE_COMPLETED,
};

enum unvmed_cmd_flags {
	/* No doorbell update after posting one or more commands */
	UNVMED_CMD_F_NODB	= 1 << 0,
	/* Use SGL in DPTR instead of PRP */
	UNVMED_CMD_F_SGL	= 1 << 1,
	/*
	 * To wake up unvmed_cmd_wait(cmd) on CQE being fetched.  This will
	 * prevent rcq entry pushed in case irq is enabled.
	 */
	UNVMED_CMD_F_WAKEUP_ON_CQE = 1 << 2,
};

struct unvme_buf {
	void *va;
	size_t len;
	/* Unmap user data buffer in unvmed_cmd_free() */
#define UNVME_CMD_BUF_F_VA_UNMAP	(1 << 0)
	/* Unmap I/O VA for user data buffer in unvmed_cmd_free() */
#define UNVME_CMD_BUF_F_IOVA_UNMAP	(1 << 1)
	unsigned int flags;

	/*
	 * Inlined single iovec representing the entire buffer.  If
	 * user wants to define their own iovec list, this can be
	 * no-used.  If user wants to issue a single iovec, user also
	 * can user this instance by updating the value inside of it.
	 */
	struct iovec iov;
};

/*
 * struct unvme_cmd - NVMe command instance
 * @u: unvme controller instance
 * @state: command state
 * @rq: command request instance provided by libvfn
 * @buf: data buffer to be mapped to DPTR in submission queue entry
 * @opaque: opaque data
 */
struct unvme_cmd {
	struct unvme *u;

	enum unvme_cmd_state state;
	unsigned long flags;

	struct unvme_sq *usq;

	/*
	 * rq->opaque will point to the current structure pointer.
	 */
	struct nvme_rq *rq;

	struct unvme_buf buf;
	struct unvme_buf mbuf;  /* mbuf is valid only in DIX mode */

	void *opaque;

	/*
	 * Command completion notifier.  Caller can wait for @completed with
	 * the futex WAIT.  It will be updated only just in case of RCQ mode.
	 * If it is set, it means CQE has already been reaped and @cmd->cqe
	 * is the one.  This field is only valid in UNVMED_CMD_F_REQ_CQE.
	 */
	bool completed;

	/*
	 * Submission Queue Entry pushed for this command.
	 */
	union nvme_cmd sqe;

	/*
	 * If @flags is set with UNVMED_CMD_F_REQ_CQE, @cqe will be updated by
	 * libunvmed when cqe is reaped from CQ (only in RCQ mode w/ interrupt
	 * enabled).
	 */
	struct nvme_cqe cqe;
};

struct unvme_hmb {
	struct {
		__le64 badd;
		__le32 bsize;
		uint32_t rsvd;
	} *descs;
	uint64_t *descs_vaddr;
	uint64_t descs_iova;
	size_t descs_size;
	int nr_descs;
	uint32_t hsize;
};

struct unvme_sq *unvmed_sq_find(struct unvme *u, uint32_t qid);
struct unvme_cq *unvmed_cq_find(struct unvme *u, uint32_t qid);

/**
 * unvmed_sq_enter - Acquire a lock for the given @usq
 * @usq: submission queue instance
 */
static inline void unvmed_sq_enter(struct unvme_sq *usq)
{
	pthread_spin_lock(&usq->lock);
}

/**
 * unvmed_sq_try_enter - Try to acquire a lock for the given @usq
 * @usq: submission queue instance
 *
 * It tries to grab a lock for the given @usq, if fails, return non-zero value.
 *
 * Return: ``0`` on success, otherwise non-zero on errors.
 */
static inline int unvmed_sq_try_enter(struct unvme_sq *usq)
{
	return pthread_spin_trylock(&usq->lock);
}

/**
 * unvmed_sq_exit - Release a lock for the given @usq
 * @usq: submission queue instance
 */
static inline void unvmed_sq_exit(struct unvme_sq *usq)
{
	pthread_spin_unlock(&usq->lock);
}

/**
 * unvmed_cq_enter - Acquire a lock for the given @ucq
 * @ucq: completion queue instance
 */
static inline void unvmed_cq_enter(struct unvme_cq *ucq)
{
	pthread_spin_lock(&ucq->lock);
}

/**
 * unvmed_cq_exit - Release a lock for the given @ucq
 * @ucq: completion queue instance
 */
static inline void unvmed_cq_exit(struct unvme_cq *ucq)
{
	pthread_spin_unlock(&ucq->lock);
}

/**
 * unvmed_sq_enabled - Check whether the submission queue is enabled (live)
 * @usq: submission queue instance
 *
 * Return: true if the given queue is alive.
 */
static inline bool unvmed_sq_enabled(struct unvme_sq *usq)
{
	if (!usq || (usq && !usq->enabled))
		return false;
	return true;
}

/**
 * unvmed_sq_entry - Return a SQ entry pointer located at @db
 * @usq: submission queue instance
 * @db: doorbell value inside of queue
 *
 * Return: SQ entry pointer
 */
static inline union nvme_cmd *unvmed_sq_entry(struct unvme_sq *usq, uint16_t db)
{
	return usq->q->mem.vaddr + db * sizeof(union nvme_cmd);
}

/**
 * unvmed_sq_for_each_entry - Macro to iterate on pending entries of @usq
 * @usq: submission queue instance
 * @id: index from 0
 * @entry: submission queue entry to be assigned
 *
 * This API is not thread-safe.  @usq should be locked with
 * `unvmed_sq_enter()`.
 */
#define unvmed_sq_for_each_entry(usq, id, entry) \
	uint32_t _i; \
	for ((id) = 0, _i = ((usq)->q)->ptail, \
		(entry) = unvmed_sq_entry(usq, _i); \
		_i != ((usq)->q)->tail; \
		_i = (_i + 1) % ((usq)->q)->qsize, \
		(entry) = unvmed_sq_entry(usq, _i), (id)++)

/**
 * unvmed_cq_enabled - Check whether the completion queue is enabled (live)
 * @u: &struct unvme
 * @qid: completion queue identifier
 *
 * Return: true if the given queue is alive.
 */
static inline bool unvmed_cq_enabled(struct unvme *u, uint32_t qid)
{
	struct unvme_cq *ucq = unvmed_cq_find(u, qid);

	if (!ucq || (ucq && !ucq->enabled))
		return false;
	return true;
}

/**
 * unvmed_cq_irq_enabled - Check whether @ucq supports interrupt
 * @ucq: completion queue instance
 *
 * Completion queue vector -1 means no interrupt supported even the actual
 * vector value is written to any other value in the controller register or
 * Create I/O CQ command.
 *
 * Return: ``true`` if given @ucq support interrupt, otherwise ``false``.
 */
static inline bool unvmed_cq_irq_enabled(struct unvme_cq *ucq)
{
	return ucq->q->vector >= 0;
}

/**
 * unvmed_init - Initialize libunvmed library
 * @logfile: logfile path, NULL if no-log mode
 *
 * Initialize libunvmed library in the current process context.
 */
void unvmed_init(const char *logfile, int log_level);

/**
 * unvmed_parse_bdf - Parse a given input string to fully formed bdf
 * @input: input string to be parsed (e.g., "0:1")
 * @bdf: output string which is fully formed as a PCI BDF format (e.g.
 *	 "0000:01:00.0"
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_parse_bdf(const char *input, char *bdf);

/**
 * unvmed_init_ctrl - Initialize PCI NVMe controller device
 * @bdf: bus-device-function address of PCI NVMe controller
 * @max_nr_ioqs: maximum number of I/O queue identifier (QID) to be supported
 *
 * Initialize the given @bdf PCI device as a NVMe controller instance (&struct
 * unvme).  @max_nr_ioqs represents a limitation of the maximum QID to be
 * supported.
 *
 * Return: &struct unvme, otherwise ``NULL`` on error with ``errno`` set.
 */
struct unvme *unvmed_init_ctrl(const char *bdf, uint32_t max_nr_ioqs);

/**
 * unvmed_free_ctrl - Free a given NVMe controller instance
 * @u: &struct unvme
 *
 * Free all the resources related to the given @u.
 */
void unvmed_free_ctrl(struct unvme *u);

/**
 * unvmed_free_ctrl_all - Free all NVMe controller instances
 * @u: &struct unvme
 *
 * Free all the resources of all the controller instances in the current
 * process context.
 */
void unvmed_free_ctrl_all(void);

/**
 * unvmed_get - Get an unvme instance
 * @bdf: bus-device-function address of PCI NVMe controller
 *
 * Return: &struct unvme, otherwise NULL.
 */
struct unvme *unvmed_get(const char *bdf);

/**
 * unvmed_cmb_init - Initialize Controller Memory Buffer
 * @u: &struct unvme
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmb_init(struct unvme *u);

/**
 * unvmed_cmb_free - Free Controller Memory Buffer
 * @u: &struct unvme
 */
void unvmed_cmb_free(struct unvme *u);

/**
 * unvmed_cmb_get_region - Get CMB region address and size
 * @u: &struct unvme
 * @vaddr: output to indicate mapped CMB region
 *
 * Return: positive value indicating the size of CMB area, otherwise error with
 * ``errno`` set.
 */
ssize_t unvmed_cmb_get_region(struct unvme *u, void **vaddr);

/**
 * unvmed_ns_get - Get a namespace instance (&struct unvme_ns) with refcnt
 *                 incremented
 * @u: &struct unvme
 * @nsid: namespace identifier
 *
 * Get a namespace instance from the given controller @u which has been
 * identified by unvmed_init_ns() with @ns->refcnt incremented which means
 * caller will keep using this queue instance until calling unvmed_ns_put()
 * explicitly.
 *
 * Return: &struct unvme_ns, otherwise NULL.
 */
struct unvme_ns *unvmed_ns_get(struct unvme *u, uint32_t nsid);

/**
 * unvmed_ns_put - Put a namespace instance (&struct unvme_ns) with recnt
 *                 decremented
 * @u: &struct unvme
 * @ns: namespace instance (&struct unvme_ns)
 *
 * It puts the given @ns instance by decrementing @ns->refcnt and if it reaches
 * to 0, @ns will be freed up and no longer valid after this call.
 *
 * Return: @ns->refcnt decremented.
 */
int unvmed_ns_put(struct unvme *u, struct unvme_ns *ns);

/**
 * unvmed_ns_find - Find a namespace instance (&struct unvme_ns)
 * @u: &struct unvme
 * @nsid: namespace identifier
 *
 * Get a namespace instance from the given controller @u which has been
 * identified by unvmed_init_ns().
 *
 * Return: &struct unvme_ns, otherwise NULL.
 */
struct unvme_ns *unvmed_ns_find(struct unvme *u, uint32_t nsid);

/**
 * unvmed_get_nslist - Get attached namespace list to the controller
 * @u: &struct unvme
 * @nslist: namespace list to copy to
 *
 * It gives namespace list attached to the controller @u.  If user has never
 * issued an Identify Namespace command by unvmed_init_ns(), the namespace will
 * won't be included in the @nslist.  Regardless to the namespaces attached to
 * the actual controller hw, it returns namespaces which have been seen by
 * unvme driver context.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_get_nslist(struct unvme *u, struct unvme_ns **nslist);

/**
 * unvmed_init_ns - Initialize namespace instance and register to driver
 * @u: &struct unvme
 * @nsid: namespace identifier
 * @identify: identify namespace data structure (can be NULL)
 *
 * This API registers the given namesapce instance to the controller instance
 * @u.  Once a namespace is registered to driver context, unvmed_get_ns() and
 * unvmed_get_nslist() will return the namespace instance.
 *
 * If @identify is given with non-NULL, it will skip issuing Identify Namespace
 * admin command to identify the namespace, instead it assumes that Identify
 * command has already been issued and the given @identify is the data returned
 * by the device controller.  Based on the @identify data, it will register a
 * namespace instance to the given controller @u.
 *
 * If @identify is NULL, it will issue an Identify Namespace admin command to
 * the controller and register a namespace instance to the driver context.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_init_ns(struct unvme *u, uint32_t nsid, void *identify);

/**
 * unvmed_init_meta_ns - Initialize namespace instance with metadata info
 * @u: &struct unvme
 * @nsid: namespace identifier
 * @nvm_id_ns: identify namespace (NVM command set) data structure (can be NULL)
 *
 * This API sets some metadata informations to the given namespace instance,
 * which has @nsid as its id.
 *
 * This function issues an Identify Controller admin command to figure out
 * whether ELBAS(Extended LBA Support) or not if caller has not
 * issued(identified) the controller before calling this function.
 *
 * If @nvm_id_nsis given with non-NULL, it will skip issuing Identify Namespace
 * for NVM command set admin command to identify the namespace, instead it
 * assumes that Identify command has already been issued and the given
 * @nvm_id_ns is the data returned by the device controller.  Based on the
 * @nvm_id_ns data, it will register a namespace instance to the given
 * controller @u.
 *
 * If @nvm_id_nsis NULL, it will issue an Identify Namespace for NVM command
 * set admin command to the controller and register a namespace instance to the
 * driver context.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_init_meta_ns(struct unvme *u, uint32_t nsid, void *nvm_id_ns);

/**
 * unvmed_nr_cmds - Get a number of in-flight commands
 * @u: &struct unvme
 *
 * It gives a number of in-flight commands for the corresponding controller @u.
 * In-flight command menas it's been issued to a sq, but not yet completed by
 * cq.
 *
 * Return: Number of in-flight commands
 */
int unvmed_nr_cmds(struct unvme *u);

/**
 * unvmed_get_sqs - Get created SQ list
 * @u: &struct unvme
 * @sqs: submission queue instance list
 *
 * It gives a list of submission queue instances (&struct nvme_sq) created to
 * the given controller @u.  @sqs will be allocated in this API and caller
 * should free up the @sqs after using it.
 *
 * Return: Number of sq in the list, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_get_sqs(struct unvme *u, struct nvme_sq **sqs);

/**
 * unvmed_get_cqs - Get created CQ list
 * @u: &struct unvme
 * @cqs: completion queue instance list
 *
 * It gives a list of completion queue instances (&struct nvme_cq) created to
 * the given controller @u.  @cqs will be allocated in this API and caller
 * should free up the @cqs after using it.
 *
 * Return: Number of cq in the list, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_get_cqs(struct unvme *u, struct nvme_cq **cqs);

/**
 * unvmed_sq_get - Get a submission queue instance with refcnt incremented
 * @u: &struct unvme
 * @qid: submission queue identifier
 *
 * Return a submission queue instance created in the given controller @u with
 * refcnt incremented which means caller will keep using this queue instance
 * until calling unvmed_sq_put() explicitly.
 *
 * Return: &struct unvme_sq, otherwise ``NULL``.
 */
struct unvme_sq *unvmed_sq_get(struct unvme *u, uint32_t qid);

/**
 * unvmed_cq_get - Get a completion queue instance with refcnt incremented
 * @u: &struct unvme
 * @qid: completion queue identifier
 *
 * Return a completion queue instance created in the given controller @u with
 * refcnt incremented which means caller will keep using this queue instance
 * until calling unvmed_cq_put() explicitly.
 *
 * Return: &struct unvme_cq, otherwise ``NULL``.
 */
struct unvme_cq *unvmed_cq_get(struct unvme *u, uint32_t qid);

/**
 * unvmed_sq_put - Put a submission queue instance with refcnt decremented
 * @u: &struct unvme
 * @usq: submission queue (&struct unvme_sq)
 *
 * It puts the given @usq instance by decrementing @usq->refcnt and if it
 * reaches to 0, @usq will be freed up and no longer valid after this call.
 *
 * Return: @usq->refcnt decremented.
 */
int unvmed_sq_put(struct unvme *u, struct unvme_sq *usq);

/**
 * unvmed_cq_put - Put a completion queue instance with refcnt decremented
 * @u: &struct unvme
 * @usq: completion queue (&struct unvme_sq)
 *
 * It puts the given @ucq instance by decrementing @ucq->refcnt and if it
 * reaches to 0, @ucq will be freed up and no longer valid after this call.
 *
 * Return: @ucq->refcnt decremented.
 */
int unvmed_cq_put(struct unvme *u, struct unvme_cq *ucq);

/**
 * unvmed_sq_find - Find a submission queue instance
 * @u: &struct unvme
 * @qid: submission queue identifier
 *
 * Return a submission queue instance created in the given controller @u.  This
 * API does not update refcnt at all.
 *
 * Return: &struct unvme_sq, otherwise ``NULL``.
 */
struct unvme_sq *unvmed_sq_find(struct unvme *u, uint32_t qid);

/**
 * unvmed_cq_find - Find a completion queue instance
 * @u: &struct unvme
 * @qid: completion queue identifier
 *
 * Return a completion queue instance created in the given controller @u.  This
 * API does not update refcnt at all.
 *
 * Return: &struct unvme_cq, otherwise ``NULL``.
 */
struct unvme_cq *unvmed_cq_find(struct unvme *u, uint32_t qid);

/**
 * unvmed_init_id_ctrl - Keep identify controller data structure
 * @u: &struct unvme
 * @id_ctrl: identify controller data structure to keep
 *
 * Copy the given @id_ctrl data and keep the data inside of @u->id_ctrl.  This
 * is to retrieve the controller identify attributes during the runtime from
 * application and this library.
 */
int unvmed_init_id_ctrl(struct unvme *u, void *id_ctrl);

/**
 * unvmed_alloc_cmd - Allocate a NVMe command instance.
 * @u: &struct unvme
 * @usq: submission queue instance (&struct unvme_sq)
 * @buf: user data buffer virtual address
 * @len: size of user data buffer in bytes
 *
 * Allocate a NVMe command instance with the given user data buffer poitner. If
 * @buf != NULL && @len > 0, it will check whether the given buffer address has
 * already been mapped to IOMMU.  If not, it will automatically map the given
 * buffer to the IOMMU table and it will be unmapped in unvmed_cmd_free().  If
 * @buf == NULL && @len > 0, it will allocate a buffer with the specific given
 * size and map it to the IOMMU table.  The buffer and the mapping of IOMMU will
 * be freed up in unvmed_cmd_free().  If @buf == NULL && @len == 0, it will not
 * prepare any data buffer to transfer.
 *
 * This API is thread-safe.
 *
 * Return: Command instance (&struct unvme_cmd), ``NULL`` on error.
 */
struct unvme_cmd *unvmed_alloc_cmd(struct unvme *u, struct unvme_sq *usq, void *buf,
				   size_t len);

/**
 * unvmed_alloc_cmd_nodata - Allocate a NVMe command instance without data
 * @u: &struct unvme
 * @usq: submission queue instance (&struct unvme_sq)
 *
 * Allocate a NVMe command instance without data buffer to trasnfer.
 *
 * This API is thread-safe.
 *
 * Return: Command instance (&struct unvme_cmd), ``NULL`` on error.
 */
struct unvme_cmd *unvmed_alloc_cmd_nodata(struct unvme *u, struct unvme_sq *usq);

/**
 * unvmed_alloc_cmd_meta - Allocate a NVMe command instance with metadata
 * @u: &struct unvme
 * @usq: submission queue instance (&struct unvme_sq)
 * @buf: user data buffer virtual address
 * @len: size of user data buffer in bytes
 * @mbuf: metadata buffer virtual address
 * @mlen: size of metadata buffer in bytes
 *
 * Allocate a NVMe command instance with data and metadata buffer to trasnfer.
 * If @ns has extended metadata buffer format, there is no need to @mbuf and
 * @mlen.
 *
 * This API is thread-safe.
 *
 * Return: Command instance (&struct unvme_cmd), ``NULL`` on error.
 */
struct unvme_cmd *unvmed_alloc_cmd_meta(struct unvme *u, struct unvme_sq *usq, void *buf,
					size_t len, void *mbuf, size_t mlen);

/**
 * __unvmed_cmd_free - Destroy a NVMe command instance
 * @cmd: command instance (&struct unvme_cmd)
 *
 * Destroy a given command instance.  @cmd->rq will be destroyed in libvfn and
 * @cmd itself will completely be zeroed.
 *
 * This API is thread-safe.
 */
void __unvmed_cmd_free(struct unvme_cmd *cmd);

/**
 * unvmed_cmd_free - Destroy a NVMe command instance with memory teardown
 * @cmd: command instance (&struct unvme_cmd)
 *
 * Destroy a given command instance after releasing data buffer.  It checks
 * @cmd->buf.flags to determine whether to unmap or free the buffer or not.
 * After this, it destroys the given command instance by __unvmed_cmd_free().
 *
 * This API is thread-safe.
 */
void unvmed_cmd_free(struct unvme_cmd *cmd);

/**
 * unvmed_reset_ctrl - Reset controller
 * @u: &struct unvme
 *
 * Reset a given NVMe controller.  First it deasserts CC.EN to 0 and wait for
 * CSTS.RDY to be 0.  And it quiesce all the submission queues to stop
 * submissions from upper layer (e.g., app) and cancel in-flight commands by
 * putting artificial CQ entries with Host Aborted status code in NVMe spec.
 * And it resumes for them to be fetched from the upper layer.  Finally, it
 * frees up all the namespace instances registered to the controller @u.
 */
void unvmed_reset_ctrl(struct unvme *u);

/**
 * unvmed_reset_ctrl_graceful - Reset controller gracefully
 * @u: &struct unvme
 *
 * Reset a given NVMe controller.  First, it deletes all the created I/O queue
 * pairs quiescing the subsmission queues to prevent upper layer's I/O
 * requests.  After that, it deasserts CC.EN to 0 and wait for CSTS.RDY to be
 * 0.
 */
void unvmed_reset_ctrl_graceful(struct unvme *u);

/**
 * unvmed_create_adminq - Configure admin SQ and CQ
 * @u: &struct unvme
 *
 * Create admin SQ and CQ instances in libvfn and configure admin queue
 * registers in controller attribute registers accordingly.  This API does not
 * enable the controller, which should be done explicitly by calling
 * unvmed_enable_ctrl().
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_create_adminq(struct unvme *u);

/**
 * unvmed_enable_ctrl - Enable NVMe controller
 * @u: &struct unvme
 * @iosqes: I/O Submission Queue Entry Size (specified as 2^n)
 * @iocqes: I/O Completion Queue Entry Size (specified as 2^n)
 * @mps: Memory Page Size (specified as (2 ^ (12 + n)))
 * @css: I/O Command Set Selected
 *
 * Enable the given NVMe controller by asserting CC.EN to 1 along with the
 * given other values to Controller Configuration register.  This API makes
 * sure that the controller is ready by waiting for CSTS.RDY to be 1.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_enable_ctrl(struct unvme *u, uint8_t iosqes, uint8_t iocqes,
		       uint8_t mps, uint8_t css);

/**
 * unvmed_create_cq - Create I/O Completion Queue
 * @u: &struct unvme
 * @qid: completion queue identifier to create
 * @qsize: number of queue entries
 * @vector: interrupt vector.  -1 to disable interrupt
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_create_cq(struct unvme *u, uint32_t qid, uint32_t qsize, int vector);

/**
 * unvmed_delete_cq - Delete I/O Completion Queue
 * @u: &struct unvme
 * @qid: completion queue identifier to create
 *
 * Issue a Delete I/O Completion Queue admin command to @u.  If the given CQ
 * has interrupt enabled, it will also disable irq and free up @ucq instance.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_delete_cq(struct unvme *u, uint32_t qid);

/**
 * unvmed_create_sq - Create I/O Submission Queue
 * @u: &struct unvme
 * @qid: submission queue identifier to create
 * @qsize: number of queue entries
 * @cqid: corresponding completion queue identifier
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_create_sq(struct unvme *u, uint32_t qid, uint32_t qsize,
		     uint32_t cqid);

/**
 * unvmed_delete_sq - Delete I/O Submission Queue
 * @u: &struct unvme
 * @qid: completion queue identifier to create
 *
 * Issue a Delete I/O Submission Queue admin command to @u.  It will also free
 * up @usq instance.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_delete_sq(struct unvme *u, uint32_t qid);

/**
 * unvmed_to_iova - Translate given vaddr to an I/O virtual address (IOVA)
 * @u: &struct unvme
 * @buf: virtual address to translate
 * @iova: output I/O virtual address
 *
 * Translate the given @buf to @iova based on IOMMU translation table.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_to_iova(struct unvme *u, void *buf, uint64_t *iova);

/**
 * unvmed_to_vaddr - Translate given I/O virtual address (IOVA) to virtual
 * @u: &struct unvme
 * @iova: output I/O virtual address
 * @vaddr: virtual address
 *
 * Translate the given @iova to @vaddr based on IOMMU translation table.
 *
 * This API is thread-safe.
 *
 * Return: accessible size on success, otherwise ``-1`` with ``errno`` set.
 */
ssize_t unvmed_to_vaddr(struct unvme *u, uint64_t iova, void **vaddr);

/**
 * unvmed_map_vaddr - Map given virtual address to IOMMU table
 * @u: &struct unvme
 * @buf: virtual address to translate
 * @len: size of given buffer @buf in bytes
 * @iova: output I/O virtual address
 * @flags: flags defined in (enum iommu_map_flags) of libvfn
 *
 * Map the given @buf virtual address for the given size @len to IOMMU
 * mapping table.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_map_vaddr(struct unvme *u, void *buf, size_t len, uint64_t *iova,
		     unsigned long flags);

/**
 * unvmed_unmap_vaddr - Unmap given virtual address from IOMMU table
 * @u: &struct unvme
 * @buf: virtual address to translate
 *
 * Unmap the given @buf virtual address from IOMMU mapping table.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_unmap_vaddr(struct unvme *u, void *buf);

/**
 * unvmed_cmd_post - Post a command to a corresponding submission queue
 * @cmd: command instance (&struct unvme_cmd)
 * @sqe: submission queue entry (&union nvme_cmd)
 * @flags: control flags (enum unvmed_cmd_flags)
 *
 * Post a given @sqe to the corresponding submission queue @cmd->usq.  If
 * @flags has UNVMED_CMD_F_NODB, it won't update the submission queue tail
 * doorbell.  By default, it updates the tail doorbell register after posting
 * the given @sqe to the @cmd->usq.
 *
 * After posting @sqe, @cmd->state will be set to UNVME_CMD_S_SUBMITTED.
 *
 * This API is not thread-safe.  Caller should acquire a lock by calling
 * unvmed_sq_enter() for the corresponding submission queue.
 */
void unvmed_cmd_post(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		     unsigned long flags);

/**
 * unvmed_get_cmd - Get &struct unvme_cmd instance
 * @usq: submission queue (&struct unvme_sq)
 * @cid: command identifier
 *
 * Return: &struct unvme_cmd pointer
 */
static inline struct unvme_cmd *unvmed_get_cmd(struct unvme_sq *usq,
					       uint16_t cid)
{
	return &usq->cmds[cid];
}

/**
 * unvmed_get_cmd_from_cqe - Convert &struct nvme_cqe to &struct unvme_cmd
 * @u: &struct unvme
 * @cqe: completion queue entry (&struct nvme_cqe)
 *
 * Convert a given @cqe to &struct unvme_cmd for uppser layer translation.
 *
 * Return: &struct unvme_cmd, otherwise ``NULL`` on error.
 */
struct unvme_cmd *unvmed_get_cmd_from_cqe(struct unvme *u,
					  struct nvme_cqe *cqe);

/**
 * __unvmed_cq_run_n - Reap CQ entries from a completion queue
 * @u: &struct unvme
 * @ucq: completion queue (&struct unvme_cq)
 * @cqes: output completion queue entry list array
 * @nr_cqes: number of cq entries to fetch
 * @nowait: whether to wait for @nr_cqes or return immedietly
 *
 * Reap @nr_cqes CQ entries from the given @ucq.  If @nowait is true, if CQ
 * is empty, return immedietly even if it has not yet fetched @cqes for
 * @nr_cqes.
 *
 * Return: Number of cq entries fetched.
 */
int __unvmed_cq_run_n(struct unvme *u, struct unvme_cq *ucq,
		      struct nvme_cqe *cqes, int nr_cqes, bool nowait);

/**
 * unvmed_cq_run - Reap all CQ entries from a completion queue
 * @u: &struct unvme
 * @ucq: completion queue (&struct unvme_cq)
 * @cqes: output completion queue entry list array
 *
 * Reap all CQ entries from @ucq as many as possible until the @ucq to be
 * empty.
 *
 * Return: Number of cq entries fetched.
 */
int unvmed_cq_run(struct unvme *u, struct unvme_cq *ucq, struct nvme_cqe *cqes);

/**
 * unvmed_cq_run_n - Reap ``N`` CQ entries from a completion queue
 * @u: &struct unvme
 * @ucq: completion queue (&struct unvme_cq)
 * @cqes: output completion queue entry list array
 * @min: minimum number of to fetch (mandatory)
 * @max: maximum number of to fetch (best effort)
 *
 * Reap @min ~ @max CQ entries from @ucq.
 *
 * Return: Number of cq entries fetched.
 */
int unvmed_cq_run_n(struct unvme *u, struct unvme_cq *ucq,
		    struct nvme_cqe *cqes, int min, int max);

/**
 * unvmed_sq_nr_pending_sqes - Get the number of pending SQ entries
 * @usq: submission queue (&struct unvme_sq)
 *
 * This API is not thread-safe for the given @usq.  Caller should acquire lock
 * for the corresponding @usq.
 *
 * Return: The number of pending SQ entries which have been pushed without tail
 * doorbell updated.
 */
int unvmed_sq_nr_pending_sqes(struct unvme_sq *usq);

/**
 * unvmed_sq_update_tail - Update tail pointer of the given submission queue.
 * @u: &struct unvme
 * @usq: submission queue (&struct unvme_sq)
 *
 * Update tail pointer, which are advanced by unvmed_cmd_post() with @flags
 * UNVMED_CMD_F_NODB, to controller doorbell register.  This is used to update
 * tail doorbell at once to issue one or more multiple commands.
 *
 * This API is not thread-safe for the given @usq.  Caller should acquire lock
 * for the corresponding @usq.
 *
 * Return: The number of SQ entries issued and 0 if no SQ entry is issued.
 */
int unvmed_sq_update_tail(struct unvme *u, struct unvme_sq *usq);


/**
 * __unvmed_mapv_prp - Map and configure iovecs as PRP to command
 * @cmd: command instance (&struct unvme_cmd)
 * @sqe: submission queue entry (&union nvme_cmd)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Make a PRP data structure for data pointer in @sqe with @iov for number of
 * @nr_iov vectors.  libvfn prepares PRP data structure and map it to the given
 * @sqe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int __unvmed_mapv_prp(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		      struct iovec *iov, int nr_iov);

/**
 * __unvmed_mapv_prp_list - Map and configure iovecs as PRP to command with
 *                          PRP list
 * @cmd: command instance (&struct unvme_cmd)
 * @sqe: submission queue entry (&union nvme_cmd)
 * @prplist: memory page address of a PRP list (address to be written to PRP2)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Make a PRP data structure for data pointer in @sqe with @iov for number of
 * @nr_iov vectors.  libvfn prepares PRP data structure and map it to the given
 * @sqe.
 *
 * Caller *should* map @prplist to the IOMMU page table before calling this
 * helper.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int __unvmed_mapv_prp_list(struct unvme_cmd *cmd, union nvme_cmd *sqe,
			   void *prplist, struct iovec *iov, int nr_iov);

/**
 * __unvmed_mapv_prp - Map and configure iovecs as PRP to command
 * @cmd: command instance (&struct unvme_cmd)
 * @sqe: submission queue entry (&union nvme_cmd)
 *
 * Make a PRP data structure for data pointer in @sqe with @cmd->buf.iov which
 * is an inline iovec structure.  It's same with __unvmed_mapv_prp(@cmd, @sqe,
 * &@cmd->buf.iov, 1);
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_mapv_prp(struct unvme_cmd *cmd, union nvme_cmd *sqe);

/**
 * __unvmed_mapv_sgl - Map and configure iovecs as SGL to command
 * @cmd: command instance (&struct unvme_cmd)
 * @sqe: submission queue entry (&union nvme_cmd)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Make a SGL data structure for data pointer in @sqe with @iov for number of
 * @nr_iov vectors.  libvfn prepares SGL data structure and map it to the given
 * @sqe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int __unvmed_mapv_sgl(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		      struct iovec *iov, int nr_iov);


/**
 * __unvmed_mapv_sgl_seg - Map and configure iovecs as SGL with segment to command
 * @cmd: command instance (&struct unvme_cmd)
 * @sqe: submission queue entry (&union nvme_cmd)
 * @seg: SGL segment memory page address
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Make a SGL data structure for data pointer in @sqe with @iov for number of
 * @nr_iov vectors.  libvfn prepares SGL data structure and map it to the given
 * @sqe.
 *
 * Caller *should* map @seg to the IOMMU page table before calling this helper.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int __unvmed_mapv_sgl_seg(struct unvme_cmd *cmd, union nvme_cmd *sqe,
			  struct nvme_sgld *seg, struct iovec *iov, int nr_iov);

/**
 * __unvmed_mapv_sgl - Map and configure iovecs as SGL to command
 * @cmd: command instance (&struct unvme_cmd)
 * @sqe: submission queue entry (&union nvme_cmd)
 *
 * Make a SGL data structure for data pointer in @sqe with @cmd->buf.iov which
 * is an inline iovec structure.  It's same with __unvmed_mapv_sgl(@cmd, @sqe,
 * &@cmd->buf.iov, 1);
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_mapv_sgl(struct unvme_cmd *cmd, union nvme_cmd *sqe);

/**
 * unvmed_cmd_prep - Prepare unvme command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @sqe: submission queue entry (&union nvme_cmd)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Prepare a unvme command instance with the given @sqe by putting it to
 * @cmd->sqe by value.  This API also maps the given @iov as PRP to
 * &cmd->sqe.dptr.
 *
 * After calling this, `unvmed_cmd_issue(@cmd)` will issue the command.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		    struct iovec *iov, int nr_iov);

/**
 * unvmed_cmd_issue - Issue a given @cmd command
 * @cmd: command instance (&struct unvme_cmd)
 *
 * Issue a given @cmd to a specific submission queue.  @cmd->sqe should be
 * filled up before calling this API by `unvmed_cmd_prep(@cmd, &sqe, ...)`.
 *
 * This API is thread-safe.
 */
void unvmed_cmd_issue(struct unvme_cmd *cmd);

/**
 * unvmed_cmd_issue_and_wait - Issue a given @cmd command and wait to complete
 * @cmd: command instance (&struct unvme_cmd)
 *
 * Issue a given @cmd to a specific submission queue.  @cmd->sqe should be
 * filled up before calling this API by `unvmed_cmd_prep(@cmd, &sqe, ...)`.
 *
 * This API waits for the @cmd to complete after submitting it.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, -1 on error, otherwise CQE status field.
 */
int unvmed_cmd_issue_and_wait(struct unvme_cmd *cmd);

/**
 * unvmed_passthru - Passthru command
 * @cmd: command instance (&struct unvme_cmd)
 * @sqe: submission queue entry (&union nvme_cmd)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Issue an user-given custom command to the controller @u.  Caller should form
 * @sqe to issue.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise CQE status field.
 */
int unvmed_passthru(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		    struct iovec *iov, int nr_iov);

/**
 * unvmed_cmd_prep_id_ns - Prepare Identify Namespace (CNS 0h) command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Prepare an Identify Namespace command instance with the given values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_id_ns(struct unvme_cmd *cmd, uint32_t nsid,
			  struct iovec *iov, int nr_iov);

/**
 * unvmed_id_ns - Identify Namespace (CNS 0h)
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Issue an Identify Namespace command to the controller @u.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise CQE status field.
 */
int unvmed_id_ns(struct unvme_cmd *cmd, uint32_t nsid,
		 struct iovec *iov, int nr_iov);

/**
 * unvmed_cmd_prep_id_ctrl - Prepare Identify Controller (CNS 1h) command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Prepare an Identify Controller command instance with the given values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_id_ctrl(struct unvme_cmd *cmd, struct iovec *iov,
			    int nr_iov);

/**
 * unvmed_id_ctrl - Identify Controller (CNS 1h)
 * @cmd: command instance (&struct unvme_cmd)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Issue an Identify Controller command to the controller @u.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise CQE status field.
 */
int unvmed_id_ctrl(struct unvme_cmd *cmd, struct iovec *iov, int nr_iov);

/**
 * unvmed_cmd_prep_id_active_nslist - Prepare Identify Active NS List (CNS 2h)
 *				      command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Prepare an Identify Active NS List command instance with the given values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_id_active_nslist(struct unvme_cmd *cmd, uint32_t nsid,
				     struct iovec *iov, int nr_iov);

/**
 * unvmed_id_active_nslist - Identify Active Namespace ID list (CNS 2h)
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Issue an Identify Active Namespace ID list to the controller @u.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise CQE status field.
 */
int unvmed_id_active_nslist(struct unvme_cmd *cmd, uint32_t nsid,
			    struct iovec *iov, int nr_iov);

/**
 * unvmed_cmd_prep_nvm_id_ns - Prepare Identify NVM Identify Namesapce (CNS 5h)
 *				      command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Prepare an Identify NVM Identify Namespace command instance with the given
 * values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_nvm_id_ns(struct unvme_cmd *cmd, uint32_t nsid,
			      struct iovec *iov, int nr_iov);

/**
 * unvmed_nvm_id_ns - Identify NVM Identify Namespace (CNS 5h)
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Issue an Identify NVM Namespace to the controller @u.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise CQE status field.
 */
int unvmed_nvm_id_ns(struct unvme_cmd *cmd, uint32_t nsid, struct iovec *iov,
		     int nr_iov);


/**
 * unvmed_cmd_prep_set_features - Prepare Set Features command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @fid: feature identifier
 * @save: to make attribute persistent
 * @cdw11: command dword 11
 * @cdw12: command dword 12
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Prepare an Set Features command instance with the given values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_set_features(struct unvme_cmd *cmd, uint32_t nsid,
				 uint8_t fid, bool save, uint32_t cdw11,
				 uint32_t cdw12, struct iovec *iov, int nr_iov);

/**
 * unvmed_set_features - Set Features
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @fid: feature identifier
 * @save: to make attribute persistent
 * @cdw11: command dword 11
 * @cdw12: command dword 12
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Issue an Set Features to the controller @u.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, -1 on error, otherwise CQE status field.
 */
int unvmed_set_features(struct unvme_cmd *cmd, uint32_t nsid, uint8_t fid,
			bool save, uint32_t cdw11, uint32_t cdw12,
			struct iovec *iov, int nr_iov);

/**
 * unvmed_cmd_prep_set_features_hmb - Prepare Set Features HMB command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @hsize: host memory buffer size in memory page size (CC.MPS) units
 * @descs_addr: host memory descriptor list address
 * @nr_descs: host memory descriptor list entry count
 * @mr: memory return
 * @enable: EHM(Enable Host Memory) field in CDW11
 *
 * Prepare an Set Features HMB command instance with the given values.
 *
 * This API should be called after calling `unvmed_hmb_init()` to initialize
 * HMB area and retrieve the result value from the driver command.  With those
 * values, Set Features command should be composed.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_set_features_hmb(struct unvme_cmd *cmd, uint32_t hsize,
				     uint64_t descs_addr, uint32_t nr_descs,
				     bool mr, bool enable);

/**
 * unvmed_set_features_hmb - Set Features for HMB
 * @cmd: command instance (&struct unvme_cmd)
 * @hsize: host memory buffer size in memory page size (CC.MPS) units
 * @descs_addr: host memory descriptor list address
 * @nr_descs: host memory descriptor list entry count
 * @mr: memory return
 * @enable: EHM(Enable Host Memory) field in CDW11
 *
 * This API should be called after calling `unvmed_hmb_init()` to initialize
 * HMB area and retrieve the result value from the driver command.  With those
 * values, Set Features command should be composed.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, -1 on error, otherwise CQE status field.
 */
int unvmed_set_features_hmb(struct unvme_cmd *cmd, uint32_t hsize,
			    uint64_t descs_addr, uint32_t nr_descs,
			    bool mr, bool enable);

/**
 * unvmed_cmd_prep_get_features - Prepare Get Features command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @fid: feature identifier
 * @sel: request attribute of the value in th returned data
 * @cdw11: command dword 11
 * @cdw14: command dword 14
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Prepare an Get Features command instance with the given values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_get_features(struct unvme_cmd *cmd, uint32_t nsid,
				 uint8_t fid, uint8_t sel, uint32_t cdw11,
				 uint32_t cdw14, struct iovec *iov, int nr_iov);

/**
 * unvmed_get_features - Get Features
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @fid: feature identifier
 * @sel: request attribute of the value in th returned data
 * @cdw11: command dword 11
 * @cdw14: command dword 14
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 *
 * Issue an Get Features to the controller @u.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, -1 on error, otherwise CQE status field.
 */
int unvmed_get_features(struct unvme_cmd *cmd, uint32_t nsid, uint8_t fid,
			uint8_t sel, uint32_t cdw11, uint32_t cdw14,
			struct iovec *iov, int nr_iov);

/**
 * unvmed_cmd_prep_read - Prepare Read command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @slba: start logical block address
 * @nlb: number of logical blocks (0-based)
 * @prinfo: prinfo for end-to-end pi
 * @atag: app tag for end-to-end pi
 * @atag_mask: app tag mask for end-to-end pi
 * @rtag: reference tag for end-to-end pi
 * @stag: storage tag for end-to-end pi
 * @stag_check: check storage tag for end-to-end pi
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 * @mbuf: metadata buffer I/O vector
 * @opaque: opaque private data for asynchronous completion
 *
 * Prepare a Read command instance with the given values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_read(struct unvme_cmd *cmd, uint32_t nsid, uint64_t slba,
			 uint16_t nlb, uint8_t prinfo, uint16_t atag,
			 uint16_t atag_mask, uint64_t rtag, uint64_t stag,
			 bool stag_check, struct iovec *iov, int nr_iov,
			 void *mbuf, void *opaque);

/**
 * unvmed_read - Read I/O command
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @slba: start logical block address
 * @nlb: number of logical blocks (0-based)
 * @prinfo: prinfo for end-to-end pi
 * @atag: app tag for end-to-end pi
 * @atag_mask: app tag mask for end-to-end pi
 * @rtag: reference tag for end-to-end pi
 * @stag: storage tag for end-to-end pi
 * @stag_check: check storage tag for end-to-end pi
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 * @mbuf: metadata buffer I/O vector
 * @opaque: opaque private data for asynchronous completion
 *
 * Issue an Read I/O command to the given namespace.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise CQE status field.
 */
int unvmed_read(struct unvme_cmd *cmd, uint32_t nsid, uint64_t slba,
		uint16_t nlb, uint8_t prinfo, uint16_t atag, uint16_t atag_mask,
		uint64_t rtag, uint64_t stag, bool stag_check,
		struct iovec *iov, int nr_iov, void *mbuf, void *opaque);

/**
 * unvmed_cmd_prep_write - Prepare Write command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @slba: start logical block address
 * @nlb: number of logical blocks (0-based)
 * @prinfo: prinfo for end-to-end pi
 * @atag: app tag for end-to-end pi
 * @atag_mask: app tag mask for end-to-end pi
 * @rtag: reference tag for end-to-end pi
 * @stag: storage tag for end-to-end pi
 * @stag_check: check storage tag for end-to-end pi
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 * @mbuf: metadata buffer I/O vector
 * @opaque: opaque private data for asynchronous completion
 *
 * Prepare a Read command instance with the given values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_write(struct unvme_cmd *cmd, uint32_t nsid, uint64_t slba,
		uint16_t nlb, uint8_t prinfo, uint16_t atag, uint16_t atag_mask,
		uint64_t rtag, uint64_t stag, bool stag_check,
		struct iovec *iov, int nr_iov, void *mbuf, void *opaque);

/**
 * unvmed_write - Write I/O command
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to identify
 * @slba: start logical block address
 * @nlb: number of logical blocks (0-based)
 * @prinfo: prinfo for end-to-end pi
 * @atag: app tag for end-to-end pi
 * @atag_mask: app tag mask for end-to-end pi
 * @rtag: reference tag for end-to-end pi
 * @stag: storage tag for end-to-end pi
 * @stag_check: check storage tag for end-to-end pi
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs dangled to @iov
 * @mbuf: metadata buffer I/O vector
 * @opaque: opaque private data for asynchronous completion
 *
 * Issue an Write I/O command to the given namespace.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise CQE status field.
 */
int unvmed_write(struct unvme_cmd *cmd, uint32_t nsid, uint64_t slba,
		 uint16_t nlb, uint8_t prinfo, uint16_t atag,
		 uint16_t atag_mask, uint64_t rtag, uint64_t stag,
		 bool stag_check, struct iovec *iov, int nr_iov, void *mbuf,
		 void *opaque);


/**
 * unvmed_cmd_prep_format - Prepare Format command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to format
 * @lbaf: LBA format index
 * @ses: secure erase settings
 * @pil: protection information location
 * @pi: protection information
 * @mset: metadata settings
 *
 * Prepare a Format command instance with the given values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_format(struct unvme_cmd *cmd, uint32_t nsid, uint8_t lbaf,
			   uint8_t ses, uint8_t pil, uint8_t pi, uint8_t mset);

/**
 * unvmed_format - Format NVM command
 * @cmd: command instance (&struct unvme_cmd)
 * @nsid: namespace identifier to format
 * @lbaf: LBA format index
 * @ses: secure erase settings
 * @pil: protection information location
 * @pi: protection information
 * @mset: metadata settings
 */
int unvmed_format(struct unvme_cmd *cmd, uint32_t nsid, uint8_t lbaf,
		  uint8_t ses, uint8_t pil, uint8_t pi, uint8_t mset);

/**
 * unvmed_cmd_prep_virt_mgmt - Prepare Virtualization Mgmt. command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @cntlid: controller identifier
 * @rt: resource type (e.g., VI Resource, VQ Resource)
 * @act: action (e.g., manage primary or secondary controller)
 * @nr: number of resources to manage
 *
 * Prepare a Virtualization Mgmt. command instance with the given values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_virt_mgmt(struct unvme_cmd *cmd, uint32_t cntlid,
			      uint32_t rt, uint32_t act, uint32_t nr);

/**
 * unvmed_virt_mgmt - Manage NVMe virtualization
 * @cmd: command instance (&struct unvme_cmd)
 * @cntlid: controller identifier
 * @rt: resource type (e.g., VI Resource, VQ Resource)
 * @act: action (e.g., manage primary or secondary controller)
 * @nr: number of resources to manage
 *
 * This function handles Virtualization Management command, such as
 * managing flexible reosurce or setting the online/offline state of
 * secondary controllers
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise CQE status field.
 */
int unvmed_virt_mgmt(struct unvme_cmd *cmd, uint32_t cntlid, uint32_t rt,
		     uint32_t act, uint32_t nr);

/**
 * unvmed_cmd_prep_id_primary_ctrl_caps - Prepare Identify Primary Controller
 *					  command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs attached to @iov
 * @cntlid: controller identifier
 *
 * Prepare an Identify Primary Controller command instance with the given
 * values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_id_primary_ctrl_caps(struct unvme_cmd *cmd,
					 struct iovec *iov, int nr_iov,
					 uint32_t cntlid);

/**
 * unvmed_id_primary_ctrl_caps - Identify Primary Controller Capabilities (CNS 14h)
 * @cmd: command instance (&struct unvme_cmd)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs attached to @iov
 * @cntlid: controller identifier
 *
 * Issues an Identify Primary Controller Capabilities command to the controller @u.
 * This command retrieves the capabilities of the specified primary controller.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise CQE status field.
**/

int unvmed_id_primary_ctrl_caps(struct unvme_cmd *cmd, struct iovec *iov,
				int nr_iov, uint32_t cntlid);

/**
 * unvmed_cmd_prep_id_secondary_ctrl_list - Prepare Identify Secondary Controller
 *					    List command instance
 * @cmd: command instance (&struct unvme_cmd)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs attached to @iov
 * @cntlid: lowest controller identifier to display
 *
 * Prepare an Identify Secondary Controller List command instance with the given
 * values.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_prep_id_secondary_ctrl_list(struct unvme_cmd *cmd,
					   struct iovec *iov, int nr_iov,
					   uint32_t cntlid);

/**
 * unvmed_id_secondary_ctrl_list - Identify Secondary Controller List (CNS 15h)
 * @cmd: command instance (&struct unvme_cmd)
 * @iov: user data buffer I/O vector (&struct iovec)
 * @nr_iov: number of iovecs attached to @iov
 * @cntlid: lowest controller identifier to display
 *
 * Issues an Identify Secondary Controller List command to the controller @u.
 * This command retrieves the list of secondary controllers associated with
 * the specified @cntlid.
 *
 * This API is thread-safe.
 *
 * Return: ``0`` on success, otherwise CQE status field.
**/
int unvmed_id_secondary_ctrl_list(struct unvme_cmd *cmd, struct iovec *iov,
				  int nr_iov, uint32_t cntlid);

/**
 * unvmed_cmd_wait - Wait until @cmd completes with @cmd->cqe
 * @cmd: command instance (&struct unvme_cmd)
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_cmd_wait(struct unvme_cmd *cmd);

/**
 * unvmed_subsystem_reset - NVM Subsystem Reset
 * @u: &struct unvme
 */
int unvmed_subsystem_reset(struct unvme *u);

/**
 * unvmed_flr - Function Level Reset
 * @u: &struct unvme
 */
int unvmed_flr(struct unvme *u);

/**
 * unvmed_hot_reset - Trigger Hot Reset to corresponding downstream port
 * @u: &struct unvme
 */
int unvmed_hot_reset(struct unvme *u);

/**
 * unvmed_link_disable - Trigger Link Disable to corresponding downstream port
 * @u: &struct unvme
 */
int unvmed_link_disable(struct unvme *u);

/**
 * unvmed_ctx_init - Snapshot current driver context
 * @u: &struct unvme
 *
 * Driver context includes controller register status with admin queues,
 * namespace instances and I/O queues.  It stores all the current driver
 * context status and keep it to restore after reset by unvmed_ctx_restore().
 *
 * This can be freed up by unvmed_ctx_free().
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_ctx_init(struct unvme *u);

/**
 * unvmed_ctx_restore - Restore controller status to kept driver context
 * @u: &struct unvme
 *
 * Re-initialize the given controller @u to a state which is snapshot before by
 * unvmed_ctx_init().  This will revive admin queues, I/O queues and namespace
 * instances.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_ctx_restore(struct unvme *u);

/**
 * unvmed_ctx_free - Free up driver context stored
 * @u: &struct unvme
 *
 * Free up driver context data structure.  This does not affect any hardware
 * status at all.
 */
void unvmed_ctx_free(struct unvme *u);

/**
 * unvmed_hmb_allocated - Check whether Host Memory Buffer has already been
 *			  allocated.
 * @u: &struct unvme
 *
 * Return: ``true`` on success, otherwise ``false``
 */
bool unvmed_hmb_allocated(struct unvme *u);

/**
 * unvmed_hmb - Get &struct unvme_hmb instance for the given controller.
 * @u: &struct unvme
 *
 * Return: &struct unvme_hmb pointer
 */
struct unvme_hmb *unvmed_hmb(struct unvme *u);

/**
 * unvmed_hmb_init - Initialize Host Memory Buffer
 * @u: &struct unvme
 * @bsize: buffer size array pointer (size is based on CC.MPS unit)
 * @nr_bsize: number of @bisze array entries
 *
 * It won't issue a Set Features admin command, but just initialize the host
 * memory buffer with IOMMU mapped.
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_hmb_init(struct unvme *u, uint32_t *bsize, int nr_bsize);

/**
 * unvmed_hmb_free - Free Host Memory buffer
 * @u: &struct unvme
 *
 * Return: ``0`` on success, otherwise ``-1`` with ``errno`` set.
 */
int unvmed_hmb_free(struct unvme *u);

/*
 * `struct unvme` starts with `struct nvme_ctrl`, so convert easily.
 */
#define __unvmed_ctrl(u)		((struct nvme_ctrl *)(u))

/*
 * `struct nvme_ctrl` of `libvfn` access helpers.
 */
#define unvmed_bdf(u)		(__unvmed_ctrl(u)->pci.bdf)
#define unvmed_reg(u)		(__unvmed_ctrl(u)->regs)
#define unvmed_cqe_status(cqe)	(le16_to_cpu((cqe)->sfp) >> 1)

/*
 * PCI MMIO access helpers
 */
#define unvmed_read32(u, offset)	\
	le32_to_cpu(mmio_read32(unvmed_reg(u) + (offset)))
#define unvmed_read64(u, offset)	\
	le64_to_cpu(mmio_read64(unvmed_reg(u) + (offset)))
#define unvmed_write32(u, offset, value) \
	mmio_write32(unvmed_reg(u) + (offset), cpu_to_le32((value)))
#define unvmed_write64(u, offset, value) \
	mmio_write64(unvmed_reg(u) + (offset), cpu_to_le64((value)))

#endif
