// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#include <sys/stat.h>
#include <sys/time.h>

#include <vfn/nvme.h>

#include <nvme/types.h>

#include <ccan/list/list.h>

#include "libunvmed.h"
#include "libunvmed-private.h"

int __unvmed_logfd = 0;

struct unvme {
	/* `ctrl` member must be the first member of `struct unvme` */
	struct nvme_ctrl ctrl;

	bool enabled;
	int nr_sqs;
	int nr_cqs;

	struct list_head ns_list;
	int nr_ns;

	struct list_node list;
};

struct __unvme_ns {
	unvme_declare_ns();
	struct list_node list;
};

struct unvme_cmd {
	struct unvme *u;

	/*
	 * rq->opaque will point to the current structure pointer.
	 */
	struct nvme_rq *rq;
	union nvme_cmd sqe;
	struct nvme_cqe cqe;

	/*
	 * Data buffer for the corresponding NVMe command, this should be
	 * replaced to iommu_dmabuf in libvfn.
	 */
	void *vaddr;
	size_t len;
	uint64_t iova;

	bool should_free;
	struct list_node list;
};

static LIST_HEAD(unvme_list);

static int unvmed_create_logfile(const char *logfile)
{
	int fd;

	if(mkdir("/var/log", 0755) < 0 && errno != EEXIST)
		return -errno;

	fd = creat(logfile, 0644);
	if (fd < 0)
		return -EINVAL;

	return fd;
}

void unvmed_init(const char *logfile)
{
	if (logfile)
		__unvmed_logfd = unvmed_create_logfile(logfile);
}

struct unvme *unvmed_get(const char *bdf)
{
	struct unvme *u;

	if (!unvme_list.n.next || !unvme_list.n.prev)
		return NULL;

	list_for_each(&unvme_list, u, list) {
		if (!strcmp(u->ctrl.pci.bdf, bdf))
			return u;
	}

	return NULL;
}

int unvmed_get_nslist(struct unvme *u, struct unvme_ns **nslist)
{
	struct __unvme_ns *ns;
	int nr_ns = 0;

	if (!nslist) {
		errno = EINVAL;
		return -1;
	}

	if (!u->nr_ns)
		return 0;

	*nslist = calloc(u->nr_ns, sizeof(struct unvme_ns));
	if (!*nslist)
		return -1;

	list_for_each(&u->ns_list, ns, list) {
		assert(nr_ns < u->nr_ns);
		memcpy(&((*nslist)[nr_ns++]), ns, sizeof(struct unvme_ns));
	}

	return nr_ns;
}

struct unvme_ns *unvmed_get_ns(struct unvme *u, uint32_t nsid)
{
	struct __unvme_ns *ns;

	list_for_each(&u->ns_list, ns, list) {
		if (ns->nsid == nsid)
			return (struct unvme_ns *)ns;
	}

	return NULL;
}

int unvmed_get_sqs(struct unvme *u, struct nvme_sq **sqs)
{
	struct nvme_sq *sq;
	int nr_sqs = 0;
	int qid;

	if (!sqs) {
		errno = EINVAL;
		return -1;
	}

	*sqs = calloc(u->nr_sqs, sizeof(struct nvme_sq));
	if (!*sqs)
		return -1;

	for (qid = 0; qid < u->nr_sqs; qid++) {
		sq = unvmed_get_sq(u, qid);
		if (!sq)
			continue;

		memcpy(&((*sqs)[nr_sqs++]), sq, sizeof(*sq));
	}

	return nr_sqs;
}

int unvmed_get_cqs(struct unvme *u, struct nvme_cq **cqs)
{
	struct nvme_cq *cq;
	int nr_cqs = 0;
	int qid;

	if (!cqs) {
		errno = EINVAL;
		return -1;
	}

	*cqs = calloc(u->nr_cqs, sizeof(struct nvme_cq));
	if (!*cqs)
		return -1;

	for (qid = 0; qid < u->nr_cqs; qid++) {
		cq = unvmed_get_cq(u, qid);
		if (!cq)
			continue;

		memcpy(&((*cqs)[nr_cqs++]), cq, sizeof(*cq));
	}

	return nr_cqs;
}

struct nvme_sq *unvmed_get_sq(struct unvme *u, uint32_t qid)
{
	struct nvme_sq *sq;

	if (qid >= u->nr_sqs)
		return NULL;

	sq = &u->ctrl.sq[qid];

	/*
	 * libvfn manages sq instance as an array so that sq instance itself
	 * would never been NULL.  Instead, we can check the vaddr and if vaddr
	 * is NULL, we can say it's not been created and we should not return
	 * the instance in this case.
	 */
	if (!sq->vaddr)
		return NULL;

	return sq;
}

struct nvme_cq *unvmed_get_cq(struct unvme *u, uint32_t qid)
{
	struct nvme_cq *cq;

	if (qid >= u->nr_cqs)
		return NULL;

	cq = &u->ctrl.cq[qid];

	/*
	 * libvfn manages cq instance as an array so that cq instance itself
	 * would never been NULL.  Instead, we can check the vaddr and if vaddr
	 * is NULL, we can say it's not been created and we should not return
	 * the instance in this case.
	 */
	if (!cq->vaddr)
		return NULL;

	return cq;
}

/*
 * Initialize NVMe controller instance in libvfn.  If exists, return the
 * existing one, otherwise it will create new one.  NULL if failure happens.
 */
struct unvme *unvmed_init_ctrl(const char *bdf, uint32_t max_nr_ioqs)
{
	struct nvme_ctrl_opts opts = {0, };
	struct unvme *u;

	u = unvmed_get(bdf);
	if (u)
		return u;

	u = zmalloc(sizeof(struct unvme));

	/*
	 * Zero-based values for I/O queues to pass to `libvfn` excluding the
	 * admin submission/completion queues.
	 */
	opts.nsqr = max_nr_ioqs - 1;
	opts.ncqr = max_nr_ioqs - 1;

	if (nvme_ctrl_init(&u->ctrl, bdf, &opts)) {
		free(u);
		return NULL;
	}

	assert(u->ctrl.opts.nsqr == opts.nsqr);
	assert(u->ctrl.opts.ncqr == opts.ncqr);

	/*
	 * XXX: Since unvme-cli does not follow all the behaviors of the driver, it does
	 * not set up nsqa and ncqa.
	 * Originally, nsqa and ncqa are set through the set feature command, but
	 * we cannot expect the user to send the set feature command.
	 * Therefore, during the `unvme_add`, nsqa and ncqa are set respectively to
	 * nsqr and ncqr.
	 */
	u->ctrl.config.nsqa = opts.nsqr;
	u->ctrl.config.ncqa = opts.ncqr;

	/*
	 * XXX: Maximum number of queues can be created in libvfn.  libvfn
	 * allocates ctrl.sq and ctrl.cq as an array with size of
	 * ctrl.opts.nsqr + 2 and ctrl.opts.ncqr + 2 respectively.  This is
	 * ugly, but we can have it until libvfn exposes these numbers as a
	 * public members.
	 */
	u->nr_sqs = opts.nsqr + 2;
	u->nr_cqs = opts.ncqr + 2;

	list_head_init(&u->ns_list);
	list_add(&unvme_list, &u->list);
	return u;
}

int unvmed_init_ns(struct unvme *u, uint32_t nsid, void *identify)
{
	struct nvme_id_ns id_ns_local;
	struct nvme_id_ns *id_ns = identify;
	struct __unvme_ns *ns;
	unsigned long flags = 0;
	uint8_t format_idx;
	int ret;

	if (unvmed_get_ns(u, nsid)) {
		errno = EEXIST;
		return -1;
	}

	if (!id_ns) {
		ret = unvmed_id_ns(u, nsid, &id_ns_local, flags);
		if (ret)
			return ret;

		id_ns = &id_ns_local;
	}

	ns = zmalloc(sizeof(struct __unvme_ns));
	if (!ns)
		return -1;

	if (id_ns->nlbaf < 16)
		format_idx = id_ns->flbas & 0xf;
	else
		format_idx = ((id_ns->flbas & 0xf) +
		       (((id_ns->flbas >> 5) & 0x3) << 4));

	ns->nsid = nsid;
	ns->lba_size = 1 << id_ns->lbaf[format_idx].ds;
	ns->nr_lbas = le64_to_cpu((uint64_t)id_ns->nsze);

	list_add_tail(&u->ns_list, &ns->list);
	u->nr_ns++;

	return 0;
}

/*
 * Free NVMe controller instance from libvfn and the libunvmed.
 */
void unvmed_free_ctrl(struct unvme *u)
{
	nvme_close(&u->ctrl);
	list_del(&u->list);
	free(u);
}

/*
 * Free all the existing controller instances from libvfn and libunvmed.
 */
void unvmed_free_ctrl_all(void)
{
	struct unvme *u, *next;

	list_for_each_safe(&unvme_list, u, next, list)
		unvmed_free_ctrl(u);
}

static void __unvme_reset_ctrl(struct unvme *u)
{
	uint32_t cc = unvmed_read32(u, NVME_REG_CC);
	uint32_t csts;

	unvmed_write32(u, NVME_REG_CC, cc & ~(1 << NVME_CC_EN_SHIFT));
	while (1) {
		csts = unvmed_read32(u, NVME_REG_CSTS);
		if (!NVME_CSTS_RDY(csts))
			break;
	}
}

/*
 * Reset NVMe controller instance memory resources along with de-asserting
 * controller enable register.  The instance itself will not be freed which can
 * be re-used in later time.
 */
void unvmed_reset_ctrl(struct unvme *u)
{
	struct nvme_sq *sq;
	struct nvme_cq *cq;
	uint32_t qid;

	__unvme_reset_ctrl(u);

	for (qid = 0; qid < u->nr_sqs; qid++) {
		sq = unvmed_get_sq(u, qid);
		if (sq)
			nvme_discard_sq(&u->ctrl, sq);
	}

	for (qid = 0; qid < u->nr_cqs; qid++) {
		cq = unvmed_get_cq(u, qid);
		if (cq)
			nvme_discard_cq(&u->ctrl, cq);
	}

	u->enabled = false;
}

int unvmed_create_adminq(struct unvme *u)
{
	if (u->enabled) {
		errno = EPERM;
		return -1;
	}

	return nvme_configure_adminq(&u->ctrl, 0);
}

int unvmed_enable_ctrl(struct unvme *u, uint8_t iosqes, uint8_t iocqes,
		      uint8_t mps, uint8_t css)
{
	uint32_t cc = unvmed_read32(u, NVME_REG_CC);
	uint32_t csts;

	if (NVME_CC_EN(cc)) {
		errno = EEXIST;
		return -1;
	}

	cc = mps << NVME_CC_MPS_SHIFT |
		iosqes << NVME_CC_IOSQES_SHIFT |
		iocqes << NVME_CC_IOCQES_SHIFT |
		1 << NVME_CC_EN_SHIFT;
	unvmed_write32(u, NVME_REG_CC, cc);

	while (1) {
		csts = unvmed_read32(u, NVME_REG_CSTS);
		if (NVME_CSTS_RDY(csts))
			break;
	}

	u->enabled = true;
	return 0;
}

int unvmed_create_cq(struct unvme *u, uint32_t qid, uint32_t qsize,
		    uint32_t vector)
{
	if (!u->enabled) {
		errno = EPERM;
		return -1;
	}

	return nvme_create_iocq(&u->ctrl, qid, qsize, vector);
}

static void __unvmed_delete_cq(struct unvme *u, uint32_t qid)
{
	struct nvme_cq *cq;

	cq = unvmed_get_cq(u, qid);
	if (cq)
		nvme_discard_cq(&u->ctrl, cq);
}

int unvmed_delete_cq(struct unvme *u, uint32_t qid)
{
	__unvmed_free_cmd struct unvme_cmd *cmd;
	struct nvme_cmd_delete_q *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, 0, 0);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_delete_q *)&cmd->sqe;
	sqe->opcode = nvme_admin_delete_cq;
	sqe->qid = cpu_to_le16(qid);

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, 0);
	cqe = unvmed_cmd_cmpl(cmd);

	if (nvme_cqe_ok(cqe))
		__unvmed_delete_cq(u, qid);

	return unvmed_cqe_status(cqe);
}

int unvmed_create_sq(struct unvme *u, uint32_t qid, uint32_t qsize,
		    uint32_t cqid)
{
	struct nvme_cq *cq;

	if (!u->enabled) {
		errno = EPERM;
		return -1;
	}

	cq = unvmed_get_cq(u, cqid);
	if (!cq) {
		errno = ENODEV;
		return -1;
	}

	return nvme_create_iosq(&u->ctrl, qid, qsize, cq, 0);
}

static void __unvmed_delete_sq(struct unvme *u, uint32_t qid)
{
	struct nvme_sq *sq;

	sq = unvmed_get_sq(u, qid);
	if (sq)
		nvme_discard_sq(&u->ctrl, sq);
}

int unvmed_delete_sq(struct unvme *u, uint32_t qid)
{
	__unvmed_free_cmd struct unvme_cmd *cmd;
	struct nvme_cmd_delete_q *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, 0, 0);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_delete_q *)&cmd->sqe;
	sqe->opcode = nvme_admin_delete_sq;
	sqe->qid = cpu_to_le16(qid);

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, 0);
	cqe = unvmed_cmd_cmpl(cmd);

	if (nvme_cqe_ok(cqe))
		__unvmed_delete_sq(u, qid);

	return unvmed_cqe_status(cqe);
}

int unvmed_map_vaddr(struct unvme *u, void *buf, size_t len,
		    uint64_t *iova, unsigned long flags)
{
	struct iommu_ctx *ctx = __iommu_ctx(&u->ctrl);

	if (iommu_map_vaddr(ctx, buf, len, iova, flags))
		return -1;

	return 0;
}

int unvmed_unmap_vaddr(struct unvme *u, void *buf)
{
	struct iommu_ctx *ctx = __iommu_ctx(&u->ctrl);

	return iommu_unmap_vaddr(ctx, buf, NULL);
}

struct unvme_cmd *unvmed_alloc_cmd(struct unvme *u, int sqid,
				   size_t data_len)
{
	struct unvme_cmd *cmd;
	struct nvme_sq *sq;
	struct nvme_rq *rq;
	uint64_t iova;

	sq = unvmed_get_sq(u, sqid);
	if (!sq) {
		errno = EINVAL;
		return NULL;
	}

	rq = nvme_rq_acquire(sq);
	if (!rq)
		return NULL;

	cmd = zmalloc(sizeof(*cmd));
	if (!cmd)
		goto free_rq;

	cmd->u = u;
	cmd->rq = rq;
	rq->opaque = cmd;

	if (data_len) {
		if (pgmap(&cmd->vaddr, data_len) != data_len)
			goto free_cmd;
		cmd->len = data_len;

		if (unvmed_map_vaddr(u, cmd->vaddr, cmd->len, &iova, 0x0))
			goto free_buf;
	}

	cmd->iova = iova;
	cmd->should_free = true;

	return cmd;

free_buf:
	pgunmap(cmd->vaddr, cmd->len);
free_cmd:
	free(cmd);
free_rq:
	nvme_rq_release(rq);
	return NULL;
}

void unvmed_cmd_free(void *p)
{
	struct unvme_cmd *cmd = *(struct unvme_cmd **)p;

	if (cmd && cmd->should_free) {
		if (cmd->len) {
			unvmed_unmap_vaddr(cmd->u, cmd->vaddr);
			pgunmap(cmd->vaddr, cmd->len);
		}
		nvme_rq_release(cmd->rq);
		free(cmd);
	}
}

void unvmed_cmd_post(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		     unsigned long flags)
{
	nvme_rq_post(cmd->rq, (union nvme_cmd *)sqe);
	unvmed_log_cmd_post(unvmed_bdf(cmd->u), cmd->rq->sq->id, sqe);

	if (!(flags & UNVMED_CMD_F_NODB))
		nvme_sq_update_tail(cmd->rq->sq);
	else
		cmd->should_free = false;
}

struct nvme_cqe *unvmed_cmd_cmpl(struct unvme_cmd *cmd)
{
	nvme_rq_spin(cmd->rq, &cmd->cqe);
	unvmed_log_cmd_cmpl(unvmed_bdf(cmd->u), &cmd->cqe);

	return &cmd->cqe;
}

static inline struct unvme_cmd *unvmed_get_cmd_from_cqe(struct unvme *u,
							struct nvme_cqe *cqe)
{
	struct nvme_rq *rq;
	struct nvme_sq *sq;

	sq = unvmed_get_sq(u, cqe->sqid);
	if (!sq)
		return NULL;

	rq = __nvme_rq_from_cqe(sq, cqe);
	return (struct unvme_cmd *)rq->opaque;
}

int unvmed_cmd_cmpl_n(struct unvme *u, uint32_t cqid, struct nvme_cqe *cqes,
		      int nr_cqes)
{
	struct nvme_cq *cq = unvmed_get_cq(u, cqid);
	struct nvme_cqe *cqe;
	struct unvme_cmd *cmd;
	int nr = 0;

	if (nr_cqes <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (!cq) {
		errno = EINVAL;
		return -1;
	}

	while (nr < nr_cqes) {
		cqe = nvme_cq_get_cqe(cq);
		if (!cqe)
			continue;

		memcpy(&cqes[nr++], cqe, sizeof(*cqe));

		cmd = unvmed_get_cmd_from_cqe(u, cqe);
		unvmed_cmd_free(&cmd);
	}

	nvme_cq_update_head(cq);
	return nr;
}

int unvmed_sq_update_tail_and_wait(struct unvme *u, uint32_t sqid,
				  struct nvme_cqe **cqes)
{
	struct nvme_sq *sq = unvmed_get_sq(u, sqid);
	int nr_sqes;
	int ret;

	if (!sq) {
		errno = EINVAL;
		return -1;
	}

	if (sq->tail >= sq->ptail)
		nr_sqes = sq->tail - sq->ptail;
	else
		nr_sqes = (sq->qsize - sq->ptail) + sq->tail;

	if (!nr_sqes)
		return 0;

	*cqes = malloc(sizeof(struct nvme_cqe) * nr_sqes);

	nvme_sq_update_tail(sq);
	ret = unvmed_cmd_cmpl_n(u, sq->cq->id, *cqes, nr_sqes);
	if (ret != nr_sqes)
		return -1;

	return nr_sqes;
}

int unvmed_map_prp(struct unvme_cmd *cmd)
{
	struct nvme_ctrl *ctrl = &cmd->u->ctrl;

	if (!cmd->len)
		return 0;

	if (nvme_rq_map_prp(ctrl, cmd->rq, (union nvme_cmd *)&cmd->sqe,
				cmd->iova, cmd->len))
		return -1;

	return 0;
}

int unvmed_id_ns(struct unvme *u, uint32_t nsid, void *buf, unsigned long flags)
{
	__unvmed_free_cmd struct unvme_cmd *cmd;

	struct nvme_cmd_identify *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, 0, NVME_IDENTIFY_DATA_SIZE);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_identify *)&cmd->sqe;
	sqe->opcode = nvme_admin_identify;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cns = cpu_to_le32(0x0);

	if (unvmed_map_prp(cmd))
		return -1;

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, flags);

	if (flags & UNVMED_CMD_F_NODB)
		return 0;

	cqe = unvmed_cmd_cmpl(cmd);
	if (buf && nvme_cqe_ok(cqe))
		memcpy(buf, cmd->vaddr, cmd->len);

	return unvmed_cqe_status(cqe);
}

int unvmed_id_active_nslist(struct unvme *u, uint32_t nsid, void *buf)
{
	__unvmed_free_cmd struct unvme_cmd *cmd;

	struct nvme_cmd_identify *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, 0, NVME_IDENTIFY_DATA_SIZE);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_identify *)&cmd->sqe;
	sqe->opcode = nvme_admin_identify;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cns = cpu_to_le32(0x2);

	if (unvmed_map_prp(cmd))
		return -1;

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, 0);

	cqe = unvmed_cmd_cmpl(cmd);
	if (buf && nvme_cqe_ok(cqe))
		memcpy(buf, cmd->vaddr, cmd->len);

	return unvmed_cqe_status(cqe);
}

int unvmed_read(struct unvme *u, uint32_t sqid, uint32_t nsid,
		uint64_t slba, uint16_t nlb,
		void *buf, size_t size, unsigned long flags)
{
	__unvmed_free_cmd struct unvme_cmd *cmd;

	struct nvme_cmd_rw *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, sqid, size);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_rw *)&cmd->sqe;
	sqe->opcode = nvme_cmd_read;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->slba = cpu_to_le64(slba);
	sqe->nlb = cpu_to_le16(nlb);

	if (unvmed_map_prp(cmd))
		return -1;

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, flags);

	if (flags & UNVMED_CMD_F_NODB)
		return 0;

	cqe = unvmed_cmd_cmpl(cmd);
	if (buf && nvme_cqe_ok(cqe))
		memcpy(buf, cmd->vaddr, size);

	return unvmed_cqe_status(cqe);
}

int unvmed_write(struct unvme *u, uint32_t sqid, uint32_t nsid,
		 uint64_t slba, uint16_t nlb,
		 void *buf, size_t size, unsigned long flags)
{
	__unvmed_free_cmd struct unvme_cmd *cmd;

	struct nvme_cmd_rw *sqe;
	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, sqid, size);
	if (!cmd)
		return -1;

	sqe = (struct nvme_cmd_rw *)&cmd->sqe;
	sqe->opcode = nvme_cmd_write;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->slba = cpu_to_le64(slba);
	sqe->nlb = cpu_to_le16(nlb);

	if (buf)
		memcpy(cmd->vaddr, buf, size);
	if (unvmed_map_prp(cmd))
		return -1;

	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, flags);

	if (flags & UNVMED_CMD_F_NODB)
		return 0;

	cqe = unvmed_cmd_cmpl(cmd);

	return unvmed_cqe_status(cqe);
}

int unvmed_passthru(struct unvme *u, uint32_t sqid, void *buf, size_t size,
		    union nvme_cmd *sqe, bool read, unsigned long flags)
{
	__unvmed_free_cmd struct unvme_cmd *cmd;

	struct nvme_cqe *cqe;

	cmd = unvmed_alloc_cmd(u, sqid, size);
	if (!cmd)
		return -1;

	memcpy(&cmd->sqe, sqe, sizeof(*sqe));

	if (!read && buf)
		memcpy(cmd->vaddr, buf, size);
	if (!cmd->sqe.dptr.prp1 && !cmd->sqe.dptr.prp2) {
		if (unvmed_map_prp(cmd))
			return -1;
	}

	unvmed_cmd_post(cmd, (union nvme_cmd *)&cmd->sqe, flags);

	if (flags & UNVMED_CMD_F_NODB)
		return 0;

	cqe = unvmed_cmd_cmpl(cmd);
	if (buf && read && nvme_cqe_ok(cqe))
		memcpy(buf, cmd->vaddr, size);

	return unvmed_cqe_status(cqe);
}
