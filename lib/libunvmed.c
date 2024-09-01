// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT

#include <vfn/pci.h>
#include <vfn/nvme.h>

#include <nvme/types.h>

#include <ccan/list/list.h>

#include "libunvmed.h"

struct unvme {
	/* `ctrl` member must be the first member of `struct unvme` */
	struct nvme_ctrl ctrl;

	bool enabled;
	int nr_sqs;
	int nr_cqs;

	struct list_head cmd_list;

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

int unvmed_pci_bind(const char *bdf)
{
	const char *target = "vfio-pci";
	unsigned long long vendor, device;

	if (pci_device_info_get_ull(bdf, "vendor", &vendor)) {
		perror("pci_device_info_get_ull");
		return -1;
	}

	if (pci_device_info_get_ull(bdf, "device", &device)) {
		perror("pci_device_info_get_ull");
		return -1;
	}

	pci_unbind(bdf);

	if (pci_driver_new_id(target, vendor, device)) {
		if (pci_bind(bdf, target)) {
			perror("pci_bind");
			return -1;
		}
	}

	return 0;
}

int unvmed_pci_unbind(const char *bdf)
{
	return pci_unbind(bdf);
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
void unvmed_cmd_get_buf(struct unvme_cmd *cmd, void **buf, size_t *len)
{
	if (buf)
		*buf = cmd->vaddr;
	if (len)
		*len = cmd->len;
}

union nvme_cmd *unvmed_cmd_get_sqe(struct unvme_cmd *cmd)
{
	return &cmd->sqe;
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

	list_head_init(&u->cmd_list);
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

	list_add(&unvme_list, &u->list);
	return u;
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
	uint32_t qid;

	__unvme_reset_ctrl(u);

	for (qid = 0; qid < u->nr_sqs; qid++)
		nvme_discard_sq(&u->ctrl, unvmed_get_sq(u, qid));

	for (qid = 0; qid < u->nr_cqs; qid++)
		nvme_discard_cq(&u->ctrl, unvmed_get_cq(u, qid));

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

int unvmed_create_sq(struct unvme *u, uint32_t qid, uint32_t qsize,
		    uint32_t cqid)
{
	struct nvme_cq *cq;

	if (!u->enabled) {
		errno = EPERM;
		return -1;
	}

	cq = unvmed_get_cq(u, qid);
	if (!cq) {
		errno = ENODEV;
		return -1;
	}

	return nvme_create_iosq(&u->ctrl, qid, qsize, cq, 0);
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

	list_add(&u->cmd_list, &cmd->list);

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
		list_del(&cmd->list);
	}
}

int unvmed_free_cmds(struct unvme *u, uint32_t sqid)
{
	struct unvme_cmd *cmd, *next;
	int nr_freed = 0;

	list_for_each_safe(&u->cmd_list, cmd, next, list) {
		if (cmd->rq->sq->id == sqid) {
			cmd->should_free = true;
			unvmed_cmd_free(&cmd);
			nr_freed++;
		}
	}

	return nr_freed;
}

void unvmed_cmd_post(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		    bool update_sqdb)
{
	nvme_rq_post(cmd->rq, (union nvme_cmd *)sqe);
	if (update_sqdb)
		nvme_sq_update_tail(cmd->rq->sq);
	else
		cmd->should_free = false;
}

struct nvme_cqe *unvmed_cmd_cmpl(struct unvme_cmd *cmd)
{
	nvme_rq_spin(cmd->rq, &cmd->cqe);

	return &cmd->cqe;
}

int unvmed_sq_update_tail_and_wait(struct unvme *u, uint32_t sqid,
				  struct nvme_cqe **cqes)
{
	struct nvme_sq *sq = unvmed_get_sq(u, sqid);
	int nr_sqes;

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
	nvme_cq_wait_cqes(sq->cq, *cqes, nr_sqes, NULL);
	nvme_cq_update_head(sq->cq);

	return nr_sqes;
}

int unvmed_map_prp(struct unvme_cmd *cmd)
{
	struct nvme_ctrl *ctrl = &cmd->u->ctrl;

	if (nvme_rq_map_prp(ctrl, cmd->rq, (union nvme_cmd *)&cmd->sqe,
				cmd->iova, cmd->len))
		return -1;

	return 0;
}
