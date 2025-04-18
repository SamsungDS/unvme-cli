// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#define _GNU_SOURCE

#include <vfn/nvme.h>
#include <nvme/types.h>
#include <ccan/list/list.h>

#include "libunvmed.h"
#include "libunvmed-private.h"

/*
 * This function is from `libnvme` with few modifications.  It updates the
 * given @sqe with cdw2, cdw3, cdw14 and cdw15, remaining fields should be
 * updated outside of this function.
 */
static int unvmed_sqe_set_tags(struct unvme *u, uint32_t nsid, struct nvme_cmd_rw *sqe,
			       uint16_t atag, uint16_t atag_mask,
			       uint64_t rtag, uint64_t stag)
{
	uint8_t pif;
	uint8_t sts;
	uint32_t cdw2 = 0;
	uint32_t cdw3 = 0;
	uint32_t cdw14 = 0;
	int refcnt;

	struct unvme_ns *ns = unvmed_ns_get(u, nsid);
	if (!ns) {
		errno = EINVAL;
		return -1;
	}

	pif = ns->pif;
	sts = ns->sts;

	refcnt = unvmed_ns_put(u, ns);
	assert(refcnt > 0);

	switch (pif) {
	case NVME_NVM_PIF_16B_GUARD:
		cdw14 = rtag & 0xffffffff;
		cdw14 |= (stag << (32 - sts)) & 0xffffffff;
		break;
	case NVME_NVM_PIF_32B_GUARD:
		cdw2 = (stag >> (sts - 16)) & 0xffff;
		cdw3 = (rtag >> 32) & 0xffffffff;
		cdw14 = rtag & 0xffffffff;
		cdw14 |= (stag << (80 - sts)) & 0xffff0000;
		if (sts >= 48)
			cdw3 |= (stag >> (sts - 48)) & 0xffffffff;
		else
			cdw3 |= (stag << (48 - sts)) & 0xffffffff;
		break;
	case NVME_NVM_PIF_64B_GUARD:
		cdw3 = (rtag >> 32) & 0xffff;
		cdw14 = rtag & 0xffffffff;
		cdw14 |= (stag << (48 - sts)) & 0xffffffff;
		if (sts >= 16)
			cdw3 |= (stag >> (sts - 16)) & 0xffff;
		else
			cdw3 |= (stag << (16 - sts)) & 0xffff;
		break;
	default:
		return -1;
	}

	sqe->apptag = cpu_to_le16(atag);
	sqe->appmask = cpu_to_le16(atag_mask);
	sqe->cdw2 = cpu_to_le32(cdw2);
	sqe->cdw3 = cpu_to_le32(cdw3);
	sqe->reftag = cpu_to_le32(cdw14);
	return 0;
}

static void unvmed_buf_free(struct unvme *u, struct unvme_buf *buf)
{
	if (buf->flags & UNVME_CMD_BUF_F_IOVA_UNMAP)
		unvmed_unmap_vaddr(u, buf->va);

	if (buf->flags & UNVME_CMD_BUF_F_VA_UNMAP)
		pgunmap(buf->va, buf->len);
}

static struct unvme_cmd *__unvmed_cmd_alloc(struct unvme *u, struct unvme_sq *usq)
{
	struct unvme_cmd *cmd;
	struct nvme_rq *rq;

	rq = nvme_rq_acquire_atomic(usq->q);
	if (!rq) {
		unvmed_log_err("failed to acquire nvme request instance");
		return NULL;
	}

	atomic_inc(&usq->nr_cmds);

	cmd = &usq->cmds[rq->cid];
	cmd->u = u;
	cmd->usq = usq;
	cmd->rq = rq;

	rq->opaque = cmd;

	return cmd;
}

static int unvmed_buf_init(struct unvme *u, struct unvme_buf *ubuf,
			   void *buf, uint32_t len)
{
	void *__buf = NULL;
	ssize_t __len;

	memset(ubuf, 0, sizeof(*ubuf));

	/*
	 * If caller gives NULL buf and non-zero len, it will allocate a user
	 * data buffer and keep the pointer and the size allocated in
	 * cmd->buf.va and cmd->buf.len.  They will be freed up in
	 * unvmed_cmd_free().  But, if caller gives non-NULL buf and non-zero
	 * len, caller *must* free up the user data buffer before or after
	 * unvmed_cmd_free().
	 */
	if (!buf && len) {
		__len = pgmap(&__buf, len);
		if (__len < 0) {
			unvmed_log_err("failed to mmap() for data buffer");
			return -1;
		}

		buf = __buf;
		len = __len;  /* Update length with a newly aligned size */

		ubuf->flags |= UNVME_CMD_BUF_F_VA_UNMAP;
	}

	if (buf && len) {
		uint64_t iova;

		if (unvmed_to_iova(u, buf, &iova)) {
			if (unvmed_map_vaddr(u, buf, len, &iova, 0x0)) {
				unvmed_log_err("failed to map vaddr for data buffer");

				if (__buf)
					pgunmap(buf, len);
				return -1;
			}
			ubuf->flags |= UNVME_CMD_BUF_F_IOVA_UNMAP;
		}
	}

	ubuf->va = buf;
	ubuf->len = len;
	ubuf->iov = (struct iovec) {.iov_base = buf, .iov_len = len};

	return 0;
}

static struct unvme_cmd *__unvmed_cmd_init(struct unvme *u, struct unvme_sq *usq,
					   void *buf, size_t len, void *mbuf,
					   size_t mlen)
{
	struct unvme_cmd *cmd;

	cmd = __unvmed_cmd_alloc(u, usq);
	if (!cmd)
		return NULL;

	if (unvmed_buf_init(u, &cmd->buf, buf, len)) {
		__unvmed_cmd_free(cmd);
		return NULL;
	}

	if (unvmed_buf_init(u, &cmd->mbuf, mbuf, mlen)) {
		unvmed_buf_free(u, &cmd->buf);
		__unvmed_cmd_free(cmd);
		return NULL;
	}

	return cmd;
}

void __unvmed_cmd_free(struct unvme_cmd *cmd)
{
	struct unvme_sq *usq = cmd->usq;

	nvme_rq_release_atomic(cmd->rq);
	memset(cmd, 0, sizeof(*cmd));

	atomic_dec(&usq->nr_cmds);
}

void unvmed_cmd_free(struct unvme_cmd *cmd)
{
	unvmed_buf_free(cmd->u, &cmd->buf);
	unvmed_buf_free(cmd->u, &cmd->mbuf);

	__unvmed_cmd_free(cmd);
}

struct unvme_cmd *unvmed_alloc_cmd(struct unvme *u, struct unvme_sq *usq,
				   void *buf, size_t len)
{
	if (!buf || !len) {
		errno = EINVAL;
		return NULL;
	}

	return __unvmed_cmd_init(u, usq, buf, len, NULL, 0);
}

struct unvme_cmd *unvmed_alloc_cmd_nodata(struct unvme *u, struct unvme_sq *usq)
{
	return __unvmed_cmd_init(u, usq, NULL, 0, NULL, 0);
}

struct unvme_cmd *unvmed_alloc_cmd_meta(struct unvme *u, struct unvme_sq *usq,
					void *buf, size_t len, void *mbuf,
					size_t mlen)
{
	if (!buf || !len) {
		errno = EINVAL;
		return NULL;
	}

	return __unvmed_cmd_init(u, usq, buf, len, mbuf, mlen);
}

int __unvmed_mapv_prp(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		      struct iovec *iov, int nr_iov)
{
	if (nvme_rq_mapv_prp(&cmd->u->ctrl, cmd->rq, sqe, iov, nr_iov))
		return -1;
	return 0;
}

int __unvmed_mapv_prp_list(struct unvme_cmd *cmd, union nvme_cmd *sqe,
			   void *prplist, struct iovec *iov, int nr_iov)
{
	if (!prplist)
		prplist = cmd->rq->page.vaddr;

	if (nvme_mapv_prp(&cmd->u->ctrl, prplist, sqe, iov, nr_iov))
		return -1;
	return 0;
}

int unvmed_mapv_prp(struct unvme_cmd *cmd, union nvme_cmd *sqe)
{
	return __unvmed_mapv_prp(cmd, sqe, &cmd->buf.iov, 1);
}

int __unvmed_mapv_sgl(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		      struct iovec *iov, int nr_iov)
{
	if (nvme_rq_mapv_sgl(&cmd->u->ctrl, cmd->rq, sqe, iov, nr_iov))
		return -1;
	return 0;
}

int __unvmed_mapv_sgl_seg(struct unvme_cmd *cmd, union nvme_cmd *sqe,
			  struct nvme_sgld *seg, struct iovec *iov, int nr_iov)
{
	if (nvme_mapv_sgl(&cmd->u->ctrl, seg, sqe, iov, nr_iov))
		return -1;
	return 0;
}

int unvmed_mapv_sgl(struct unvme_cmd *cmd, union nvme_cmd *sqe)
{
	return __unvmed_mapv_sgl(cmd, sqe, &cmd->buf.iov, 1);
}

int unvmed_id_ns(struct unvme *u, struct unvme_cmd *cmd, uint32_t nsid,
		 struct iovec *iov, int nr_iov, unsigned long flags)
{
	struct nvme_cmd_identify sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_admin_identify;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.cns = cpu_to_le32(0x0);

	if (nr_iov > 0) {
		if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
		}
	}

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, flags);

	if (flags & UNVMED_CMD_F_NODB) {
		unvmed_sq_exit(cmd->usq);
		return 0;
	}

	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}

int unvmed_id_ctrl(struct unvme *u, struct unvme_cmd *cmd, struct iovec *iov,
		   int nr_iov, unsigned long flags)
{
	struct nvme_cmd_identify sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_admin_identify;
	sqe.cns = NVME_IDENTIFY_CNS_CTRL;

	if (nr_iov > 0) {
		if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
		}
	}

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, flags);

	if (flags & UNVMED_CMD_F_NODB) {
		unvmed_sq_exit(cmd->usq);
		return 0;
	}

	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}

int unvmed_id_active_nslist(struct unvme *u, struct unvme_cmd *cmd,
			    uint32_t nsid, struct iovec *iov, int nr_iov)
{
	struct nvme_cmd_identify sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_admin_identify;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.cns = cpu_to_le32(0x2);

	if (nr_iov > 0) {
		if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
		}
	}

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);

	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}

int unvmed_nvm_id_ns(struct unvme *u, struct unvme_cmd *cmd,
		     uint32_t nsid, struct iovec *iov, int nr_iov)
{
	struct nvme_cmd_identify sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_admin_identify;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.cns = NVME_IDENTIFY_CNS_CSI_NS;

	if (nr_iov > 0) {
		if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
		}
	}

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);

	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}

int unvmed_set_features(struct unvme *u, struct unvme_cmd *cmd,
			uint32_t nsid, uint8_t fid, bool save, uint32_t cdw11,
			uint32_t cdw12, struct iovec *iov, int nr_iov,
			struct nvme_cqe *cqe)
{
	const int CDW10_SAVE_SHIFT = 15;
	struct nvme_cmd_features sqe = {0, };

	sqe.opcode = nvme_admin_set_features;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.fid = fid;
	sqe.rsvd42 = cpu_to_le16(save << CDW10_SAVE_SHIFT);
	sqe.cdw11 = cpu_to_le32(cdw11);
	sqe.cdw12 = cpu_to_le32(cdw12);

	if (nr_iov > 0) {
		if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
		}
	}

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);

	unvmed_cq_run_n(u, cmd->usq->ucq, cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(cqe);
}

static int unvmed_hmb_init(struct unvme *u, uint32_t *bsize, int nr_bsize)
{
	const size_t page_size = unvmed_pow(2, u->mps + 12);
	void *descs = NULL;
	uint64_t iova;
	ssize_t ret;
	size_t hsize = 0;
	int i;

	if (u->hmb.descs) {
		unvmed_log_err("failed to initialize HMB (already exists)");
		errno = EEXIST;
		return -1;
	}

	ret = pgmap(&descs, nr_bsize * sizeof(*u->hmb.descs));
	if (ret < 0) {
		unvmed_log_err("failed to allocate HMB buffer descriptors");
		return -1;
	}

	if (unvmed_map_vaddr(u, descs, ret, &iova, 0x0) < 0) {
		unvmed_log_err("failed to map HMB buffer descriptors to IOMMU");
		goto free;
	}

	u->hmb.descs_vaddr = calloc(nr_bsize, sizeof(uint64_t));
	if (!u->hmb.descs_vaddr) {
		unvmed_log_err("failed to allocate HMB buffer descriptors");
		goto free;
	}

	u->hmb.descs = descs;
	u->hmb.descs_iova = iova;
	u->hmb.descs_size = ret;
	u->hmb.nr_descs = nr_bsize;

	unvmed_log_info("HMB descriptors (vaddr=%p, iova=%#lx, size=%ldbytes)",
			descs, iova, ret);

	for (i = 0; i < nr_bsize; i++) {
		size_t size = bsize[i] * page_size;
		void *buf = NULL;

		ret = pgmap(&buf, size);
		if (ret < 0) {
			unvmed_log_err("failed to allocate HMB buffer");
			goto free;
		}

		if (unvmed_map_vaddr(u, buf, ret, &iova, 0x0) < 0) {
			unvmed_log_err("failed to map HMB buffer to IOMMU");
			goto free;
		}

		u->hmb.descs_vaddr[i] = (uint64_t)buf;
		u->hmb.descs[i].badd = cpu_to_le64(iova);
		u->hmb.descs[i].bsize = cpu_to_le32(bsize[i]);

		hsize += bsize[i];
		unvmed_log_info("HMB descriptor #%d (vaddr=%p, iova=%#lx, size=%ldbytes)",
				i, buf, iova, ret);
	}

	u->hmb.hsize = hsize;
	return 0;
free:
	for (i = 0; i < nr_bsize; i++) {
		size_t size = bsize[i] * page_size;
		if (u->hmb.descs[i].badd) {
			unvmed_unmap_vaddr(u, (void *)u->hmb.descs_vaddr[i]);
			pgunmap((void *)u->hmb.descs_vaddr[i], size);
		}
	}

	if (u->hmb.descs_vaddr)
		free(u->hmb.descs_vaddr);
	unvmed_unmap_vaddr(u, descs);
	pgunmap(descs, ret);

	memset(&u->hmb, 0, sizeof(u->hmb));

	errno = ENOMEM;
	return -1;
}

static int unvmed_hmb_free(struct unvme *u)
{
	int i;

	if (!u->hmb.descs) {
		errno = ENOMEM;
		return -1;
	}

	for (i = 0; i < u->hmb.nr_descs; i++) {
		if (u->hmb.descs[i].badd) {
			unvmed_unmap_vaddr(u, (void *)u->hmb.descs_vaddr[i]);
			pgunmap((void *)u->hmb.descs_vaddr[i], u->hmb.descs_size);
			unvmed_log_info("HMB descriptor #%d freed", i);
		}
	}

	if (unvmed_unmap_vaddr(u, u->hmb.descs) < 0)
		unvmed_log_err("failed to unmap HMB buffer descriptors from IOMMU");

	pgunmap(u->hmb.descs, u->hmb.descs_size);

	memset(&u->hmb, 0, sizeof(u->hmb));
	return 0;
}

int unvmed_set_features_hmb(struct unvme *u, bool enable, uint32_t *bsize,
			    int nr_bsize, struct nvme_cqe *cqe)
{
	struct unvme_cmd *cmd;
	struct nvme_cmd_features sqe = {0 ,};

	if (!u->asq) {
		unvmed_log_err("controller is not enabled (no admin sq)");
		errno = ENODEV;
		return -1;
	}

	cmd = unvmed_alloc_cmd_nodata(u, u->asq);
	if (!cmd) {
		unvmed_log_err("failed to allocate a command instance");
		return -1;
	}

	if (enable && unvmed_hmb_init(u, bsize, nr_bsize) < 0) {
		unvmed_cmd_free(cmd);
		return -1;
	}

	sqe.opcode = nvme_admin_set_features;
	sqe.fid = NVME_FEAT_FID_HOST_MEM_BUF;
	sqe.cdw11 = cpu_to_le32(!!enable);
	sqe.cdw12 = cpu_to_le32(u->hmb.hsize);
	sqe.cdw13 = cpu_to_le32(u->hmb.descs_iova & 0xffffffff);
	sqe.cdw14 = cpu_to_le32(u->hmb.descs_iova >> 32);
	sqe.cdw15 = cpu_to_le32(u->hmb.nr_descs);

	unvmed_sq_enter(u->asq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);

	unvmed_cq_run_n(u, u->acq, cqe, 1, 1);
	unvmed_sq_exit(u->asq);

	unvmed_cmd_free(cmd);

	if (!enable && nvme_cqe_ok(cqe))
		unvmed_hmb_free(u);

	return unvmed_cqe_status(cqe);
}

int unvmed_get_features(struct unvme *u, struct unvme_cmd *cmd, uint32_t nsid,
			uint8_t fid, uint8_t sel, uint32_t cdw11,
			uint32_t cdw14, struct iovec *iov, int nr_iov,
			struct nvme_cqe *cqe)
{
	struct nvme_cmd_features sqe = {0, };

	sqe.opcode = nvme_admin_get_features;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.fid = fid;
	sqe.sel = sel;
	sqe.cdw11 = cpu_to_le32(cdw11);
	sqe.cdw14 = cpu_to_le32(cdw14);

	if (nr_iov > 0) {
		if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
		}
	}

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);

	unvmed_cq_run_n(u, cmd->usq->ucq, cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(cqe);
}

int unvmed_read(struct unvme *u, struct unvme_cmd *cmd, uint32_t nsid,
		uint64_t slba, uint16_t nlb, uint8_t prinfo,
		uint16_t atag, uint16_t atag_mask, uint64_t rtag,
		uint64_t stag, bool stag_check,
		struct iovec *iov, int nr_iov, void *mbuf,
		unsigned long flags, void *opaque)
{
	struct nvme_cmd_rw sqe = {0, };
	struct nvme_cqe cqe;
	int ret;

	sqe.opcode = nvme_cmd_read;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.slba = cpu_to_le64(slba);
	sqe.nlb = cpu_to_le16(nlb);

	if (flags & UNVMED_CMD_F_SGL)
		ret = __unvmed_mapv_sgl(cmd, (union nvme_cmd *)&sqe, iov, nr_iov);
	else
		ret = __unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov);
	if (ret) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}

	if (flags & UNVMED_CMD_F_SGL)
		sqe.flags |= NVME_CMD_FLAGS_PSDT_SGL_MPTR_CONTIG <<
			NVME_CMD_FLAGS_PSDT_SHIFT;

	/*
	 * If user does not give `mbuf` for metadata buffer, try with the
	 * pre-initialized meta data buffer initialized when @cmd was created.
	 */
	if (!mbuf && cmd->mbuf.va)
		mbuf = cmd->mbuf.va;

	if (mbuf) {
		uint64_t iova;

		if (unvmed_to_iova(u, mbuf, &iova)) {
			errno = EFAULT;
			return -1;
		}

		/*
		 * Mapping MPTR should be done in libvfn, but we don't have
		 * helpers for MPTR yet, just do it here until helpers are
		 * provided.
		 */
		sqe.mptr = cpu_to_le64(iova);
	}

	unvmed_sqe_set_tags(u, nsid, &sqe, atag, atag_mask, rtag, stag);
	sqe.control |= (prinfo << 10);
	if (stag_check)
		sqe.control |= NVME_IO_STC;

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, flags);

	if (flags & UNVMED_CMD_F_NODB) {
		unvmed_sq_exit(cmd->usq);
		cmd->opaque = opaque;
		return 0;
	}

	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}

int unvmed_write(struct unvme *u, struct unvme_cmd *cmd, uint32_t nsid,
		 uint64_t slba, uint16_t nlb, uint8_t prinfo,
		 uint16_t atag, uint16_t atag_mask, uint64_t rtag,
		 uint64_t stag, bool stag_check,
		 struct iovec *iov, int nr_iov, void *mbuf,
		 unsigned long flags, void *opaque)
{
	struct nvme_cmd_rw sqe = {0, };
	struct nvme_cqe cqe;
	int ret;

	sqe.opcode = nvme_cmd_write;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.slba = cpu_to_le64(slba);
	sqe.nlb = cpu_to_le16(nlb);

	if (flags & UNVMED_CMD_F_SGL)
		ret = __unvmed_mapv_sgl(cmd, (union nvme_cmd *)&sqe, iov, nr_iov);
	else
		ret = __unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov);
	if (ret) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}

	if (flags & UNVMED_CMD_F_SGL)
		sqe.flags |= NVME_CMD_FLAGS_PSDT_SGL_MPTR_CONTIG <<
			NVME_CMD_FLAGS_PSDT_SHIFT;

	/*
	 * If user does not give `mbuf` for metadata buffer, try with the
	 * pre-initialized meta data buffer initialized when @cmd was created.
	 */
	if (!mbuf && cmd->mbuf.va)
		mbuf = cmd->mbuf.va;

	if (mbuf) {
		uint64_t iova;

		if (unvmed_to_iova(u, mbuf, &iova)) {
			errno = EFAULT;
			return -1;
		}

		/*
		 * Mapping MPTR should be done in libvfn, but we don't have
		 * helpers for MPTR yet, just do it here until helpers are
		 * provided.
		 */
		sqe.mptr = cpu_to_le64(iova);
	}

	unvmed_sqe_set_tags(u, nsid, &sqe, atag, atag_mask, rtag, stag);
	sqe.control |= (prinfo << 10);
	if (stag_check)
		sqe.control |= NVME_IO_STC;

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, flags);

	if (flags & UNVMED_CMD_F_NODB) {
		unvmed_sq_exit(cmd->usq);
		cmd->opaque = opaque;
		return 0;
	}

	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}

int unvmed_passthru(struct unvme *u, struct unvme_cmd *cmd, union nvme_cmd *sqe,
		    bool read, struct iovec *iov, int nr_iov, unsigned long flags)
{
	struct nvme_cqe cqe;

	if (nr_iov > 0) {
		if (!sqe->dptr.prp1 && !sqe->dptr.prp2) {
			if (__unvmed_mapv_prp(cmd, sqe, iov, nr_iov)) {
				unvmed_log_err("failed to map iovec for prp");
				return -1;
			}
		}
	}

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)sqe, flags);

	if (flags & UNVMED_CMD_F_NODB) {
		unvmed_sq_exit(cmd->usq);
		return 0;
	}

	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}

int unvmed_format(struct unvme *u, struct unvme_cmd *cmd, uint32_t nsid,
		  uint8_t lbaf, uint8_t ses, uint8_t pil, uint8_t pi,
		  uint8_t mset)
{
	union nvme_cmd sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_admin_format_nvm;
	sqe.nsid = cpu_to_le32(nsid);
	sqe.cdw10 = ((lbaf >> 4 & 3) << 12) | ((ses & 0x7) << 9) |
		((pil & 0x1) << 8) | ((pi & 0x7) << 5) | ((mset & 0x1) << 4) |
		(lbaf & 0xf);

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, &sqe, 0x0);
	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}

int unvmed_virt_mgmt(struct unvme *u, struct unvme_cmd *cmd, uint32_t cntlid,
                     uint32_t rt, uint32_t act, uint32_t nr)
{
	union nvme_cmd sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_admin_virtual_mgmt;
	sqe.cdw10 = ((act & 0xf) | ((rt & 0x7) << 8) | ((cntlid & 0xffff) << 16));
	sqe.cdw11 = (nr & 0xffff);

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, &sqe, 0x0);
	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}

int unvmed_id_primary_ctrl_caps(struct unvme *u, struct unvme_cmd *cmd,
				struct iovec *iov, int nr_iov, uint32_t cntlid)
{
	struct nvme_cmd_identify sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_admin_identify;
	sqe.ctrlid = cntlid;
	sqe.cns = NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP;

	if (nr_iov > 0) {
		if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
		}
	}

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);
	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}

int unvmed_id_secondary_ctrl_list(struct unvme *u, struct unvme_cmd *cmd,
				  struct iovec *iov, int nr_iov, uint32_t cntlid)
{
	struct nvme_cmd_identify sqe = {0, };
	struct nvme_cqe cqe;

	sqe.opcode = nvme_admin_identify;
	sqe.ctrlid = cntlid;
	sqe.cns = NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST;

	if (nr_iov > 0) {
		if (__unvmed_mapv_prp(cmd, (union nvme_cmd *)&sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
		}
	}

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, (union nvme_cmd *)&sqe, 0);
	unvmed_cq_run_n(u, cmd->usq->ucq, &cqe, 1, 1);
	unvmed_sq_exit(cmd->usq);

	return unvmed_cqe_status(&cqe);
}
