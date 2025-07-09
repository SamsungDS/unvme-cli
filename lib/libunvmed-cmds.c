// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#define _GNU_SOURCE

#include <vfn/nvme.h>
#include <nvme/types.h>
#include <ccan/list/list.h>

#include "libunvmed.h"
#include "libunvmed-private.h"

static inline int __find_first_zero(uint8_t byte)
{
	if (byte == -1)
		return -1;

	for (int i = 0; i < 8; i++) {
		if (!(byte & (1 << i)))
			return i;
	}

	return -1;
}

static int unvmed_cid_alloc(struct unvme_sq *usq, uint16_t *cid)
{
	struct unvme_bitmap *bitmap = &usq->cids;
	int i = atomic_load_acquire(&bitmap->top);

	for (;;) {
		uint8_t old = atomic_load_acquire(&bitmap->bits[i]);
		uint8_t desired;
		int pos;

		if (old == 0xFF)
			break;

		pos = __find_first_zero(old);
		if (pos < 0)
			break;

		desired = old | (1 << pos);
		if (atomic_cmpxchg(&bitmap->bits[i], old, desired)) {
			*cid = i * 8 + pos;
			return 0;
		}
	}

	for (i = 0; i < bitmap->nr_bytes; ++i) {
		uint8_t old = atomic_load_acquire(&bitmap->bits[i]);
		uint8_t desired;
		int pos;

		if (old == 0xFF)
			continue;

		pos = __find_first_zero(old);
		if (pos < 0)
			continue;

		desired = old | (1 << pos);
		if (atomic_cmpxchg(&bitmap->bits[i], old, desired)) {
			atomic_store_release(&bitmap->top, i);
			*cid = i * 8 + pos;
			return 0;
		}
	}

	errno = EBUSY;
	return -1;
}

static int unvmed_cid_alloc_n(struct unvme_sq *usq, uint16_t cid)
{
	struct unvme_bitmap *bitmap = &usq->cids;
	size_t byte_index = cid / 8;
	size_t bit_index = cid % 8;

	uint8_t mask = 1 << bit_index;
	uint8_t old;
	uint8_t desired;

	if (cid >= bitmap->size) {
		errno = EINVAL;
		return -1;
	}

	do {
		old = atomic_load_acquire(&bitmap->bits[byte_index]);
		if (old & mask) {
			errno = EBUSY;
			return -1;
		}

		desired = old | mask;
	} while (!atomic_cmpxchg(&bitmap->bits[byte_index], old, desired));

	return 0;
}

static int unvmed_cid_free(struct unvme_sq *usq, uint16_t cid)
{
	struct unvme_bitmap *bitmap = &usq->cids;
	size_t byte_index = cid / 8;
	size_t bit_index = cid % 8;

	uint8_t mask = ~(1 << bit_index);
	uint8_t old;
	uint8_t desired;

	if (cid >= bitmap->size) {
		errno = EINVAL;
		return -1;
	}

	do {
		old = atomic_load_acquire(&bitmap->bits[byte_index]);
		desired = old & mask;
	} while (!atomic_cmpxchg(&bitmap->bits[byte_index], old, desired));

	return 0;
}

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

static struct unvme_cmd *__unvmed_cmd_alloc(struct unvme *u,
					    struct unvme_sq *usq, uint16_t *cid)
{
	struct unvme_cmd *cmd;
	struct nvme_rq *rq;
	uint16_t __cid;

	if (cid) {
		__cid = *cid;

		if (unvmed_cid_alloc_n(usq, __cid))
			return NULL;
	} else {
		if (unvmed_cid_alloc(usq, &__cid))
			return NULL;
	}

	rq = nvme_rq_acquire_atomic(usq->q);
	if (!rq) {
		unvmed_cid_free(usq, __cid);
		return NULL;
	}

	atomic_inc(&usq->nr_cmds);

	cmd = &usq->cmds[__cid];
	memset(cmd, 0, sizeof(*cmd));
	cmd->cid = __cid;
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
					   uint16_t *cid, void *buf,
					   size_t len, void *mbuf, size_t mlen)
{
	struct unvme_cmd *cmd;

	cmd = __unvmed_cmd_alloc(u, usq, cid);
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
	struct nvme_rq *rq = cmd->rq;
	uint16_t cid = cmd->cid;

	memset(cmd, 0, sizeof(*cmd));
	atomic_dec(&usq->nr_cmds);

	unvmed_cid_free(usq, cid);
	nvme_rq_release_atomic(rq);
}

void unvmed_cmd_free(struct unvme_cmd *cmd)
{
	unvmed_buf_free(cmd->u, &cmd->buf);
	unvmed_buf_free(cmd->u, &cmd->mbuf);

	__unvmed_cmd_free(cmd);
}

struct unvme_cmd *unvmed_alloc_cmd(struct unvme *u, struct unvme_sq *usq,
				   uint16_t *cid, void *buf, size_t len)
{
	if (!buf || !len) {
		errno = EINVAL;
		return NULL;
	}

	return __unvmed_cmd_init(u, usq, cid, buf, len, NULL, 0);
}

struct unvme_cmd *unvmed_alloc_cmd_nodata(struct unvme *u,
					  struct unvme_sq *usq, uint16_t *cid)
{
	return __unvmed_cmd_init(u, usq, cid, NULL, 0, NULL, 0);
}

struct unvme_cmd *unvmed_alloc_cmd_meta(struct unvme *u, struct unvme_sq *usq,
					uint16_t *cid, void *buf, size_t len,
					void *mbuf, size_t mlen)
{
	if (!buf || !len) {
		errno = EINVAL;
		return NULL;
	}

	return __unvmed_cmd_init(u, usq, cid, buf, len, mbuf, mlen);
}

int __unvmed_mapv_prp(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		      struct iovec *iov, int nr_iov)
{
	if (nr_iov <= 0)
		return 0;

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

int unvmed_cmd_prep(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		    struct iovec *iov, int nr_iov)
{
	union nvme_cmd *__sqe = &cmd->sqe;

	*__sqe  = *sqe;
	__sqe->cid = cmd->cid;

	if (!__sqe->dptr.prp1 && !__sqe->dptr.prp2) {
		if (__unvmed_mapv_prp(cmd, __sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
		}
	}
	return 0;
}

void unvmed_cmd_issue(struct unvme_cmd *cmd)
{
	cmd->flags |= UNVMED_CMD_F_WAKEUP_ON_CQE;

	unvmed_sq_enter(cmd->usq);
	unvmed_cmd_post(cmd, &cmd->sqe, cmd->flags);
	unvmed_sq_exit(cmd->usq);
}

int unvmed_cmd_issue_and_wait(struct unvme_cmd *cmd)
{
	unvmed_cmd_issue(cmd);

	unvmed_cmd_wait(cmd);
	return unvmed_cqe_status(&cmd->cqe);
}

int unvmed_passthru(struct unvme_cmd *cmd, union nvme_cmd *sqe,
		    struct iovec *iov, int nr_iov)
{
	if (unvmed_cmd_prep(cmd, sqe, iov, nr_iov) < 0) {
		unvmed_log_err("failed to prepare a command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_id_ns(struct unvme_cmd *cmd, uint32_t nsid,
			  struct iovec *iov, int nr_iov)
{
	struct nvme_cmd_identify *sqe = (struct nvme_cmd_identify *)&cmd->sqe;

	sqe->opcode = nvme_admin_identify;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cns = cpu_to_le32(0x0);
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}

int unvmed_id_ns(struct unvme_cmd *cmd, uint32_t nsid,
		 struct iovec *iov, int nr_iov)
{
	if (unvmed_cmd_prep_id_ns(cmd, nsid, iov, nr_iov) < 0) {
		unvmed_log_err("failed to prepare Identify Namespace command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_id_ctrl(struct unvme_cmd *cmd, struct iovec *iov, int nr_iov)
{
	struct nvme_cmd_identify *sqe = (struct nvme_cmd_identify *)&cmd->sqe;

	sqe->opcode = nvme_admin_identify;
	sqe->cns = NVME_IDENTIFY_CNS_CTRL;
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}

int unvmed_id_ctrl(struct unvme_cmd *cmd, struct iovec *iov, int nr_iov)
{
	if (unvmed_cmd_prep_id_ctrl(cmd, iov, nr_iov) < 0) {
		unvmed_log_err("failed to prepare Identify Controller command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_id_active_nslist(struct unvme_cmd *cmd, uint32_t nsid,
				     struct iovec *iov, int nr_iov)
{
	struct nvme_cmd_identify *sqe = (struct nvme_cmd_identify *)&cmd->sqe;

	sqe->opcode = nvme_admin_identify;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cns = cpu_to_le32(0x2);
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}

int unvmed_id_active_nslist(struct unvme_cmd *cmd, uint32_t nsid,
			    struct iovec *iov, int nr_iov)
{
	if (unvmed_cmd_prep_id_active_nslist(cmd, nsid, iov, nr_iov) < 0) {
		unvmed_log_err("failed to prepare Identify Active NS List command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_nvm_id_ns(struct unvme_cmd *cmd, uint32_t nsid,
			      struct iovec *iov, int nr_iov)
{
	struct nvme_cmd_identify *sqe = (struct nvme_cmd_identify *)&cmd->sqe;

	sqe->opcode = nvme_admin_identify;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cns = NVME_IDENTIFY_CNS_CSI_NS;
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}

int unvmed_nvm_id_ns(struct unvme_cmd *cmd, uint32_t nsid, struct iovec *iov,
		     int nr_iov)
{
	if (unvmed_cmd_prep_nvm_id_ns(cmd, nsid, iov, nr_iov) < 0) {
		unvmed_log_err("failed to prepare Identify NVM Namespace command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_set_features(struct unvme_cmd *cmd, uint32_t nsid,
				 uint8_t fid, bool save, uint32_t cdw11,
				 uint32_t cdw12, struct iovec *iov, int nr_iov)
{
	struct nvme_cmd_features *sqe = (struct nvme_cmd_features *)&cmd->sqe;
	const int CDW10_SAVE_SHIFT = 15;

	sqe->opcode = nvme_admin_set_features;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->fid = fid;
	sqe->rsvd42 = cpu_to_le16(save << CDW10_SAVE_SHIFT);
	sqe->cdw11 = cpu_to_le32(cdw11);
	sqe->cdw12 = cpu_to_le32(cdw12);
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}


int unvmed_set_features(struct unvme_cmd *cmd, uint32_t nsid, uint8_t fid,
			bool save, uint32_t cdw11, uint32_t cdw12,
			struct iovec *iov, int nr_iov)
{
	if (unvmed_cmd_prep_set_features(cmd, nsid, fid, save, cdw11, cdw12,
				iov, nr_iov) < 0) {
		unvmed_log_err("failed to prepare Set Features command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_set_features_hmb(struct unvme_cmd *cmd, uint32_t hsize,
				     uint64_t descs_addr, uint32_t nr_descs,
				     bool mr, bool enable)
{
	struct nvme_cmd_features *sqe = (struct nvme_cmd_features *)&cmd->sqe;

	sqe->opcode = nvme_admin_set_features;
	sqe->fid = NVME_FEAT_FID_HOST_MEM_BUF;
	sqe->cdw11 = cpu_to_le32((!!mr << 1) | !!enable);
	sqe->cdw12 = cpu_to_le32(hsize);
	sqe->cdw13 = cpu_to_le32(descs_addr & 0xffffffff);
	sqe->cdw14 = cpu_to_le32(descs_addr >> 32);
	sqe->cdw15 = cpu_to_le32(nr_descs);
	sqe->cid = cmd->cid;

	return 0;
}

int unvmed_set_features_hmb(struct unvme_cmd *cmd, uint32_t hsize,
			    uint64_t descs_addr, uint32_t nr_descs,
			    bool mr, bool enable)
{
	struct unvme *u = cmd->u;

	if (unvmed_cmd_prep_set_features_hmb(cmd, u->hmb.hsize,
				u->hmb.descs_iova, u->hmb.nr_descs,
				mr, enable) < 0) {
		unvmed_log_err("failed to prepare Set Features HMB command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_get_features(struct unvme_cmd *cmd, uint32_t nsid,
				 uint8_t fid, uint8_t sel, uint32_t cdw11,
				 uint32_t cdw14, struct iovec *iov, int nr_iov)
{
	struct nvme_cmd_features *sqe = (struct nvme_cmd_features *)&cmd->sqe;

	sqe->opcode = nvme_admin_get_features;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->fid = fid;
	sqe->sel = sel;
	sqe->cdw11 = cpu_to_le32(cdw11);
	sqe->cdw14 = cpu_to_le32(cdw14);
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}

int unvmed_get_features(struct unvme_cmd *cmd, uint32_t nsid,
			uint8_t fid, uint8_t sel, uint32_t cdw11,
			uint32_t cdw14, struct iovec *iov, int nr_iov)
{
	if (unvmed_cmd_prep_get_features(cmd, nsid, fid, sel, cdw11, cdw14,
				iov, nr_iov) < 0) {
		unvmed_log_err("failed to prepare Get Features command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_read(struct unvme_cmd *cmd, uint32_t nsid, uint64_t slba,
			 uint16_t nlb, uint8_t prinfo, uint16_t atag,
			 uint16_t atag_mask, uint64_t rtag, uint64_t stag,
			 bool stag_check, struct iovec *iov, int nr_iov,
			 void *mbuf, void *opaque)
{
	struct nvme_cmd_rw *sqe = (struct nvme_cmd_rw *)&cmd->sqe;
	int ret;

	sqe->opcode = nvme_cmd_read;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->slba = cpu_to_le64(slba);
	sqe->nlb = cpu_to_le16(nlb);
	sqe->cid = cmd->cid;

	if (cmd->flags & UNVMED_CMD_F_SGL)
		ret = __unvmed_mapv_sgl(cmd, &cmd->sqe, iov, nr_iov);
	else
		ret = __unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov);
	if (ret) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}

	if (cmd->flags & UNVMED_CMD_F_SGL)
		sqe->flags |= NVME_CMD_FLAGS_PSDT_SGL_MPTR_CONTIG <<
			NVME_CMD_FLAGS_PSDT_SHIFT;

	/*
	 * If user does not give `mbuf` for metadata buffer, try with the
	 * pre-initialized meta data buffer initialized when @cmd was created.
	 */
	if (!mbuf && cmd->mbuf.va)
		mbuf = cmd->mbuf.va;

	if (mbuf) {
		uint64_t iova;

		if (unvmed_to_iova(cmd->u, mbuf, &iova)) {
			errno = EFAULT;
			return -1;
		}

		/*
		 * Mapping MPTR should be done in libvfn, but we don't have
		 * helpers for MPTR yet, just do it here until helpers are
		 * provided.
		 */
		sqe->mptr = cpu_to_le64(iova);
	}

	unvmed_sqe_set_tags(cmd->u, nsid, sqe, atag, atag_mask, rtag, stag);
	sqe->control |= (prinfo << 10);
	if (stag_check)
		sqe->control |= NVME_IO_STC;

	cmd->opaque = opaque;
	return 0;
}

int unvmed_read(struct unvme_cmd *cmd, uint32_t nsid, uint64_t slba,
		uint16_t nlb, uint8_t prinfo, uint16_t atag, uint16_t atag_mask,
		uint64_t rtag, uint64_t stag, bool stag_check,
		struct iovec *iov, int nr_iov, void *mbuf, void *opaque)
{
	if (unvmed_cmd_prep_read(cmd, nsid, slba, nlb, prinfo, atag, atag_mask,
				rtag, stag, stag_check, iov, nr_iov, mbuf,
				opaque) < 0) {
		unvmed_log_err("failed to prepare Read command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_write(struct unvme_cmd *cmd, uint32_t nsid, uint64_t slba,
		uint16_t nlb, uint8_t prinfo, uint16_t atag, uint16_t atag_mask,
		uint64_t rtag, uint64_t stag, bool stag_check,
		struct iovec *iov, int nr_iov, void *mbuf, void *opaque)
{
	struct nvme_cmd_rw *sqe = (struct nvme_cmd_rw *)&cmd->sqe;
	int ret;

	sqe->opcode = nvme_cmd_write;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->slba = cpu_to_le64(slba);
	sqe->nlb = cpu_to_le16(nlb);
	sqe->cid = cmd->cid;

	if (cmd->flags & UNVMED_CMD_F_SGL)
		ret = __unvmed_mapv_sgl(cmd, &cmd->sqe, iov, nr_iov);
	else
		ret = __unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov);
	if (ret) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}

	if (cmd->flags & UNVMED_CMD_F_SGL)
		sqe->flags |= NVME_CMD_FLAGS_PSDT_SGL_MPTR_CONTIG <<
			NVME_CMD_FLAGS_PSDT_SHIFT;

	/*
	 * If user does not give `mbuf` for metadata buffer, try with the
	 * pre-initialized meta data buffer initialized when @cmd was created.
	 */
	if (!mbuf && cmd->mbuf.va)
		mbuf = cmd->mbuf.va;

	if (mbuf) {
		uint64_t iova;

		if (unvmed_to_iova(cmd->u, mbuf, &iova)) {
			errno = EFAULT;
			return -1;
		}

		/*
		 * Mapping MPTR should be done in libvfn, but we don't have
		 * helpers for MPTR yet, just do it here until helpers are
		 * provided.
		 */
		sqe->mptr = cpu_to_le64(iova);
	}

	unvmed_sqe_set_tags(cmd->u, nsid, sqe, atag, atag_mask, rtag, stag);
	sqe->control |= (prinfo << 10);
	if (stag_check)
		sqe->control |= NVME_IO_STC;

	cmd->opaque = opaque;
	return 0;
}

int unvmed_write(struct unvme_cmd *cmd, uint32_t nsid, uint64_t slba,
		 uint16_t nlb, uint8_t prinfo, uint16_t atag,
		 uint16_t atag_mask, uint64_t rtag, uint64_t stag,
		 bool stag_check, struct iovec *iov, int nr_iov, void *mbuf,
		 void *opaque)
{
	if (unvmed_cmd_prep_write(cmd, nsid, slba, nlb, prinfo, atag, atag_mask,
				rtag, stag, stag_check, iov, nr_iov, mbuf,
				opaque) < 0) {

		unvmed_log_err("failed to prepare Write command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_format(struct unvme_cmd *cmd, uint32_t nsid, uint8_t lbaf,
			   uint8_t ses, uint8_t pil, uint8_t pi, uint8_t mset)
{
	union nvme_cmd *sqe = &cmd->sqe;

	sqe->opcode = nvme_admin_format_nvm;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cdw10 = ((lbaf >> 4 & 3) << 12) | ((ses & 0x7) << 9) |
		((pil & 0x1) << 8) | ((pi & 0x7) << 5) | ((mset & 0x1) << 4) |
		(lbaf & 0xf);
	sqe->cid = cmd->cid;

	return 0;
}

int unvmed_format(struct unvme_cmd *cmd, uint32_t nsid, uint8_t lbaf,
		  uint8_t ses, uint8_t pil, uint8_t pi, uint8_t mset)
{
	if (unvmed_cmd_prep_format(cmd, nsid, lbaf, ses, pil, pi, mset) < 0) {
		unvmed_log_err("failed to prepare Format command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_virt_mgmt(struct unvme_cmd *cmd, uint32_t cntlid,
			      uint32_t rt, uint32_t act, uint32_t nr)
{
	union nvme_cmd *sqe = &cmd->sqe;

	sqe->opcode = nvme_admin_virtual_mgmt;
	sqe->cdw10 = ((act & 0xf) | ((rt & 0x7) << 8) | ((cntlid & 0xffff) << 16));
	sqe->cdw11 = (nr & 0xffff);
	sqe->cid = cmd->cid;

	return 0;
}

int unvmed_virt_mgmt(struct unvme_cmd *cmd, uint32_t cntlid, uint32_t rt,
		     uint32_t act, uint32_t nr)
{
	if (unvmed_cmd_prep_virt_mgmt(cmd, cntlid, rt, act, nr) < 0) {
		unvmed_log_err("failed to prepare Virtualization Mgmt. command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_id_primary_ctrl_caps(struct unvme_cmd *cmd,
					 struct iovec *iov, int nr_iov,
					 uint32_t cntlid)
{
	struct nvme_cmd_identify *sqe = (struct nvme_cmd_identify *)&cmd->sqe;

	sqe->opcode = nvme_admin_identify;
	sqe->ctrlid = cntlid;
	sqe->cns = NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP;
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}

int unvmed_id_primary_ctrl_caps(struct unvme_cmd *cmd, struct iovec *iov,
				int nr_iov, uint32_t cntlid)
{
	if (unvmed_cmd_prep_id_primary_ctrl_caps(cmd, iov, nr_iov, cntlid) < 0) {
		unvmed_log_err("failed to prepare Identify Primary Controller command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_id_secondary_ctrl_list(struct unvme_cmd *cmd,
					   struct iovec *iov, int nr_iov,
					   uint32_t cntlid)
{
	struct nvme_cmd_identify *sqe = (struct nvme_cmd_identify *)&cmd->sqe;

	sqe->opcode = nvme_admin_identify;
	sqe->ctrlid = cntlid;
	sqe->cns = NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST;
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}

int unvmed_id_secondary_ctrl_list(struct unvme_cmd *cmd, struct iovec *iov,
				  int nr_iov, uint32_t cntlid)
{
	if (unvmed_cmd_prep_id_secondary_ctrl_list(cmd, iov, nr_iov, cntlid) < 0) {
		unvmed_log_err("failed to prepare Identify Secondary Controller command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_create_ns(struct unvme_cmd *cmd, uint64_t nsze,
			      uint64_t ncap, uint8_t flbas, uint8_t dps,
			      uint8_t nmic, uint32_t anagrp_id,
			      uint16_t nvmset_id, uint16_t endg_id,
			      uint8_t csi, uint64_t lbstm, uint16_t nphndls,
			      uint16_t *phndls, struct iovec *iov, int nr_iov)
{
	union nvme_cmd *sqe = &cmd->sqe;
	struct nvme_ns_mgmt_host_sw_specified *id_ns =
		(struct nvme_ns_mgmt_host_sw_specified *)cmd->buf.va;

	id_ns->nsze = cpu_to_le64(nsze);
	id_ns->ncap = cpu_to_le64(ncap);
	id_ns->flbas = flbas;
	id_ns->dps = dps;
	id_ns->nmic = nmic;
	id_ns->anagrpid = cpu_to_le32(anagrp_id);
	id_ns->nvmsetid = cpu_to_le16(nvmset_id);
	id_ns->endgid = cpu_to_le16(endg_id);
	id_ns->lbstm = cpu_to_le64(lbstm);
	id_ns->nphndls = cpu_to_le16(nphndls);
	for (int i = 0; i < nphndls; i++)
		id_ns->phndl[i] = cpu_to_le16(phndls[i]);

	sqe->opcode = nvme_admin_ns_mgmt;
	sqe->cdw10 = NVME_NS_MGMT_SEL_CREATE;
	sqe->cdw11 = cpu_to_le32(csi << 24);
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}

int unvmed_create_ns(struct unvme_cmd *cmd, uint64_t nsze, uint64_t ncap,
		     uint8_t flbas, uint8_t dps, uint8_t nmic,
		     uint32_t anagrp_id, uint16_t nvmset_id, uint16_t endg_id,
		     uint8_t csi, uint64_t lbstm, uint16_t nphndls,
		     uint16_t *phndls, struct iovec *iov, int nr_iov)
{
	if (unvmed_cmd_prep_create_ns(cmd, nsze, ncap, flbas, dps, nmic,
				      anagrp_id, nvmset_id, endg_id, csi, lbstm,
				      nphndls, phndls, iov, nr_iov) < 0) {
		unvmed_log_err("failed to prepare Create Namespace command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_delete_ns(struct unvme_cmd *cmd, uint32_t nsid)
{
	union nvme_cmd *sqe = &cmd->sqe;

	sqe->opcode = nvme_admin_ns_mgmt;
	sqe->cdw10 = NVME_NS_MGMT_SEL_DELETE;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cid = cmd->cid;

	return 0;
}

int unvmed_delete_ns(struct unvme_cmd *cmd, uint32_t nsid)
{
	if (unvmed_cmd_prep_delete_ns(cmd, nsid) < 0) {
		unvmed_log_err("failed to prepare Delete Namespace command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_attach_ns(struct unvme_cmd *cmd, uint32_t nsid,
			      int nr_ctrlids, uint16_t *ctrlids,
			      struct iovec *iov, int nr_iov)
{
	union nvme_cmd *sqe = &cmd->sqe;
	__le16 *__ctrlids = (uint16_t *)cmd->buf.va;

	__ctrlids[0] = cpu_to_le16(nr_ctrlids);
	for (int i = 0; i < nr_ctrlids; i++)
		__ctrlids[i+1] = cpu_to_le16(ctrlids[i]);

	sqe->opcode = nvme_admin_ns_attach;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cdw10 = NVME_NS_ATTACH_SEL_CTRL_ATTACH;
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}

int unvmed_attach_ns(struct unvme_cmd *cmd, uint32_t nsid,
		     int nr_ctrlids, uint16_t *ctrlids,
		     struct iovec *iov, int nr_iov)
{
	if (unvmed_cmd_prep_attach_ns(cmd, nsid, nr_ctrlids, ctrlids, iov, nr_iov) < 0) {
		unvmed_log_err("failed to prepare Attach Namespace command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_prep_detach_ns(struct unvme_cmd *cmd, uint32_t nsid,
			      int nr_ctrlids, uint16_t *ctrlids,
			      struct iovec *iov, int nr_iov)
{
	union nvme_cmd *sqe = &cmd->sqe;
	__le16 *__ctrlids = (uint16_t *)cmd->buf.va;

	__ctrlids[0] = cpu_to_le16(nr_ctrlids);
	for (int i = 0; i < nr_ctrlids; i++)
		__ctrlids[i+1] = cpu_to_le16(ctrlids[i]);

	sqe->opcode = nvme_admin_ns_attach;
	sqe->nsid = cpu_to_le32(nsid);
	sqe->cdw10 = NVME_NS_ATTACH_SEL_CTRL_DEATTACH;
	sqe->cid = cmd->cid;

	if (__unvmed_mapv_prp(cmd, &cmd->sqe, iov, nr_iov)) {
		unvmed_log_err("failed to map iovec for prp");
		return -1;
	}
	return 0;
}

int unvmed_detach_ns(struct unvme_cmd *cmd, uint32_t nsid,
		     int nr_ctrlids, uint16_t *ctrlids,
		     struct iovec *iov, int nr_iov)
{
	if (unvmed_cmd_prep_detach_ns(cmd, nsid, nr_ctrlids, ctrlids, iov, nr_iov) < 0) {
		unvmed_log_err("failed to prepare Deattach Namespace command");
		return -1;
	}

	return unvmed_cmd_issue_and_wait(cmd);
}

int unvmed_cmd_wait(struct unvme_cmd *cmd)
{
	return __unvmed_cmd_wait(cmd);
}

int unvmed_cmd_prep_create_sq(struct unvme_cmd *cmd, struct unvme *u, uint32_t qid, uint32_t qsize,
			      uint32_t cqid)
{
	struct nvme_cmd_create_sq *sqe = (struct nvme_cmd_create_sq *)&cmd->sqe;

	sqe->opcode = nvme_admin_create_sq;
	sqe->qid = cpu_to_le16(qid);
	sqe->prp1 = cpu_to_le64(u->ctrl.sq[qid].mem.iova);
	sqe->qsize = cpu_to_le16((uint16_t)(qsize - 1));
	sqe->qflags = cpu_to_le16(NVME_Q_PC);
	sqe->cqid = cpu_to_le16((uint16_t)cqid);
	sqe->cid = cmd->cid;

	return 0;
}

int unvmed_cmd_prep_delete_sq(struct unvme_cmd *cmd, uint32_t qid)
{
	struct nvme_cmd_delete_q *sqe = (struct nvme_cmd_delete_q *)&cmd->sqe;

	sqe->opcode = nvme_admin_delete_sq;
	sqe->qid = cpu_to_le16(qid);
	sqe->cid = cmd->cid;

	return 0;
}

int unvmed_cmd_prep_create_cq(struct unvme_cmd *cmd, struct unvme *u, uint32_t qid, uint32_t qsize,
			      int vector)
{
	struct nvme_cmd_create_cq *sqe = (struct nvme_cmd_create_cq *)&cmd->sqe;
	uint16_t qflags = NVME_Q_PC;
	uint16_t iv = 0;

	if (vector >= 0) {
		qflags |= NVME_CQ_IEN;
		iv = (uint16_t)vector;
	}

	sqe->opcode = nvme_admin_create_cq;
	sqe->qid = cpu_to_le16(qid);
	sqe->prp1 = cpu_to_le64(u->ctrl.cq[qid].mem.iova);
	sqe->qsize = cpu_to_le16((uint16_t)(qsize - 1));
	sqe->qflags = cpu_to_le16(qflags);
	sqe->iv = cpu_to_le16(iv);
	sqe->cid = cmd->cid;

	return 0;
}

int unvmed_cmd_prep_delete_cq(struct unvme_cmd *cmd, uint32_t qid)
{
	struct nvme_cmd_delete_q *sqe = (struct nvme_cmd_delete_q *)&cmd->sqe;

	sqe->opcode = nvme_admin_delete_cq;
	sqe->qid = cpu_to_le16(qid);
	sqe->cid = cmd->cid;

	return 0;
}
