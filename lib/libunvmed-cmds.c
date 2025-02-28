// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#define _GNU_SOURCE

#include <vfn/nvme.h>
#include <nvme/types.h>

#include "libunvmed.h"

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

	if (!sqe->dptr.prp1 && !sqe->dptr.prp2) {
		if (__unvmed_mapv_prp(cmd, sqe, iov, nr_iov)) {
			unvmed_log_err("failed to map iovec for prp");
			return -1;
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
