// SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#include <sys/time.h>

#include <vfn/nvme.h>
#include <nvme/types.h>

#include "libunvmed.h"
#include "libunvmed-private.h"

static char __buf[256];
#define LOG_MAX_LEN sizeof(__buf)

static const char *unvmed_log_delete_sq(union nvme_cmd *sqe)
{
	uint16_t sqid = le32_to_cpu(sqe->cdw10) & 0xFFFF;

	snprintf(__buf, LOG_MAX_LEN, "unvmed_admin_delete_sq sqid=%u", sqid);

	return __buf;
}

static const char *unvmed_log_create_sq(union nvme_cmd *sqe)
{
	uint16_t sqid = le32_to_cpu(sqe->cdw10) & 0xFFFF;
	uint16_t qsize = (le32_to_cpu(sqe->cdw10) >> 16) & 0xFFFF;
	uint16_t sq_flags = le32_to_cpu(sqe->cdw11) & 0xFFFF;
	uint16_t cqid = (le32_to_cpu(sqe->cdw11) >> 16) & 0xFFFF;

	snprintf(__buf, LOG_MAX_LEN, "unvmed_admin_create_sq "
		 "sqid=%u, qsize=%u, sq_flags=0x%x, cqid=%u",
		 sqid, qsize, sq_flags, cqid);

	return __buf;
}

static const char *unvmed_log_delete_cq(union nvme_cmd *sqe)
{
	uint16_t cqid = le32_to_cpu(sqe->cdw10) & 0xFFFF;

	snprintf(__buf, LOG_MAX_LEN, "unvmed_admin_delete_cq cqid=%u", cqid);

	return __buf;
}

static const char *unvmed_log_create_cq(union nvme_cmd *sqe)
{
	uint16_t cqid = le32_to_cpu(sqe->cdw10) & 0xFFFF;
	uint16_t qsize = (le32_to_cpu(sqe->cdw10) >> 16) & 0xFFFF;
	uint16_t cq_flags = le32_to_cpu(sqe->cdw11) & 0xFFFF;
	uint16_t irq_vector = (le32_to_cpu(sqe->cdw11) >> 16) & 0xFFFF;

	snprintf(__buf, LOG_MAX_LEN, "unvmed_admin_create_cq "
		 "cqid=%u, qsize=%u, cq_flags=0x%x, irq_vector=%u",
		 cqid, qsize, cq_flags, irq_vector);

	return __buf;
}

static const char *unvmed_log_admin_identify(union nvme_cmd *sqe)
{
	uint8_t cns = le32_to_cpu(sqe->cdw10) & 0xFF;
	uint16_t ctrlid = (le32_to_cpu(sqe->cdw10) >> 16) & 0xFFFF;

	snprintf(__buf, LOG_MAX_LEN, "nvme_admin_identify "
		 "cns=%u, ctrlid=%u", cns, ctrlid);

	return __buf;
}

static const char *unvmed_log_read_write(union nvme_cmd *sqe)
{
	uint64_t slba = ((uint64_t) sqe->cdw11 << 32) | sqe->cdw10;
	uint16_t length = le32_to_cpu(sqe->cdw12) & 0xFF;
	uint16_t control = (le32_to_cpu(sqe->cdw12) >> 16) & 0xFFFF;
	uint32_t dsmgmt = sqe->cdw13;
	uint32_t reftag = sqe->cdw14;

	if (sqe->opcode == 1)
		snprintf(__buf, LOG_MAX_LEN, "write "
			 "slba=%lu, len=%u, ctrl=0x%x, dsmgmt=%u, reftag=%u",
			 slba, length, control, dsmgmt, reftag);
	else
		snprintf(__buf, LOG_MAX_LEN, "read "
			 "slba=%lu, len=%u, ctrl=0x%x, dsmgmt=%u, reftag=%u",
			 slba, length, control, dsmgmt, reftag);

	return __buf;
}

static const char *unvmed_log_common(union nvme_cmd *sqe)
{
	snprintf(__buf, LOG_MAX_LEN, "opcode=0x%x, cdw2=0x%x, cdw3=0x%x, "
		 "cdw10=0x%x, cdw11=0x%x, cdw12=0x%x, "
		 "cdw13=0x%x, cdw14=0x%x, cdw15=0x%x",
		 sqe->opcode, sqe->cdw2, sqe->cdw3,
		 sqe->cdw10, sqe->cdw11, sqe->cdw12,
		 sqe->cdw13, sqe->cdw14, sqe->cdw15);

	return __buf;
}

static const char *unvmed_log_io_cmd(union nvme_cmd *sqe)
{
	switch (sqe->opcode) {
	case nvme_cmd_write:
	case nvme_cmd_read:
		return unvmed_log_read_write(sqe);
	}

	return unvmed_log_common(sqe);
}

static const char *unvmed_log_admin_cmd(union nvme_cmd *sqe)
{
	switch (sqe->opcode) {
	case nvme_admin_delete_sq:
		return unvmed_log_delete_sq(sqe);
	case nvme_admin_create_sq:
		return unvmed_log_create_sq(sqe);
	case nvme_admin_delete_cq:
		return unvmed_log_delete_cq(sqe);
	case nvme_admin_create_cq:
		return unvmed_log_create_cq(sqe);
	case nvme_admin_identify:
		return unvmed_log_admin_identify(sqe);
	}

	return unvmed_log_common(sqe);
}

void unvmed_log_cmd_post(const char *bdf, uint32_t sqid, union nvme_cmd *sqe)
{
	bool admin = (!sqid) ? true : false;
	int psdt = (sqe->flags >> 6) & 0x3;
	char * psdt_type;
	uint64_t dptr0 = 0;
	uint64_t dptr1 = 0;
	const char *str;

	switch(psdt) {
		case 0:
			psdt_type = "prp";
			dptr0 = sqe->dptr.prp1;
			dptr1 = sqe->dptr.prp2;
			break;
		case 1:
		case 2:
			psdt_type = "sgl";
			dptr0 = sqe->dptr.sgl.addr;
			dptr1 = sqe->dptr.sgl.len;
			break;
		default:
			psdt_type = "reserved";
	}

	str = (admin) ? unvmed_log_admin_cmd(sqe) : unvmed_log_io_cmd(sqe);

	unvmed_log_nvme("unvmed_cmd_post: %s: sqe (qid=%d, cid=%d, nsid=%d, "
		 "fuse=0x%x, psdt=%d(%s), mptr=0x%lx, "
		 "dptr0=0x%lx, dptr1=0x%lx, cmd=(%s))",
		 bdf, sqid, sqe->cid, sqe->nsid,
		 sqe->flags & 0x3, psdt, psdt_type, sqe->mptr,
		 dptr0, dptr1, str);
}

void unvmed_log_cmd_cmpl(const char *bdf, struct nvme_cqe *cqe)
{
	uint16_t sfp = cqe->sfp;

	unvmed_log_nvme("unvmed_cmd_cmpl: %s: cqe (qid=%d, cid=%d, "
		 "dw0=0x%x, dw1=0x%x, head=%d, phase=%d, sct=0x%x, sc=0x%x, "
		 "crd=0x%x, more=%d, dnr=%d)",
		 bdf, cqe->sqid, cqe->cid,
		 cqe->dw0, cqe->dw1, cqe->sqhd, sfp & 0x1,
		 (sfp >> 9) & 0x7, (sfp >> 1) & 0xFF,
		 (sfp >> 12) & 0xFF, (sfp >> 14) & 0x1, (sfp >> 15) & 0x1);
}
