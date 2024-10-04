// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <ccan/str/str.h>

#include <vfn/nvme.h>
#include <nvme/types.h>
#include <libunvmed.h>

#include "unvme.h"
#include "unvmed.h"

void unvme_pr_raw(void *vaddr, size_t len)
{
	for (int i = 0; i < len; i++)
		unvme_pr("%c", ((char *)vaddr)[i]);
}

void unvme_pr_id_ns(void *vaddr)
{
	struct nvme_id_ns *id_ns = (struct nvme_id_ns *)vaddr;

	unvme_pr("nsze: %lx\n", le64_to_cpu(id_ns->nsze));
	unvme_pr("ncap: %lx\n", le64_to_cpu(id_ns->ncap));
}

void unvme_pr_show_regs(struct unvme *u)
{
	unvme_pr("cap     : %lx\n",	unvmed_read64(u, NVME_REG_CAP));
	unvme_pr("version : %x\n",	unvmed_read32(u, NVME_REG_VS));
	unvme_pr("cc      : %x\n",	unvmed_read32(u, NVME_REG_CC));
	unvme_pr("csts    : %x\n",	unvmed_read32(u, NVME_REG_CSTS));
	unvme_pr("nssr    : %x\n",	unvmed_read32(u, NVME_REG_NSSR));
	unvme_pr("intms   : %x\n",	unvmed_read32(u, NVME_REG_INTMS));
	unvme_pr("intmc   : %x\n",	unvmed_read32(u, NVME_REG_INTMC));
	unvme_pr("aqa     : %x\n",	unvmed_read32(u, NVME_REG_AQA));
	unvme_pr("asq     : %lx\n",	unvmed_read64(u, NVME_REG_ASQ));
	unvme_pr("acq     : %lx\n",	unvmed_read64(u, NVME_REG_ACQ));
	unvme_pr("cmbloc  : %x\n",	unvmed_read32(u, NVME_REG_CMBLOC));
	unvme_pr("cmbsz   : %x\n",	unvmed_read32(u, NVME_REG_CMBSZ));
	unvme_pr("bpinfo  : %x\n",	unvmed_read32(u, NVME_REG_BPINFO));
	unvme_pr("bprsel  : %x\n",	unvmed_read32(u, NVME_REG_BPRSEL));
	unvme_pr("bpmbl   : %lx\n",	unvmed_read64(u, NVME_REG_BPMBL));
	unvme_pr("cmbmsc  : %lx\n",	unvmed_read64(u, NVME_REG_CMBMSC));
	unvme_pr("cmbsts  : %x\n",	unvmed_read32(u, NVME_REG_CMBSTS));
	unvme_pr("pmrcap  : %x\n",	unvmed_read32(u, NVME_REG_PMRCAP));
	unvme_pr("pmrctl  : %x\n",	unvmed_read32(u, NVME_REG_PMRCTL));
	unvme_pr("pmrsts  : %x\n",	unvmed_read32(u, NVME_REG_PMRSTS));
	unvme_pr("pmrebs  : %x\n",	unvmed_read32(u, NVME_REG_PMREBS));
	unvme_pr("pmrswtp : %x\n",	unvmed_read32(u, NVME_REG_PMRSWTP));
	unvme_pr("pmrmscl : %x\n",	unvmed_read32(u, NVME_REG_PMRMSCL));
	unvme_pr("pmrmscu : %x\n",	unvmed_read32(u, NVME_REG_PMRMSCU));
}

void unvme_pr_status(struct unvme *u)
{
	uint32_t cc = unvmed_read32(u, NVME_REG_CC);
	uint32_t csts = unvmed_read32(u, NVME_REG_CSTS);
	uint32_t qid;
	struct nvme_sq *sq;
	struct nvme_cq *cq;

	unvme_pr("Controller				: %s\n", unvmed_bdf(u));
	unvme_pr("Controller Configuration	(CC)	: %#x\n", cc);
	unvme_pr("Controller Status		(CSTS)	: %#x\n\n", csts);

	unvme_pr("Submission Queue\n");
	unvme_pr("qid  vaddr              iova               cqid tail ptail qsize\n");
	unvme_pr("---- ------------------ ------------------ ---- ---- ----- -----\n");
	for (qid = 0; ; qid++) {
		sq = unvmed_get_sq(u, qid);
		if (!sq)
			break;

		unvme_pr("%4d %18p %#18lx %4d %4d %5d %5d\n",
			 sq->id, sq->vaddr, sq->iova,
			 sq->cq->id, sq->tail, sq->ptail, sq->qsize);
	}
	unvme_pr("\n");
	unvme_pr("Completion Queue\n");
	unvme_pr("qid  vaddr              iova               head qsize phase vec \n");
	unvme_pr("---- ------------------ ------------------ ---- ----- ----- ----\n");
	for (qid = 0; ; qid++) {
		cq = unvmed_get_cq(u, qid);
		if (!cq)
			break;

		unvme_pr("%4d %18p %#18lx %4d %5d %5d %4d\n",
			 cq->id, cq->vaddr, cq->iova,
			 cq->head, cq->qsize, cq->phase, cq->vector);
	}
	unvme_pr("\n");
}
