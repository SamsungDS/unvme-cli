// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <sys/time.h>

#include <ccan/str/str.h>

#include <vfn/nvme.h>
#include <sys/msg.h>
#include <nvme/types.h>
#include <nvme/util.h>

#include "libunvmed.h"
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
	uint8_t in_use;
	nvme_id_ns_flbas_to_lbaf_inuse(id_ns->flbas, &in_use);

	unvme_pr("%10s:\t%#lx\n", "nsze", le64_to_cpu(id_ns->nsze));
	unvme_pr("%10s:\t%#lx\n", "ncap", le64_to_cpu(id_ns->ncap));
	unvme_pr("%10s:\t%#lx\n", "nuse", le64_to_cpu(id_ns->nuse));
	unvme_pr("%10s:\t%#x\n", "nsfeat", id_ns->nsfeat);
	unvme_pr("%10s:\t%#x\n", "nlbaf", id_ns->nlbaf);
	unvme_pr("%10s:\t%#x\n", "flbas", id_ns->flbas);
	unvme_pr("%10s:\t%#x\n", "mc", id_ns->mc);
	unvme_pr("%10s:\t%#x\n", "dpc", id_ns->dpc);
	unvme_pr("%10s:\t%#x\n", "dps", id_ns->dps);
	unvme_pr("%10s:\t%#x\n", "nmic", id_ns->nmic);
	unvme_pr("%10s:\t%#x\n", "rescap", id_ns->rescap);
	unvme_pr("%10s:\t%#x\n", "fpi", id_ns->fpi);
	unvme_pr("%10s:\t%#x\n", "dlfeat", id_ns->dlfeat);
	unvme_pr("%10s:\t%#x\n", "nawun", le16_to_cpu(id_ns->nawun));
	unvme_pr("%10s:\t%#x\n", "nawupf", le16_to_cpu(id_ns->nawupf));
	unvme_pr("%10s:\t%#x\n", "nacwu", le16_to_cpu(id_ns->nacwu));
	unvme_pr("%10s:\t%#x\n", "nabsn", le16_to_cpu(id_ns->nabsn));
	unvme_pr("%10s:\t%#x\n", "nabo", le16_to_cpu(id_ns->nabo));
	unvme_pr("%10s:\t%#x\n", "nabspf", le16_to_cpu(id_ns->nabspf));
	unvme_pr("%10s:\t%#x\n", "noiob", le16_to_cpu(id_ns->noiob));
	unvme_pr("%10s:\tlo: %#lx, hi: %#lx\n", "nvmcap",
			le64_to_cpu(*(leint64_t *)&id_ns->nvmcap[0]),
			le64_to_cpu(*(leint64_t *)&id_ns->nvmcap[8]));
	unvme_pr("%10s:\t%#x\n", "npwg", le16_to_cpu(id_ns->npwg));
	unvme_pr("%10s:\t%#x\n", "npwa", le16_to_cpu(id_ns->npwa));
	unvme_pr("%10s:\t%#x\n", "npdg", le16_to_cpu(id_ns->npdg));
	unvme_pr("%10s:\t%#x\n", "npda", le16_to_cpu(id_ns->npda));
	unvme_pr("%10s:\t%#x\n", "nows", le16_to_cpu(id_ns->nows));
	unvme_pr("%10s:\t%#x\n", "mssrl", le16_to_cpu(id_ns->mssrl));
	unvme_pr("%10s:\t%#x\n", "mcl", le32_to_cpu(id_ns->mcl));
	unvme_pr("%10s:\t%#x\n", "msrc", id_ns->msrc);
	unvme_pr("%10s:\t%#x\n", "nulbaf", id_ns->nulbaf);
	unvme_pr("%10s:\t%#x\n", "anagrpid", le32_to_cpu(id_ns->anagrpid));
	unvme_pr("%10s:\t%#x\n", "nsattr", id_ns->nsattr);
	unvme_pr("%10s:\t%#x\n", "nvmsetid", le16_to_cpu(id_ns->nvmsetid));
	unvme_pr("%10s:\t%#x\n", "endgid", le16_to_cpu(id_ns->endgid));
	unvme_pr("%10s:\tlo: %#lx, hi: %#lx\n", "nguid",
			le64_to_cpu(*(leint64_t *)&id_ns->nguid[0]),
			le64_to_cpu(*(leint64_t *)&id_ns->nguid[8]));
	unvme_pr("%10s:\t%#lx\n", "eui64", le64_to_cpu(*(leint64_t *)id_ns->eui64));

	for (int i = 0; i < id_ns->nlbaf + 1; i++) {
		struct nvme_lbaf *lbaf = &id_ns->lbaf[i];

		unvme_pr("%c%6s[%2d]:\tms: %4d, ds: %4d, rp: %4d\n",
				i == in_use ? '*' : ' ', "lbaf", i,
				le16_to_cpu(lbaf->ms), lbaf->ds, lbaf->rp);
	}
}

void unvme_pr_nvm_id_ns(void *vaddr)
{
	struct nvme_nvm_id_ns *nvm_id_ns = (struct nvme_nvm_id_ns *)vaddr;

	unvme_pr("lbstm    : %#lx\n", le64_to_cpu(nvm_id_ns->lbstm));
	unvme_pr("pic      : %#x\n", nvm_id_ns->pic);
	unvme_pr("pifa     : %#x\n", nvm_id_ns->pifa);
	for (int i = 0; i < 64; i++) {
		uint32_t elbaf = le32_to_cpu(nvm_id_ns->elbaf[i]);
		unvme_pr("elbaf[%2d]: qpif:%d pif:%d sts:%-2d\n",
				i, (elbaf >> 9) & 0xF, (elbaf >> 7) & 0x3, elbaf & 0x7F);
	}
}

void unvme_pr_id_active_nslist(void *vaddr)
{
	uint32_t *id = (uint32_t *)vaddr;

	while (*id) {
		unvme_pr("%s%u", (id == vaddr) ? "" : ", ", *id);
		id++;
	}
	unvme_pr("\n");
}

void unvme_pr_get_features_noq(uint32_t dw0)
{
	unvme_pr("nsqa: %d\n", dw0 & 0xffff);
	unvme_pr("ncqa: %d\n", dw0 >> 16);
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
	struct unvme_ns *nslist = NULL;
	struct nvme_sq *sqs;
	struct nvme_cq *cqs;
	int nr_ns, nr_sqs, nr_cqs;
	struct unvme_ns *ns;
	struct nvme_sq *sq;
	struct nvme_cq *cq;

	nr_ns = unvmed_get_nslist(u, &nslist);
	if (nr_ns < 0) {
		unvme_pr_err("failed to get namespaces\n");
		return;
	}

	nr_sqs = unvmed_get_sqs(u, &sqs);
	if (nr_sqs < 0) {
		free(nslist);
		unvme_pr_err("failed to get submission queues\n");
		return;
	}

	nr_cqs = unvmed_get_cqs(u, &cqs);
	if (nr_cqs < 0) {
		free(nslist);
		free(sqs);
		unvme_pr_err("failed to get completion queues\n");
		return;
	}

	unvme_pr("Controller				: %s\n", unvmed_bdf(u));
	unvme_pr("Controller Configuration	(CC)	: %#x\n", cc);
	unvme_pr("Controller Status		(CSTS)	: %#x\n\n", csts);

	unvme_pr("Number of inflight commands		: %d\n", unvmed_nr_cmds(u));
	unvme_pr("\n");

	unvme_pr("Namespaces\n");
	unvme_pr("nsid       block size(B) meta size(B) size(blocks) meta(b)\n");
	unvme_pr("---------- ------------- ------------ ------------ -----------------\n");
	for (int i = 0; i < nr_ns; i++) {
		ns = &nslist[i];

		unvme_pr("%#10x %13u %12u %#12lx ",
				ns->nsid, ns->lba_size, ns->ms, ns->nr_lbas);
		if (ns->ms)
			unvme_pr("[%2d]%s:pi%d:st%d\n", ns->format_idx, ns->mset ? "dif" : "dix",
					16 * (ns->pif + 1), ns->sts);
		else
			unvme_pr("\n");
	}
	unvme_pr("\n");

	unvme_pr("Submission Queue\n");
	unvme_pr("qid  vaddr              iova               cqid tail ptail qsize\n");
	unvme_pr("---- ------------------ ------------------ ---- ---- ----- -----\n");
	for (int i = 0; i < nr_sqs; i++) {
		sq = &sqs[i];

		unvme_pr("%4d %18p %#18lx %4d %4d %5d %5d\n",
			 sq->id, sq->vaddr, sq->iova,
			 sq->cq->id, sq->tail, sq->ptail, sq->qsize);
	}
	unvme_pr("\n");
	unvme_pr("Completion Queue\n");
	unvme_pr("qid  vaddr              iova               head qsize phase vec \n");
	unvme_pr("---- ------------------ ------------------ ---- ----- ----- ----\n");
	for (int i = 0; i < nr_cqs; i++) {
		cq = &cqs[i];
		if (!cq)
			break;

		unvme_pr("%4d %18p %#18lx %4d %5d %5d %4d\n",
			 cq->id, cq->vaddr, cq->iova,
			 cq->head, cq->qsize, cq->phase, cq->vector);
	}
	unvme_pr("\n");

	free(nslist);
	free(cqs);
	free(sqs);
}
