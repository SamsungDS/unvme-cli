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

void unvme_pr_id_ctrl(void *vaddr)
{
	struct nvme_id_ctrl *id_ctrl = (struct nvme_id_ctrl *)vaddr;

	unvme_pr("%10s: \t%#x\n", "vid", le16_to_cpu(id_ctrl->vid));
	unvme_pr("%10s: \t%#x\n", "ssvid", le16_to_cpu(id_ctrl->ssvid));
	unvme_pr("%10s: \t%-.*s\n", "sn", (int)sizeof(id_ctrl->sn), id_ctrl->sn);
	unvme_pr("%10s: \t%-.*s\n", "mn", (int)sizeof(id_ctrl->mn), id_ctrl->mn);
	unvme_pr("%10s: \t%-.*s\n", "fr", (int)sizeof(id_ctrl->fr), id_ctrl->fr);
	unvme_pr("%10s: \t%#x\n", "rab", id_ctrl->rab);
	unvme_pr("%10s: \t%02x%02x%02x\n", "ieee", id_ctrl->ieee[2],
			id_ctrl->ieee[1], id_ctrl->ieee[0]);
	unvme_pr("%10s: \t%#x\n", "cmic", id_ctrl->cmic);
	unvme_pr("%10s: \t%#x\n", "mdts", id_ctrl->mdts);
	unvme_pr("%10s: \t%#x\n", "cntlid", le16_to_cpu(id_ctrl->cntlid));
	unvme_pr("%10s: \t%#x\n", "ver", le32_to_cpu(id_ctrl->ver));
	unvme_pr("%10s: \t%#x\n", "rtd3r", le32_to_cpu(id_ctrl->rtd3r));
	unvme_pr("%10s: \t%#x\n", "rtd3e", le32_to_cpu(id_ctrl->rtd3e));
	unvme_pr("%10s: \t%#x\n", "oaes", le32_to_cpu(id_ctrl->oaes));
	unvme_pr("%10s: \t%#x\n", "ctratt", le32_to_cpu(id_ctrl->ctratt));
	unvme_pr("%10s: \t%#x\n", "rrls", le16_to_cpu(id_ctrl->rrls));
	unvme_pr("%10s: \t%#x\n", "cntrltype", id_ctrl->cntrltype);
	unvme_pr("%10s: \t", "fguid");
	for (int i = 0; i < 16; i++) {
		unvme_pr("%02x", id_ctrl->fguid[i]);
		if (i == 3 || i == 5 || i == 7 || i == 9)
			unvme_pr("-");
	}
	unvme_pr("\n%10s: \t%#x\n", "crdt1", le16_to_cpu(id_ctrl->crdt1));
	unvme_pr("%10s: \t%#x\n", "crdt2", le16_to_cpu(id_ctrl->crdt2));
	unvme_pr("%10s: \t%#x\n", "crdt3", le16_to_cpu(id_ctrl->crdt3));
	unvme_pr("%10s: \t%#x\n", "nvmsr", id_ctrl->nvmsr);
	unvme_pr("%10s: \t%#x\n", "vwci", id_ctrl->vwci);
	unvme_pr("%10s: \t%#x\n", "mec", id_ctrl->mec);
	unvme_pr("%10s: \t%#x\n", "oacs", le16_to_cpu(id_ctrl->oacs));
	unvme_pr("%10s: \t%#x\n", "acl", id_ctrl->acl);
	unvme_pr("%10s: \t%#x\n", "aerl", id_ctrl->aerl);
	unvme_pr("%10s: \t%#x\n", "frmw", id_ctrl->frmw);
	unvme_pr("%10s: \t%#x\n", "lpa", id_ctrl->lpa);
	unvme_pr("%10s: \t%#x\n", "elpe", id_ctrl->elpe);
	unvme_pr("%10s: \t%#x\n", "npss", id_ctrl->npss);
	unvme_pr("%10s: \t%#x\n", "avscc", id_ctrl->avscc);
	unvme_pr("%10s: \t%#x\n", "apsta", id_ctrl->apsta);
	unvme_pr("%10s: \t%#x\n", "wctemp", le16_to_cpu(id_ctrl->wctemp));
	unvme_pr("%10s: \t%#x\n", "cctemp", le16_to_cpu(id_ctrl->cctemp));
	unvme_pr("%10s: \t%#x\n", "mtfa", le16_to_cpu(id_ctrl->mtfa));
	unvme_pr("%10s: \t%#x\n", "hmpre", le32_to_cpu(id_ctrl->hmpre));
	unvme_pr("%10s: \t%#x\n", "hmmin", le32_to_cpu(id_ctrl->hmmin));
	unvme_pr("%10s:\tlo: %#lx, hi: %#lx\n", "tnvmcap",
			le64_to_cpu(*(leint64_t *)&id_ctrl->tnvmcap[0]),
			le64_to_cpu(*(leint64_t *)&id_ctrl->tnvmcap[8]));
	unvme_pr("%10s:\tlo: %#lx, hi: %#lx\n", "unvmcap",
			le64_to_cpu(*(leint64_t *)&id_ctrl->unvmcap[0]),
			le64_to_cpu(*(leint64_t *)&id_ctrl->unvmcap[8]));
	unvme_pr("%10s: \t%#x\n", "rpmbs", le32_to_cpu(id_ctrl->rpmbs));
	unvme_pr("%10s: \t%#x\n", "edstt", le16_to_cpu(id_ctrl->edstt));
	unvme_pr("%10s: \t%#x\n", "dsto", id_ctrl->dsto);
	unvme_pr("%10s: \t%#x\n", "fwug", id_ctrl->fwug);
	unvme_pr("%10s: \t%#x\n", "kas", le16_to_cpu(id_ctrl->kas));
	unvme_pr("%10s: \t%#x\n", "hctma", le16_to_cpu(id_ctrl->hctma));
	unvme_pr("%10s: \t%#x\n", "mntmt", le16_to_cpu(id_ctrl->mntmt));
	unvme_pr("%10s: \t%#x\n", "mxtmt", le16_to_cpu(id_ctrl->mxtmt));
	unvme_pr("%10s: \t%#x\n", "sanicap", le32_to_cpu(id_ctrl->sanicap));
	unvme_pr("%10s: \t%#x\n", "hmminds", le32_to_cpu(id_ctrl->hmminds));
	unvme_pr("%10s: \t%#x\n", "hmmaxd", le16_to_cpu(id_ctrl->hmmaxd));
	unvme_pr("%10s: \t%#x\n", "nsetidmax", le16_to_cpu(id_ctrl->nsetidmax));
	unvme_pr("%10s: \t%#x\n", "endgidmax", le16_to_cpu(id_ctrl->endgidmax));
	unvme_pr("%10s: \t%#x\n", "anatt", id_ctrl->anatt);
	unvme_pr("%10s: \t%#x\n", "anacap", id_ctrl->anacap);
	unvme_pr("%10s: \t%#x\n", "anagrpmax", le32_to_cpu(id_ctrl->anagrpmax));
	unvme_pr("%10s: \t%#x\n", "nanagrpid", le32_to_cpu(id_ctrl->nanagrpid));
	unvme_pr("%10s: \t%#x\n", "pels", le32_to_cpu(id_ctrl->pels));
	unvme_pr("%10s: \t%#x\n", "domainid", le16_to_cpu(id_ctrl->domainid));
	unvme_pr("%10s:\tlo: %#lx, hi: %#lx\n", "megcap",
			le64_to_cpu(*(leint64_t *)&id_ctrl->megcap[0]),
			le64_to_cpu(*(leint64_t *)&id_ctrl->megcap[8]));
	unvme_pr("%10s: \t%#x\n", "tmpthha", id_ctrl->tmpthha);
	unvme_pr("%10s: \t%#x\n", "sqes", id_ctrl->sqes);
	unvme_pr("%10s: \t%#x\n", "cqes", id_ctrl->cqes);
	unvme_pr("%10s: \t%#x\n", "maxcmd", le16_to_cpu(id_ctrl->maxcmd));
	unvme_pr("%10s: \t%#x\n", "nn", le32_to_cpu(id_ctrl->nn));
	unvme_pr("%10s: \t%#x\n", "oncs", le16_to_cpu(id_ctrl->oncs));
	unvme_pr("%10s: \t%#x\n", "fuses", le16_to_cpu(id_ctrl->fuses));
	unvme_pr("%10s: \t%#x\n", "fna", id_ctrl->fna);
	unvme_pr("%10s: \t%#x\n", "vwc", id_ctrl->vwc);
	unvme_pr("%10s: \t%#x\n", "awun", le16_to_cpu(id_ctrl->awun));
	unvme_pr("%10s: \t%#x\n", "awupf", le16_to_cpu(id_ctrl->awupf));
	unvme_pr("%10s: \t%#x\n", "icsvscc", id_ctrl->icsvscc);
	unvme_pr("%10s: \t%#x\n", "nwpc", id_ctrl->nwpc);
	unvme_pr("%10s: \t%#x\n", "acwu", le16_to_cpu(id_ctrl->acwu));
	unvme_pr("%10s: \t%#x\n", "ocfs", le16_to_cpu(id_ctrl->ocfs));
	unvme_pr("%10s: \t%#x\n", "sgls", le32_to_cpu(id_ctrl->sgls));
	unvme_pr("%10s: \t%#x\n", "mnan", le32_to_cpu(id_ctrl->mnan));
	unvme_pr("%10s:\tlo: %#lx, hi: %#lx\n", "maxdna",
			le64_to_cpu(*(leint64_t *)&id_ctrl->maxdna[0]),
			le64_to_cpu(*(leint64_t *)&id_ctrl->maxdna[8]));
	unvme_pr("%10s: \t%#x\n", "maxcna", le32_to_cpu(id_ctrl->maxcna));
	unvme_pr("%10s: \t%#x\n", "oaqd", le32_to_cpu(id_ctrl->oaqd));
	unvme_pr("%10s: \t%-.*s\n", "subnqn", (int)sizeof(id_ctrl->subnqn), id_ctrl->subnqn);
}

void unvme_pr_nvm_id_ns(void *vaddr)
{
	struct nvme_nvm_id_ns *nvm_id_ns = (struct nvme_nvm_id_ns *)vaddr;

	unvme_pr("%10s:\t%#lx\n", "lbstm", le64_to_cpu(nvm_id_ns->lbstm));
	unvme_pr("%10s:\t%#x\n", "pic", nvm_id_ns->pic);
	unvme_pr("%10s:\t%#x\n", "pifa", nvm_id_ns->pifa);
	for (int i = 0; i < 64; i++) {
		uint32_t elbaf = le32_to_cpu(nvm_id_ns->elbaf[i]);
		unvme_pr("%c%6s[%2d]:\tqpif: %4d, pif: %4d, sts: %4d\n",
				' ', "elbaf", i,
				(elbaf >> 9) & 0xf, (elbaf >> 7) & 0x3, elbaf & 0x7f);
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

void unvme_pr_id_primary_ctrl_caps(void *vaddr)
{
	struct nvme_primary_ctrl_cap *id_primary = (struct nvme_primary_ctrl_cap *)vaddr;

	unvme_pr("%10s: \t%#x\n", "cntlid", le16_to_cpu(id_primary->cntlid));
	unvme_pr("%10s: \t%#x\n", "portid", le16_to_cpu(id_primary->portid));
	unvme_pr("%10s: \t%#x\n", "crt", id_primary->crt);
	unvme_pr("%10s: \t%#x\n", "vqfrt", le32_to_cpu(id_primary->vqfrt));
	unvme_pr("%10s: \t%#x\n", "vqrfa", le32_to_cpu(id_primary->vqrfa));
	unvme_pr("%10s: \t%#x\n", "vqrfap", le16_to_cpu(id_primary->vqrfap));
	unvme_pr("%10s: \t%#x\n", "vqprt", le16_to_cpu(id_primary->vqprt));
	unvme_pr("%10s: \t%#x\n", "vqfrsm", le16_to_cpu(id_primary->vqfrsm));
	unvme_pr("%10s: \t%#x\n", "vqgran", le16_to_cpu(id_primary->vqgran));
	unvme_pr("%10s: \t%#x\n", "vifrt", le32_to_cpu(id_primary->vifrt));
	unvme_pr("%10s: \t%#x\n", "virfa", le32_to_cpu(id_primary->virfa));
	unvme_pr("%10s: \t%#x\n", "virfap", le16_to_cpu(id_primary->virfap));
	unvme_pr("%10s: \t%#x\n", "viprt", le16_to_cpu(id_primary->viprt));
	unvme_pr("%10s: \t%#x\n", "vifrsm", le16_to_cpu(id_primary->vifrsm));
	unvme_pr("%10s: \t%#x\n", "vigran", le16_to_cpu(id_primary->vigran));
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
