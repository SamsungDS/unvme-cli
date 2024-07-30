#include <nvme/types.h>
#include <ccan/str/str.h>

#include "unvme.h"

void unvmed_pr_raw(void *vaddr, size_t len)
{
	for (int i = 0; i < len; i++)
		unvme_pr("%c", ((char *)vaddr)[i]);
}

void unvmed_pr_id_ns(void *vaddr)
{
	struct nvme_id_ns *id_ns = (struct nvme_id_ns *)vaddr;

	unvme_pr("nsze: %llx\n", id_ns->nsze);
	unvme_pr("ncap: %llx\n", id_ns->ncap);
}

void unvmed_pr_show_regs(void *vaddr)
{
	unvme_pr("cap     : %lx\n", le64_to_cpu(mmio_read64(vaddr + 0x0)));
	unvme_pr("version : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x8)));
	unvme_pr("cc      : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x14)));
	unvme_pr("csts    : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x1c)));
	unvme_pr("nssr    : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x20)));
	unvme_pr("intms   : %x\n", le32_to_cpu(mmio_read32(vaddr + 0xc)));
	unvme_pr("intmc   : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x10)));
	unvme_pr("aqa     : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x24)));
	unvme_pr("asq     : %lx\n", le64_to_cpu(mmio_read64(vaddr + 0x28)));
	unvme_pr("acq     : %lx\n", le64_to_cpu(mmio_read64(vaddr + 0x30)));
	unvme_pr("cmbloc  : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x38)));
	unvme_pr("cmbsz   : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x3c)));
	unvme_pr("bpinfo  : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x40)));
	unvme_pr("bprsel  : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x44)));
	unvme_pr("bpmbl   : %lx\n", le64_to_cpu(mmio_read64(vaddr + 0x48)));
	unvme_pr("cmbmsc  : %lx\n", le64_to_cpu(mmio_read64(vaddr + 0x50)));
	unvme_pr("cmbsts  : %x\n", le32_to_cpu(mmio_read32(vaddr + 0x58)));
	unvme_pr("pmrcap  : %x\n", le32_to_cpu(mmio_read32(vaddr + 0xe00)));
	unvme_pr("pmrctl  : %x\n", le32_to_cpu(mmio_read32(vaddr + 0xe04)));
	unvme_pr("pmrsts  : %x\n", le32_to_cpu(mmio_read32(vaddr + 0xe08)));
	unvme_pr("pmrebs  : %x\n", le32_to_cpu(mmio_read32(vaddr + 0xe0c)));
	unvme_pr("pmrswtp : %x\n", le32_to_cpu(mmio_read32(vaddr + 0xe10)));
	unvme_pr("pmrmscl : %x\n", le32_to_cpu(mmio_read32(vaddr + 0xe14)));
	unvme_pr("pmrmscu : %x\n", le32_to_cpu(mmio_read32(vaddr + 0xe18)));
}

void unvmed_pr_status(struct unvme *unvme)
{
	int cc = le32_to_cpu(mmio_read32(unvme->ctrl.regs + 0x14));
	int csts = le32_to_cpu(mmio_read32(unvme->ctrl.regs + 0x1c));
	struct unvme_sq* usq;
	struct unvme_cq* ucq;

	unvme_pr("Controller				: %s\n", unvme->bdf);
	unvme_pr("Controller Configuration	(CC)	: %#x\n", cc);
	unvme_pr("Controller Status		(CSTS)	: %#x\n\n", csts);

	unvme_pr("Submission Queue\n");
	unvme_pr("qid  vaddr              iova               cqid tail ptail qsize\n");
	unvme_pr("---- ------------------ ------------------ ---- ---- ----- -----\n");
	list_for_each_rev(&unvme->sq_list, usq, list) {
		unvme_pr("%4d %18p %#18lx %4d %4d %5d %5d\n",
			 usq->sq->id, usq->sq->vaddr, usq->sq->iova,
			 usq->sq->cq->id, usq->sq->tail, usq->sq->ptail, usq->sq->qsize);
	}
	unvme_pr("\n");
	unvme_pr("Completion Queue\n");
	unvme_pr("qid  vaddr              iova               head qsize phase vec \n");
	unvme_pr("---- ------------------ ------------------ ---- ----- ----- ----\n");
	list_for_each_rev(&unvme->cq_list, ucq, list) {
		unvme_pr("%4d %18p %#18lx %4d %5d %5d %4d\n",
			 ucq->cq->id, ucq->cq->vaddr, ucq->cq->iova,
			 ucq->cq->head, ucq->cq->qsize, ucq->cq->phase, ucq->cq->vector);
	}
	unvme_pr("\n");
}
