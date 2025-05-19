// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <sys/time.h>

#include <ccan/str/str.h>

#include <vfn/nvme.h>
#include <sys/msg.h>
#include <nvme/types.h>
#include <nvme/util.h>
#include <json-c/json.h>

#include "libunvmed.h"
#include "unvme.h"
#include "unvmed.h"

void unvme_pr_sqe(union nvme_cmd *sqe)
{
	struct json_object *root = json_object_new_object();
	struct json_object *sqe_obj = json_object_new_object();

	json_object_object_add(sqe_obj, "opcode", json_object_new_int(sqe->opcode));
	json_object_object_add(sqe_obj, "flags", json_object_new_int(sqe->flags));
	json_object_object_add(sqe_obj, "cid", json_object_new_int(sqe->cid));
	json_object_object_add(sqe_obj, "nsid", json_object_new_int64(le32_to_cpu(sqe->nsid)));
	json_object_object_add(sqe_obj, "cdw2", json_object_new_int64(le32_to_cpu(sqe->cdw2)));
	json_object_object_add(sqe_obj, "cdw3", json_object_new_int64(le32_to_cpu(sqe->cdw3)));
	json_object_object_add(sqe_obj, "mptr", json_object_new_int64(le64_to_cpu(sqe->mptr)));
	json_object_object_add(sqe_obj, "prp1", json_object_new_int64(le64_to_cpu(sqe->dptr.prp1)));
	json_object_object_add(sqe_obj, "prp2", json_object_new_int64(le64_to_cpu(sqe->dptr.prp2)));
	json_object_object_add(sqe_obj, "cdw10", json_object_new_int64(le32_to_cpu(sqe->cdw10)));
	json_object_object_add(sqe_obj, "cdw11", json_object_new_int64(le32_to_cpu(sqe->cdw11)));
	json_object_object_add(sqe_obj, "cdw12", json_object_new_int64(le32_to_cpu(sqe->cdw12)));
	json_object_object_add(sqe_obj, "cdw13", json_object_new_int64(le32_to_cpu(sqe->cdw13)));
	json_object_object_add(sqe_obj, "cdw14", json_object_new_int64(le32_to_cpu(sqe->cdw14)));
	json_object_object_add(sqe_obj, "cdw15", json_object_new_int64(le32_to_cpu(sqe->cdw15)));

	json_object_object_add(root, "sqe", sqe_obj);
	unvme_pr_err("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_SPACED));

	json_object_put(root);
}

void unvme_pr_cqe(struct nvme_cqe *cqe)
{
	uint32_t sct, sc;

	sct = (le16_to_cpu(cqe->sfp) >> 9) & 0x7;
	sc = (le16_to_cpu(cqe->sfp) >> 1) & 0xff;

	struct json_object *root = json_object_new_object();
	struct json_object *cqe_obj = json_object_new_object();

	json_object_object_add(cqe_obj, "sqid", json_object_new_int(le16_to_cpu(cqe->sqid)));
	json_object_object_add(cqe_obj, "sqhd", json_object_new_int(le16_to_cpu(cqe->sqhd)));
	json_object_object_add(cqe_obj, "cid", json_object_new_int(cqe->cid));
	json_object_object_add(cqe_obj, "dw0", json_object_new_int(le32_to_cpu(cqe->dw0)));
	json_object_object_add(cqe_obj, "dw1", json_object_new_int(le32_to_cpu(cqe->dw1)));
	json_object_object_add(cqe_obj, "sct", json_object_new_int(sct));
	json_object_object_add(cqe_obj, "sc", json_object_new_int(sc));

	json_object_object_add(root, "cqe", cqe_obj);
	unvme_pr_err("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_SPACED));
	
	json_object_put(root);
}

void unvme_pr_raw(void *vaddr, size_t len)
{
	for (int i = 0; i < len; i++)
		unvme_pr("%c", ((char *)vaddr)[i]);
}

void unvme_pr_id_ns(const char *format, void *vaddr)
{
	struct nvme_id_ns *id_ns = (struct nvme_id_ns *)vaddr;
	uint8_t in_use;
	nvme_id_ns_flbas_to_lbaf_inuse(id_ns->flbas, &in_use);

	if (streq(format, "normal")) {
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
	} else if (streq(format, "json")) {
		json_object *root = json_object_new_object();
		json_object *lbafs = json_object_new_array();

		json_object_object_add(root, "nsze", json_object_new_int64(le64_to_cpu(id_ns->nsze)));
		json_object_object_add(root, "ncap", json_object_new_int64(le64_to_cpu(id_ns->ncap)));
		json_object_object_add(root, "nuse", json_object_new_int64(le64_to_cpu(id_ns->nuse)));
		json_object_object_add(root, "nsfeat", json_object_new_int(id_ns->nsfeat));
		json_object_object_add(root, "nlbaf", json_object_new_int(id_ns->nlbaf));
		json_object_object_add(root, "flbas", json_object_new_int(id_ns->flbas));
		json_object_object_add(root, "mc", json_object_new_int(id_ns->mc));
		json_object_object_add(root, "dpc", json_object_new_int(id_ns->dpc));
		json_object_object_add(root, "dps", json_object_new_int(id_ns->dps));
		json_object_object_add(root, "nmic", json_object_new_int(id_ns->nmic));
		json_object_object_add(root, "rescap", json_object_new_int(id_ns->rescap));
		json_object_object_add(root, "fpi", json_object_new_int(id_ns->fpi));
		json_object_object_add(root, "dlfeat", json_object_new_int(id_ns->dlfeat));
		json_object_object_add(root, "nawun", json_object_new_int(le16_to_cpu(id_ns->nawun)));
		json_object_object_add(root, "nawupf", json_object_new_int(le16_to_cpu(id_ns->nawupf)));
		json_object_object_add(root, "nacwu", json_object_new_int(le16_to_cpu(id_ns->nacwu)));
		json_object_object_add(root, "nabsn", json_object_new_int(le16_to_cpu(id_ns->nabsn)));
		json_object_object_add(root, "nabo", json_object_new_int(le16_to_cpu(id_ns->nabo)));
		json_object_object_add(root, "nabspf", json_object_new_int(le16_to_cpu(id_ns->nabspf)));
		json_object_object_add(root, "noiob", json_object_new_int(le16_to_cpu(id_ns->noiob)));

		json_object *nvmcap = json_object_new_object();
		json_object_object_add(nvmcap, "lo", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ns->nvmcap[0])));
		json_object_object_add(nvmcap, "hi", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ns->nvmcap[8])));
		json_object_object_add(root, "nvmcap", nvmcap);

		json_object_object_add(root, "npwg", json_object_new_int(le16_to_cpu(id_ns->npwg)));
		json_object_object_add(root, "npwa", json_object_new_int(le16_to_cpu(id_ns->npwa)));
		json_object_object_add(root, "npdg", json_object_new_int(le16_to_cpu(id_ns->npdg)));
		json_object_object_add(root, "npda", json_object_new_int(le16_to_cpu(id_ns->npda)));
		json_object_object_add(root, "nows", json_object_new_int(le16_to_cpu(id_ns->nows)));
		json_object_object_add(root, "mssrl", json_object_new_int(le16_to_cpu(id_ns->mssrl)));
		json_object_object_add(root, "mcl", json_object_new_int(le32_to_cpu(id_ns->mcl)));
		json_object_object_add(root, "msrc", json_object_new_int(id_ns->msrc));
		json_object_object_add(root, "nulbaf", json_object_new_int(id_ns->nulbaf));
		json_object_object_add(root, "anagrpid", json_object_new_int(le32_to_cpu(id_ns->anagrpid)));
		json_object_object_add(root, "nsattr", json_object_new_int(id_ns->nsattr));
		json_object_object_add(root, "nvmsetid", json_object_new_int(le16_to_cpu(id_ns->nvmsetid)));
		json_object_object_add(root, "endgid", json_object_new_int(le16_to_cpu(id_ns->endgid)));

		json_object *nguid = json_object_new_object();
		json_object_object_add(nguid, "lo", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ns->nguid[0])));
		json_object_object_add(nguid, "hi", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ns->nguid[8])));
		json_object_object_add(root, "nguid", nguid);

		json_object_object_add(root, "eui64", json_object_new_int64(le64_to_cpu(*(leint64_t *)id_ns->eui64)));

		for (int i = 0; i < id_ns->nlbaf + 1; i++) {
			struct nvme_lbaf *lbaf = &id_ns->lbaf[i];
			json_object *lbaf_obj = json_object_new_object();

			json_object_object_add(lbaf_obj, "ms", json_object_new_int(le16_to_cpu(lbaf->ms)));
			json_object_object_add(lbaf_obj, "ds", json_object_new_int(lbaf->ds));
			json_object_object_add(lbaf_obj, "rp", json_object_new_int(lbaf->rp));

			json_object_array_add(lbafs, lbaf_obj);
		}
		json_object_object_add(root, "lbafs", lbafs);

		unvme_pr("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
		json_object_put(root);
	}
}

void unvme_pr_id_ctrl(const char *format, void *vaddr)
{
	struct nvme_id_ctrl *id_ctrl = (struct nvme_id_ctrl *)vaddr;

	if (streq(format, "normal")) {
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
	} else if (streq(format, "json")) {
		json_object *root = json_object_new_object();

		json_object_object_add(root, "vid", json_object_new_int(le16_to_cpu(id_ctrl->vid)));
		json_object_object_add(root, "ssvid", json_object_new_int(le16_to_cpu(id_ctrl->ssvid)));
		json_object_object_add(root, "sn", json_object_new_string_len(id_ctrl->sn, sizeof(id_ctrl->sn)));
		json_object_object_add(root, "mn", json_object_new_string_len(id_ctrl->mn, sizeof(id_ctrl->mn)));
		json_object_object_add(root, "fr", json_object_new_string_len(id_ctrl->fr, sizeof(id_ctrl->fr)));
		json_object_object_add(root, "rab", json_object_new_int(id_ctrl->rab));

		char ieee[10];
		snprintf(ieee, sizeof(ieee), "%02x%02x%02x", id_ctrl->ieee[2], id_ctrl->ieee[1], id_ctrl->ieee[0]);
		json_object_object_add(root, "ieee", json_object_new_string(ieee));

		json_object_object_add(root, "cmic", json_object_new_int(id_ctrl->cmic));
		json_object_object_add(root, "mdts", json_object_new_int(id_ctrl->mdts));
		json_object_object_add(root, "cntlid", json_object_new_int(le16_to_cpu(id_ctrl->cntlid)));
		json_object_object_add(root, "ver", json_object_new_int(le32_to_cpu(id_ctrl->ver)));
		json_object_object_add(root, "rtd3r", json_object_new_int(le32_to_cpu(id_ctrl->rtd3r)));
		json_object_object_add(root, "rtd3e", json_object_new_int(le32_to_cpu(id_ctrl->rtd3e)));
		json_object_object_add(root, "oaes", json_object_new_int(le32_to_cpu(id_ctrl->oaes)));
		json_object_object_add(root, "ctratt", json_object_new_int(le32_to_cpu(id_ctrl->ctratt)));
		json_object_object_add(root, "rrls", json_object_new_int(le16_to_cpu(id_ctrl->rrls)));
		json_object_object_add(root, "cntrltype", json_object_new_int(id_ctrl->cntrltype));

		char fguid[40] = {0};
		for (int i = 0; i < 16; i++) {
			snprintf(fguid + (i * 2) + (i > 9 ? 4 : (i > 7 ? 3 : (i > 5 ? 2 : (i > 3 ? 1 : 0)))), 3, "%02x", id_ctrl->fguid[i]);
			if (i == 3)
				strcat(fguid + 8, "-");
			else if (i == 5)
				strcat(fguid + 13, "-"); 
			else if (i == 7)
				strcat(fguid + 18, "-");
			else if (i == 9)
				strcat(fguid + 23, "-");
		}
		json_object_object_add(root, "fguid", json_object_new_string(fguid));

		json_object_object_add(root, "crdt1", json_object_new_int(le16_to_cpu(id_ctrl->crdt1)));
		json_object_object_add(root, "crdt2", json_object_new_int(le16_to_cpu(id_ctrl->crdt2)));
		json_object_object_add(root, "crdt3", json_object_new_int(le16_to_cpu(id_ctrl->crdt3)));
		json_object_object_add(root, "nvmsr", json_object_new_int(id_ctrl->nvmsr));
		json_object_object_add(root, "vwci", json_object_new_int(id_ctrl->vwci));
		json_object_object_add(root, "mec", json_object_new_int(id_ctrl->mec));
		json_object_object_add(root, "oacs", json_object_new_int(le16_to_cpu(id_ctrl->oacs)));
		json_object_object_add(root, "acl", json_object_new_int(id_ctrl->acl));
		json_object_object_add(root, "aerl", json_object_new_int(id_ctrl->aerl));
		json_object_object_add(root, "frmw", json_object_new_int(id_ctrl->frmw));
		json_object_object_add(root, "lpa", json_object_new_int(id_ctrl->lpa));
		json_object_object_add(root, "elpe", json_object_new_int(id_ctrl->elpe));
		json_object_object_add(root, "npss", json_object_new_int(id_ctrl->npss));
		json_object_object_add(root, "avscc", json_object_new_int(id_ctrl->avscc));
		json_object_object_add(root, "apsta", json_object_new_int(id_ctrl->apsta));
		json_object_object_add(root, "wctemp", json_object_new_int(le16_to_cpu(id_ctrl->wctemp)));
		json_object_object_add(root, "cctemp", json_object_new_int(le16_to_cpu(id_ctrl->cctemp)));
		json_object_object_add(root, "mtfa", json_object_new_int(le16_to_cpu(id_ctrl->mtfa)));
		json_object_object_add(root, "hmpre", json_object_new_int(le32_to_cpu(id_ctrl->hmpre)));
		json_object_object_add(root, "hmmin", json_object_new_int(le32_to_cpu(id_ctrl->hmmin)));

		json_object *tnvmcap = json_object_new_object();
		json_object_object_add(tnvmcap, "lo", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ctrl->tnvmcap[0])));
		json_object_object_add(tnvmcap, "hi", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ctrl->tnvmcap[8])));
		json_object_object_add(root, "tnvmcap", tnvmcap);

		json_object *unvmcap = json_object_new_object();
		json_object_object_add(unvmcap, "lo", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ctrl->unvmcap[0])));
		json_object_object_add(unvmcap, "hi", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ctrl->unvmcap[8])));
		json_object_object_add(root, "unvmcap", unvmcap);

		json_object_object_add(root, "rpmbs", json_object_new_int(le32_to_cpu(id_ctrl->rpmbs)));
		json_object_object_add(root, "edstt", json_object_new_int(le16_to_cpu(id_ctrl->edstt)));
		json_object_object_add(root, "dsto", json_object_new_int(id_ctrl->dsto));
		json_object_object_add(root, "fwug", json_object_new_int(id_ctrl->fwug));
		json_object_object_add(root, "kas", json_object_new_int(le16_to_cpu(id_ctrl->kas)));
		json_object_object_add(root, "hctma", json_object_new_int(le16_to_cpu(id_ctrl->hctma)));
		json_object_object_add(root, "mntmt", json_object_new_int(le16_to_cpu(id_ctrl->mntmt)));
		json_object_object_add(root, "mxtmt", json_object_new_int(le16_to_cpu(id_ctrl->mxtmt)));
		json_object_object_add(root, "sanicap", json_object_new_int(le32_to_cpu(id_ctrl->sanicap)));
		json_object_object_add(root, "hmminds", json_object_new_int(le32_to_cpu(id_ctrl->hmminds)));
		json_object_object_add(root, "hmmaxd", json_object_new_int(le16_to_cpu(id_ctrl->hmmaxd)));
		json_object_object_add(root, "nsetidmax", json_object_new_int(le16_to_cpu(id_ctrl->nsetidmax)));
		json_object_object_add(root, "endgidmax", json_object_new_int(le16_to_cpu(id_ctrl->endgidmax)));
		json_object_object_add(root, "anatt", json_object_new_int(id_ctrl->anatt));
		json_object_object_add(root, "anacap", json_object_new_int(id_ctrl->anacap));
		json_object_object_add(root, "anagrpmax", json_object_new_int(le32_to_cpu(id_ctrl->anagrpmax)));
		json_object_object_add(root, "nanagrpid", json_object_new_int(le32_to_cpu(id_ctrl->nanagrpid)));
		json_object_object_add(root, "pels", json_object_new_int(le32_to_cpu(id_ctrl->pels)));
		json_object_object_add(root, "domainid", json_object_new_int(le16_to_cpu(id_ctrl->domainid)));

		json_object *megcap = json_object_new_object();
		json_object_object_add(megcap, "lo", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ctrl->megcap[0])));
		json_object_object_add(megcap, "hi", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ctrl->megcap[8])));
		json_object_object_add(root, "megcap", megcap);

		json_object_object_add(root, "tmpthha", json_object_new_int(id_ctrl->tmpthha));
		json_object_object_add(root, "sqes", json_object_new_int(id_ctrl->sqes));
		json_object_object_add(root, "cqes", json_object_new_int(id_ctrl->cqes));
		json_object_object_add(root, "maxcmd", json_object_new_int(le16_to_cpu(id_ctrl->maxcmd)));
		json_object_object_add(root, "nn", json_object_new_int(le32_to_cpu(id_ctrl->nn)));
		json_object_object_add(root, "oncs", json_object_new_int(le16_to_cpu(id_ctrl->oncs)));
		json_object_object_add(root, "fuses", json_object_new_int(le16_to_cpu(id_ctrl->fuses)));
		json_object_object_add(root, "fna", json_object_new_int(id_ctrl->fna));
		json_object_object_add(root, "vwc", json_object_new_int(id_ctrl->vwc));
		json_object_object_add(root, "awun", json_object_new_int(le16_to_cpu(id_ctrl->awun)));
		json_object_object_add(root, "awupf", json_object_new_int(le16_to_cpu(id_ctrl->awupf)));
		json_object_object_add(root, "icsvscc", json_object_new_int(id_ctrl->icsvscc));
		json_object_object_add(root, "nwpc", json_object_new_int(id_ctrl->nwpc));
		json_object_object_add(root, "acwu", json_object_new_int(le16_to_cpu(id_ctrl->acwu)));
		json_object_object_add(root, "ocfs", json_object_new_int(le16_to_cpu(id_ctrl->ocfs)));
		json_object_object_add(root, "sgls", json_object_new_int(le32_to_cpu(id_ctrl->sgls)));
		json_object_object_add(root, "mnan", json_object_new_int(le32_to_cpu(id_ctrl->mnan)));

		json_object *maxdna = json_object_new_object();
		json_object_object_add(maxdna, "lo", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ctrl->maxdna[0])));
		json_object_object_add(maxdna, "hi", json_object_new_int64(le64_to_cpu(*(leint64_t *)&id_ctrl->maxdna[8])));
		json_object_object_add(root, "maxdna", maxdna);

		json_object_object_add(root, "maxcna", json_object_new_int(le32_to_cpu(id_ctrl->maxcna)));
		json_object_object_add(root, "oaqd", json_object_new_int(le32_to_cpu(id_ctrl->oaqd)));
		json_object_object_add(root, "subnqn", json_object_new_string(id_ctrl->subnqn));

		unvme_pr("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
		json_object_put(root);
	}
}

void unvme_pr_nvm_id_ns(const char *format, void *vaddr)
{
	struct nvme_nvm_id_ns *nvm_id_ns = (struct nvme_nvm_id_ns *)vaddr;

	if (streq(format, "normal")) {
		unvme_pr("%10s:\t%#lx\n", "lbstm", le64_to_cpu(nvm_id_ns->lbstm));
		unvme_pr("%10s:\t%#x\n", "pic", nvm_id_ns->pic);
		unvme_pr("%10s:\t%#x\n", "pifa", nvm_id_ns->pifa);
		for (int i = 0; i < 64; i++) {
			uint32_t elbaf = le32_to_cpu(nvm_id_ns->elbaf[i]);
			unvme_pr("%c%6s[%2d]:\tqpif: %4d, pif: %4d, sts: %4d\n",
					' ', "elbaf", i,
					(elbaf >> 9) & 0xf, (elbaf >> 7) & 0x3, elbaf & 0x7f);
		}
	} else if (streq(format, "json")) {
		struct json_object *root = json_object_new_object();
		json_object_object_add(root, "lbstm", json_object_new_int64(le64_to_cpu(nvm_id_ns->lbstm)));
		json_object_object_add(root, "pic", json_object_new_int(nvm_id_ns->pic));
		json_object_object_add(root, "pifa", json_object_new_int(nvm_id_ns->pifa));

		struct json_object *elbaf_array = json_object_new_array();
		for (int i = 0; i < 64; i++) {
			uint32_t elbaf = le32_to_cpu(nvm_id_ns->elbaf[i]);
			struct json_object *entry = json_object_new_object();
			json_object_object_add(entry, "qpif", json_object_new_int((elbaf >> 9) & 0xf));
			json_object_object_add(entry, "pif", json_object_new_int((elbaf >> 7) & 0x3));
			json_object_object_add(entry, "sts", json_object_new_int(elbaf & 0x7f));
			json_object_array_add(elbaf_array, entry);
		}
		json_object_object_add(root, "elbaf", elbaf_array);

		unvme_pr("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
		json_object_put(root);
	}
}

void unvme_pr_id_active_nslist(const char *format, void *vaddr)
{
	uint32_t *id = (uint32_t *)vaddr;

	if (streq(format, "normal")) {
		while (*id) {
			unvme_pr("%s%u", (id == vaddr) ? "" : ", ", *id);
			id++;
		}
		unvme_pr("\n");
	} else if (streq(format, "json")) {
		struct json_object *array = json_object_new_array();
		while (*id) {
			json_object_array_add(array, json_object_new_int(*id));
			id++;
		}
		unvme_pr("%s\n", json_object_to_json_string_ext(array, JSON_C_TO_STRING_PRETTY));
		json_object_put(array);
	}
}

void unvme_pr_id_primary_ctrl_caps(const char *format, void *vaddr)
{
	struct nvme_primary_ctrl_cap *id_primary = (struct nvme_primary_ctrl_cap *)vaddr;

	if (streq(format, "normal")) {
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
	} else if (streq(format, "json")) {
		struct json_object *root = json_object_new_object();
		json_object_object_add(root, "cntlid", json_object_new_int(le16_to_cpu(id_primary->cntlid)));
		json_object_object_add(root, "portid", json_object_new_int(le16_to_cpu(id_primary->portid)));
		json_object_object_add(root, "crt", json_object_new_int(id_primary->crt));
		json_object_object_add(root, "vqfrt", json_object_new_int(le32_to_cpu(id_primary->vqfrt)));
		json_object_object_add(root, "vqrfa", json_object_new_int(le32_to_cpu(id_primary->vqrfa)));
		json_object_object_add(root, "vqrfap", json_object_new_int(le16_to_cpu(id_primary->vqrfap)));
		json_object_object_add(root, "vqprt", json_object_new_int(le16_to_cpu(id_primary->vqprt)));
		json_object_object_add(root, "vqfrsm", json_object_new_int(le16_to_cpu(id_primary->vqfrsm)));
		json_object_object_add(root, "vqgran", json_object_new_int(le16_to_cpu(id_primary->vqgran)));
		json_object_object_add(root, "vifrt", json_object_new_int(le32_to_cpu(id_primary->vifrt)));
		json_object_object_add(root, "virfa", json_object_new_int(le32_to_cpu(id_primary->virfa)));
		json_object_object_add(root, "virfap", json_object_new_int(le16_to_cpu(id_primary->virfap)));
		json_object_object_add(root, "viprt", json_object_new_int(le16_to_cpu(id_primary->viprt)));
		json_object_object_add(root, "vifrsm", json_object_new_int(le16_to_cpu(id_primary->vifrsm)));
		json_object_object_add(root, "vigran", json_object_new_int(le16_to_cpu(id_primary->vigran)));

		unvme_pr("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
		json_object_put(root);
	}
}

void unvme_pr_id_secondary_ctrl_list(const char *format, void *vaddr)
{
	struct nvme_secondary_ctrl_list *sc_list = (struct nvme_secondary_ctrl_list *)vaddr;
	const struct nvme_secondary_ctrl *sc_entry = &sc_list->sc_entry[0];

	if (streq(format, "normal")) {
		unvme_pr("Identify Secondary Controller List:\n");
		unvme_pr("%13s: \t%#x\n", "nument", sc_list->num);

		for (int i = 0; i < sc_list->num; i++) {
			unvme_pr("..............\n");
			unvme_pr("SC Entry[%-3d]:\n", i);
			unvme_pr("%13s: \t%#x\n", "scid", le16_to_cpu(sc_entry[i].scid));
			unvme_pr("%13s: \t%#x\n", "pcid", le16_to_cpu(sc_entry[i].pcid));
			unvme_pr("%13s: \t%#x (%s)\n", "crt", sc_entry[i].scs, sc_entry[i].scs & 0x1 ? "Online" : "Offline");
			unvme_pr("%13s: \t%#x\n", "vfn", le16_to_cpu(sc_entry[i].vfn));
			unvme_pr("%13s: \t%#x\n", "nvq", le16_to_cpu(sc_entry[i].nvq));
			unvme_pr("%13s: \t%#x\n", "nvi", le16_to_cpu(sc_entry[i].nvi));
		}
	} else if (streq(format, "json")) {
		struct json_object *root = json_object_new_object();
		json_object_object_add(root, "nument", json_object_new_int(sc_list->num));

		struct json_object *entries = json_object_new_array();
		for (int i = 0; i < sc_list->num; i++) {
			struct json_object *entry = json_object_new_object();
			json_object_object_add(entry, "scid", json_object_new_int(le16_to_cpu(sc_entry[i].scid)));
			json_object_object_add(entry, "pcid", json_object_new_int(le16_to_cpu(sc_entry[i].pcid)));
			json_object_object_add(entry, "scs", json_object_new_int(sc_entry[i].scs));
			json_object_object_add(entry, "status", json_object_new_string(sc_entry[i].scs & 0x1 ? "Online" : "Offline"));
			json_object_object_add(entry, "vfn", json_object_new_int(le16_to_cpu(sc_entry[i].vfn)));
			json_object_object_add(entry, "nvq", json_object_new_int(le16_to_cpu(sc_entry[i].nvq)));
			json_object_object_add(entry, "nvi", json_object_new_int(le16_to_cpu(sc_entry[i].nvi)));
			json_object_array_add(entries, entry);
		}
		json_object_object_add(root, "entries", entries);

		unvme_pr("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
		json_object_put(root);
	}
}

void unvme_pr_get_features_noq(const char *format, uint32_t dw0)
{
	if (streq(format, "normal")) {
		unvme_pr("nsqa: %d\n", dw0 & 0xffff);
		unvme_pr("ncqa: %d\n", dw0 >> 16);
	} else if (streq(format, "json")) {
		struct json_object *root = json_object_new_object();
		json_object_object_add(root, "nsqa", json_object_new_int(dw0 & 0xffff));
		json_object_object_add(root, "ncqa", json_object_new_int(dw0 >> 16));
		unvme_pr("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
		json_object_put(root);
	}
}

void unvme_pr_show_regs(const char *format, struct unvme *u)
{
	if (streq(format, "normal")) {
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
	} else if (streq(format, "json")) {
		struct json_object *root = json_object_new_object();
		json_object_object_add(root, "cap", json_object_new_int64(unvmed_read64(u, NVME_REG_CAP)));
		json_object_object_add(root, "version", json_object_new_int(unvmed_read32(u, NVME_REG_VS)));
		json_object_object_add(root, "cc", json_object_new_int(unvmed_read32(u, NVME_REG_CC)));
		json_object_object_add(root, "csts", json_object_new_int(unvmed_read32(u, NVME_REG_CSTS)));
		json_object_object_add(root, "nssr", json_object_new_int(unvmed_read32(u, NVME_REG_NSSR)));
		json_object_object_add(root, "intms", json_object_new_int(unvmed_read32(u, NVME_REG_INTMS)));
		json_object_object_add(root, "intmc", json_object_new_int(unvmed_read32(u, NVME_REG_INTMC)));
		json_object_object_add(root, "aqa", json_object_new_int(unvmed_read32(u, NVME_REG_AQA)));
		json_object_object_add(root, "asq", json_object_new_int64(unvmed_read64(u, NVME_REG_ASQ)));
		json_object_object_add(root, "acq", json_object_new_int64(unvmed_read64(u, NVME_REG_ACQ)));
		json_object_object_add(root, "cmbloc", json_object_new_int(unvmed_read32(u, NVME_REG_CMBLOC)));
		json_object_object_add(root, "cmbsz", json_object_new_int(unvmed_read32(u, NVME_REG_CMBSZ)));
		json_object_object_add(root, "bpinfo", json_object_new_int(unvmed_read32(u, NVME_REG_BPINFO)));
		json_object_object_add(root, "bprsel", json_object_new_int(unvmed_read32(u, NVME_REG_BPRSEL)));
		json_object_object_add(root, "bpmbl", json_object_new_int64(unvmed_read64(u, NVME_REG_BPMBL)));
		json_object_object_add(root, "cmbmsc", json_object_new_int64(unvmed_read64(u, NVME_REG_CMBMSC)));
		json_object_object_add(root, "cmbsts", json_object_new_int(unvmed_read32(u, NVME_REG_CMBSTS)));
		json_object_object_add(root, "pmrcap", json_object_new_int(unvmed_read32(u, NVME_REG_PMRCAP)));
		json_object_object_add(root, "pmrctl", json_object_new_int(unvmed_read32(u, NVME_REG_PMRCTL)));
		json_object_object_add(root, "pmrsts", json_object_new_int(unvmed_read32(u, NVME_REG_PMRSTS)));
		json_object_object_add(root, "pmrebs", json_object_new_int(unvmed_read32(u, NVME_REG_PMREBS)));
		json_object_object_add(root, "pmrswtp", json_object_new_int(unvmed_read32(u, NVME_REG_PMRSWTP)));
		json_object_object_add(root, "pmrmscl", json_object_new_int(unvmed_read32(u, NVME_REG_PMRMSCL)));
		json_object_object_add(root, "pmrmscu", json_object_new_int(unvmed_read32(u, NVME_REG_PMRMSCU)));

		unvme_pr("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
		json_object_put(root);
	}
}

void unvme_pr_status(const char *format, struct unvme *u)
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
	struct unvme_hmb *hmb;

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

	hmb = unvmed_hmb(u);

	if (streq(format, "normal")) {
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
				 sq->id, sq->mem.vaddr, sq->mem.iova,
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
				 cq->id, cq->mem.vaddr, cq->mem.iova,
				 cq->head, cq->qsize, cq->phase, cq->vector);
		}
		unvme_pr("\n");

		unvme_pr("Host Memory Buffer\n");
		unvme_pr("Size (CC.MPS unit):    %d\n", hmb->hsize);
		unvme_pr("Descriptor Address:    %#lx\n", hmb->descs_iova);
		unvme_pr("Number of descriptors: %d\n", hmb->nr_descs);
		unvme_pr("\n");
		unvme_pr("index baddr              bsize\n");
		unvme_pr("----- ------------------ ------\n");
		for (int i = 0; i < hmb->nr_descs; i++)
			unvme_pr("%5d %#18llx %6d\n", i, hmb->descs[i].badd, hmb->descs[i].bsize);

	} else if (streq(format, "json")) {
		struct json_object *root = json_object_new_object();
		json_object_object_add(root, "controller", json_object_new_string(unvmed_bdf(u)));
		json_object_object_add(root, "cc", json_object_new_int(cc));
		json_object_object_add(root, "csts", json_object_new_int(csts));
		json_object_object_add(root, "nr_inflight_cmds", json_object_new_int(unvmed_nr_cmds(u)));

		struct json_object *ns_array = json_object_new_array();
		for (int i = 0; i < nr_ns; i++) {
			ns = &nslist[i];
			struct json_object *ns_obj = json_object_new_object();
			json_object_object_add(ns_obj, "nsid", json_object_new_int(ns->nsid));
			json_object_object_add(ns_obj, "block_size", json_object_new_int(ns->lba_size));
			json_object_object_add(ns_obj, "meta_size", json_object_new_int(ns->ms));
			json_object_object_add(ns_obj, "nr_blocks", json_object_new_int64(ns->nr_lbas));
			if (ns->ms) {
				char meta_info[64];
				sprintf(meta_info, "[%d]%s:pi%d:st%d", ns->format_idx, ns->mset ? "dif" : "dix", 16 * (ns->pif + 1), ns->sts);
				json_object_object_add(ns_obj, "meta_info", json_object_new_string(meta_info));
			}
			json_object_array_add(ns_array, ns_obj);
		}
		json_object_object_add(root, "ns", ns_array);

		struct json_object *sq_array = json_object_new_array();
		for (int i = 0; i < nr_sqs; i++) {
			sq = &sqs[i];
			struct json_object *sq_obj = json_object_new_object();
			json_object_object_add(sq_obj, "id", json_object_new_int(sq->id));
			json_object_object_add(sq_obj, "vaddr", json_object_new_int64((uint64_t)sq->mem.vaddr));
			json_object_object_add(sq_obj, "iova", json_object_new_int64(sq->mem.iova));
			json_object_object_add(sq_obj, "cq_id", json_object_new_int(sq->cq->id));
			json_object_object_add(sq_obj, "tail", json_object_new_int(sq->tail));
			json_object_object_add(sq_obj, "ptail", json_object_new_int(sq->ptail));
			json_object_object_add(sq_obj, "qsize", json_object_new_int(sq->qsize));
			json_object_array_add(sq_array, sq_obj);
		}
		json_object_object_add(root, "sq", sq_array);

		struct json_object *cq_array = json_object_new_array();
		for (int i = 0; i < nr_cqs; i++) {
			cq = &cqs[i];
			if (!cq)
				break;
			struct json_object *cq_obj = json_object_new_object();
			json_object_object_add(cq_obj, "id", json_object_new_int(cq->id));
			json_object_object_add(cq_obj, "vaddr", json_object_new_int64((uint64_t)cq->mem.vaddr));
			json_object_object_add(cq_obj, "iova", json_object_new_int64(cq->mem.iova));
			json_object_object_add(cq_obj, "head", json_object_new_int(cq->head));
			json_object_object_add(cq_obj, "qsize", json_object_new_int(cq->qsize));
			json_object_object_add(cq_obj, "phase", json_object_new_int(cq->phase));
			json_object_object_add(cq_obj, "vector", json_object_new_int(cq->vector));
			json_object_array_add(cq_array, cq_obj);
		}
		json_object_object_add(root, "cq", cq_array);

		struct json_object *hmb_obj = json_object_new_object();
		json_object_object_add(hmb_obj, "hsize", json_object_new_int((uint32_t)hmb->hsize));
		json_object_object_add(hmb_obj, "descs_addr", json_object_new_int64((uint64_t)hmb->descs_iova));
		json_object_object_add(hmb_obj, "nr_descs", json_object_new_int((uint32_t)hmb->nr_descs));
		json_object_object_add(root, "hmb", hmb_obj);

		struct json_object *hmb_array = json_object_new_array();
		for (int i = 0; i < hmb->nr_descs; i++) {
			struct json_object *block_obj = json_object_new_object();
			json_object_object_add(block_obj, "badd", json_object_new_int64((uint64_t)le64_to_cpu(hmb->descs[i].badd)));
			json_object_object_add(block_obj, "bsize", json_object_new_int((uint32_t)le32_to_cpu(hmb->descs[i].bsize)));
			json_object_array_add(hmb_array, block_obj);
		}
		json_object_object_add(hmb_obj, "descs", hmb_array);

		unvme_pr("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
		json_object_put(root);
	}

	free(nslist);
	free(cqs);
	free(sqs);
}
