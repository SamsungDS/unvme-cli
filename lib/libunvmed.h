/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */

#ifndef LIBUNVMED_H
#define LIBUNVMED_H

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/time.h>

/*
 * `libunvmed`-specific structures
 */
struct unvme;
struct unvme_cmd;

/*
 * NVMe spec-based data structures defined in `libvfn`
 */
union nvme_cmd;
struct nvme_cqe;

/*
 * `libvfn`-specific structures
 */
struct nvme_sq;
struct nvme_cq;

int unvmed_pci_bind(const char *bdf);
int unvmed_pci_unbind(const char *bdf);

struct unvme *unvmed_get(const char *bdf);

struct nvme_sq *unvmed_get_sq(struct unvme *u, uint32_t qid);
struct nvme_cq *unvmed_get_cq(struct unvme *u, uint32_t qid);
void unvmed_cmd_get_buf(struct unvme_cmd *cmd, void **addr, size_t *len);
union nvme_cmd *unvmed_cmd_get_sqe(struct unvme_cmd *cmd);

struct unvme *unvmed_init_ctrl(const char *bdf, uint32_t max_nr_ioqs);
void unvmed_free_ctrl(struct unvme *u);
void unvmed_free_ctrl_all(void);
void unvmed_reset_ctrl(struct unvme *u);
int unvmed_create_adminq(struct unvme *u);
int unvmed_enable_ctrl(struct unvme *u, uint8_t iosqes, uint8_t iocqes, uint8_t mps, uint8_t css);
int unvmed_create_cq(struct unvme *u, uint32_t qid, uint32_t qsize, uint32_t vector);
int unvmed_create_sq(struct unvme *u, uint32_t qid, uint32_t qsize, uint32_t cqid);
int unvmed_map_vaddr(struct unvme *u, void *buf, size_t len, uint64_t *iova, unsigned long flags);
int unvmed_unmap_vaddr(struct unvme *u, void *buf);
struct unvme_cmd *unvmed_alloc_cmd(struct unvme *u, int sqid, size_t data_len);
void unvmed_cmd_free(void *p);
int unvmed_free_cmds(struct unvme *u, uint32_t sqid);
void unvmed_cmd_post(struct unvme_cmd *cmd, union nvme_cmd *sqe, bool update_sqdb);
struct nvme_cqe *unvmed_cmd_cmpl(struct unvme_cmd *cmd);
int unvmed_sq_update_tail_and_wait(struct unvme *u, uint32_t sqid, struct nvme_cqe **cqes);
int unvmed_map_prp(struct unvme_cmd *cmd);

/*
 * `struct unvme` starts with `struct nvme_ctrl`, so convert easily.
 */
#define __unvmed_ctrl(u)		((struct nvme_ctrl *)(u))

/*
 * `struct nvme_ctrl` of `libvfn` access helpers.
 */
#define unvmed_bdf(u)		(__unvmed_ctrl(u)->pci.bdf)
#define unvmed_reg(u)		(__unvmed_ctrl(u)->regs)

#define unvmed_read32(u, offset)	\
	le32_to_cpu(mmio_read32(unvmed_reg(u) + (offset)))
#define unvmed_read64(u, offset)	\
	le64_to_cpu(mmio_read64(unvmed_reg(u) + (offset)))
#define unvmed_write32(u, offset, value) \
	mmio_write32(unvmed_reg(u) + (offset), cpu_to_le32((value)))
#define unvmed_write64(u, offset, value) \
	mmio_write64(unvmed_reg(u) + (offset), cpu_to_le64((value)))

#define __unvmed_free_cmd __attribute__((cleanup(unvmed_cmd_free)))

#endif
