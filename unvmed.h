/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UNVMED_H
#define UNVMED_H

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
static inline void unvme_free(void *p)
{
	void **ptr = (void **)p;
	if (*ptr) {
		free(*ptr);
		*ptr = NULL;
	}
}
#pragma GCC diagnostic pop
#define __unvme_free __attribute__((cleanup(unvme_free)))

struct unvme_msg;
struct unvme;
union nvme_cmd;
struct nvme_cqe;

/*
 * unvmed-print.c
 */
void unvme_pr_raw(void *vaddr, size_t len);
void unvme_pr_id_ns(void *vaddr);
void unvme_pr_id_active_nslist(void *vaddr);
void unvme_pr_get_features_noq(uint32_t cdw0);
void unvme_pr_nvm_id_ns(void *vaddr);
void unvme_pr_show_regs(struct unvme *u);
void unvme_pr_status(struct unvme *u);

/*
 * unvmed-file.c
 */
bool unvme_is_abspath(const char *path);
char *unvme_get_filepath(char *pwd, const char *filename);
int unvme_write_file(const char *abspath, void *buf, size_t len);
int unvme_read_file(const char *abspath, void *buf, size_t len);

const char *unvmed_get_libfio(void);

/*
 * per-thread stdio stream objects
 */
extern __thread FILE *__stdout;
extern __thread FILE *__stderr;

void unvme_exit_job(int ret);

#ifdef unvme_pr
#undef unvme_pr
#endif

#ifdef unvme_pr_err
#undef unvme_pr_err
#endif

#define unvme_pr(fmt, ...)				\
	do {						\
		fprintf(__stdout, fmt, ##__VA_ARGS__);	\
	} while(0)

#define unvme_pr_err(fmt, ...)				\
	do {						\
		fprintf(__stderr, fmt, ##__VA_ARGS__);	\
	} while(0)

#endif
