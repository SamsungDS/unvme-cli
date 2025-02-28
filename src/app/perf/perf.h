/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdint.h>

int unvmed_perf(struct unvme *u, uint32_t sqid, uint32_t nsid,
		const char *io_pattern, bool rand, int io_depth,
		uint32_t sec_runtime, uint32_t sec_warmup,
		uint32_t update_interval);
