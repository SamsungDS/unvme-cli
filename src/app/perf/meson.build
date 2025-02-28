perf_inc = []
perf_inc += libunvmed_inc

perf_src = [
  'perf.c',
]

perf_lib = static_library(
  'unvmed',
  [perf_src],
  dependencies: [vfn_lib, nvme_lib, unvmed_dep],
  link_with: [ccan_lib],
  include_directories: [ccan_inc, perf_inc],
)
