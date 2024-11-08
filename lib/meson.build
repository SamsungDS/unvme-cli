libunvmed_inc = include_directories('.')
libunvmed_src = [
  'libunvmed.c',
  'libunvmed-logs.c',
]
libunvmed_hdr = [
  'libunvmed.h',
]

libunvmed = static_library(
  'unvmed',
  libunvmed_src,
  dependencies: [vfn_lib, nvme_lib],
  link_with: [ccan_lib],
  include_directories: [ccan_inc, libunvmed_inc],
)

libunvmed_so = shared_library(
  'unvmed',
  libunvmed_src,
  dependencies: [vfn_lib, nvme_lib],
  link_with: [ccan_lib],
  include_directories: [ccan_inc, libunvmed_inc],
  install: true,
)

install_headers(libunvmed_hdr)

unvmed_dep = declare_dependency(
  include_directories:  [ccan_inc, libunvmed_inc],
  link_with: libunvmed
)
