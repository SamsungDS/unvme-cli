libunvmed_inc = include_directories('.')
libunvmed_src = [
  'libunvmed.c',
]
libunvmed_hdr = [
  'libunvmed.h',
]

unvmed = library(
  'unvmed',
  libunvmed_src,
  version: '0.1',
  dependencies: [vfn_lib, nvme_lib],
  link_with: [ccan_lib],
  include_directories: [ccan_inc, libunvmed_inc],
  install: true,
)

install_headers(libunvmed_hdr)

unvmed_dep = declare_dependency(link_with: unvmed)
