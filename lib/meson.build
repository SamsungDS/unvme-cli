libunvmed_inc = include_directories('.')
libunvmed_src = [
  'libunvmed.c',
  'libunvmed-logs.c',
]
libunvmed_hdr = [
  'libunvmed.h',
]

libunvmed_so = shared_library(
  'unvmed',
  libunvmed_src,
  dependencies: [vfn_lib, nvme_lib],
  link_with: [ccan_lib],
  include_directories: [ccan_inc, libunvmed_inc],
  install: true,
  install_dir: get_option('libdir'),
)

install_headers(libunvmed_hdr)

unvmed_dep = declare_dependency(
  include_directories:  [ccan_inc, libunvmed_inc],
  link_with: libunvmed_so
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(
  libunvmed_so,
  version: '0.1',
  description: 'unvme-cli daemon process library',
)
