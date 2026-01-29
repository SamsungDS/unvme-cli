libunvmed_inc = include_directories('.')
libunvmed_src = [
  'libunvmed.c',
  'libunvmed-cmds.c',
  'libunvmed-logs.c',
]
libunvmed_hdr = [
  'libunvmed.h',
  'libunvmed-logs.h',
]

ver = '0.0.1'
libunvmed_so = shared_library(
  'unvmed',
  libunvmed_src,
  version: ver,
  dependencies: [vfn_lib, nvme_lib, jsonc_lib],
  link_with: [ccan_lib],
  include_directories: [ccan_inc, libunvmed_inc],
  install: true,
  install_dir: get_option('libdir'),
)

conf.set('LIBUNVMED_VERSION', '"' + ver + '"')

install_headers(libunvmed_hdr)

unvmed_dep = declare_dependency(
  include_directories:  [ccan_inc, libunvmed_inc],
  link_with: libunvmed_so
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(
  libunvmed_so,
  version: ver,
  description: 'unvme-cli daemon process library',
)
