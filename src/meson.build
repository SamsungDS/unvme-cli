inc = include_directories('.')

unvme_sources = [
  'unvmed.c', 'unvme.c', 'unvmed-cmds.c', 'unvmed-print.c', 'unvmed-file.c',
  'unvme-cmds.c',
]

fio_lib = []
perf_lib = []
subdir('app')

configure_file(
    output: 'config.h',
    configuration: conf
)

executable(
  'unvme',
  unvme_sources,
  dependencies: [vfn_lib, nvme_lib, unvmed_dep],
  link_with: [ccan_lib, argtable3_lib],
  link_whole: [fio_lib, perf_lib],
  include_directories: [inc, ccan_inc, argtable3_inc, libunvmed_inc],
  install: true,
  install_dir: get_option('bindir'),
)
