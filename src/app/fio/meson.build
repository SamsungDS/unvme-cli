conf.set('UNVME_FIO', '')

fio_inc = []
fio_inc += include_directories(fio)
fio_inc += libunvmed_inc

fio_src = [
  'fio.c',
]

fio_lib = static_library(
  'unvmed',
  [fio_src],
  dependencies: [vfn_lib, nvme_lib, unvmed_dep],
  include_directories: fio_inc,
)

ver = '0.0.1'
ioengine_lib = shared_library(
  'unvmed-ioengine',
  ['libunvmed-engine.c'],
  version: ver,
  override_options: ['b_lundef=false'],  # To remove -Wl,--no-undefined
  dependencies: [vfn_lib, nvme_lib, unvmed_dep],
  include_directories: fio_inc,
  install: true,
  install_dir: get_option('libdir'),
)

conf.set('LIBUNVMED_IOENGINE_VERSION', '"' + ver + '"')

pkgconfig = import('pkgconfig')
pkgconfig.generate(
  ioengine_lib,
  version: ver,
  description: 'fio ioengine plugin for unvme-cli daemon process',
)
