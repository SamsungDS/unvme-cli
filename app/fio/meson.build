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

ioengine_lib = shared_library(
  'unvmed-ioengine',
  ['libunvmed-engine.c'],
  override_options: ['b_lundef=false'],  # To remove -Wl,--no-undefined
  dependencies: [nvme_lib, unvmed_dep],
  include_directories: fio_inc,
  install: true,
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(
  ioengine_lib,
  version: '0.1',
  description: 'fio ioengine plugin for unvme-cli daemon process',
)
