conf.set('UNVME_FIO', '')

fio_inc = []
fio_inc += include_directories(fio)
fio_inc += libunvmed_inc

fio_src = [
  'fio.c',
  'libunvmed-engine.c',
]

fio_lib = static_library(
  'unvmed',
  [fio_src],
  dependencies: [vfn_lib, nvme_lib, unvmed_dep],
  include_directories: fio_inc,
)
