project('unvme-cli', 'c',
        version: '0.1',
        license: 'GPL-2.0-or-later',
        )

subdir('ccan')

vfn_lib = dependency('libvfn', version: '>=5.0.0')

executable(
  'unvme',
  ['unvmed.c', 'unvme.c', 'unvmed-cmds.c', 'unvmed-print.c', 'unvmed-file.c', 'unvme-cmds.c',],
  dependencies: [vfn_lib],
  link_with: ccan_lib,
  include_directories: [ccan_inc],
  install: true,
  install_dir: get_option('bindir'),
)
