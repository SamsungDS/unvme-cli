project('unvme-cli', 'c',
        version: '0.1',
        license: 'GPL-2.0-or-later',
        )

static = get_option('static')

if static
  add_project_link_arguments('-static', language: 'c')
endif

vfn_lib = dependency('libvfn', version: '>=5.1.0', static: static)
nvme_lib = dependency('libnvme', version: '>=1.8.0', static: static)

subdir('ccan')
subdir('lib')

executable(
  'unvme',
  ['unvmed.c', 'unvme.c', 'unvmed-cmds.c', 'unvmed-print.c', 'unvmed-file.c',
   'unvmed-logs.c', 'unvme-cmds.c',],
  dependencies: [vfn_lib, nvme_lib, unvmed_dep],
  link_with: [ccan_lib],
  include_directories: [ccan_inc, libunvmed_inc],
  install: true,
  install_dir: get_option('bindir'),
)

conf = configuration_data()

# Set the unvme-cli version
conf.set('UNVME_VERSION', '"' + meson.project_version() + '"')

configure_file(
    output: 'config.h',
    configuration: conf
)
