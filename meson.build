project('unvme-cli', 'c',
        version: '0.1',
        license: 'GPL-2.0-or-later',
        )

static = get_option('static')
buildtype = get_option('buildtype')

args = []
link_args = []

if static
  link_args += ['-static']
endif

conf = configuration_data()

args += ['-g']
link_args += ['-g']

if buildtype == 'debug'
  args += ['-p']
  link_args += ['-p']

  conf.set('UNVME_DEBUG', '')
endif

add_project_arguments(args, language: 'c')
add_project_link_arguments(link_args, language: 'c')

vfn_lib = dependency('libvfn', version: '>=5.1.0', static: static)
nvme_lib = dependency('libnvme', version: '>=1.8.0', static: static)

subdir('ccan')
subdir('lib')
subdir('argtable3')

fio_lib = []
perf_lib = []
subdir('app')

executable(
  'unvme',
  ['unvmed.c', 'unvme.c', 'unvmed-cmds.c', 'unvmed-print.c', 'unvmed-file.c',
   'unvme-cmds.c',],
  dependencies: [vfn_lib, nvme_lib, unvmed_dep],
  link_with: [ccan_lib, argtable3_lib],
  link_whole: [fio_lib, perf_lib],
  include_directories: [ccan_inc, libunvmed_inc],
  install: true,
  install_dir: get_option('bindir'),
)

# Set the unvme-cli version
is_git = run_command('git', 'rev-parse', '--short=12', 'HEAD', check: false)
if is_git.returncode() == 0
  hash = is_git.stdout().strip()

  diff = run_command('git', 'diff', '--quiet', check: false)
  if diff.returncode() == 1
    hash += '+'
  endif

  conf.set('UNVME_VERSION', '"' + meson.project_version() + '-g' + hash + '"')
else
  conf.set('UNVME_VERSION', '"' + meson.project_version() + '"')
endif

configure_file(
    output: 'config.h',
    configuration: conf
)
