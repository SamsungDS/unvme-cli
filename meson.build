project('unvme-cli', 'c',
        version: '0.1',
        license: 'GPL-2.0-only',
        )

static = get_option('static')
buildtype = get_option('buildtype')

args = ['-g']
link_args = ['-g']

if static
  link_args += ['-static']
endif

conf = configuration_data()

if buildtype == 'debug'
  args += ['-p']
  link_args += ['-p']

  conf.set('UNVME_DEBUG', '')
endif

# Set the unvme-cli version
is_git = run_command('git', 'describe', 'HEAD', check: false)
if is_git.returncode() == 0
  ver = is_git.stdout().strip()

  diff = run_command('git', 'diff', '--quiet', check: false)
  if diff.returncode() == 1
    ver += '+'
  endif

  conf.set('UNVME_VERSION', '"' + ver + '"')
else
  conf.set('UNVME_VERSION', '"' + meson.project_version() + '"')
endif

add_project_arguments(args, language: 'c')
add_project_link_arguments(link_args, language: 'c')

c = meson.get_compiler('c')
vfn_lib_path = get_option('with-libvfn')
if vfn_lib_path != ''
  vfn_lib = declare_dependency(
    # It will search libvfn.so* in the given directory with no recursive search.
    # To make sure that libvfn.so* to be in <path>/lib directory, give '--libdir=lib'
    # when you run meson setup.
    dependencies: c.find_library('libvfn', dirs : [vfn_lib_path + '/lib']),
    include_directories: include_directories(vfn_lib_path + '/include')
  )
else
  vfn_lib = dependency('libvfn', version: '>=5.1.0', static: static)
endif

nvme_lib = dependency('libnvme', version: '>=1.8.0', static: static)
jsonc_lib = dependency('json-c', version: '>=0.15', static: static)

subdir('ccan')
subdir('argtable3')
subdir('lib')
subdir('src')
