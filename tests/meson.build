# Sample applications that link against libunvmed directly (no unvmed daemon).
# They are built by default but never installed.

tests_inc = include_directories('.')

test_apps = {
  'test_cid_conflict': 'test_cid_conflict.c',
  'test_irq_no_reaper': 'test_irq_no_reaper.c',
}

foreach name, src : test_apps
  executable(
    name,
    src,
    dependencies: [vfn_lib, nvme_lib, jsonc_lib, unvmed_dep],
    link_with: [ccan_lib],
    include_directories: [tests_inc, libunvmed_inc],
    install: false,
  )
endforeach
