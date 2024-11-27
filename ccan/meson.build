# no configuration data for now, so go with empty one.
conf_data = configuration_data()

# Generate a config.h file as a configurator to compile ccan/*.c
# Example: https://ccodearchive.net/example-config.h
configure_file(
  output: 'config.h',
  configuration: conf_data
)

ccan_inc = include_directories('.')
ccan_src = [
  'ccan/str/str.c',
  'ccan/list/list.c',
]

ccan_lib = static_library('ccan', [ccan_src], include_directories: ccan_inc)
