argtable3_inc= include_directories('.')
argtable3_src= [
  'argtable3.c',
]

cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required: false)

argtable3_lib = static_library(
  'argtable3',
  [argtable3_src],
  include_directories: argtable3_inc,
  dependencies: m_dep,
)
