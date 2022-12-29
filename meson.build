# Copyright 2022 Google LLC
# SPDX-License-Identifier: MIT

project(
  'meminfo',
  'c',
  version: '0.1',
  license: 'MIT',
  meson_version: '>=0.54',
  default_options: ['c_std=c11', 'warning_level=3'],
)

cc = meson.get_compiler('c')

warning_args = cc.get_supported_arguments([
  '-Wno-pedantic',
  '-Wno-missing-field-initializers',
  '-Wno-unused-parameter',
])

add_project_arguments(['-D_GNU_SOURCE', warning_args], language: 'c')

dep_curses = dependency('curses')

tests = [
  'clear',
  'formats',
  'tri',
  'tex',
  'tex_depth',
  'ubo',
  'msaa',
  'gs',
  'tess',
  'push_const',
  'compute',
  'ycbcr',
]

executable(
  'meminfo',
  sources: ['meminfo.c'],
  dependencies: [dep_curses],
)
