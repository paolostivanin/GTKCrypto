project('gtkcrypto', 'c',
  version: '2.0.0',
  meson_version: '>= 0.62.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'b_pie=true',
  ],
)

gnome = import('gnome')

cc = meson.get_compiler('c')

add_project_arguments(
  cc.get_supported_arguments(
    '-Wformat=2',
    '-Wmissing-format-attribute',
    '-fstack-protector-strong',
    '-Wundef',
    '-Wstrict-prototypes',
    '-Wunreachable-code',
    '-Wchar-subscripts',
    '-Wwrite-strings',
    '-Wpointer-arith',
    '-Wbad-function-cast',
    '-Wcast-align',
    '-Werror=format-security',
    '-Werror=implicit-function-declaration',
    '-Wno-sign-compare',
    '-D_LARGEFILE_SOURCE',
    '-D_FILE_OFFSET_BITS=64',
    '-D_GNU_SOURCE',
  ),
  language: 'c',
)

if host_machine.system() == 'linux'
  add_project_link_arguments(
    cc.get_supported_link_arguments(
      '-Wl,--no-add-needed',
      '-Wl,--as-needed',
      '-Wl,--no-undefined',
      '-Wl,-z,relro,-z,now',
    ),
    language: 'c',
  )
endif

gtk_dep = dependency('gtk4', version: '>= 4.16')
adw_dep = dependency('libadwaita-1', version: '>= 1.6')
gcrypt_dep = dependency('libgcrypt', version: '>= 1.10.1')
gpgme_dep = dependency('gpgme', version: '>= 1.8.0')

subdir('src')
subdir('data')
