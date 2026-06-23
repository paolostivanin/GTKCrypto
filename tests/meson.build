core_test = executable(
  'core-test',
  'test-core.c',
  include_directories: include_directories('../src'),
  link_with: crypto_lib,
  dependencies: [glib_dep, gio_dep, gcrypt_dep],
)

test('core', core_test, timeout: 180)

bash = find_program('bash')
test(
  'cli',
  bash,
  args: [files('test-cli.sh'), cli_exe],
  timeout: 180,
)

gpg = find_program('gpg', required: false)
if gpg.found()
  gpg_test = executable(
    'gpg-test',
    ['test-gpg.c', '../src/gpgme-misc.c'],
    include_directories: include_directories('../src'),
    link_with: crypto_lib,
    dependencies: [glib_dep, gio_dep, gcrypt_dep, gpgme_dep],
  )
  test('gpg', gpg_test, args: [gpg.full_path()], timeout: 180)
endif

appstreamcli = find_program('appstreamcli', required: false)
if appstreamcli.found()
  test(
    'appstream',
    appstreamcli,
    args: ['validate', '--no-net',
           meson.project_source_root() / 'data' / 'com.github.paolostivanin.gtkcrypto.metainfo.xml'],
  )
endif

if get_option('fuzzing')
  fuzz_args = ['-fsanitize=fuzzer,address,undefined',
               '-fno-omit-frame-pointer']
  executable(
    'fuzz-v3-text',
    'fuzz-v3-text.c',
    include_directories: include_directories('../src'),
    link_with: crypto_lib,
    dependencies: [glib_dep, gio_dep, gcrypt_dep],
    c_args: fuzz_args,
    link_args: fuzz_args,
  )
endif
