gnome = import('gnome')

resources = gnome.compile_resources(
  'gtkcrypto-resources',
  'gtkcrypto.gresource.xml',
  c_name: 'gtkcrypto',
)

# Crypto core: GTK-free, shared between the GUI and the CLI.
crypto_sources = files(
  'encrypt-file.c',
  'decrypt-file.c',
  'hash.c',
  'hmac.c',
  'crypt-common.c',
  'get-file-size.c',
  'gpgme-misc.c',
  'cleanup.c',
)

crypto_lib = static_library('gtkcrypto-core',
  crypto_sources,
  dependencies: [glib_dep, gio_dep, gcrypt_dep, gpgme_dep],
  install: false,
)

gui_sources = files(
  'main.c',
  'gtkcrypto-application.c',
  'gtkcrypto-window.c',
  'state.c',
  'pages/hashing-page.c',
  'pages/file-crypto-page.c',
  'pages/text-crypto-page.c',
  'pages/gpg-page.c',
)

executable('gtkcrypto',
  gui_sources,
  resources,
  link_with: crypto_lib,
  dependencies: [gtk_dep, adw_dep, gcrypt_dep, gpgme_dep],
  install: true,
)

executable('gtkcrypto-cli',
  files('cli/cli-main.c'),
  link_with: crypto_lib,
  dependencies: [glib_dep, gio_dep, gcrypt_dep, gpgme_dep],
  install: true,
)
