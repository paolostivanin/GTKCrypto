gnome = import('gnome')

resources = gnome.compile_resources(
  'gtkcrypto-resources',
  'gtkcrypto.gresource.xml',
  c_name: 'gtkcrypto',
)

sources = files(
  # Application core
  'main.c',
  'gtkcrypto-application.c',
  'gtkcrypto-window.c',

  # Crypto core (GTK-free)
  'encrypt-file.c',
  'decrypt-file.c',
  'hash.c',
  'hmac.c',
  'crypt-common.c',
  'get-file-size.c',
  'gpgme-misc.c',
  'cleanup.c',

  # Pages
  'pages/hashing-page.c',
  'pages/file-crypto-page.c',
  'pages/text-crypto-page.c',
  'pages/gpg-page.c',
)

executable('gtkcrypto',
  sources,
  resources,
  dependencies: [gtk_dep, adw_dep, gcrypt_dep, gpgme_dep],
  install: true,
)
