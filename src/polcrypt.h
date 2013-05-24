/* Sviluppatore: Paolo Stivanin
 * Copyright: 2013
 * Licenza: GNU GPL v3 <http://www.gnu.org/licenses/gpl-3.0.html>
 * Sito web: <https://github.com/polslinux/PolCrypt>
 */

#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define VERS "1.0-beta"

int check_pkcs7(unsigned char *, unsigned char *);
int encrypt_file(const char *, const char *);
int decrypt_file(const char *, const char *);
unsigned char *calculate_hmac(const char *, const unsigned char *, size_t, int);
int delete_input_file(const char *, size_t);
int random_write(int, int, size_t, int);
int zero_write(int, size_t, int);

struct metadata{
	unsigned char salt[32];
	unsigned char iv[16];
};
extern struct metadata s_mdata;

#endif
