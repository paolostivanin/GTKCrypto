#ifndef POLCRYPT_H_INCLUDED
#define POLCRYPT_H_INCLUDED

#define GCRYPT_MIN_VER "1.5.0"
#define BUF_FILE 1048576 /* 1 MiB di memoria per il file come buffer massimo, poi spezzo */
#define VERS "1.1.0-dev"

int check_pkcs7(unsigned char *, unsigned char *);
int encrypt_file(const char *, const char *);
int decrypt_file(const char *, const char *);
unsigned char *calculate_hmac(const char *, const unsigned char *, size_t, int);
int delete_input_file(const char *, size_t);
int random_write(int, int, size_t, int);
int zero_write(int, size_t, int);
int compute_sha1(const char *);
int compute_sha256(const char *);
int compute_sha512(const char *);
int compute_md5(const char *);
int compute_whirlpool(const char *);
int compute_rmd160(const char *);
int compute_all(const char *);
int do_action();

struct metadata{
	unsigned char salt[32];
	unsigned char iv[16];
};
extern struct metadata s_mdata;

struct argvArgs{
	char *inputFilePath;
	char *outputFilePath;
	char *algo;
	int check; //1 encrypt, 2 decrypt, 3 hash
};
extern struct argvArgs args;

#endif
