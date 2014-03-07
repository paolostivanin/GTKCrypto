#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "polcrypt.h"

//mode = 0 encrypt, mode = 1 decrypt
unsigned char *calculate_hmac(const char *filename, const unsigned char *key, size_t keylen, int mode){
	int fd, retVal;
	struct stat fileStat;
	char *fAddr;
	size_t fsize = 0, donesize = 0, diff = 0;
	off_t offset = 0;
	
	fd = open(filename, O_RDONLY | O_NOFOLLOW);
  	if(fstat(fd, &fileStat) < 0){
  		fprintf(stderr, "hmac fstat: %s\n", strerror(errno));
    	close(fd);
    	return (unsigned char *)1;
  	}
  	fsize = fileStat.st_size;
  	if(mode == 1) fsize -= 64;
	
	gcry_md_hd_t hd;
	gcry_md_open(&hd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(hd, key, keylen);
	
	if(fsize < BUF_FILE){
		fAddr = mmap(NULL, fsize, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if(fAddr == MAP_FAILED){
			fprintf(stderr, "%s\n", strerror(errno));
			return (unsigned char *)1;
		}
		gcry_md_write(hd, fAddr, fsize);
		retVal = munmap(fAddr, fsize);
		if(retVal == -1){
			perror("--> munmap ");
			return (unsigned char *)1;
		}
		goto nowhile;
	}
	
	while(fsize > donesize){
		fAddr = mmap(NULL, BUF_FILE, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
		if(fAddr == MAP_FAILED){
			fprintf(stderr, "compute_md5: %s\n", strerror(errno));
			return (unsigned char *)1;
		}
		gcry_md_write(hd, fAddr, 16);
		donesize+=16;
		diff=fsize-donesize;
		offset += BUF_FILE;
		if(diff > 0 && diff < 16){
			fAddr = mmap(NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if(fAddr == MAP_FAILED){
				fprintf(stderr, "compute_md5: %s\n", strerror(errno));
				return (unsigned char *)1;
			}
			gcry_md_write(hd, fAddr, diff);
			retVal = munmap(fAddr, diff);
			if(retVal == -1){
				perror("--> munmap ");
				return (unsigned char *)1;
			}
			break;
		}
		retVal = munmap(fAddr, 16);
		if(retVal == -1){
			perror("--> munmap ");
			return (unsigned char *)1;
		}
	}
	nowhile:
	gcry_md_final(hd);
	unsigned char *tmp_hmac = gcry_md_read(hd, GCRY_MD_SHA512);
 	unsigned char *hmac = malloc(64);
 	memcpy(hmac, tmp_hmac, 64);
	gcry_md_close(hd);
	return hmac;
}
