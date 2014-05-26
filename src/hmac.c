#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "polcrypt.h"

//mode = 0 encrypt, mode = 1 decrypt
guchar *calculate_hmac(const gchar *filename, const guchar *key, size_t keylen, gint mode){
	gint fd, retVal;
	struct stat fileStat;
	gchar *fAddr;
	size_t fsize = 0, donesize = 0, diff = 0;
	off_t offset = 0;
	
	fd = open(filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		fprintf(stderr, "calculate_hmac: %s\n", strerror(errno));
		return (guchar *)1;
	}
  	if(fstat(fd, &fileStat) < 0){
		fprintf(stderr, "calculate_hmac: %s\n", strerror(errno));
    	close(fd);
    	return (guchar *)1;
  	}
  	fsize = fileStat.st_size;
  	if(mode == 1) fsize -= 64;

	gcry_md_hd_t hd;
	gcry_md_open(&hd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(hd, key, keylen);
	if(fsize < BUF_FILE){
		fAddr = mmap(NULL, fsize, PROT_READ, MAP_SHARED, fd, 0);
		if(fAddr == MAP_FAILED){
			fprintf(stderr, "calculate_hmac: %s\n", strerror(errno));
			return (guchar *)1;
		}
		gcry_md_write(hd, fAddr, fsize);
		retVal = munmap(fAddr, fsize);
		if(retVal == -1){
			perror("calculate_hmac: --> munmap error");
			return (guchar *)1;
		}
		goto nowhile;
	}
	while(fsize > donesize){
		fAddr = mmap(NULL, BUF_FILE, PROT_READ, MAP_SHARED, fd, offset);
		if(fAddr == MAP_FAILED){
			fprintf(stderr, "calculate_hmac: %s\n", strerror(errno));
			return (guchar *)1;
		}
		gcry_md_write(hd, fAddr, BUF_FILE);
		donesize+=BUF_FILE;
		diff=fsize-donesize;
		offset += BUF_FILE;
		if(diff > 0 && diff < BUF_FILE){
			fAddr = mmap(NULL, diff, PROT_READ, MAP_SHARED, fd, offset);
			if(fAddr == MAP_FAILED){
				fprintf(stderr, "calculate_hmac:  %s\n", strerror(errno));
				return (guchar *)1;
			}
			gcry_md_write(hd, fAddr, diff);
			retVal = munmap(fAddr, diff);
			if(retVal == -1){
				perror("calculate_hmac: --> munmap ");
				return (guchar *)1;
			}
			break;
		}
		retVal = munmap(fAddr, BUF_FILE);
		if(retVal == -1){
			perror("calculate_hmac: --> munmap ");
			return (guchar *)1;
		}
	}
	nowhile:
	gcry_md_final(hd);
	guchar *tmp_hmac = gcry_md_read(hd, GCRY_MD_SHA512);
 	guchar *hmac = malloc(64);
 	memcpy(hmac, tmp_hmac, 64);
	gcry_md_close(hd);
	return hmac;
}
