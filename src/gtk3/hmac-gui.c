#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

//mode = 0 encrypt, mode = 1 decrypt
guchar *calculate_hmac(const gchar *filename, const guchar *key, size_t keylen, gint mode){
	gint fd;
	struct stat fileStat;
	gchar *buffer;
	FILE *fp;
	size_t fsize = 0, donesize = 0, diff = 0;
	fd = open(filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		return (guchar *)1;
	}
  	if(fstat(fd, &fileStat) < 0){
		fprintf(stderr, "%s\n", strerror(errno));
    	close(fd);
    	return (guchar *)1;
  	}
  	fsize = fileStat.st_size;
  	if(mode == 1) fsize -= 64;
  	close(fd);  	
	
	fp = fopen(filename, "r");
	if(fp == NULL){
		return (guchar *)1;
	}
	gcry_md_hd_t hd;
	gcry_md_open(&hd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(hd, key, keylen);
	if(fsize < 16){
		buffer = malloc(fsize);
  		if(buffer == NULL){
  			fprintf(stderr, "hmac malloc error\n");
  			return (guchar *)1;
  		}
		if(fread(buffer, 1, fsize, fp) != fsize){
			fprintf(stderr, "hmac fread error \n");
			return (guchar *)1;
		}
		gcry_md_write(hd, buffer, fsize);
		goto nowhile;
	}
	buffer = malloc(16);
  	if(buffer == NULL){
  		fprintf(stderr, "hmac malloc error\n");
  		return (guchar *)1;
  	}
	while(fsize > donesize){
		if(fread(buffer, 1, 16, fp) != 16){
			fprintf(stderr, "fread error hmac\n");
			return (guchar *)1;
		}
		gcry_md_write(hd, buffer, 16);
		donesize+=16;
		diff=fsize-donesize;
		if(diff > 0 && diff < 16){
			if(fread(buffer, 1, diff, fp) != diff){
				fprintf(stderr, "hmac fread error\n");
				return (guchar *)1;
			}
			gcry_md_write(hd, buffer, diff);
			break;
		}
	}
	nowhile:
	gcry_md_final(hd);
	guchar *tmp_hmac = gcry_md_read(hd, GCRY_MD_SHA512);
	free(buffer);
 	fclose(fp);
 	guchar *hmac = malloc(64);
 	memcpy(hmac, tmp_hmac, 64);
	gcry_md_close(hd);
	return hmac;
}
