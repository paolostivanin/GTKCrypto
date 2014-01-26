#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../polcrypt.h"

int compute_sha512(struct hashes *s_SHA512){
   	if(!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s_SHA512->checkS512))){
		goto fine;
	}
	else if(strlen(gtk_entry_get_text(GTK_ENTRY(s_SHA512->entryS512))) == 128){
		goto fine;
	}
	int algo, i, fd;
	char sha512hash[129];
	struct stat fileStat;
	char *buffer;
	const char *name = gcry_md_algo_name(GCRY_MD_SHA512);
	algo = gcry_md_map_name(name);
	off_t fsize = 0, donesize = 0, diff = 0;

	fd = open(s_SHA512->filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		fprintf(stderr, "compute_sha512: %s\n", strerror(errno));
		return 1;
	}
  	if(fstat(fd, &fileStat) < 0){
  		fprintf(stderr, "compute_sha512: %s\n", strerror(errno));
    	close(fd);
    	return 1;
  	}
  	fsize = fileStat.st_size;
  	close(fd);
  	
	FILE *fp;
	fp = fopen(s_SHA512->filename, "r");
	if(fp == NULL){
		fprintf(stderr, "compute_sha512: %s\n", strerror(errno));
		return -1;
	}
	gcry_md_hd_t hd;
	gcry_md_open(&hd, algo, 0);
	if(fsize < BUF_FILE){
		buffer = malloc(fsize);
  		if(buffer == NULL){
			fprintf(stderr, "compute_sha512: memory allocation error\n");
			fclose(fp);
			return -1;
  		}
		fread(buffer, 1, fsize, fp);
		gcry_md_write(hd, buffer, fsize);
		goto nowhile;
	}
	buffer = malloc(BUF_FILE);
  	if(buffer == NULL){
  		fprintf(stderr, "compute_sha512: memory allocation error\n");
  		fclose(fp);
  		return -1;
  	}
	while(fsize > donesize){
		fread(buffer, 1, BUF_FILE, fp);
		gcry_md_write(hd, buffer, BUF_FILE);
		donesize+=BUF_FILE;
		diff=fsize-donesize;
		if(diff < BUF_FILE){
			fread(buffer, 1, diff, fp);
			gcry_md_write(hd, buffer, diff);
			break;
		}
	}
	nowhile:
	gcry_md_final(hd);
	unsigned char *sha512 = gcry_md_read(hd, algo);
 	for(i=0; i<64; i++){
 		sprintf(sha512hash+(i*2), "%02x", sha512[i]);
 	}
 	sha512hash[128] = '\0';
 	gtk_entry_set_text(GTK_ENTRY(s_SHA512->entryS512), sha512hash);
 	free(buffer);
 	fclose(fp);
	gcry_md_close(hd);
	fine:
	return 0;
}
