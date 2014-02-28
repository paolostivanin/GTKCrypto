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

gint compute_sha1(struct hashes *s_SHA1){
   	if(!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s_SHA1->checkS1))){
		gtk_entry_set_text(GTK_ENTRY(s_SHA1->entryS1), "");
		goto fine;
	}
	else if(strlen(gtk_entry_get_text(GTK_ENTRY(s_SHA1->entryS1))) == 40){
		goto fine;
	}
	gint algo, i, fd;
	gchar sha1hash[41];
	struct stat fileStat;
	gchar *buffer;
	const gchar *name = gcry_md_algo_name(GCRY_MD_SHA1);
	algo = gcry_md_map_name(name);
	off_t fsize = 0, donesize = 0, diff = 0;

	fd = open(s_SHA1->filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		fprintf(stderr, "compute_sha1: %s\n", strerror(errno));
		return 1;
	}
  	if(fstat(fd, &fileStat) < 0){
  		fprintf(stderr, "compute_sha1: %s\n", strerror(errno));
    	close(fd);
    	return 1;
  	}
  	fsize = fileStat.st_size;
  	close(fd);
  	
	FILE *fp;
	fp = fopen(s_SHA1->filename, "r");
	if(fp == NULL){
		fprintf(stderr, "compute_sha1: %s\n", strerror(errno));
		return -1;
	}
	gcry_md_hd_t hd;
	gcry_md_open(&hd, algo, 0);
	if(fsize < BUF_FILE){
		buffer = malloc(fsize);
  		if(buffer == NULL){
			fprintf(stderr, "compute_sha1: memory allocation error\n");
			fclose(fp);
			return -1;
  		}
		fread(buffer, 1, fsize, fp);
		gcry_md_write(hd, buffer, fsize);
		goto nowhile;
	}
	buffer = malloc(BUF_FILE);
  	if(buffer == NULL){
  		fprintf(stderr, "compute_sha1: memory allocation error\n");
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
	guchar *sha = gcry_md_read(hd, algo);
 	for(i=0; i<20; i++){
 		sprintf(sha1hash+(i*2), "%02x", sha[i]);
 	}
 	sha1hash[40] = '\0';
 	gtk_entry_set_text(GTK_ENTRY(s_SHA1->entryS1), sha1hash);
 	free(buffer);
 	fclose(fp);
	gcry_md_close(hd);
	fine:
	return 0;
}
