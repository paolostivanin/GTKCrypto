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
#include <sys/mman.h>
#include "../polcrypt.h"

gint compute_hash(struct hashWidget_t *HashWidget){
	gint algo, i, fd, retVal, LEN=0, MD5, SHA1, SHA256, SHA512, WHIRLPOOL;
	struct stat fileStat;
	gchar *fAddr;
	off_t fsize = 0, donesize = 0, diff = 0, offset = 0;
	
	if(HashWidget->computeMD5){
		LEN=16;
		MD5=1;
	}
	else if(HashWidget->computeS1){
		LEN=20;
		SHA1=1;
	}
	else if(HashWidget->computeS256){
		LEN=32;
		SHA256=1;
	}
	else if(HashWidget->computeS512){
		LEN=64;
		SHA512=1;
	}
	else if(HashWidget->computeWhir){
		LEN=64;
		WHIRLPOOL=1;
	}

 	if(MD5){
		const gchar *name = "MD5";
		algo = gcry_md_map_name(name);
	}
	
	if(SHA1){
		const gchar *name = "SHA1";
		algo = gcry_md_map_name(name);
	}
	
	if(SHA256){
		const gchar *name = "SHA256";
		algo = gcry_md_map_name(name);
	}
	
	if(SHA512){
		const gchar *name = "SHA512";
		algo = gcry_md_map_name(name);
	}
	
	if(WHIRLPOOL){
		const gchar *name = "WHIRLPOOL";
		algo = gcry_md_map_name(name);
	}
	
	gchar hashBuf[(LEN*2)+1];

	fd = open(HashWidget->filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		fprintf(stderr, "compute_hash: %s\n", strerror(errno));
		return -1;
	}
  	if(fstat(fd, &fileStat) < 0){
  		fprintf(stderr, "compute_hash: %s\n", strerror(errno));
    	close(fd);
    	return -1;
  	}
  	fsize = fileStat.st_size;

	gcry_md_hd_t hd;
	gcry_md_open(&hd, algo, 0);
	
	if(fsize < BUF_FILE){
		fAddr = mmap(NULL, fsize, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if(fAddr == MAP_FAILED){
			perror("--> mmap2 ");
			return -1;
		}
		gcry_md_write(hd, fAddr, fsize);
		retVal = munmap(fAddr, fsize);
		if(retVal == -1){
			perror("--> munmap ");
			return -1;
		}
		goto nowhile;
	}

	while(fsize > donesize){
		fAddr = mmap(NULL, BUF_FILE, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
		if(fAddr == MAP_FAILED){
			printf("%d - %s\n", errno, strerror(errno));
			return -1;
		}
		gcry_md_write(hd, fAddr, BUF_FILE);
		donesize+=BUF_FILE;
		diff=fsize-donesize;
		offset += BUF_FILE;
		if(diff < BUF_FILE && diff != 0){
			fAddr = mmap(NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if(fAddr == MAP_FAILED){
				perror("--> mmap2 ");
				return -1;
			}
			gcry_md_write(hd, fAddr, diff);
			break;
		}
		retVal = munmap(fAddr, BUF_FILE);
		if(retVal == -1){
			perror("--> munmap ");
			return -1;
		}
	}
	
	nowhile:
	gcry_md_final(hd);
	guchar *hash = gcry_md_read(hd, algo);
 	for(i=0; i<LEN; i++){
 		sprintf(hashBuf+(i*2), "%02x", hash[i]);
 	}
 	hashBuf[LEN*2] = '\0';
 	
 	if(MD5)
 	gtk_entry_set_text(GTK_ENTRY(HashWidget->entryMD5), hashBuf);
 	
	if(SHA1)
	gtk_entry_set_text(GTK_ENTRY(HashWidget->entryS1), hashBuf);
	
	if(SHA256)
	gtk_entry_set_text(GTK_ENTRY(HashWidget->entryS256), hashBuf);
	
	if(SHA512)
	gtk_entry_set_text(GTK_ENTRY(HashWidget->entryS512), hashBuf);
	
	if(WHIRLPOOL)
	gtk_entry_set_text(GTK_ENTRY(HashWidget->entryWhir), hashBuf);
	
	gcry_md_close(hd);

	return 0;
}
