#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../polcrypt.h"

int compute_sha256(const char *filename){
	int algo, i, fd;
	char sha256hash[65];
	struct stat fileStat;
	char *buffer;
	const char *name = gcry_md_algo_name(GCRY_MD_SHA256);
	algo = gcry_md_map_name(name);
	off_t fsize = 0, donesize = 0, diff = 0;

	fd = open(filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		printf("--> compute_sha256: failed to open file\n");
		return 1;
	}
  	if(fstat(fd, &fileStat) < 0){
  		perror("Fstat error");
    	close(fd);
    	return 1;
  	}
  	fsize = fileStat.st_size;
  	close(fd);
  	
	FILE *fp;
	fp = fopen(filename, "r");
	gcry_md_hd_t hd;
	gcry_md_open(&hd, algo, 0);
	if(fsize < BUF_FILE){
		buffer = malloc(fsize);
  		if(buffer == NULL){
  			printf("malloc error\n");
  			return 1;
  		}
		fread(buffer, 1, fsize, fp);
		gcry_md_write(hd, buffer, fsize);
		goto nowhile;
	}
	buffer = malloc(BUF_FILE);
  	if(buffer == NULL){
  		printf("malloc error\n");
  		return 1;
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
	unsigned char *sha = gcry_md_read(hd, algo);
 	for(i=0; i<32; i++){
 		sprintf(sha256hash+(i*2), "%02x", sha[i]);
 	}
 	sha256hash[64] = '\0';
 	printf("sha256: %s\n", sha256hash);
 	free(buffer);
 	fclose(fp);
	gcry_md_close(hd);
	return 0;
}
