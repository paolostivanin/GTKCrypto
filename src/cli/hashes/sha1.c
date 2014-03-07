#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "../polcrypt.h"

int compute_sha1(const char *filename){
	int algo, i, fd, retVal;
	char sha1hash[41];
	struct stat fileStat;
	char *fAddr;
	const char *name = gcry_md_algo_name(GCRY_MD_SHA1);
	algo = gcry_md_map_name(name);
	off_t fsize = 0, donesize = 0, diff = 0, offset = 0;

	fd = open(filename, O_RDONLY | O_NOFOLLOW);
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

	gcry_md_hd_t hd;
	gcry_md_open(&hd, algo, 0);

	if(fsize < BUF_FILE){
		fAddr = mmap(NULL, fsize, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if(fAddr == MAP_FAILED){
			fprintf(stderr, "compute_md5: %s\n", strerror(errno));
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
			fprintf(stderr, "compute_md5: %s\n", strerror(errno));
			return -1;
		}
		gcry_md_write(hd, fAddr, BUF_FILE);
		donesize+=BUF_FILE;
		diff=fsize-donesize;
		offset += BUF_FILE;
		if(diff < BUF_FILE){
			fAddr = mmap(NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if(fAddr == MAP_FAILED){
				fprintf(stderr, "compute_md5: %s\n", strerror(errno));
				return -1;
			}
			gcry_md_write(hd, fAddr, diff);
			retVal = munmap(fAddr, BUF_FILE);
			if(retVal == -1){
				perror("--> munmap ");
				return -1;
			}
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
	unsigned char *sha = gcry_md_read(hd, algo);
 	for(i=0; i<20; i++){
 		sprintf(sha1hash+(i*2), "%02x", sha[i]);
 	}
 	sha1hash[40] = '\0';
 	printf("SHA1:\t\t%s\n", sha1hash);
	gcry_md_close(hd);
	return 0;
}
