#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "../polcrypt.h"

void *compute_whirlpool(struct argvArgs_t *Args){
	int algo, i, fd, retVal;
	char whirlpoolhash[129];
	struct stat fileStat;
	char *fAddr;
	const char *name = gcry_md_algo_name(GCRY_MD_WHIRLPOOL);
	algo = gcry_md_map_name(name);
	off_t fsize = 0, donesize = 0, diff = 0, offset = 0;

	fd = open(Args->inputFilePath, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		fprintf(stderr, "compute_whirlpool: %s\n", strerror(errno));
		return NULL;
	}
  	if(fstat(fd, &fileStat) < 0){
  		fprintf(stderr, "compute_whirlpool: %s\n", strerror(errno));
    	close(fd);
    	return NULL;
  	}
  	fsize = fileStat.st_size;

	gcry_md_hd_t hd;
	gcry_md_open(&hd, algo, 0);

	if(fsize < BUF_FILE){
		fAddr = mmap(NULL, fsize, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if(fAddr == MAP_FAILED){
			fprintf(stderr, "compute_md5: %s\n", strerror(errno));
			return NULL;
		}
		gcry_md_write(hd, fAddr, fsize);
		retVal = munmap(fAddr, fsize);
		if(retVal == -1){
			perror("--> munmap ");
			return NULL;
		}
		goto nowhile;
	}

	while(fsize > donesize){
		fAddr = mmap(NULL, BUF_FILE, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
		if(fAddr == MAP_FAILED){
			fprintf(stderr, "compute_md5: %s\n", strerror(errno));
			return NULL;
		}
		gcry_md_write(hd, fAddr, BUF_FILE);
		donesize+=BUF_FILE;
		diff=fsize-donesize;
		offset += BUF_FILE;
		if(diff < BUF_FILE){
			fAddr = mmap(NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if(fAddr == MAP_FAILED){
				fprintf(stderr, "compute_md5: %s\n", strerror(errno));
				return NULL;
			}
			gcry_md_write(hd, fAddr, diff);
			retVal = munmap(fAddr, BUF_FILE);
			if(retVal == -1){
				perror("--> munmap ");
				return NULL;
			}
			break;
		}
		retVal = munmap(fAddr, BUF_FILE);
		if(retVal == -1){
			perror("--> munmap ");
			return NULL;
		}
	}

	nowhile:
	gcry_md_final(hd);
	unsigned char *whirlpool = gcry_md_read(hd, algo);
 	for(i=0; i<64; i++){
 		sprintf(whirlpoolhash+(i*2), "%02x", whirlpool[i]);
 	}
 	whirlpoolhash[128] = '\0';
 	printf("WHIRLPOOL:\t%s\n", whirlpoolhash);
	gcry_md_close(hd);
}
