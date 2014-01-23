#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "polcrypt.h"

#define BUFSIZE 24576

int zero_write(int file, size_t fSize, int isBigger){
	if(isBigger  == 0){
		unsigned char zBuf[fSize];
		memset(zBuf, 0, sizeof(zBuf));
		write(file, zBuf, sizeof(zBuf));
		if(fsync(file) == -1){
			fprintf(stderr, "zero_write fsync: %s\n", strerror(errno));
			return -1;
		}
		return 0;
	}
	else{
		unsigned char zBuf[BUFSIZE];
		memset(zBuf, 0, sizeof(zBuf));
		size_t doneSize = 0, writeBytes = 0;
		while(fSize > doneSize){
			writeBytes = write(file, zBuf, sizeof(zBuf));
			doneSize += writeBytes;
			if((fSize-doneSize) > 0 && (fSize-doneSize) < BUFSIZE){
				write(file, zBuf, (fSize-doneSize));
				if(fsync(file) == -1){
					fprintf(stderr, "zero_write fsync: %s\n", strerror(errno));
					return -1;
				}
				break;
			}
		}
		return 0;
	}
}
