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

int random_write(int file, int fileRand, size_t fSize, int isBigger){
	if(isBigger == 0){
		unsigned char bRand[fSize];
		read(fileRand, bRand, sizeof(bRand));
		write(file, bRand, sizeof(bRand));
		if(fsync(file) == -1){
			fprintf(stderr, "fsync: %s\n", strerror(errno));
			return -1;
		}
		return 0;
	}
	else{
		unsigned char bytesRandom[BUFSIZE];
		size_t doneSize = 0, writeBytes = 0;
		read(fileRand, bytesRandom, sizeof(bytesRandom));
		while(fSize > doneSize){
			writeBytes = write(file, bytesRandom, sizeof(bytesRandom));
			doneSize += writeBytes;
			if((fSize-doneSize) > 0 && (fSize-doneSize) < BUFSIZE){
				read(fileRand, bytesRandom, sizeof(bytesRandom));
				write(file, bytesRandom, (fSize-doneSize));
				if(fsync(file) == -1){
					fprintf(stderr, "fsync: %s\n", strerror(errno));
					return -1;
				}
				break;
			}
		}
		return 0;
	}
}
