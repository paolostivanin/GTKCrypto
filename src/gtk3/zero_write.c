#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <glib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "polcrypt.h"

gint zero_write(gint file, size_t fSize, gint isBigger){
	if(isBigger  == 0){
		guchar zBuf[fSize];
		memset(zBuf, 0, sizeof(zBuf));
		write(file, zBuf, sizeof(zBuf));
		if(fsync(file) == -1){
			fprintf(stderr, "zero_write fsync: %s\n", strerror(errno));
			return -1;
		}
		return 0;
	}
	else{
		guchar zBuf[BUFSIZE];
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
