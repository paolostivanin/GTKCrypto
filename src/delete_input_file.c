#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "polcrypt.h"

#define BUFSIZE 24576 

int delete_input_file(const char *inputFilePath, size_t fileSize){
	int fd, fdRandom;
	size_t doneSize = 0, writeBytes = 0;
	fd = open(inputFilePath, O_WRONLY);
	fdRandom = open("/dev/random", O_RDONLY);
	
	if(fileSize < BUFSIZE){
		char zeroBuffer[fileSize];
		memset(zeroBuffer, 0, sizeof(zeroBuffer));
		char bytesRandom[fileSize];
		read(fdRandom, bytesRandom, sizeof(bytesRandom));
		write(fd, bytesRandom, sizeof(bytesRandom));
		if(fsync(fd) == -1){
			printf("fsync error\n");
			return -1;
		}
		lseek(fd, 0, SEEK_SET);
		write(fd, zeroBuffer, sizeof(zeroBuffer));
		if(fsync(fd) == -1){
			printf("fsync error\n");
			return -1;
		}
	}
	else{
		char zeroBuffer[BUFSIZE], bytesRandom[BUFSIZE];
		memset(zeroBuffer, 0, sizeof(zeroBuffer));
		read(fdRandom, bytesRandom, sizeof(bytesRandom));
		while(fileSize > doneSize){
			writeBytes = write(fd, bytesRandom, sizeof(bytesRandom));
			doneSize += writeBytes;
			if((fileSize-doneSize) > 0 && (fileSize-doneSize) < BUFSIZE){
				read(fdRandom, bytesRandom, sizeof(bytesRandom));
				writeBytes = write(fd, bytesRandom, (fileSize-doneSize));
				break;
			}
		}
		if(fsync(fd) == -1){
			printf("fsync error\n");
			return -1;
		}
		doneSize = 0;
		writeBytes = 0;
		lseek(fd, 0, SEEK_SET);
		while(fileSize > doneSize){
			writeBytes = write(fd, zeroBuffer, sizeof(zeroBuffer));
			doneSize += writeBytes;
			if((fileSize-doneSize) > 0 && (fileSize-doneSize) < BUFSIZE){
				write(fd, zeroBuffer, (fileSize-doneSize));
				break;
			}
		}
		if(fsync(fd) == -1){
			printf("fsync error\n");
			return -1;
		}
	}
	ftruncate(fd, 0);
	if(fsync(fd) == -1){
		printf("fsync error\n");
		return -1;
	}
	
	close(fd);
	close(fdRandom);
	if(remove(inputFilePath) == -1){
		printf("error during rm\n");
		return -2;
	}
		
	return 0;
}