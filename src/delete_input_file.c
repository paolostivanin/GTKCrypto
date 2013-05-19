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
	fd = open(inputFilePath, O_WRONLY | O_NOFOLLOW);
	fdRandom = open("/dev/random", O_RDONLY);
	
	if(fileSize < BUFSIZE){
		zero_write(fd, fileSize, 0);
		lseek(fd, 0, SEEK_SET);
		random_write(fd, fdRandom, fileSize, 0);
	}
	else{
		zero_write(fd, fileSize, 1);
		lseek(fd, 0, SEEK_SET);
		random_write(fd, fdRandom, fileSize, 1);
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
		return -1;
	}
		
	return 0;
}