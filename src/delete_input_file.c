#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "polcrypt.h"

gint random_write(gint, gint, size_t, gint);
gint zero_write(gint, size_t, gint);

gint delete_input_file(struct widget_t *WidgetMain, size_t fileSize){
	gint fd, fdRandom;
	fd = open(WidgetMain->filename, O_WRONLY | O_NOFOLLOW);
	fdRandom = open("/dev/random", O_RDONLY);
	if(fd == -1){
		fprintf(stderr, "Input file: %s\n", strerror(errno));
		return -1;
	}
	if(fdRandom == -1){
		fprintf(stderr, "Random file: %s\n", strerror(errno));
		return -1;
	}
	if(fileSize < BUFSIZE){
		random_write(fd, fdRandom, fileSize, 0);
		lseek(fd, 0, SEEK_SET);
		zero_write(fd, fileSize, 0);
	}
	else{
		random_write(fd, fdRandom, fileSize, 1);
		lseek(fd, 0, SEEK_SET);
		zero_write(fd, fileSize, 1);
	}
	ftruncate(fd, 0);
	if(fsync(fd) == -1){
		fprintf(stderr, "fsync: %s\n", strerror(errno));
		return -1;
	}
	close(fd);
	close(fdRandom);

	if(remove(WidgetMain->filename) == -1){
		fprintf(stderr, "Input file remove: %s\n", strerror(errno));
		return -2;
	}
		
	return 0;
}
