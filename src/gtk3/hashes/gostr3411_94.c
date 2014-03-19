#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <nettle/gosthash94.h>
#include <sys/mman.h>
#include "../polcrypt.h"
          
static void show_error(const gchar *);

void *compute_gostr(struct hashWidget_t *HashWidget){
   	if(!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(HashWidget->checkGOSTR))){
		gtk_entry_set_text(GTK_ENTRY(HashWidget->entryGOSTR), "");
		goto fine;
	}
	else if(strlen(gtk_entry_get_text(GTK_ENTRY(HashWidget->entryGOSTR))) == 32){
		goto fine;
	}

	struct stat fileStat;
	struct gosthash94_ctx ctx;
	uint8_t digest[GOSTHASH94_DIGEST_SIZE];
	gint fd, i, retVal;
	off_t fsize = 0, donesize = 0, diff = 0, offset = 0;
	gchar hash[33];
	uint8_t *fAddr;
	
	fd = open(HashWidget->filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		show_error(strerror(errno));
		return NULL;
	}
  	if(fstat(fd, &fileStat) < 0){
  		fprintf(stderr, "compute_gosthash94: %s\n", strerror(errno));
    	close(fd);
    	return NULL;
  	}
  	fsize = fileStat.st_size;
       
	gosthash94_init(&ctx);

	if(fsize < BUF_FILE){
		fAddr = mmap(NULL, fsize, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if(fAddr == MAP_FAILED){
			show_error(strerror(errno));
			return NULL;
		}
		gosthash94_update(&ctx, fsize, fAddr);
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
			show_error(strerror(errno));
			return NULL;
		}
		gosthash94_update(&ctx, BUF_FILE, fAddr);
		donesize+=BUF_FILE;
		diff=fsize-donesize;
		offset += BUF_FILE;
		if(diff < BUF_FILE && diff > 0){
			fAddr = mmap(NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if(fAddr == MAP_FAILED){
				show_error(strerror(errno));
				return NULL;
			}
			gosthash94_update(&ctx, diff, fAddr);
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
	gosthash94_digest(&ctx, GOSTHASH94_DIGEST_SIZE, digest);
 	for(i=0; i<16; i++){
 		sprintf(hash+(i*2), "%02x", digest[i]);
 	}
 	hash[32] = '\0';
 	gtk_entry_set_text(GTK_ENTRY(HashWidget->entryGOSTR), hash);
 	
	close(fd);
	fine:
	return NULL;
}

static void show_error(const gchar *message){
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new(NULL,
            GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_ERROR,
            GTK_BUTTONS_OK,
            "%s", message);
	gtk_window_set_title(GTK_WINDOW(dialog), "Error");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}
