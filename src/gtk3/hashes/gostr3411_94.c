#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
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
  
	gint algo, i, fd, retVal;
	gchar gostrhash[33];
	struct stat fileStat;
	gchar *fAddr;
	const gchar *name = gcry_md_algo_name(GCRY_MD_GOSTR3411_94);
	algo = gcry_md_map_name(name);
	off_t fsize = 0, donesize = 0, diff = 0, offset = 0;

	fd = open(HashWidget->filename, O_RDONLY | O_NOFOLLOW);
	if(fd == -1){
		show_error(strerror(errno));
		return NULL;
	}
  	if(fstat(fd, &fileStat) < 0){
  		fprintf(stderr, "compute_gostr: %s\n", strerror(errno));
    	close(fd);
    	return NULL;
  	}
  	fsize = fileStat.st_size;
  	
	gcry_md_hd_t hd;
	gcry_md_open(&hd, algo, 0);
	if(fsize < BUF_FILE){
		fAddr = mmap(NULL, fsize, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
		if(fAddr == MAP_FAILED){
			fprintf(stderr, "compute_gostr: %s\n", strerror(errno));
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
			fprintf(stderr, "compute_gostr: %s\n", strerror(errno));
			return NULL;
		}
		gcry_md_write(hd, fAddr, BUF_FILE);
		donesize+=BUF_FILE;
		diff=fsize-donesize;
		offset += BUF_FILE;
		if(diff < BUF_FILE && diff > 0){
			fAddr = mmap(NULL, diff, PROT_READ, MAP_FILE | MAP_SHARED, fd, offset);
			if(fAddr == MAP_FAILED){
				fprintf(stderr, "compute_gostr: %s\n", strerror(errno));
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
	guchar *gostr = gcry_md_read(hd, algo);
 	for(i=0; i<16; i++){
 		sprintf(gostrhash+(i*2), "%02x", gostr[i]);
 	}
 	gostrhash[32] = '\0';
 	gtk_entry_set_text(GTK_ENTRY(HashWidget->entryGOSTR), gostrhash);
	gcry_md_close(hd);
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
