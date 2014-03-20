#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "polcrypt.h"

gint check_pkcs7(guchar *deBuf, guchar *hexBuf){
	gint i,j,k, ok=0;
	for(j=0; j<16; j++){
		for(i=0; i<15; i++){
			if(deBuf[j] == hexBuf[i]){
				for(k=15; k>=j; k--){
					if(deBuf[k] == hexBuf[i]){
						ok+=1;
					}
				}
				if(ok != (16-j)) ok = 0;
				else return 16-ok;
			}
		}
	}
}
