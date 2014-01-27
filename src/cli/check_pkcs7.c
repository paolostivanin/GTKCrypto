#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "polcrypt.h"

int check_pkcs7(unsigned char *deBuf, unsigned char *hexBuf){
	int i,j,k, ok=0;
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
