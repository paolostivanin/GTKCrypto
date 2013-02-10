#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "polcrypt.h"

int check_pkcs7(unsigned char *deBuf, unsigned char *hexBuf){
	int i,j,k, ok=0;
	for(j=0; j<16; j++){
		for(i=0; i<15; i++){ // Ciclo annidato: debuf[0] -> tutti gli hexbuf, debuf[1] -> tutti gli hexbuf e così via
			if(deBuf[j] == hexBuf[i]){ // Se debuf[5] == hexbuf[8]...
				for(k=15; k>=j; k--){ // ...allora controllo le posizioni di debuf dalla 15 alla 8 (incluse)...
					if(deBuf[k] == hexBuf[i]){ //...e se corrispondono aumento il contatore ok di 1...
						ok+=1;
					}
				}
				if(ok != (16-j)) ok = 0; /* Ora devo controllare che siano state visitate tutte le posizioni. Esempio: il carattere terminatore
				è visto come 10 in hex quindi potrei avere un falso positivo (debuf[5] == 10) quindi devo controllare se ok è uguale o meno a 16-j.
				Infatti se è uguale a 16-j allora ho trovato quanti bytes di padding ci sono, altrimenti devo azzerare il contatore o al prossimo giro
				avrei un valore errato. */
				else return 16-ok;
			}
		}
	}
	return -1;
}