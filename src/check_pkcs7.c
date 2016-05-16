#include <glib.h>

gint
check_pkcs7 (guchar *dec_buf, guchar *hex_buf) {
	gint i, j, k, ok=0;
	for (j = 0; j < 16; j++) {
		for (i = 0; i < 15; i++) {
			if (dec_buf[j] == hex_buf[i]) {
				for (k = 15; k >= j; k--) {
					if (dec_buf[k] == hex_buf[i])
						ok += 1;
				}
				if (ok != (16-j))
					ok = 0;
				else
					return 16 - ok;
			}
		}
	}
}
