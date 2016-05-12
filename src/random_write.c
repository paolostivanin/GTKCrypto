#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <errno.h>
#include "gtkcrypto.h"

gint random_write(gint file, gint random_fd, gsize file_size, gint isBigger) {
    if (isBigger == 0) {
        guchar buf_rand[file_size];
        if (read(random_fd, buf_rand, sizeof(buf_rand)) == -1)
            g_printerr("random_write read: %s\n", g_strerror(errno));

        if (write(file, buf_rand, sizeof(buf_rand)) == -1)
            g_printerr("random_write write: %s\n", g_strerror(errno));

        if (fsync(file) == -1)
            g_printerr("random write fsync: %s\n", g_strerror(errno));

        return 0;
    }
    else {
        guchar random_bytes[BUFSIZE];
        gssize done_size = 0, writeBytes = 0;
        if (read(random_fd, random_bytes, sizeof(random_bytes)) == -1)
            g_printerr("random_write read: %s\n", g_strerror(errno));

        while (file_size > done_size) {
            writeBytes = write(file, random_bytes, sizeof(random_bytes));
            done_size += writeBytes;
            if ((file_size - done_size) > 0 && (file_size - done_size) < BUFSIZE) {
                if (read(random_fd, random_bytes, sizeof(random_bytes)) == -1)
                    g_printerr("random_write read: %s\n", g_strerror(errno));

                if (write(file, random_bytes, (file_size - done_size)) == -1)
                    g_printerr("random_write read: %s\n", g_strerror(errno));

                if (fsync(file) == -1)
                    g_printerr("random_write fsync: %s\n", g_strerror(errno));

                break;
            }
        }
        return 0;
    }
}
