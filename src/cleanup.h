#pragma once

void crypto_keys_cleanup    (CryptoKeys *encryption_keys);

void gfile_cleanup          (GFile *ifile,
                             GFile *ofile);

void gstream_cleanup        (GFileInputStream  *istream,
                             GFileOutputStream *ostream);

void data_cleanup           (gpointer data1,
                             gpointer data2,
                             gpointer data3);