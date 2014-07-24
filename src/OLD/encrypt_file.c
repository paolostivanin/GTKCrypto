void *encrypt_file_gui(struct widget_t *WidgetMain){

	gcry_cipher_open(&hd, algo, mode, 0);
	
	if((derived_key = gcry_malloc_secure(64)) == NULL){
		g_print(_("encrypt_file: gcry_malloc_secure failed (derived)\n"));
		gcry_free(inputKey);
		return;
	}
	
	if((crypto_key = gcry_malloc_secure(32)) == NULL){
		g_print(_("encrypt_file: gcry_malloc_secure failed (crypto)\n"));
		gcry_free(inputKey);
		gcry_free(derived_key);
		return;
	}
	
	if((mac_key = gcry_malloc_secure(32)) == NULL){
		g_print(_("encrypt_file: gcry_malloc_secure failed (mac)\n"));
		gcry_free(crypto_key);
		gcry_free(inputKey);
		gcry_free(derived_key);
		return;
	}

	tryAgainDerive:
	if(gcry_kdf_derive (inputKey, len+1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, Metadata.salt, 32, 150000, 64, derived_key) != 0){
		if(counterForGoto == 3){
			g_print(_("encrypt_file: Key derivation error\n"));
			gcry_free(derived_key);
			gcry_free(crypto_key);
			gcry_free(mac_key);
			gcry_free(inputKey);
			return;
		}
		counterForGoto += 1;
		goto tryAgainDerive;
	}
	memcpy(crypto_key, derived_key, 32);
	memcpy(mac_key, derived_key + 32, 32);

	gcry_cipher_setkey(hd, crypto_key, keyLength);
	if(mode == GCRY_CIPHER_MODE_CBC)
		gcry_cipher_setiv(hd, Metadata.iv, blkLength);
	else
		gcry_cipher_setctr(hd, Metadata.iv, blkLength);
	

	fseek(fp, 0, SEEK_SET);

	fwrite(&Metadata, sizeof(struct metadata_t), 1, fpout);

	if(mode == GCRY_CIPHER_MODE_CBC){
		while(number_of_block > block_done){
			memset(plain_text, 0, sizeof(plain_text));
			retval = fread(plain_text, 1, 16, fp);
			if(retval < 16){
				for(i=retval; i<16; i++){
					if(retval == 1) plain_text[i] = hex[14];
					if(retval == 2) plain_text[i] = hex[13];
					if(retval == 3) plain_text[i] = hex[12];
					if(retval == 4) plain_text[i] = hex[11];
					if(retval == 5) plain_text[i] = hex[10];
					if(retval == 6) plain_text[i] = hex[9];
					if(retval == 7) plain_text[i] = hex[8];
					if(retval == 8) plain_text[i] = hex[7];
					if(retval == 9) plain_text[i] = hex[6];
					if(retval == 10) plain_text[i] = hex[5];
					if(retval == 11) plain_text[i] = hex[4];
					if(retval == 12) plain_text[i] = hex[3];
					if(retval == 13) plain_text[i] = hex[2];
					if(retval == 14) plain_text[i] = hex[1];
					if(retval == 15) plain_text[i] = hex[0];
				}
			}
			gcry_cipher_encrypt(hd, encBuffer, txtLenght, plain_text, txtLenght);
			fwrite(encBuffer, 1, txtLenght, fpout);
		}
		block_done++;
	}
	else{
		while(fsize > doneSize){
			memset(plain_text, 0, sizeof(plain_text));
			retval = fread(plain_text, 1, 16, fp);
			gcry_cipher_encrypt(hd, encBuffer, retval, plain_text, retval);
			fwrite(encBuffer, 1, retval, fpout);
			doneSize += retval;
		}
	}
	fclose(fpout);
	fclose(fp);

	guchar *hmac = calculate_hmac(outFilename, mac_key, keyLength, 0);
	if(hmac == (guchar *)1){
		g_print(_("Error during HMAC calculation"));
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return;
	}
	fpout = fopen(outFilename, "a");
	fwrite(hmac, 1, 64, fpout);
	free(hmac);
	
	retcode = delete_input_file(filename, fsize);
	if(retcode == -1)
		g_print(_("Secure file deletion failed, overwrite it manually"));
	if(retcode == -2)
		g_print(_("File unlink failed, remove it manually"));
		
	gcry_cipher_close(hd);
	gcry_free(derived_key);
	gcry_free(crypto_key);
	gcry_free(mac_key);
	gcry_free(encBuffer);
	gcry_free(inputKey);
	
	g_free(filename);
	g_free(outFilename);
	
	fclose(fpout);
	
	send_notification("PolCrypt", "Encryption successfully done");
}
