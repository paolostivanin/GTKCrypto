void *decrypt_file_gui(struct widget_t *WidgetMain){

	if(fseek(fp, 0, SEEK_SET) == -1){
		g_print("decrypt_file: %s\n", strerror(errno));
		gcry_free(inputKey);
		return;
	}

	retval = fread(&Metadata, sizeof(struct metadata_t), 1, fp);
	if(retval != 1){
		g_print(_("decrypt_file: cannot read file metadata_t\n"));
		gcry_free(inputKey);
		return;
	}
	
	if(Metadata.algo_type == 0){
		algo = gcry_cipher_map_name("aes256");
	}
	else if(Metadata.algo_type == 1){
		algo = gcry_cipher_map_name("serpent256");
	}
	else if(Metadata.algo_type == 2){
		algo = gcry_cipher_map_name("twofish");
		
	}
	else if(Metadata.algo_type == 3){
		algo = gcry_cipher_map_name("camellia256");
	}
	if(Metadata.algo_mode == 1){
		mode = GCRY_CIPHER_MODE_CBC;
	}
	else{
		mode = GCRY_CIPHER_MODE_CTR;
	}

	number_of_block = (fsize - sizeof(struct metadata_t) - 64)/16;
	bytes_before_mac = fsize-64;

	gcry_cipher_open(&hd, algo, mode, 0);
	
	if((derived_key = gcry_malloc_secure(64)) == NULL){
		g_print(_("decrypt_file: gcry_malloc_secure failed (derived)\n"));
		gcry_free(inputKey);
		return;
	}
	
	if((crypto_key = gcry_malloc_secure(32)) == NULL){
		g_print(_("decrypt_file: gcry_malloc_secure failed (crypto)\n"));
		gcry_free(inputKey);
		gcry_free(derived_key);
		return;
	}
	
	if((mac_key = gcry_malloc_secure(32)) == NULL){
		g_print(_("decrypt_file: gcry_malloc_secure failed (mac)\n"));
		gcry_free(crypto_key);
		gcry_free(inputKey);
		gcry_free(derived_key);
		return;
	}

	tryAgainDerive:
	if(gcry_kdf_derive (inputKey, pwd_len+1, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, Metadata.salt, 32, 150000, 64, derived_key) != 0){
		if(counterForGoto == 3){
			g_print(_("decrypt_file: Key derivation error\n"));
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

	if((current_file_offset = ftell(fp)) == -1){
		g_print("decrypt_file: %s\n", strerror(errno));
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return;		
	}
	if(fseek(fp, bytes_before_mac, SEEK_SET) == -1){
		g_print("decrypt_file: %s\n", strerror(errno));
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return;		
	}
	if(fread(mac_of_file, 1, 64, fp) != 64){
		g_print(_("decrypt_file: fread mac error\n"));;
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return;
	}
	guchar *hmac = calculate_hmac(filename, mac_key, keyLength, 1);
	if(hmac == (guchar *)1){
		g_print(_("Error during HMAC calculation\n"));
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return;
	}
	if(memcmp(mac_of_file, hmac, 64) != 0){
		send_notification("PolCrypt", "HMAC doesn't match. This is caused by\n1) wrong password\nor\n2) corrupted file\n");
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		g_free(filename);
		g_free(outFilename);
		return;
	}
	free(hmac);
	if(fseek(fp, current_file_offset, SEEK_SET) == -1){
		g_print("decrypt_file: %s\n", strerror(errno));
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return;		
	}

	fpout = fopen(outFilename, "w");
	if(fpout == NULL){
		g_print("%s\n", strerror(errno));
		gcry_free(derived_key);
		gcry_free(crypto_key);
		gcry_free(mac_key);
		gcry_free(inputKey);
		return;
	}

	if(mode == GCRY_CIPHER_MODE_CBC){
		while(number_of_block > block_done){
			memset(cipher_text, 0, sizeof(cipher_text));
			retval = fread(cipher_text, 1, 16, fp);
			gcry_cipher_decrypt(hd, decBuffer, retval, cipher_text, retval);
			if(block_done == (number_of_block-1)){
				number_of_pkcs7_byte = check_pkcs7(decBuffer, hex);
				fwrite(decBuffer, 1, number_of_pkcs7_byte, fpout);	
				goto end;
			}
			fwrite(decBuffer, 1, retval, fpout);
			block_done++;
		}
	}
	else{
		while(realSize > doneSize){
			memset(cipher_text, 0, sizeof(cipher_text));
			if(realSize-doneSize < 16){
				retval = fread(cipher_text, 1, realSize-doneSize, fp);
				gcry_cipher_decrypt(hd, decBuffer, retval, cipher_text, retval);
				fwrite(decBuffer, 1, retval, fpout);
				break;
			}
			else{
				retval = fread(cipher_text, 1, 16, fp);
				gcry_cipher_decrypt(hd, decBuffer, retval, cipher_text, retval);
				fwrite(decBuffer, 1, retval, fpout);
				doneSize += retval;
			}
		}
	}
	
	end:
	
	gcry_cipher_close(hd);
	gcry_free(inputKey);
	gcry_free(derived_key);
	gcry_free(crypto_key);
	gcry_free(mac_key);
	gcry_free(decBuffer);
	g_free(outFilename);
	g_free(filename);
	
	fclose(fp);
	fclose(fpout);
	
	send_notification("PolCrypt", "Decryption successfully done");
}
