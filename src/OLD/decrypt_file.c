void *decrypt_file_gui(struct widget_t *WidgetMain){

	number_of_block = (fsize - sizeof(struct metadata_t) - 64)/16;
	bytes_before_mac = fsize-64;
		
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
