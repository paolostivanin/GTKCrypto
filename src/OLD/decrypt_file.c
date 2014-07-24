void *decrypt_file_gui(struct widget_t *WidgetMain){

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
