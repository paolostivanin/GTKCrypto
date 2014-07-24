void *encrypt_file_gui(struct widget_t *WidgetMain){

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
