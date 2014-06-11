#include "CommonFunctions.h"

void initialize()
{
	OPENSSL_config(NULL);
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
}

void clean_up()
{
	ERR_remove_state(0);
	ERR_free_strings();

	EVP_cleanup();

	CONF_modules_finish();
	CONF_modules_free();
	CONF_modules_unload(1);

	CRYPTO_cleanup_all_ex_data();
}