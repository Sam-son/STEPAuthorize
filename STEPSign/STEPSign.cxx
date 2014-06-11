#include <iostream>
#include <fstream>
#include <conio.h>
#include <sstream>

#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#pragma comment(lib,"libeay32.lib")
#pragma comment(lib,"Crypt32.lib")

int password_cb(char *buf, int size, int rwflag, void *userdata)
{
	std::cout << "Password?: ";
	std::cout.flush();
	std::string pwd;
	int i = 0;
	do
	{
		char a = _getch();
		if ('\b' == a && i>0)	//Support for backspaces
		{
			pwd.pop_back();
			i--;
		}
		else
		{
			pwd.push_back(a);
			i++;
		}
	} while (pwd.back() != 13 && i < 512);	//13 is 'return' key code

	//	std::cin >> pwd;
	std::cout << std::endl;
	pwd.pop_back();
	strncpy_s(buf, size, pwd.c_str(), pwd.size());
	return pwd.size();
}

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

	ENGINE_cleanup();
	EVP_cleanup();

	CONF_modules_finish();
	CONF_modules_free();
	CONF_modules_unload(1);

	CRYPTO_cleanup_all_ex_data();
}


int sign_data(EVP_PKEY *key,std::istream &data_file,char * signature_file)
{
	char *data;
	int data_len;

	unsigned char *sig;
	unsigned int sig_len;

	int rv;

	EVP_MD_CTX *ctx = EVP_MD_CTX_create();

	sig = (unsigned char*)malloc(EVP_PKEY_size(key));
	sig_len = EVP_PKEY_size(key);

	rv = EVP_SignInit_ex(ctx, EVP_sha256(), NULL);
	if (1 != EVP_SignInit_ex(ctx, EVP_sha256(), NULL))
	{
		std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
		return EXIT_FAILURE;
	}
	
	data = (char*)malloc(1024);
	data_file.read(data, 1024);
	data_len = data_file.gcount();
	//data_len = fread(data, 1, 1024, data_file);
	while (data_len > 0) {
		if (1 != EVP_SignUpdate(ctx, data, data_len))
		{
			std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
			return EXIT_FAILURE;
		}
		data_file.read(data, 1024);
		data_len = data_file.gcount();
	}

	if (1 != EVP_SignFinal(ctx, sig, &sig_len, key))
	{
		std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
		return EXIT_FAILURE;
	}
	
	FILE * out = _fsopen(signature_file, "a", _SH_DENYNO);
	if (NULL == out)
	{
		return EXIT_FAILURE;
	}
	BIO *bio, *b64;						//Initialize some BIO stuff so we can output the information in base64 encoding 
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(out, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_write(bio, sig, sig_len);
	BIO_flush(bio);
	BIO_free(bio);
	fprintf(out, "ENDSEC;\n");
	fclose(out);

	EVP_MD_CTX_destroy(ctx);
	free(sig);
	free(data);
	return EXIT_SUCCESS;
}


int main(int argc, char **argv)
{
	if (argc < 4) {
		std::cout <<"Usage: " <<argv[0] <<" <data file> <key file> <signature file>\n";
		exit(1);
	}

	initialize();

	std::ifstream in(argv[1]);
	if (!in.is_open())
	{
		std::cout << "Error opening data file.\n";
		return EXIT_FAILURE;
	}
	BIO * bio = BIO_new_file(argv[2], "r");
	EVP_PKEY *Private = PEM_read_bio_PrivateKey(bio, NULL, password_cb, NULL);
	if (NULL == Private)
	{
		std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
		return EXIT_FAILURE;
	}
	BIO_free(bio);

/*	EVP_PKEY * Private = EVP_PKEY_new();
	if (1 != EVP_PKEY_set1_RSA(Private, PKEY))
	{
		std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
		return EXIT_FAILURE;
	}
	*/
	std::ofstream outfile(argv[3]);
	if (!outfile)
	{
		std::cout << "Error opening file for writing.\n";
		return EXIT_FAILURE;
	}
	outfile << in.rdbuf();	//put all of the input into output.
	outfile << "\nSIGNATURE;\n"; //print the signature designator.
	outfile.close();
	in.seekg(0, in.beg);	//Reset input stream.
	std::stringstream data;
	while (!in.eof() && !in.fail())
	{
		char c = in.get();
		if (((c >= 0x20) && (c <= 0xFF)) && c != 0x7f)
		{
			data << c;
		}
	}
	int rv=sign_data(Private, data,argv[3]);
	EVP_PKEY_free(Private);
	clean_up();

	return rv;
}