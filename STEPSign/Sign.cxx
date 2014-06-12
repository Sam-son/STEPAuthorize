#include <iostream>
#include <fstream>
#include <conio.h>
#include <sstream>

#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include "Sign.h"
#include "CommonFunctions.h"

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

int sign_data(EVP_PKEY *key, std::istream &data_file, const char * signature_file)
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

int new_sign_data(EVP_PKEY *key, std::istream &data_file, X509 * Certificate, const char * outfile)
{
	BIO *bio=BIO_new(BIO_s_mem());
	char data[513];
	while (!data_file.eof())
	{
		data_file.read(data, 512);
		auto data_len = data_file.gcount();
		data[data_len] = '\0';
		BIO_puts(bio, data);
	}
	PKCS7 * Signature = PKCS7_sign(Certificate, key, NULL, bio, PKCS7_DETACHED);
	FILE *out = _fsopen(outfile, "a", _SH_DENYNO);
	PEM_write_PKCS7(out, Signature);
	fclose(out);
	return EXIT_SUCCESS;
}
int Sign(bool verbose,bool newmode, char * privatekeyfile, char * certificatefile, char * datafile)
{
	initialize();
	std::string outname("signed_");
	outname.append(datafile);

	//Open Files for reading and writing.
	std::ifstream in(datafile);
	if (!in.is_open())
	{
		std::cout << "Error opening data file.\n";
		return EXIT_FAILURE;
	}
	std::ofstream outfile(outname, std::ofstream::binary);
	if (!outfile)
	{
		std::cout << "Error opening file for writing.\n";
		return EXIT_FAILURE;
	}

	//OPEN THE PRIVATE KEY
	if (verbose) std::cout << "Reading Private Key... ";

	BIO * bio = BIO_new_file(privatekeyfile, "r");
	EVP_PKEY *Private = PEM_read_bio_PrivateKey(bio, NULL, password_cb, NULL);
	if (NULL == Private)
	{
		std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
		return EXIT_FAILURE;
	}
	BIO_free(bio);

	//OPEN THE CERTIFICATE
	bio = BIO_new_file(certificatefile, "r");
	X509 *Certificate = X509_new();
	if (verbose) std::cout << "Reading Certificate...\n";
	if (NULL == PEM_read_bio_X509(bio, &Certificate, password_cb, NULL))
	{
		std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
		return EXIT_FAILURE;
	}
	BIO_free(bio);
	if (verbose)
	{
		char *buf = X509_NAME_oneline(X509_get_subject_name(Certificate), NULL, NULL);
		std::string comname(buf);
		auto comnamepos = comname.find("CN=") + 3;
		comname = comname.substr(comnamepos, comname.size() - comnamepos);
		std::cout << "Certificate Owner: " << comname << '\n';
	}
	//If everything opened OK, then we can start outputting the data. First we fill the output file with the data from input.
	if (verbose) std::cout << "Writing data to signed file...\n";
	outfile << in.rdbuf();
	if (!newmode)
	{
		if (verbose)std::cout << "Writing Signature to signed file...\n";
		outfile << "\nSIGNATURE;\n"; //print the signature designator.
		outfile.close();
	}
	in.seekg(0, in.beg);	//Reset input stream.
	//Now we take all the data in the file and put it into a stream, so that we can later use that stream in the digest function.
	std::stringstream data;
	while (!in.eof() && !in.fail())
	{
		char c = in.get();
		if (((c >= 0x20) && (c <= 0xFF)) && c != 0x7f)
		{
			data << c;
		}
	}
	//Next, we digest the stream and output a base64 encoded signature to the file.
	int rv=EXIT_FAILURE;
	if (!newmode)
	{
		rv = sign_data(Private, data, outname.data());
		if (rv == EXIT_SUCCESS)
		{
			if (verbose) std::cout << "Signature output, writing Certificate...\n";
			//If we were able to output a signature, then we append a certificate field.
			FILE * output = _fsopen(outname.data(), "a", _SH_DENYNO);
			fprintf(output, "\nCERTIFICATE;\n");
			PEM_write_X509(output, Certificate);
			fprintf(output, "ENDSEC;\n");
		}
		else std::cout << "Error Generating Signature.\n";
	}
	else
	{
		if (verbose) std::cout << "Writing signature to file...\n";
		outfile << "\nSIGNATURE;\n";
		outfile.close();
		rv = new_sign_data(Private, data, Certificate,outname.c_str());
		if (rv == EXIT_SUCCESS)
		{
			outfile.open(outname,std::ios::binary|std::ios::app);
			outfile << "ENDSEC;";
			if (verbose) std::cout << "Signature Successfully written.\n";
		}
	}
	EVP_PKEY_free(Private);
	clean_up();
	return rv;
}
