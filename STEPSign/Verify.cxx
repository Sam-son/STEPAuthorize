#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include "Verify.h"
#include "CommonFunctions.h"

int verify_data(std::istream& data, std::istream& sig, std::istream& cert,bool verbose)
{
	EVP_PKEY *public_key;
	BIO *bio = BIO_new(BIO_s_mem());
	cert.seekg(0, cert.end);
	int length = cert.tellg();
	cert.seekg(0, cert.beg);
	char buffer[1025];
	char * rbuf = new char[length];
	cert.read(rbuf, length);
	BIO_puts(bio, rbuf);

	X509 * Certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (Certificate == NULL)
	{
		std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
		return EXIT_FAILURE;
	}
	public_key = X509_get_pubkey(Certificate);

	int result;

	EVP_MD_CTX *ctx = EVP_MD_CTX_create();

	const EVP_MD *md = EVP_get_digestbyname("SHA256");

	if (!md) {
		std::cout <<"Error creating message digest"
			<< ERR_error_string(ERR_get_error(), NULL) << std::endl;
		return EXIT_FAILURE;
	}

	if (1 != EVP_VerifyInit_ex(ctx, md, NULL))	//TODO: Check if the hash matches a handmade one, it might not be the signature breaking...
	{
		std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
		return EXIT_FAILURE;
	}
	if (verbose)
	{
		char *buf = X509_NAME_oneline(X509_get_subject_name(Certificate), NULL, NULL);
		std::string comname(buf);
		auto comnamepos = comname.find("CN=") + 3;
		comname = comname.substr(comnamepos, comname.size() - comnamepos);
		std::cout << "Signed by: " << comname << '\n';
	}
	data.read(buffer, 1024);
	int data_len = data.gcount();
	buffer[data_len] = '\0';
	//data_len = fread(data, 1, 1024, data_file);
	while (data_len > 0) {
		if (1 != EVP_VerifyUpdate(ctx,buffer , data_len))
		{
			std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
			return EXIT_FAILURE;
		}
		data.read(buffer, 1024);
		data_len = data.gcount();
		buffer[data_len] = '\0';
	}
	BIO_free(bio);
	sig.seekg(0, sig.end);
	length = sig.tellg();
	sig.seekg(0, sig.beg);
	char*sigbuf = new char[length+1];
	sig.read(sigbuf,length);
	sigbuf[length] = '\0';
	BIO *b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	BIO_write(bio, sigbuf, length);
	bio = BIO_push(b64, bio);
	char*buf2 = new char[length + 1];
	std::vector<unsigned char> buf3;
	int inlen = 0;
	int inl=0;
	for (;;)
	{
		inl = BIO_read(bio, buf2, length);
		if (inl <= 0) break;
		for (int i = 0; i < inl; i++)
		{
			buf3.push_back(buf2[i]);
		}
	}

	result = EVP_VerifyFinal(ctx, buf3.data(), buf3.size(), public_key);
	EVP_MD_CTX_destroy(ctx);

	delete[] buf2;
	delete[] rbuf;
	delete[] sigbuf;
	return result;
}

int new_verify_data(std::istream&data, std::istream&sig, bool verbose) //Sig is a PKCS7 structure.
{
	BIO *bio = BIO_new(BIO_s_mem());
	char buffer[513];
	while (!data.eof())
	{
		data.read(buffer, 512);
		auto data_len = data.gcount();
		buffer[data_len] = '\0';
		BIO_puts(bio, buffer);
	}
	BIO *sigBIO= BIO_new(BIO_s_mem());
	while (!sig.eof())
	{
		sig.read(buffer, 512);
		auto data_len = sig.gcount();
		buffer[data_len] = '\0';
		BIO_puts(sigBIO, buffer);
	}
	PKCS7 *p7 = PEM_read_bio_PKCS7(sigBIO, NULL, NULL, NULL);
	return PKCS7_verify(p7, NULL, NULL, bio, NULL, PKCS7_NOVERIFY);
}

std::istream& safeGetline(std::istream& is, std::string& t)
{
	t.clear();

	// The characters in the stream are read one-by-one using a std::streambuf.
	// That is faster than reading them one-by-one using the std::istream.
	// Code that uses streambuf this way must be guarded by a sentry object.
	// The sentry object performs various tasks,
	// such as thread synchronization and updating the stream state.

	std::istream::sentry se(is, true);
	std::streambuf* sb = is.rdbuf();

	for (;;) {
		int c = sb->sbumpc();
		switch (c) {
		case '\n':
			return is;
		case '\r':
			if (sb->sgetc() == '\n')
				sb->sbumpc();
			return is;
		case EOF:
			// Also handle the case when the last line has no line ending
			if (t.empty())
				is.setstate(std::ios::eofbit);
			return is;
		default:
			t += (char)c;
		}
	}
}


//Given an input, breaks up the data, signature, and certificate. If newmode is set, then we skip separating out the certificate(since it's in the PKCS7 field)
int Break(bool newmode,std::istream& input, std::ostream& data,std::ostream& sig, std::ostream& cert)
{
	auto place = input.tellg();
	std::string line;
	while (!input.eof() && !input.fail())
	{
		safeGetline(input, line);
		if (line == "SIGNATURE;") break;
		data << line;
		place = input.tellg();
		safeGetline(input, line);
		if (line != "SIGNATURE;") data << std::endl;	//This prevents a trailing \n at the end of the file.
		input.seekg(place);
	}
	if (input.eof() || input.fail())
	{
		std::cout << "No Signature Found" << std::endl;
		return EXIT_FAILURE;
	}
	while (!input.eof() && !input.fail())
	{
		safeGetline(input, line);
		if (line == "ENDSEC;") break;
		sig<< line << std::endl;
	}
	if (input.eof() || input.fail())
	{
		std::cout << "Malformed Signature." << std::endl;
		return EXIT_FAILURE;
	}
	if (newmode) return EXIT_SUCCESS;
	bool readcert=false;
	while (!input.eof() && !input.fail())
	{
		safeGetline(input, line);
		if (line == "CERTIFICATE;")
		{
			readcert = true;
			safeGetline(input, line);
		}
		if (readcert == true)
		{
			cert << line;
			cert << '\n';
			if (line == "-----END CERTIFICATE-----") break;
		}
	}
	if (input.fail())
	{
		std::cout << "Malformed Signature." << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int Verify(bool verbose,bool newmode, char * signedfile)
{
	initialize();
	std::ifstream input(signedfile, std::istream::in | std::ifstream::binary);
	if (!input)
	{
		std::cout << "Error reading file." << std::endl;
		return EXIT_FAILURE;
	}
	std::stringstream data(std::ios::in | std::ios::out | std::ios::binary),
		sig(std::ios::in | std::ios::out | std::ios::binary),
		cert(std::ios::in | std::ios::out | std::ios::binary),
		stripped(std::ios::in | std::ios::out | std::ios::binary);
	if (EXIT_FAILURE == Break(newmode,input, data, sig, cert))	//if newmode is true, then cert will be empty.
		return EXIT_FAILURE;
	while (!data.eof() && !data.fail())
	{
		char c = data.get();
		if (((c >= 0x20) && (c <= 0xFF)) && c != 0x7f)
		{
			stripped << c;
		}
	}
	stripped.seekg(0, stripped.beg);
	int rv = EXIT_SUCCESS;
	if (newmode)
	{
		if (1 != new_verify_data(stripped, sig, verbose))
		{
			std::cout << "Verification Failure." << std::endl;
			rv=EXIT_FAILURE;
		}
		else std::cout << "Verified Successfully!";
	}
	else
	{
		if (1 != verify_data(stripped, sig, cert, verbose))
		{
			std::cout << "Verification Failure." << std::endl;
			rv=EXIT_FAILURE;
		}
		else std::cout << "Verified Successfully!";
	}
	clean_up();
	return rv;
}
