#include <iostream>
#include <string>

#include "Sign.h"





int Verify(bool verbose, char * signedfile)
{
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	if (argc < 1)
	{
		std::cout << "Usage: " << argv[0] << "[Sign,Verify]" << std::endl;
		return EXIT_FAILURE;
	}
	std::string mode(argv[1]);
	if ((mode == "SIGN" || mode == "sign") && argc<5)
	{
		std::cout <<"Usage: " <<argv[0] <<" SIGN <data file> <private key file> <certificate file> [-v]" <<std::endl;
		return EXIT_FAILURE;
	}
	if ((mode == "VERIFY" || mode == "verify") && argc<3)
	{
		std::cout << "Usage: " << argv[0] << " VERIFY <signed file> [-v]" << std::endl;
	}
	int rv = -1;
	bool verbose = false;
	if (mode == "SIGN" || mode == "sign")
	{
		if (argc>4)
		{
			if (std::string(argv[4]) == "-v") verbose = true;
		}
		rv = Sign(verbose, argv[3], argv[4], argv[2]);
	}
	if (mode == "VERIFY" || mode == "verify")
	{
		if (argc > 3)
		{
			if (std::string(argv[3]) == "-v") verbose = true;
		}
		rv = Verify(verbose, argv[2]);
	}
	return rv;
}