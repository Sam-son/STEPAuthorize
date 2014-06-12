#include <iostream>
#include <string>

#include "Sign.h"
#include "Verify.h"

int main(int argc, char **argv)
{
	if (argc < 2)
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
		return EXIT_FAILURE;
	}
	int rv = -1;
	bool verbose = false;
	if (mode == "SIGN" || mode == "sign")
	{
		bool newmode = false;
		if (argc>4)
		{
			for (int i = 4; i < argc; i++)
			{
				if (std::string(argv[i]) == "-v") verbose = true;
				if (std::string(argv[i]) == "-new") newmode = true;
			}
		}
		rv = Sign(verbose, newmode,argv[3], argv[4], argv[2]);
	}
	if (mode == "VERIFY" || mode == "verify")
	{
		bool newmode = false;
		if (argc > 3)
		{
			for (int i = 3; i < argc; i++)
			{
				if (std::string(argv[i]) == "-v") verbose = true;
				if (std::string(argv[i]) == "-new") newmode= true;
			}
		}
		rv = Verify(verbose, newmode,argv[2]);
	}
	return rv;
}