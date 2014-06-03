#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		std::cout << "stepbreak.exe input.stp\n";
		return EXIT_FAILURE;
	}
	std::ifstream input(argv[1]);
	if (!input)
	{
		std::cout << "Error reading file.\n";
		return EXIT_FAILURE;
	}
	std::string line,fname(argv[1]);
	fname.append(".tmp");
	std::ofstream tempout(fname);
	fname.clear();
	if (!tempout)
	{
		std::cout << "error opening temporary file for writing.\n";
		return EXIT_FAILURE;
	}
	int place = 0;
	while (!input.eof() && !input.fail())
	{
		getline(input, line);
		if (line == "SIGNATURE;") break;
		tempout << line;
		place=input.tellg();
		getline(input, line);
		if (line != "SIGNATURE;") tempout << std::endl;	//This prevents a trailing \n at the end of the file.
		input.seekg(place);
	}
	if (input.eof())
	{
		std::cout << "No Signature Found\n";
		return EXIT_FAILURE;
	}
	fname.append(argv[1]);
	fname.append(".signature");
	std::ofstream outsig(fname);
	if (!outsig)
	{
		std::cout << "Error opening signature output\n";
		return EXIT_FAILURE;
	}
	while (!input.eof() && !input.fail())
	{
		getline(input, line);
		if (line == "ENDSEC;") break;
		outsig << line <<std::endl;
	}
	if (input.eof())
	{
		std::cout << "Malformed Signature\n";
		return EXIT_FAILURE;
	}
	bool readpub = false;
	fname.clear();
	fname.append(argv[1]);
	fname.append(".pub");
	std::ofstream outpub(fname);
	if (!outpub)
	{
		std::cout << "Error opening public key for writing\n";
		return EXIT_FAILURE;
	}
	while (!input.eof() && !input.fail())
	{
		getline(input, line);
		if (line == "PUBLIC KEY;")
		{
			readpub = true;
			getline(input, line);
		}
		if (readpub == true)
		{
			if (line == "ENDSEC;") break;
			outpub << line;
			outpub << '\n';
		}
	}
	if (input.eof())
	{
		std::cout << "Malformed Signature\n";
		return EXIT_FAILURE;
	}
	bool readcert = false;
	fname.clear();
	fname.append(argv[1]);
	fname.append(".cert");
	std::ofstream outcert(fname);
	if (!outcert)
	{
		std::cout << "Error opening certificate for writing\n";
		return EXIT_FAILURE;
	}
	while (!input.eof() && !input.fail())
	{
		getline(input, line);
		if (line == "CERTIFICATE;")
		{
			readcert = true;
			getline(input, line);
		}
		if (readcert == true)
		{
			outcert << line;
			outcert <<'\n';
			if (line == "-----END CERTIFICATE-----") break;
		}
	}
	if (input.eof())
	{
		std::cout << "Malformed Signature\n";
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}