#include <iostream>
#include <fstream>
#include <string>

std::istream& safeGetline(std::istream& is, std::string& t);

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		std::cout << "stepbreak.exe input.stp" <<std::endl;
		return EXIT_FAILURE;
	}
	std::ifstream input(argv[1], std::ios::in | std::ios::binary);
	if (!input)
	{
		std::cout << "Error reading file." <<std::endl;
		return EXIT_FAILURE;
	}
	std::string line,fname(argv[1]);
	fname.append(".tmp");
	std::ofstream tempout(fname);
	fname.clear();
	if (!tempout)
	{
		std::cout << "error opening temporary file for writing." <<std::endl;
		return EXIT_FAILURE;
	}
	auto place = input.tellg();
	while (!input.eof() && !input.fail())
	{
		safeGetline(input, line);
		if (line == "SIGNATURE;") break;
		tempout << line;
		place=input.tellg();
		safeGetline(input, line);
		if (line != "SIGNATURE;") tempout << std::endl;	//This prevents a trailing \n at the end of the file.
		input.seekg(place);
	}
	if (input.eof() ||input.fail())
	{
		std::cout << "No Signature Found" <<std::endl;
		return EXIT_FAILURE;
	}
	fname.append(argv[1]);
	fname.append(".signature");
	std::ofstream outsig(fname);
	if (outsig.is_open()==NULL)
	{
		std::cout << "Error opening signature output." <<std::endl;
		return EXIT_FAILURE;
	}
	while (!input.eof() && !input.fail())
	{
		safeGetline(input, line);
		if (line == "ENDSEC;") break;
		outsig << line <<std::endl;
	}
	if (input.eof() || input.fail())
	{
		std::cout << "Malformed Signature." <<std::endl;
		return EXIT_FAILURE;
	}
	bool readpub = false;
	fname.clear();
	fname.append(argv[1]);
	fname.append(".pub");
	std::ofstream outpub(fname);
	if (!outpub)
	{
		std::cout << "Error opening public key for writing" <<std::endl;
		return EXIT_FAILURE;
	}
	bool readcert = false;
	fname.clear();
	fname.append(argv[1]);
	fname.append(".cert");
	std::ofstream outcert(fname);
	if (!outcert)
	{
		std::cout << "Error opening certificate for writing." <<std::endl;
		return EXIT_FAILURE;
	}

	while (!input.eof() && !input.fail())
	{
		safeGetline(input, line);
		if (line == "PUBLIC KEY;")
		{
			readpub = true;
			safeGetline(input, line);
		}
		if (readpub == true)
		{
			if (line == "ENDSEC;") break;
			outpub << line;
			outpub << '\n';
		}
		if (line == "CERTIFICATE;") goto cert;	//Horrible hack. If there's no public key we skip it.
	}
	if (input.eof() || input.fail())
	{
		std::cout << "Malformed Signature." <<std::endl;
		return EXIT_FAILURE;
	}

	while (!input.eof() && !input.fail())
	{
		safeGetline(input, line);
		if (line == "CERTIFICATE;")
		{
			cert:
			readcert = true;
			safeGetline(input, line);
		}
		if (readcert == true)
		{
			outcert << line;
			outcert <<'\n';
			if (line == "-----END CERTIFICATE-----") break;
		}
	}
	if (input.fail())
	{
		std::cout << "Malformed Signature." <<std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
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