#include <iostream>
#include <fstream>

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		std::cout << "Usage: " << argv[0] << " infile.stp\n";
		return EXIT_FAILURE;
	}
	std::ifstream input(argv[1]);
	if (!input)
	{
		std::cout << "Error opening file for reading.\n";
		return EXIT_FAILURE;
	}
	std::ofstream output(std::string(argv[1]) + ".stripped");
	if (!output)
	{
		std::cout << "Error opening file for writing.\n";
		return EXIT_FAILURE;
	}
	while (!input.eof() && !input.fail())
	{
		char c = input.get();
		if (((c >= 0x20) && (c <= 0xFF)) && c != 0x7f)
		{
			output << c;
		}
	}
	if (input.fail() &&!input.eof())
	{
		std::cout << "Error reading file.\n";
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}