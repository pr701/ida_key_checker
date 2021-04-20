/*
* IDA key checker/dumper
*/

#include <cstdint>
#include <cstdio>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>

#ifdef WIN32
#include <Windows.h>
#include <tchar.h>
#endif

#if defined(WIN32) && defined(UNICODE)
#define file_path(x)	get_file_path(x)	
#else
#define file_path(x)	x
#endif

#include "ida_key.hpp"
#include "ida_rsa_patches.h"

#include <cxxopts.hpp>

using namespace ida;

bool write_file(const path& path, const uint8_t* data, size_t size)
{
	std::ofstream file(path, std::ios::binary);
	if (file)
	{
		file.write(reinterpret_cast<const char*>(data), size);
		file.close();
		return true;
	}
	return false;
}

// Check key file
int check_key_file(path ida_key_file, path signature_file = "")
{
	if (!exists(ida_key_file))
	{
		cout << "File not found: " << ida_key_file << endl;
		return 2;
	}

	cout << endl << "Key file: " << ida_key_file << endl;

	key_t key;
	if (!parse_key(ida_key_file, key))
	{
		cout << "Invalid or legacy license." << endl;
		return 3;
	}

	bool is_sign_decrypted = false;
	bool is_pirated = true;
	bool is_valid_md5 = false;

	license_t license;

	if (decrypt_signature(key.signature, license))
	{
		is_sign_decrypted = true;
		is_pirated = false;
	}
	else
	{
		// check pirated versions
		for (const auto& mod : k_patch_mods)
			if (decrypt_signature(key.signature, license, mod))
			{
				is_sign_decrypted = true;
				break;
			}
	}

	cout << "Pirated Key:" << '\t' << is_pirated << endl;
	if (is_sign_decrypted)
	{
		is_valid_md5 = !memcmp(key.md5, license.md5, MD5_SIZE) ? true : false;

		if (is_pirated) cout << "Patched RSA:" << '\t' << 1 << endl;
		cout << "MD5 is valid:" << '\t' << is_valid_md5 << endl;
	}

	cout << endl << "Key:" << endl;
	print_key(key);

	if (is_sign_decrypted)
	{
		cout << endl << "Signature:" << endl;
		print_license(license);
	}

	if (!signature_file.empty())
	{
		signature_file.replace_extension("bin");

		cout << endl << "Save signature to: " << signature_file << endl;
		if (!write_file(signature_file, key.signature, sizeof(signature_t)))
			cout << "Error: access fail" << endl;
		else
			cout << "Signature saved" << endl;

		if (is_sign_decrypted)
		{
			signature_file.replace_extension("decrypted");

			cout << endl << "Save decrypted signature to: " << signature_file << endl;
			if (!write_file(signature_file, reinterpret_cast<uint8_t*>(&license), sizeof(license_t)))
				cout << "Error: access fail" << endl;
			else
				cout << "Decrypted signature saved" << endl;
		}
	}
	return 0;
}

// Check binary signature
int check_signature(path bin_file, path decrypted_file = "")
{
	license_t license;
	signature_t signature;
	memset(&signature, 0, sizeof(signature_t));

	ifstream file(bin_file, ios::binary);
	if (!file.is_open())
	{
		cout << "Access error to file: " << bin_file << endl;
		return 2;
	}
	
	file.seekg(0, ios::end);
	size_t size = file.tellg();
	file.seekg(0, ios::beg);

	if (size)
	{
		file.read(reinterpret_cast<char*>(&signature),
			size < sizeof(signature_t) ? size : sizeof(signature_t));
	}
	file.close();

	bool is_sign_decrypted = false;
	bool is_pirated = true;

	if (decrypt_signature(signature, license))
	{
		is_sign_decrypted = true;
		is_pirated = false;
	}
	else
	{
		// check pirated versions
		for (const auto& mod : k_patch_mods)
			if (decrypt_signature(signature, license, mod))
			{
				is_sign_decrypted = true;
				break;
			}
	}

	cout << endl << "Signature block: " << bin_file << endl;

	if (!is_sign_decrypted)
	{
		cout << "Incorrect block or unknown key" << endl;
		return 2;
	}

	cout << "Is Pirated:" << '\t' << is_pirated << endl;
	print_license(license);

	if (!decrypted_file.empty())
	{
		cout << endl << "Save decrypted signature to: " << decrypted_file << endl;
		if (!write_file(decrypted_file, reinterpret_cast<uint8_t*>(&license), sizeof(license_t)))
			cout << "Error: access fail" << endl;
		else
			cout << "Decrypted signature saved" << endl;
	}
	return 0;
}

#if defined(WIN32) && defined(UNICODE)
path get_file_path(const string& filepath)
{
	wstring unicode;
	int count = MultiByteToWideChar(CP_UTF8, 0, filepath.c_str(), filepath.length(), nullptr, 0);
	if (count)
	{
		unicode.resize(count + 1);
		count = MultiByteToWideChar(CP_UTF8, 0, filepath.c_str(), filepath.length(), unicode.data(), count);
		if (count) unicode.resize(count);
	}
	return path(unicode);
}
#endif

#ifdef UNICODE
int _tmain(int argc, TCHAR* argv[])
#else
int main(int argc, char* argv[])
#endif
{
	cxxopts::Options options("ida_key_checker", "Check IDA Pro key or signature");

	string file_input;
	string file_output;
	string file_type;

	options.add_options()
		("i,input", "input file", cxxopts::value<std::string>(file_input)->default_value("ida.key"))
		("o,output", "output encrypted signature block filename", cxxopts::value<std::string>(file_output))
		("t,type", "type of file (key, bin or idb)", cxxopts::value<std::string>(file_type)->default_value("key"))
		("help", "print help");

	cxxopts::ParseResult result;
	try
	{
		result = options.parse(argc, argv);
	}
	catch (cxxopts::OptionParseException e)
	{
		cout << options.help() << endl;
		return 1;
	}

	if (!result.arguments().size() || result.count("help"))
	{
		cout << options.help() << std::endl;
		return 1;
	}
	
	path input(file_path(file_input));
	path output;

	if (result.count("output"))
		output = file_path(result["output"].as<std::string>());

	if (!file_type.compare("key"))
	{
		return check_key_file(input, output);
	}
	else if (!file_type.compare("bin"))
	{
		// only signature data
		return check_signature(input, output);
	}
	else if (!file_type.compare("idb"))
	{
		// ida database
		return 0;
	}
	else
	{
		cout << "Unknown file type: " << file_type << endl;
		return 1;
	}
}

