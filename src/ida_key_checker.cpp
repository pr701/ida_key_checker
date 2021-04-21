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
#include <memory>

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
#include "idb3.h"

#include <cxxopts.hpp>

using namespace ida;

bool write_file(const path& path, const void* data, size_t size)
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

// Decrypt signature
bool decrypt_sign(const signature_t& sign, license_t& license, bool& is_pirated)
{
	bool is_sign_decrypted = false;
	is_pirated = true;

	if (decrypt_signature(sign, license))
	{
		is_sign_decrypted = true;
		is_pirated = false;
	}
	else
	{
		// check pirated versions
		for (const auto& mod : k_patch_mods)
			if (decrypt_signature(sign, license, mod))
			{
				is_sign_decrypted = true;
				break;
			}
	}
	return is_sign_decrypted;
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
	is_sign_decrypted = decrypt_sign(key.signature, license, is_pirated);

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
	streampos size = file.tellg();
	file.seekg(0, ios::beg);

	if (size)
	{
		file.read(reinterpret_cast<char*>(&signature),
			size < sizeof(signature_t) ? size : sizeof(signature_t));
	}
	file.close();

	bool is_sign_decrypted = false;
	bool is_pirated = true;

	is_sign_decrypted = decrypt_sign(signature, license, is_pirated);

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

int check_idb_user(path idb_database, path signature_file = "")
{
	try
	{
		if (!exists(idb_database))
		{
			cout << "File not found: " << idb_database << endl;
			return 2;
		}

		cout << "Database:" << '\t' << idb_database << endl;

		IDBFile idb(std::make_shared<std::ifstream>(idb_database, ios::binary));
		ID0File id0(idb, idb.getsection(ID0File::INDEX));
		
		uint64_t loadernode = id0.node("$ loader name");
		cout << "Loader:" << '\t' << '\t'
			<< id0.getstr(loadernode, 'S', 0) << " - "
			<< id0.getstr(loadernode, 'S', 1) << endl;

		uint64_t rootnode = id0.node("Root Node");
		std::string params = id0.getdata(rootnode, 'S', 0x41b994);
		std::string cpu;

		for (int i = 5; i < 14; ++i)
		{
			if ((params[i] >= 'A' && params[i] <= 'Z') ||
				(params[i] >= 'a' && params[i] <= 'z') ||
				(params[i] >= '0' && params[i] <= '9'))
				cpu += params[i];
		}

		uint32_t uVersion = id0.getuint(rootnode, 'A', -1);
		string strVersion = id0.getstr(rootnode, 'S', 1303);
		time_t time = id0.getuint(rootnode, 'A', -2);
		uint32_t crc = id0.getuint(rootnode, 'A', -5);
		string md5 = id0.getdata(rootnode, 'S', 1302);

		cout << "CPU:" << '\t' << '\t' << cpu << endl
			<< "IDA Version:" << '\t' << uVersion << "[" << strVersion << "]" << endl
			<< "Time:" << '\t' << '\t' << get_time(time, true) << endl
			<< "CRC:" << '\t' << '\t' << get_hex(crc) << endl
			<< "Binary MD5:" << '\t' << get_hex(md5) << endl;

		string originaluser = id0.getdata(id0.node("$ original user"), 'S', 0);
		string user1 = id0.getdata(id0.node("$ user1"), 'S', 0);

		license_t license;
		signature_t signature;

		bool is_pirated;
		bool is_decrypted;

		if (!originaluser.empty())
		{
			memset(signature, 0, sizeof(signature_t));
			memcpy(signature, originaluser.data(), originaluser.size() < sizeof(signature_t)
				? originaluser.size() : sizeof(signature_t));
			
			is_decrypted = decrypt_sign(signature, license, is_pirated);
			cout << endl << "Original User:" << endl
				<< "Pirated Key:" << '\t' << is_pirated << endl;
			
			if (is_decrypted) print_license(license);

			if (!signature_file.empty())
			{
				signature_file.replace_extension("originaluser");

				cout << endl << "Save original user to: " << signature_file << endl;
				if (!write_file(signature_file, originaluser.data(), originaluser.size()))
					cout << "Error: access fail" << endl;
				else
					cout << "Signature saved" << endl;

				if (is_decrypted)
				{
					signature_file.replace_extension("decrypted");

					cout << endl << "Save decrypted original user to: " << signature_file << endl;
					if (!write_file(signature_file, reinterpret_cast<uint8_t*>(&license), sizeof(license_t)))
						cout << "Error: access fail" << endl;
					else
						cout << "Decrypted signature saved" << endl;
				}
			}
		}
		if (!user1.empty())
		{
			license.zero = 0;
			memcpy(reinterpret_cast<uint8_t*>(&license) + 1,
				user1.data(), user1.size() < sizeof(signature_t)
				? user1.size() : sizeof(signature_t));

			cout << endl << "User1:" << endl;
			print_license(license);

			if (!signature_file.empty())
			{
				signature_file.replace_extension("user1");

				cout << endl << "Save user1 to: " << signature_file << endl;
				if (!write_file(signature_file, user1.data(), user1.size()))
					cout << "Error: access fail" << endl;
				else
					cout << "Signature saved" << endl;
			}
		}
	}
	catch (std::exception e)
	{
		cout << "Error: " << e.what() << endl;
		return 1;
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
		return check_idb_user(input, output);
	}
	else
	{
		cout << "Unknown file type: " << file_type << endl;
		return 1;
	}
}

