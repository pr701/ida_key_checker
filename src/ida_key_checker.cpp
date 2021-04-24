/*
* IDA key checker/dumper
* 
* RnD, 2021
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

#include <idb3.hpp>
#include <cxxopts.hpp>

#include "ida_key.hpp"
#include "ida_rsa_patches.h"

#if defined(WIN32) && defined(UNICODE)
#define file_path(x)	get_file_path(x)	
#else
#define file_path(x)	x
#endif

using namespace ida;

// Helpers
enum EFileType
{
	EFileType_Unknown = -1,
	EFileType_KEY = 0,
	EFileType_IDB,
	EFileType_BIN
};

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

int check_idb_user(path idb_database, path signature_file = "")
{
	try
	{
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

		bool is_pirated = true;
		bool is_decrypted = false;
		bool is_evaluation = false;

		if (originaluser.empty())
		{
			cout << endl << "OriginalUser block not present" << endl;
		}
		else
		{
			memset(signature, 0, sizeof(signature_t));
			memcpy(signature, originaluser.data(), originaluser.size() < sizeof(signature_t)
				? originaluser.size() : sizeof(signature_t));
			
			if (signature[0] == 0)
			{
				// check evaluation version
				license_t* license = reinterpret_cast<license_t*>(&signature[0] - 1);
				if (!memcmp(license->username, "Evaluation version", 18))
				{
					is_pirated = false;
					is_evaluation = true;
				}
			}
			else
			{
				is_decrypted = decrypt_sign(signature, license, is_pirated);
			}

			cout << endl << "Original User:" << endl
				<< "Pirated Key:" << '\t' << is_pirated << endl;
			if (is_evaluation) cout << "Evaluation Key:" << '\t' << is_evaluation << endl;

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
			print_license(license, true);

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

int check_file_type(path filepath)
{
	const auto magic_size = 19;

	ifstream file(filepath, ios::binary);
	if (!file.is_open()) return false;

	file.seekg(0, ios::end);
	size_t size = file.tellg();
	file.seekg(0, ios::beg);

	if (size > magic_size)
	{
		string magic;
		magic.resize(magic_size);

		file.read(magic.data(), magic_size);

		if (magic.find("HEXRAYS_LICENSE") == 0)
			return EFileType_KEY;

		if (magic.find("IDA0") == 0 ||
			magic.find("IDA1") == 0 || 
			magic.find("IDA2") == 0)
			return EFileType_IDB;

		if (size == 128 || size == 160)
			return EFileType_BIN;
	}
	return EFileType_Unknown;
}

int ckeck_key(path in_file, path out_file = "")
{
	if (!exists(in_file))
	{
		cout << "File not found: " << in_file << endl;
		return 2;
	}
	int result = 1;

	switch (check_file_type(in_file))
	{
	case EFileType_KEY:
		result = check_key_file(in_file, out_file);
		break;
	case EFileType_IDB:
		result = check_idb_user(in_file, out_file);
		break;
	case EFileType_BIN:
		result = check_signature(in_file, out_file);
		break;
	default:
		cout << "Unknown file type: " << in_file << endl;
	}
	return result;
}

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
		("o,output", "output filename (optional)", cxxopts::value<std::string>(file_output))
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

	if (result.count("output")) output = file_path(result["output"].as<std::string>());

	return ckeck_key(input, output);
}

