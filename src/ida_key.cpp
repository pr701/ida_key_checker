/*
* IDA Pro key parser
* 
* RnD, 2021
*/

#include "ida_key.hpp"
#include "md5.hpp"
#include "base64.h"

namespace ida
{
	typedef struct branding_t
	{
		uint8_t id;
		string code;
		string description;
	} branding_t;

	vector<branding_t> g_editions = {
	{ EProduct_IDASTA, "IDASTA", "IDA Starter" },
	{ EProduct_IDAADV, "IDAADV", "IDA Pro Advanced" },
	{ EProduct_IDAPRO, "IDAPRO", "IDA Professional" },

	{ EProduct_IDAPC, "IDAPC", "IDA Home PC" },
	{ EProduct_IDAPPC, "IDAPPC", "IDA Home PPC" },
	{ EProduct_IDAARM, "IDAARM", "IDA Home ARM" },
	{ EProduct_IDAM68K, "IDAM68K", "IDA Home M68K" },
	{ EProduct_IDAMIPS, "IDAMIPS", "IDA Home MIPS" },

	{ EProduct_HEX86, "HEXX86", "x86 Decompiler" },
	{ EProduct_HEX64, "HEXX64", "x64 Decompiler" },
	{ EProduct_ARM64, "HEXARM64", "ARM64 Decompiler" },
	{ EProduct_PPC64, "HEXPPC64", "PPC64 Decompiler" },
	{ EProduct_ARM, "HEXARM", "ARM Decompiler" },
	{ EProduct_PPC, "HEXPPC", "PPC Decompiler" },
	{ EProduct_MIPS, "HEXMIPS", "MIPS Decompiler" },
	};

	vector<branding_t> g_licenses = {
		{ ELicense_Named, "N", " Named License" },
		{ ELicense_Computer, "C", " Computer License" },
		{ ELicense_Floating, "F", " Floating License" },
	};

	vector<branding_t> g_platforms = {
		{ EPlatform_Windows, "W", " (Windows)" },
		{ EPlatform_Mac, "M", " (Mac)" },
		{ EPlatform_Linux, "L", " (Linux)" },
	};

	string get_brand(const vector<branding_t>& set, uint8_t id, bool description)
	{
		for (const auto& val : set)
			if (val.id == id)
				return description ? val.description : val.code;
		return "";
	}

	const char* get_code_part(const vector<branding_t>& set, const char* code, uint8_t& id)
	{
		for (const auto& val : set)
			if (!strncmp(code, val.code.c_str(), val.code.length()))
			{
				code += val.code.length();
				id = val.id;
				break;
			}
		return code;
	}

	string get_product_string(const product_code_t& product, bool description)
	{
		string id;

		id = get_brand(g_editions, product.id, description);
		id += get_brand(g_licenses, product.license, description);
		id += get_brand(g_platforms, product.platform, description);

		return id;
	}

	product_code_t get_product_from_code(string code)
	{
		product_code_t result;
		const char* s = code.c_str();
		s = get_code_part(g_editions, s, result.id);
		s = get_code_part(g_licenses, s, result.license);
		s = get_code_part(g_platforms, s, result.platform);

		return result;
	}

	const char* get_param_value(const char* line)
	{
		if (!line) return nullptr;

		size_t p = 0;
		bool next_value = false;

		for (size_t i = 0; i < strlen(line); ++i)
		{
			if (line[i] == ' ' || line[i] == '\t')
			{
				next_value = true;
			}
			if (next_value && line[i] != ' ' && line[i] != '\t')
			{
				p = i;
				break;
			}
		}
		if (p)
		{
			return &line[p];
		}
		return line;
	}

	inline string get_param_value(const string& line)
	{
		const char* s = get_param_value(line.c_str());
		if (!s) return "";
		return string(s);
	}

	inline string strip_value(const string& line)
	{
		for (size_t i = 0; i < line.length(); ++i)
			if (line[i] == ' ' || line[i] == '\t')
				return line.substr(0, i);
		return "";
	}

	void base_64_to_data(const string& base64, void* dst, size_t size)
	{
		string value;
		try
		{
			value = base64_decode(base64);
			memcpy(dst, value.data(), value.size() > size ? size : value.size());
		}
		catch (const std::exception&)
		{
		}
	}

	bool parse_key(path filepath, key_t& key)
	{
		key = key_t();
		bool result = false;

		ifstream file(filepath, ios::binary);
		if (!file.is_open()) return false;

		bool isKey = false;
		bool isEnded = false;

		string line;
		string value;
		string rnd;
		string sign;
		size_t len;
		int id0, id1, id2, id3, id4, id5;

		MD5_CTX md5_ctx;
		MD5_Init(&md5_ctx);

		while (getline(file, line))
		{
			len = line.length();

			if (len && line[0] == '\r')
				continue;

			if (len && line[len - 1] == '\r')
				line.erase(len - 1);

			float fver = 0.0;
			if (sscanf_s(line.c_str(), "HEXRAYS_LICENSE %f", &fver) == 1)
			{
				key.version = static_cast<uint16_t>(fver * 100. + .5);
				isKey = true;
			}
			if (!isKey) continue;

			if (line.find("USER") == 0)
			{
				key.username = get_param_value(line);
			}
			if (line.find("EMAIL") == 0)
			{
				key.email = get_param_value(line);
			}
			if (line.find("ISSUED_ON") == 0)
			{
				value = get_param_value(line);
				key.issued = get_time(value, true);
			}
			// Product line
			if (sscanf_s(line.c_str(), "%02X-%02X%02X-%02X%02X-%02X",
				&id0, &id1, &id2, &id3, &id4, &id5) == 6)
			{
				product_t product;

				product.licenseId[0] = static_cast<uint8_t>(id0);
				product.licenseId[1] = static_cast<uint8_t>(id1);
				product.licenseId[2] = static_cast<uint8_t>(id2);
				product.licenseId[3] = static_cast<uint8_t>(id3);
				product.licenseId[4] = static_cast<uint8_t>(id4);
				product.licenseId[5] = static_cast<uint8_t>(id5);

				// product
				const char* val = get_param_value(line.c_str());
				value = strip_value(val);
				product.product = get_product_from_code(value);
				// count
				val = get_param_value(val);
				value = strip_value(val);
				if (sscanf_s(value.c_str(), "%d", &id0) == 1)
					product.count = id0;
				// support
				val = get_param_value(val);
				value = strip_value(val);
				product.support = get_time(value);
				// expires
				val = get_param_value(val);
				value = strip_value(val);
				product.expires = get_time(value);

				key.products.push_back(product);
			}
			// Seller data?
			if (line.find("R:") == 0)
			{
				rnd.append(line.substr(2));
			}
			// Signature
			if (line.find("S:") == 0)
			{
				if (!isEnded) isEnded = true;
				sign.append(line.substr(2));
			}
			if (!isEnded) MD5_Update(&md5_ctx, line.c_str(), line.length());
		}
		if (isKey)
		{
			MD5_Final(key.md5, &md5_ctx);

			base_64_to_data(rnd, key.rnd, sizeof(rnd_t));
			base_64_to_data(sign, key.signature, sizeof(signature_t));

			return true;
		}
		file.close();

		return result;
	}

	void print_key(const key_t& key)
	{
		uint16_t major = (key.version / 100);
		uint16_t minor = (key.version - major * 100) / 10;

		cout << "HexRays License" << '\t' << major << "." << minor << endl << endl
			<< "User" << '\t' << '\t' << key.username << endl
			<< "Email" << '\t' << '\t' << key.email << endl
			<< "Issued On" << '\t' << get_time(key.issued, true) << endl
			<< "MD5" << '\t' << '\t' << get_hex(key.md5, sizeof(md5_t)) << endl;

		if (key.products.size())
		{
			cout << endl << "Products" << endl
				<< ' ' << setw(15) << "LICENSE ID" << setw(1) << ' '
				<< setw(3) << "#" << setw(1) << ' '
				<< setw(10) << "SUPPORT" << setw(1) << ' '
				<< setw(10) << "EXPIRES" << setw(1) << ' '
				<< setw(1) << "NAME" << endl;

			for (const auto& product : key.products)
			{
				cout << ' ' << get_license_id(product.licenseId) << ' ' <<
					setw(3) << product.count << setw(1) << ' ' <<
					setw(10) << get_time(product.support) << setw(1) << ' ' <<
					setw(10) << get_time(product.expires) << setw(1) << ' ' <<
					get_product_string(product.product, true) << endl;
			}
		}
	}

	string print_key_view(const key_t& key, bool print_sign)
	{
		// build license
		int major = key.version / 100;
		int minor = (key.version - major * 100) / 10;

		stringstream str;
		str << "HEXRAYS_LICENSE " << major << "." << minor << '\n' << '\n'
			<< "USER            " << key.username << '\n'
			<< "EMAIL           " << key.email << '\n'
			<< "ISSUED_ON       " << get_time(key.issued, true) << '\n' << '\n'
			<< "  LICENSE_ID    PRODUCT     #  SUPPORT    EXPIRES        DESCRIPTION" << '\n'
			<< "--------------- ---------- -- ---------- ---------  -----------------------------" << '\n';
		for (const auto& product : key.products)
		{
			str << setfill(' ') << left
				<< get_license_id(product.licenseId) << " "
				<< setw(10) << get_product_string(product.product, false) << setw(1) << " "
				<< setw(2) << right << to_string(product.count) << left << setw(1) << " "
				<< setw(10) << get_time(product.support) << setw(1) << " "
				<< setw(10) << get_time(product.expires) << setw(1) << " "
				<< get_product_string(product.product, true) << '\n';
		}
		str << '\n' << "R:" << base64_encode(string(reinterpret_cast<const char*>(key.rnd), sizeof(rnd_t))) << '\n';
		
		if (print_sign)
		{
			string sign(reinterpret_cast<const char*>(key.signature), sizeof(signature_t));
			sign.resize(160); sign = "S:" + base64_encode(sign);
			sign.insert(78, "\r\nS:");
			sign.insert(157, "\r\nS:");
			str << sign << '\r\n';
		}

		return str.str();
	}
}