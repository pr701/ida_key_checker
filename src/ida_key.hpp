/*
* IDA Pro key parser header
*
* RnD, 2021
*/

#ifdef _MSC_VER
#pragma once
#endif

#ifndef _IDA_KEY_HPP_
#define _IDA_KEY_HPP_

#include <cstdint>
#include <cstdio>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip> 
#include <fstream>
#include <filesystem>

#include "ida_license.hpp"
#include "ida_cnv_utils.hpp"

#undef max
#undef min

namespace ida
{
	using namespace std;
	using namespace filesystem;

	// https://www.hex-rays.com/cgi-bin/quote.cgi
	enum EProduct
	{
		// IDA
		EProduct_IDASTA,
		EProduct_IDAADV,
		EProduct_IDAPRO,
		// Ext
		EProduct_IDAPC,
		EProduct_IDAARM,
		EProduct_IDAM68K,
		EProduct_IDAMIPS,
		EProduct_IDAPPC,
		// HEX
		EProduct_HEX86,
		EProduct_HEX64,
		EProduct_ARM,
		EProduct_ARM64,
		EProduct_PPC,
		EProduct_PPC64,
		EProduct_MIPS,
	};

	enum EPlatform
	{
		EPlatform_Windows,
		EPlatform_Mac,
		EPlatform_Linux,
	};

	typedef uint8_t rnd_t[57];

	typedef struct product_code_t
	{
		uint8_t id;
		uint8_t license;
		uint8_t platform;

		product_code_t() : id(0), license(0), platform(0)
		{}
	} product_code_t;

	typedef struct product_t
	{
		id_t licenseId;
		product_code_t product;
		uint32_t count;
		time_t support;
		time_t expires;

		product_t() : count(0), support(0), expires(0)
		{
			memset(&licenseId, 0, sizeof(id_t));
		}
	} product_t;

	typedef struct key_t
	{
		uint16_t version;
		string username;
		string email;
		time_t issued;
		vector<product_t> products;
		md5_t md5;
		rnd_t rnd; // seller data?
		signature_t signature;

		key_t() : version(0)
		{
			memset(&md5, 0, sizeof(md5_t));
			memset(&rnd, 0, sizeof(rnd_t));
			memset(&signature, 0, sizeof(signature_t));
		}
	} key_t;

	// parse ida.key
	bool parse_key(path filepath, key_t& key);
	void print_key(const key_t& key);

	// utils
	string get_product_string(const product_code_t& product, bool description = false);
	product_code_t get_product_from_code(string code);
}

#endif // _IDA_KEY_HPP_