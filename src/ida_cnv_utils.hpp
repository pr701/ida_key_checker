/*
* Some conversion utils header
*
* RnD, 2021
*/

#ifdef _MSC_VER
#pragma once
#endif

#ifndef _IDA_CONVERSION_UTILS_HPP_
#define _IDA_CONVERSION_UTILS_HPP_

#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>

#include "ida_license.hpp"
#include "ida_key.hpp"

using namespace std;

namespace ida
{
	void print_license(const license_t& license, bool skip_ver = false);
	void print_rays_license(const rays_license_t& license);

	string get_license_type(uint16_t type);
	string get_license_id(const id_t& id);
	string get_time(time_t time, bool extended = false);
	string get_string(const char* str, size_t limit);
	string get_hex(const uint8_t* data, size_t size);
	string get_hex(const string& value);

	template<typename T>
	string get_hex(const T& value)
	{
		std::stringstream str;
		str << std::hex << std::setfill('0') << std::setw(sizeof(T) * 2);
		if (sizeof(T) == 1)
			str << static_cast<uint16_t>(value);
		else
			str << value;
		return str.str();
	}

	time_t get_time(const string& value, bool extended = false);
}

#endif // _IDA_CONVERSION_UTILS_HPP_