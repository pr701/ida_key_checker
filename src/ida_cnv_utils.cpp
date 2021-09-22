/*
* Some conversion utils
* 
* RnD, 2021
*/

#include "ida_cnv_utils.hpp"

namespace ida
{
	void print_license(const license_t& license, bool skip_ver)
	{
		if (license.zero)
		{
			cout << "Invalid Key Content." << endl;
			return;
		}

		if (!skip_ver)
			cout << "Key Number:" << endl << '\t' << license.keyNumber << endl
			<< '\t' << get_hex(&license.keyNumber, sizeof(license.keyNumber)) << endl
			<< "Key Version:" << endl << '\t' << license.keyVer << endl
			<< '\t' << get_hex(&license.keyVer, sizeof(license.keyVer)) << endl;

		cout << "License Type:" << endl << '\t' << get_license_type(license.typeLic) << endl
			<< '\t' << get_hex(&license.typeLic, sizeof(license.typeLic)) << endl
			<< "User Number:" << endl << '\t' << license.userNumber << endl
			<< '\t' << get_hex(&license.userNumber, sizeof(license.userNumber)) << endl
			<< "Reserved0:" << endl << '\t' << license.reserved0 << endl
			<< '\t' << get_hex(&license.reserved0, sizeof(license.reserved0)) << endl
			<< "Reserved1:" << endl << '\t' << license.reserved1 << endl
			<< '\t' << get_hex(&license.reserved1, sizeof(license.reserved1)) << endl
			<< "Started:" << endl << '\t' << get_time(license.started, true) << endl
			<< '\t' << get_hex(&license.started, sizeof(license.started)) << endl
			<< "Expires:" << endl << '\t' << get_time(license.expires, true) << endl
			<< '\t' << get_hex(&license.expires, sizeof(license.expires)) << endl
			<< "Support Exp:" << endl << '\t' << get_time(license.expSupp, true) << endl
			<< '\t' << get_hex(&license.expSupp, sizeof(license.expSupp)) << endl
			<< "License ID:" << endl << '\t' << get_license_id(license.licenseId) << endl
			<< "Username:" << endl << '\t' << get_string(license.username, IDA_LIC_USERNAME_SIZE) << endl
			<< "Version Flag:" << endl << '\t' << "0x" << setfill('0') << setw(8) << hex << license.versionFlag << endl
			<< "MD5:" << endl << '\t' << get_hex(license.md5, sizeof(md5_t)) << endl;
	}

	void print_rays_license(const rays_license_t& license)
	{
		typedef struct pair_t
		{
			uint8_t id;
			string product;
		} pair_t;

		vector<pair_t> k_pair = {
			{ 0x50, "MIPS" },
			{ 0x51, "MIPS" },
			{ 0x52, "PPC64" },
			{ 0x53, "PPC" },
			{ 0x54, "ARM64" },
			{ 0x55, "x64" },
			{ 0x56, "ARM" },
			{ 0x57, "x86" },
		};

		cout << "IDA ID:" << endl << '\t' << get_license_id(license.ida_id) << endl
			<< "Plugin ID:" << endl << '\t' << get_license_id(license.plugin_id);

		for (const auto& p : k_pair)
			if (p.id == license.plugin_id[0])
			{
				cout << '\t' << "(" << p.product << ")";
				break;
			}
		cout << endl
			<< "Username:" << endl << '\t' << get_string(license.name, sizeof(license.name)) << endl
			<< "Issued:" << endl << '\t' << get_time(license.creation, true) << endl
			<< "Support:" << endl << '\t' << get_time(license.support, true) << endl
			<< "MD5:" << endl << '\t' << get_string(license.md5, sizeof(license.md5)) << endl;
	}

	string get_license_type(uint16_t type)
	{
		switch (type)
		{
		case ELicense_Fixed:
			return "Fixed";
			break;
		case ELicense_Named:
			return "Named";
			break;
		case ELicense_Computer:
			return "Computer";
			break;
		case ELicense_Floating:
			return "Floating";
			break;
		default:
			return "Unknown";
			break;
		}
	}

	string get_license_id(const id_t& id)
	{
		char buff[24] = { 0 };
		sprintf_s(buff, 24, "%02X-%02X%02X-%02X%02X-%02X",
			id[0], id[1], id[2], id[3], id[4], id[5]);
		return buff;
	}

	string get_time(time_t time, bool extended)
	{
		if (time == 0) return "Never";

		tm tms = { 0 };
		localtime_s(&tms, &time);
		char buff[24] = { 0 };

		if (extended)
		{
			sprintf_s(buff, 24, "%04d-%02d-%02d %02d:%02d:%02d",
				tms.tm_year + 1900,
				tms.tm_mon + 1,
				tms.tm_mday,
				tms.tm_hour,
				tms.tm_min,
				tms.tm_sec);
		}
		else
		{
			sprintf_s(buff, 24, "%04d-%02d-%02d",
				tms.tm_year + 1900,
				tms.tm_mon + 1,
				tms.tm_mday);
		}
		return buff;
	}

	string get_string(const char* str, size_t limit)
	{
		if (!str) return "";

		string buf; buf.resize(limit + 1);
		memcpy(buf.data(), str, limit);
		return string(buf.c_str());
	}

	string get_hex(const void* data, size_t size)
	{
		if (!data || !size) return "null";
		
		string result;
		for (size_t i = 0; i < size; ++i)
		{
			char val[8] = { 0 };
			sprintf_s(val, 8, "%02X", reinterpret_cast<const uint8_t*>(data)[i]);
			result.append(val);
			if (i != size - 1) result.append(" ");
		}
		return result;
	}

	string get_hex(const string& value)
	{
		return get_hex(reinterpret_cast<const uint8_t*>(value.data()), value.size());
	}

	time_t get_time(const string& value, bool extended)
	{
		bool isTime = false;
		tm time;
		memset(&time, 0, sizeof(tm));

		if (extended)
		{
			if (sscanf_s(value.c_str(), "%d-%d-%d %d:%d:%d",
				&time.tm_year, &time.tm_mon, &time.tm_mday,
				&time.tm_hour, &time.tm_min, &time.tm_sec) == 6)
				isTime = true;
		}
		else
		{
			if (sscanf_s(value.c_str(), "%d-%d-%d",
				&time.tm_year, &time.tm_mon, &time.tm_mday) == 3)
				isTime = true;
		}
		if (isTime)
		{
			time.tm_year -= 1900;
			time.tm_mon--;
			return mktime(&time);
		}
		return 0;
	}
}