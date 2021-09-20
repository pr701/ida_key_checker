/*
* IDA Hex-Rays reverse-engineered license data
* 
* RnD, 2021
*/

#ifdef _MSC_VER
#pragma once
#endif

#ifndef _IDA_HEXRAYS_LICENSE_HPP_
#define _IDA_HEXRAYS_LICENSE_HPP_

#include "ida_license.hpp"

namespace ida
{
#pragma pack(push, 1)
	typedef char rays_signature_t[32]; // "HEXRAYS_VERSIONX.X.X.XXXXXX"

	typedef struct rays_license_t
	{
		uint32_t flag1;		// 0x01fe0000
		uint32_t flag2;		// 0x00010000
		uint32_t flag3;
		uint32_t reserved0;
		uint32_t creation;	// unixtimestamp
		uint32_t reserved1;
		uint32_t support;	// unixtimestamp
		id_t plugin_id;
		char name[157];
		char md5[33];		// string
		id_t ida_id;
	} rays_license_t;
#pragma pack(pop)

	const uint8_t ida_rays_version_text[] = { 
		0x48, 0x45, 0x58, 0x52, 0x41, 0x59, 0x53, 0x5F, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4F, 0x4E
	};
	const uint8_t ida_rays_license_sign[] = {
		0x00, 0x00, 0xFE, 0x01, 0x00, 0x00, 0x01, 0x00
	};
}

#endif