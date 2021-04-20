/*
* IDA Pro signature decryptor and printer
*/

#include "ida_license.hpp"
#include "bigint.hpp"

namespace ida
{
	using namespace std;

	void reverse_block(uint8_t* buffer, size_t size)
	{
		uint8_t t;
		size_t i;
		size_t s = size - 1;
		for (i = 0; i < size / 2; i++)
		{
			t = buffer[i];
			buffer[i] = buffer[s - i];
			buffer[s - i] = t;
		}
	}

	bool decrypt_signature(const signature_t& sign, license_t& license,
		const uint8_t* customModulus)
	{
		assert(sizeof(license_t) == sizeof(signature_t));

		if (sign[0] == 0 || sign[1] == 0) return false;

		BI_CTX* BI;
		bigint* pub, * mod, * msg, * emsg;

		signature_t modulus;
		signature_t data;

		if (customModulus)
			memcpy(modulus, customModulus, sizeof(signature_t));
		else
			memcpy(modulus, ida_rsa_mod, sizeof(signature_t));

		memcpy(data, sign, sizeof(signature_t));

		reverse_block(modulus, sizeof(signature_t));
		reverse_block(data, sizeof(signature_t));

		BI = bi_initialize();

		mod = bi_import(BI, modulus, 128);
		bi_set_mod(BI, mod, BIGINT_M_OFFSET);

		msg = bi_import(BI, data, IDA_RSA_BLOCK_SIZE);
		pub = int_to_bi(BI, ida_rsa_pub);
		emsg = bi_mod_power(BI, msg, pub);
		bi_export(BI, emsg, (uint8_t*)&license, IDA_RSA_BLOCK_SIZE);

		bi_free_mod(BI, BIGINT_M_OFFSET);
		bi_terminate(BI);

		return !license.zero ? true : false;
	}
}