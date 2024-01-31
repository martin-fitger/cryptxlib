#include <malloc.h>
#include <stdexcept>
#include <cassert>
#include <cryptxlib/RsaKey.h>

namespace cryptx
{
	CPublicRsaKey::CPublicRsaKey(CPublicRsaKey&& other)
		: m_Bytes(other.m_Bytes)
		, m_ExponentSize(other.m_ExponentSize)
		, m_ModulusSize(other.m_ModulusSize)
	{
		other.m_Bytes = nullptr;
		other.m_ExponentSize = 0;
		other.m_ModulusSize = 0;
	}

	CPublicRsaKey::~CPublicRsaKey()
	{
		Free();
	}

	CPublicRsaKey CPublicRsaKey::FromPkcs1Blob(const void* pkcs1_blob, size_t size)
	{
		auto parseLength = [](const uint8_t*& at) -> uint16_t
		{
			if (*at < 0x80)
			{
				return *at++;
			}
			++at;
			uint16_t length = (at[0] << 8) | at[1];
			at += 2;
			return length;
		};

		auto* at = (const uint8_t*)pkcs1_blob;
		if (at[0] != 0x30)
		{
			throw std::runtime_error("Expected PKCS#1 to start with 0x30");
		}
		++at;
		const auto blob_length = parseLength(at);
		assert(at + blob_length == (const uint8_t*)pkcs1_blob + size);

		if (at[0] != 0x02)  // Tag for "integer"
		{
			throw std::runtime_error("Expected integer modulus value");
		}
		++at;

		auto modulus_length = parseLength(at);
		while (*at == 0)
		{
			++at;
			--modulus_length;
		}
		const uint8_t* ptrModulus = at;
		at += modulus_length;

		if (at[0] != 0x02)  // Tag for "integer"
		{
			throw std::runtime_error("Expected integer modulus value");
		}
		++at;

		const auto exponent_length = parseLength(at);
		const uint8_t* ptrExponent = at;
		at += exponent_length;

		assert(at == (const uint8_t*)pkcs1_blob + size);

		CPublicRsaKey key;
		key.m_Bytes = (uint8_t*)malloc(exponent_length + modulus_length);
		key.m_ExponentSize = exponent_length;
		key.m_ModulusSize = modulus_length;
		memcpy((uint8_t*)key.Exponent(), ptrExponent, exponent_length);
		memcpy((uint8_t*)key.Modulus(), ptrModulus, modulus_length);

		return key;
	}

	void CPublicRsaKey::Free()
	{
		free(m_Bytes);
		m_Bytes = nullptr;
		m_ExponentSize = 0;
		m_ModulusSize = 0;
	}
}