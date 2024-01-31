#include <cryptxlib/Platform.h>
#ifdef CRYPTX_WIN

#include <cassert>
#include "BCryptUtils.h"

#pragma comment (lib, "bcrypt")
#pragma comment (lib, "Crypt32")

namespace cryptx
{
	bcrypt_alg_handle_t OpenAlgorithmProvider(LPCWSTR pszAlgId)
	{
		bcrypt_alg_handle_t hAlg;
		ThrowIfFailed(BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, 0), "BCryptOpenAlgorithmProvider failed");
		return hAlg;
	}

	bcrypt_key_handle_t ImportPublicRsaKey(BCRYPT_ALG_HANDLE hAlg, const CPublicRsaKey& key)
	{
		const size_t buffer_size = sizeof(BCRYPT_RSAKEY_BLOB) + key.ExponentSize() + key.ModulusSize();
		auto* ptr = (uint8_t*)alloca(buffer_size);

		BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)ptr;
		memset(header, 0, sizeof(*header));
		header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
		header->BitLength = key.ModulusSize() * 8;
		header->cbModulus = key.ModulusSize();
		header->cbPublicExp = key.ExponentSize();
		ptr += sizeof(BCRYPT_RSAKEY_BLOB);
		memcpy(ptr, key.Exponent(), key.ExponentSize());
		ptr += key.ExponentSize();
		memcpy(ptr, key.Modulus(), key.ModulusSize());
		ptr += key.ModulusSize();
		assert(ptr - (uint8_t*)header == buffer_size);

		bcrypt_key_handle_t hKey;
		ThrowIfFailed(BCryptImportKeyPair(
			hAlg,
			NULL,
			BCRYPT_RSAPUBLIC_BLOB,
			&hKey,
			(PUCHAR)header,
			(ULONG)buffer_size,
			0/*BCRYPT_NO_KEY_VALIDATION*/), "BCryptImportKeyPair failed");

		return hKey;
	}

	std::vector<uint8_t> Base64ToBytes(std::string_view base64)
	{
		const DWORD flags = CRYPT_STRING_BASE64;

		std::vector<uint8_t> bytes;
		DWORD byte_count = 0;
		if (!CryptStringToBinary(base64.data(), (DWORD)base64.length(), flags, nullptr, &byte_count, nullptr, nullptr))
		{
			throw std::system_error{ (int)GetLastError(), std::system_category(), "CryptStringToBinary failed" };
		}
		bytes.reserve(byte_count);
		bytes.resize(byte_count);
		if (!CryptStringToBinary(base64.data(), (DWORD)base64.length(), flags, bytes.data(), &byte_count, nullptr, nullptr))
		{
			throw std::system_error{ (int)GetLastError(), std::system_category(), "CryptStringToBinary failed" };
		}
		return bytes;
	}

	std::string BytesToBase64(const void* bytes, size_t byte_count)
	{
		const DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
		DWORD length = 0;
		if (!CryptBinaryToString((const BYTE*)bytes, (DWORD)byte_count, flags, nullptr, &length))
		{
			throw std::system_error{ (int)GetLastError(), std::system_category(), "CryptBinaryToString failed" };
		}
		std::string base64;
		base64.reserve(length - 1);
		if (!CryptBinaryToString((const BYTE*)bytes, (DWORD)byte_count, flags, base64.data(), &length))
		{
			throw std::system_error{ (int)GetLastError(), std::system_category(), "CryptBinaryToString failed" };
		}
		return base64;
	}
}

#endif