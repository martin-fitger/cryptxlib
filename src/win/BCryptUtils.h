#pragma once

#include <system_error>
#include <string>
#include <vector>
#include <Windows.h>
#include <cryptxlib/RsaKey.h>
#include "unique_handle.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

namespace cryptx
{
	template <typename T>
	inline void ThrowIfFailed(NTSTATUS ntstatus, T&& msg)
	{
		if (!NT_SUCCESS(ntstatus))
		{
			throw std::system_error{ (int)GetLastError(), std::system_category(), std::forward<T>(msg) };
		}
	}

	inline void BCryptCloseAlgorithmProviderSimple(BCRYPT_ALG_HANDLE hAlg)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}

	UNIQUE_HANDLE_DECL(bcrypt_alg_handle_t, BCRYPT_ALG_HANDLE, nullptr, BCryptCloseAlgorithmProviderSimple);
	UNIQUE_HANDLE_DECL(bcrypt_hash_handle_t, BCRYPT_HASH_HANDLE, nullptr, BCryptDestroyHash);
	UNIQUE_HANDLE_DECL(bcrypt_key_handle_t, BCRYPT_KEY_HANDLE, nullptr, BCryptDestroyKey);

	bcrypt_alg_handle_t OpenAlgorithmProvider(LPCWSTR pszAlgId);

	bcrypt_key_handle_t ImportPublicRsaKey(BCRYPT_ALG_HANDLE hAlg, const CPublicRsaKey& key);

	std::vector<uint8_t> Base64ToBytes(std::string_view base64);

	std::string BytesToBase64(const void* bytes, size_t byte_count);
}