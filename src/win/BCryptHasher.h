#pragma once

#include "Windows.h"
#include <bcrypt.h>
#include <cryptxlib/Hash.h>

namespace cryptx
{
	class CBCryptHasher {
	public:
		CBCryptHasher(const wchar_t* algorithmId);
		~CBCryptHasher();

		size_t HashSize() const;

		void HashData(const void* data, size_t byte_count);

		void FinishHash(void* buffer, size_t buffer_size);

	private:
		void Free();

		BCRYPT_ALG_HANDLE m_hAlg = nullptr;
		BCRYPT_HASH_HANDLE m_hHash = nullptr;
		unsigned char* m_HashObject = nullptr;
	};

	const wchar_t* BCryptHashAlgorithmId(cryptx::EHashAlgorithm algorithm);
}