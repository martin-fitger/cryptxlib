#include <cryptxlib/Platform.h>
#ifdef CRYPTX_WIN

#include "BCryptUtils.h"
#include "BCryptHasher.h"
#include <bcrypt.h>
#include <stdexcept>
#include <system_error>

namespace cryptx
{
	CBCryptHasher::CBCryptHasher(const wchar_t* algorithmId)
	{
		DWORD cbData = 0;
		try
		{
			ThrowIfFailed(BCryptOpenAlgorithmProvider(&m_hAlg, algorithmId, NULL, 0), "BCryptOpenAlgorithmProvider failed");

			DWORD cbHashObject = 0;
			ThrowIfFailed(BCryptGetProperty(m_hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(cbHashObject), &cbData, 0), "BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed");

			m_HashObject = (PBYTE)malloc(cbHashObject);
			if (NULL == m_HashObject)
			{
				throw std::runtime_error("Allocation of hash object failed");
			}

			ThrowIfFailed(BCryptCreateHash(m_hAlg, &m_hHash, m_HashObject, cbHashObject, NULL, 0, 0), "BCryptCreateHash failed");
		}
		catch (...)
		{
			Free();
			throw;
		}
	}

	CBCryptHasher::~CBCryptHasher()
	{
		Free();
	}

	size_t CBCryptHasher::HashSize() const
	{
		DWORD cbData = 0;
		DWORD cbHashLength = 0;
		ThrowIfFailed(BCryptGetProperty(m_hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashLength, sizeof(cbHashLength), &cbData, 0), "BCryptGetProperty(BCRYPT_HASH_LENGTH) failed");
		return cbHashLength;
	}

	void CBCryptHasher::HashData(const void* data, size_t byte_count)
	{
		ThrowIfFailed(BCryptHashData(m_hHash, (PBYTE)data, (ULONG)byte_count, 0), "BCryptHashData failed");
	}

	void CBCryptHasher::FinishHash(void* buffer, size_t buffer_size)
	{
		ThrowIfFailed(BCryptFinishHash(m_hHash, (PBYTE)buffer, (DWORD)buffer_size, 0), "BCryptFinishHash failed");
	}

	void CBCryptHasher::Free()
	{
		if (m_hHash)
		{
			BCryptDestroyHash(m_hHash);
			m_hHash = nullptr;
		}

		if (m_HashObject) {
			free(m_HashObject);
			m_HashObject = nullptr;
		}

		if (m_hAlg)
		{
			BCryptCloseAlgorithmProvider(m_hAlg, 0);
			m_hAlg = nullptr;
		}
	}

	const wchar_t* BCryptHashAlgorithmId(cryptx::EHashAlgorithm algorithm)
	{
		switch (algorithm)
		{
		case EHashAlgorithm::Sha1:
			return BCRYPT_SHA1_ALGORITHM;
		case EHashAlgorithm::Sha512:
			return BCRYPT_SHA512_ALGORITHM;
		default:
			throw std::runtime_error("Unsupported hash algorithm");
		}
	}
}

#endif