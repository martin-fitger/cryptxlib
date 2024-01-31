#pragma once

#include <cstdint>

namespace cryptx
{
	class CPublicRsaKey
	{
	public:
		CPublicRsaKey() {}
		CPublicRsaKey(CPublicRsaKey&& other);
		CPublicRsaKey(const CPublicRsaKey&) = delete;

		~CPublicRsaKey();

		static CPublicRsaKey FromPkcs1Blob(const void* pkcs1_blob, size_t pkcs1_blob_size);

		inline const uint8_t* Exponent() const;
		inline uint16_t ExponentSize() const;

		inline const uint8_t* Modulus() const;
		inline uint16_t ModulusSize() const;

	private:
		void Free();

		uint8_t* m_Bytes = nullptr;
		uint16_t m_ExponentSize = 0;
		uint16_t m_ModulusSize = 0;
	};

	inline const uint8_t* CPublicRsaKey::Exponent() const 
	{
		return m_Bytes; 
	}
	
	inline uint16_t CPublicRsaKey::ExponentSize() const 
	{ 
		return m_ExponentSize; 
	}

	inline const uint8_t* CPublicRsaKey::Modulus() const 
	{ 
		return m_Bytes + m_ExponentSize;
	}
	
	inline uint16_t CPublicRsaKey::ModulusSize() const 
	{ 
		return m_ModulusSize; 
	}
}