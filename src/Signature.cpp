#include <cryptxlib/Platform.h>
#include <cryptxlib/RsaKey.h>
#include <cryptxlib/Signature.h>

#if defined(CRYPTX_WIN)
	#include "win/BCryptUtils.h"
#endif

namespace cryptx
{
	bool VerifySignature(const std::span<const uint8_t>& signature, const std::span<const uint8_t>& hash, const CPublicRsaKey& key, SignatureType signatureType)
	{
		#if defined(CRYPTX_WIN)
			auto algProvider = OpenAlgorithmProvider(BCRYPT_RSA_ALGORITHM);
			auto publicKey = ImportPublicRsaKey(algProvider.get(), key);
			NTSTATUS result = 0;
			switch (signatureType)
			{
			case SignatureType::RsaSha512:
			{
				BCRYPT_PKCS1_PADDING_INFO paddingInfo = { 0 };
				paddingInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM;
				result = BCryptVerifySignature(publicKey.get(), &paddingInfo, (PUCHAR)hash.data(), (ULONG)hash.size(), (PUCHAR)signature.data(), (ULONG)signature.size(), BCRYPT_PAD_PKCS1);
				break;
			}
			case SignatureType::RsaSsaPssSha512Mgf1:
			{
				BCRYPT_PSS_PADDING_INFO paddingInfo = { 0 };
				paddingInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM;
				paddingInfo.cbSalt = (ULONG)hash.size();  // The salt length must match the length of the hash
				result = BCryptVerifySignature(publicKey.get(), &paddingInfo, (PUCHAR)hash.data(), (ULONG)hash.size(), (PUCHAR)signature.data(), (ULONG)signature.size(), BCRYPT_PAD_PSS);
				break;
			}
			default:
				throw std::runtime_error("Unsupported signature type");
			}
			return NT_SUCCESS(result);
		#else
			throw std::runtime_error("Not implemented on this platform")
		#endif	
	}
}