#pragma once

#include <span>
#include "RsaKey.h"

namespace cryptx
{
	enum class SignatureType
	{
		RsaSha512,
		RsaSsaPssSha512Mgf1,
	};

	bool VerifySignature(const std::span<const uint8_t>& signature, const std::span<const uint8_t>& hash, const CPublicRsaKey& key, SignatureType signatureType);
}