#pragma once

#include <cstdint>
#include <span>

#define CRYPTX_SHA1_HASH_SIZE   20
#define CRYPTX_SHA512_HASH_SIZE 64

namespace cryptx
{
	enum class EHashAlgorithm
	{
		Sha1,
		Sha512,
	};

	void CalcHash(const void* data, size_t data_size, EHashAlgorithm algorithm, const std::span<uint8_t>& out_hash);
}