#include <stdexcept>
#include <cryptxlib/Platform.h>
#include <cryptxlib/Hash.h>

#ifdef CRYPTX_WIN
	#include "win/BCryptHasher.h"
#endif

namespace cryptx
{
	void CalcHash(const void* data, size_t data_size, EHashAlgorithm algorithm, const std::span<uint8_t>& out_hash)
	{
		#if defined(CRYPTX_WIN)
			CBCryptHasher hasher(BCryptHashAlgorithmId(algorithm));
			hasher.HashData(data, data_size);
			hasher.FinishHash(out_hash.data(), out_hash.size());
		#else
			throw std::runtime_error("Not implemented on this platform")
		#endif	
	}
}