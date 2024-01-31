#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <string_view>

namespace cryptx
{
	std::vector<uint8_t> Base64ToBytes(std::string_view base64);

	std::string BytesToBase64(const void* bytes, size_t byte_count);
}