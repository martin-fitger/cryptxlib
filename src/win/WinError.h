#include <string>

namespace cryptx
{
	void ThrowLastSystemError(const char* format, ...);

	std::string GetSystemErrorString(int errorCode);

	void ThrowSystemError(int errorCode, const char* errMsg);
}