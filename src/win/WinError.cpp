#include <cryptxlib/Platform.h>
#ifdef CRYPTX_WIN

#include "Windows.h"
#include <cstdarg>
#include <stdexcept>
#include "WinError.h"

namespace cryptx
{
	void ThrowLastSystemError(const char* format, ...)
	{
		char buf[4096];
		va_list args;
		va_start(args, format);
		vsnprintf(buf, sizeof(buf), format, args);

		ThrowSystemError(GetLastError(), buf);
	}

	std::string GetSystemErrorString(int errorCode)
	{
		char errorBuffer[1024];
		int result = FormatMessageA(
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			errorCode,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			errorBuffer,
			sizeof(errorBuffer),
			NULL);
		if (result == 0) {
			return "Unknown error";
		}
		return errorBuffer;
	}

	void ThrowSystemError(int errorCode, const char* errMsg)
	{
		char buf[2048];
		sprintf_s(buf, "%s. %s (error code 0x%.8X).", errMsg, GetSystemErrorString(errorCode).c_str(), errorCode);
		throw std::runtime_error(buf);
	}
}

#endif