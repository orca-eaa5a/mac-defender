
#include "version.h"

uint32_t __stdcall MockVersion::GetFileVersionInfoSizeExW(uint32_t dwFlags, char16_t* lptstrFilename, uint32_t* lpdwHandle) {
	debug_log("<version.dll!%s> called..\n", "GetFileVersionInfoSizeExW");

	return 0;
}

bool __stdcall MockVersion::GetFileVersionInfoExW(uint32_t dwFlags, char16_t* lptstrFilename, uint32_t dwHandle, uint32_t dwLen, void* lpData) {
	debug_log("<version.dll!%s> called..\n", "GetFileVersionInfoExW");

	return true;
}

bool __stdcall MockVersion::VerQueryValueW(void* pBlock, char16_t* lpSubBlock, void** lplpBuffer, uint32_t* puLen) {
	debug_log("<version.dll!%s> called..\n", "VerQueryValueW");

	return true;
}

