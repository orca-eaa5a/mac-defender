
#include "version.h"

uint32_t __stdcall MockVersion::GetFileVersionInfoSizeExW(uint32_t dwFlags, wchar_t* lptstrFilename, uint32_t* lpdwHandle) {
	return 0;
}

bool __stdcall MockVersion::GetFileVersionInfoExW(uint32_t dwFlags, wchar_t* lptstrFilename, uint32_t dwHandle, uint32_t dwLen, void* lpData) {
	return true;
}

bool __stdcall MockVersion::VerQueryValueW(void* pBlock, wchar_t* lpSubBlock, void** lplpBuffer, uint32_t* puLen) {
	return true;
}

