
#include "version.h"

unsigned int __stdcall MockVersion::GetFileVersionInfoSizeExW(unsigned int dwFlags, wchar_t* lptstrFilename, unsigned int* lpdwHandle) {
	return 0;
}

bool __stdcall MockVersion::GetFileVersionInfoExW(unsigned int dwFlags, wchar_t* lptstrFilename, unsigned int dwHandle, unsigned int dwLen, void* lpData) {
	return true;
}

bool __stdcall MockVersion::VerQueryValueW(void* pBlock, wchar_t* lpSubBlock, void** lplpBuffer, unsigned int* puLen) {
	return true;
}

