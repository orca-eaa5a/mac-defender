#pragma once
#ifndef _VERSION_H_
#define _VERSION_H_

#include <cstdint>
#include <windows.h>
#include <functional>
#include "../exports.h"

class MockVersion {
public:
	function<void(void)> set_version_hookaddr = [](void) {
		APIExports::add_hook_info("version.dll", "GetFileVersionInfoSizeExW", (void*)MockVersion::GetFileVersionInfoSizeExW);
		APIExports::add_hook_info("version.dll", "GetFileVersionInfoExW", (void*)MockVersion::GetFileVersionInfoExW);
		APIExports::add_hook_info("version.dll", "VerQueryValueW", (void*)MockVersion::VerQueryValueW);

	};

	static unsigned int __stdcall MockVersion::GetFileVersionInfoSizeExW(unsigned int dwFlags, wchar_t* lptstrFilename, unsigned int* lpdwHandle);
	static bool __stdcall MockVersion::GetFileVersionInfoExW(unsigned int dwFlags, wchar_t* lptstrFilename, unsigned int dwHandle, unsigned int dwLen, void* lpData);
	static bool __stdcall MockVersion::VerQueryValueW(void* pBlock, wchar_t* lpSubBlock, void** lplpBuffer, unsigned int* puLen);
};

#endif // !_VERSION_H_
