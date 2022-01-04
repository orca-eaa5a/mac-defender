#if defined(__WINDOWS__)
#pragma once
#endif
#ifndef _VERSION_H_
#define _VERSION_H_

#include <cstdint>
#include <functional>
#include "../exports.h"
#include "../strutils.hpp"

#if defined(__APPLE__) || defined(__LINUX__)
#include "include/windows.h"
#endif

class MockVersion {
public:
	function<void(void)> set_version_hookaddr = [](void) {
		APIExports::add_hook_info("version.dll", "GetFileVersionInfoSizeExW", (void*)GetFileVersionInfoSizeExW);
		APIExports::add_hook_info("version.dll", "GetFileVersionInfoExW", (void*)GetFileVersionInfoExW);
		APIExports::add_hook_info("version.dll", "VerQueryValueW", (void*)VerQueryValueW);

	};
#if defined(__WINDOWS__)
	static uint32_t __stdcall MockVersion::GetFileVersionInfoSizeExW(uint32_t dwFlags, char16_t* lptstrFilename, uint32_t* lpdwHandle);
	static bool __stdcall MockVersion::GetFileVersionInfoExW(uint32_t dwFlags, char16_t* lptstrFilename, uint32_t dwHandle, uint32_t dwLen, void* lpData);
	static bool __stdcall MockVersion::VerQueryValueW(void* pBlock, char16_t* lpSubBlock, void** lplpBuffer, uint32_t* puLen);
#else
	static uint32_t __stdcall GetFileVersionInfoSizeExW(uint32_t dwFlags, char16_t* lptstrFilename, uint32_t* lpdwHandle);
	static bool __stdcall GetFileVersionInfoExW(uint32_t dwFlags, char16_t* lptstrFilename, uint32_t dwHandle, uint32_t dwLen, void* lpData);
	static bool __stdcall VerQueryValueW(void* pBlock, char16_t* lpSubBlock, void** lplpBuffer, uint32_t* puLen);
#endif
};

#endif // !_VERSION_H_
