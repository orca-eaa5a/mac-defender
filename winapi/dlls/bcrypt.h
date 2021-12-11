#pragma once
#ifndef _BCRYPT_H_
#define _BCRYPT_H_
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <windows.h>
#include "../exports.h"

class MockBcrypt {
public:
	function<void(void)> set_k32_hookaddr = [](void) {
		APIExports::add_hook_info("bcrypt.dll", "BCryptOpenAlgorithmProvider", (void*)MockBcrypt::BCryptOpenAlgorithmProvider);
		APIExports::add_hook_info("bcrypt.dll", "BCryptCloseAlgorithmProvider", (void*)MockBcrypt::BCryptCloseAlgorithmProvider);
		APIExports::add_hook_info("bcrypt.dll", "GetStartupInfoA", (void*)MockBcrypt::BCryptGenRandom);
	};

	static NTSTATUS __stdcall BCryptOpenAlgorithmProvider(void* phAlgorithm, wchar_t* pszAlgId, wchar_t* pszImplementation, unsigned int dwFlags);
	static NTSTATUS __stdcall BCryptCloseAlgorithmProvider(void* hAlgorithm, unsigned long dwFlags);
	static NTSTATUS __stdcall MockBcrypt::BCryptGenRandom(void* phAlgorithm, unsigned char* pbBuffer, unsigned long cbBuffer, unsigned long dwFlags);
};
#endif // !_BCRYPT_H_
