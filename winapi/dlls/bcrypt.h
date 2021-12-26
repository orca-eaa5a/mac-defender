#if defined(__WINDOWS__)
#pragma once
#endif

#ifndef _BCRYPT_H_
#define _BCRYPT_H_
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include "../exports.h"

#if defined(__APPLE__) || defined(__LINUX__)
#include "include/windows.h"
typedef uint32_t NTSTATUS;
#endif


class MockBcrypt {
public:
	function<void(void)> set_bcrypt_hookaddr = [](void) {
		APIExports::add_hook_info("bcrypt.dll", "BCryptOpenAlgorithmProvider", (void*)BCryptOpenAlgorithmProvider);
		APIExports::add_hook_info("bcrypt.dll", "BCryptCloseAlgorithmProvider", (void*)BCryptCloseAlgorithmProvider);
		APIExports::add_hook_info("bcrypt.dll", "BCryptGenRandom", (void*)BCryptGenRandom);
	};
#if defined(__WINDOWS__)
	static NTSTATUS __stdcall MockBcrypt::BCryptOpenAlgorithmProvider(void* phAlgorithm, wchar_t* pszAlgId, wchar_t* pszImplementation, uint32_t dwFlags);
	static NTSTATUS __stdcall MockBcrypt::BCryptCloseAlgorithmProvider(void* hAlgorithm, uint32_t dwFlags);
	static NTSTATUS __stdcall MockBcrypt::BCryptGenRandom(void* phAlgorithm, uint8_t* pbBuffer, uint32_t cbBuffer, uint32_t dwFlags);
#else
	static NTSTATUS __stdcall BCryptOpenAlgorithmProvider(void* phAlgorithm, wchar_t* pszAlgId, wchar_t* pszImplementation, uint32_t dwFlags);
	static NTSTATUS __stdcall BCryptCloseAlgorithmProvider(void* hAlgorithm, uint32_t dwFlags);
	static NTSTATUS __stdcall BCryptGenRandom(void* phAlgorithm, uint8_t* pbBuffer, uint32_t cbBuffer, uint32_t dwFlags);
#endif
};
#endif // !_BCRYPT_H_
