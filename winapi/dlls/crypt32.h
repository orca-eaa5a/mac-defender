#if defined(__WINDOWS__)
#pragma once
#endif
#ifndef _CRYPT32_H_
#define _CRYPT32_H_
#include <functional>
#include "../exports.h"

#if defined(__APPLE__) || defined(__LINUX__)
#include "include/windows.h"
#else
#include <windows.h>
#endif

class MockCrypt32 {
public:
	function<void(void)> set_crypt32_hookaddr = [](void) {
		APIExports::add_hook_info("crypt32.dll", "CertOpenStore", (void*)CertOpenStore);
		APIExports::add_hook_info("crypt32.dll", "CertCloseStore", (void*)CertCloseStore);
		APIExports::add_hook_info("crypt32.dll", "CertStrToNameW", (void*)CertStrToNameW);
	};
#if defined(__WINDOWS__)
	static void* __stdcall MockCrypt32::CertOpenStore(char* lpszStoreProvider, uint32_t dwMsgAndCertEncodingType, void* hCryptProv, uint32_t dwFlags, void* pvPara);
	static bool __stdcall MockCrypt32::CertCloseStore(void* hCertStore, uint32_t dwFlags);
	static bool __stdcall MockCrypt32::CertStrToNameW(uint32_t dwCertEncodingType, void* pszX500, uint32_t dwStrType, void* pvReserved, uint8_t* pbEncoded, uint32_t* pcbEncoded, void* ppszError);
#else
	static void* __stdcall CertOpenStore(char* lpszStoreProvider, uint32_t dwMsgAndCertEncodingType, void* hCryptProv, uint32_t dwFlags, void* pvPara);
	static bool __stdcall CertCloseStore(void* hCertStore, uint32_t dwFlags);
	static bool __stdcall CertStrToNameW(uint32_t dwCertEncodingType, void* pszX500, uint32_t dwStrType, void* pvReserved, uint8_t* pbEncoded, uint32_t* pcbEncoded, void* ppszError);
#endif

};
#endif // !_CRYPT32_H_
