#pragma once
#ifndef _CRYPT32_H_
#define _CRYPT32_H_
#include <functional>
#include <windows.h>
#include "../exports.h"

class MockCrypt32 {
public:
	function<void(void)> set_crypt32_hookaddr = [](void) {
		APIExports::add_hook_info("crypt32.dll", "CertOpenStore", (void*)MockCrypt32::CertOpenStore);
		APIExports::add_hook_info("crypt32.dll", "CertStrToNameW", (void*)MockCrypt32::CertStrToNameW);
	};
	static void* __stdcall MockCrypt32::CertOpenStore(char* lpszStoreProvider, unsigned int dwMsgAndCertEncodingType, void* hCryptProv, unsigned int dwFlags, void* pvPara);
	static bool __stdcall MockCrypt32::CertStrToNameW(unsigned int dwCertEncodingType, void* pszX500, unsigned int dwStrType, void* pvReserved, unsigned char* pbEncoded, unsigned int* pcbEncoded, void* ppszError);
};
#endif // !_CRYPT32_H_
