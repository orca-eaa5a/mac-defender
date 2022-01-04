#include "crypt32.h"

void* __stdcall MockCrypt32::CertOpenStore(char* lpszStoreProvider, uint32_t dwMsgAndCertEncodingType, void* hCryptProv, uint32_t dwFlags, void* pvPara) {
	debug_log("<crypt32.dll!%s> called..\n", "CertOpenStore");

	return (HANDLE) 'mock';
}
bool __stdcall MockCrypt32::CertCloseStore(void* hCertStore, uint32_t dwFlags) {
	debug_log("<crypt32.dll!%s> called..\n", "CertCloseStore");

	return true;
}

bool __stdcall MockCrypt32::CertStrToNameW(uint32_t dwCertEncodingType, void* pszX500, uint32_t dwStrType, void* pvReserved, uint8_t* pbEncoded, uint32_t* pcbEncoded, void* ppszError) {
	debug_log("<crypt32.dll!%s> called..\n", "CertStrToNameW");

	return false;
}
