#include "crypt32.h"

void* __stdcall MockCrypt32::CertOpenStore(char* lpszStoreProvider, uint32_t dwMsgAndCertEncodingType, void* hCryptProv, uint32_t dwFlags, void* pvPara) {
	return (HANDLE) 'mock';
}
bool __stdcall MockCrypt32::CertCloseStore(void* hCertStore, uint32_t dwFlags) {
	return true;
}

bool __stdcall MockCrypt32::CertStrToNameW(uint32_t dwCertEncodingType, void* pszX500, uint32_t dwStrType, void* pvReserved, uint8_t* pbEncoded, uint32_t* pcbEncoded, void* ppszError) {

	return false;
}
