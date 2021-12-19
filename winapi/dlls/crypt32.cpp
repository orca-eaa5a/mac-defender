#include "crypt32.h"

void* __stdcall MockCrypt32::CertOpenStore(char* lpszStoreProvider, unsigned int dwMsgAndCertEncodingType, void* hCryptProv, unsigned int dwFlags, void* pvPara) {
	return (HANDLE) 'mock';
}

bool __stdcall MockCrypt32::CertStrToNameW(unsigned int dwCertEncodingType, void* pszX500, unsigned int dwStrType, void* pvReserved, unsigned char* pbEncoded, unsigned int* pcbEncoded, void* ppszError) {
	/*
	uint16_t CertName[] = L"Totally Legitimate Certificate Name";
	char *name = CreateAnsiFromWide(pszX500);

	DebugLog("%u, %p [%s], %u, %p, %p, %p, %p", dwCertEncodingType,
		pszX500,
		name,
		dwStrType,
		pvReserved,
		pbEncoded,
		pcbEncoded,
		ppszError);
	free(name);
	wchar_t* cert_name = L""
	*pcbEncoded = sizeof(CertName);

	if (pbEncoded) {
		memcpy(pbEncoded, CertName, sizeof(CertName));
	}
	*/
	return false;
}