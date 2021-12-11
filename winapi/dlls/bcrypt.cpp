#include "bcrypt.h"

NTSTATUS __stdcall MockBcrypt::BCryptOpenAlgorithmProvider(void* phAlgorithm, wchar_t* pszAlgId, wchar_t* pszImplementation, unsigned int dwFlags){
	return 0;
}

NTSTATUS __stdcall MockBcrypt::BCryptCloseAlgorithmProvider(void* hAlgorithm, unsigned long dwFlags){
	return 0;
}

NTSTATUS __stdcall MockBcrypt::BCryptGenRandom(void* phAlgorithm, unsigned char* pbBuffer, unsigned long cbBuffer, unsigned long dwFlags){
	static int randomfd = -1;
	for (int i = 0; cbBuffer > i * 2; i++) {
		unsigned short r = (unsigned short)rand();
		memset((pbBuffer+i), r, sizeof(unsigned short));
	}
	return 0;
}

