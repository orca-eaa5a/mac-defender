#include "bcrypt.h"

NTSTATUS __stdcall MockBcrypt::BCryptOpenAlgorithmProvider(void* phAlgorithm, char16_t* pszAlgId, char16_t* pszImplementation, uint32_t dwFlags){
	return 0;
}

NTSTATUS __stdcall MockBcrypt::BCryptCloseAlgorithmProvider(void* hAlgorithm, uint32_t dwFlags){
	return 0;
}

NTSTATUS __stdcall MockBcrypt::BCryptGenRandom(void* phAlgorithm, uint8_t* pbBuffer, uint32_t cbBuffer, uint32_t dwFlags){
	for (int i = 0; cbBuffer > i * 2; i++) {
		uint16_t r = (uint16_t)rand();
		memset((pbBuffer+i), r, sizeof(uint16_t));
	}
	return 0;
}
