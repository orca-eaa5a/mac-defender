#include "wintrust.h"

bool __stdcall MockWintrust::CryptCATAdminAcquireContext(void* phCatAdmin, void* pgSubsystem, unsigned int dwFlags) {
	return true;
}

void* __stdcall MockWintrust::CryptCATAdminEnumCatalogFromHash(void* hCatAdmin, unsigned char* pbHash, unsigned int cbHash, unsigned int dwFlags, void* phPrevCatInfo) {
	return NULL;
}