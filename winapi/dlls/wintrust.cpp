#include "wintrust.h"

bool __stdcall MockWintrust::CryptCATAdminAcquireContext(void* phCatAdmin, void* pgSubsystem, uint32_t dwFlags) {
	return true;
}

void* __stdcall MockWintrust::CryptCATAdminEnumCatalogFromHash(void* hCatAdmin, uint8_t* pbHash, uint32_t cbHash, uint32_t dwFlags, void* phPrevCatInfo) {
	return NULL;
}
