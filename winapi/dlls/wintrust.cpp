#include "wintrust.h"

bool __stdcall MockWintrust::CryptCATAdminAcquireContext(void* phCatAdmin, void* pgSubsystem, uint32_t dwFlags) {
	debug_log("<wintrust.dll!%s> called..\n", "CryptCATAdminAcquireContext");

	return true;
}

void* __stdcall MockWintrust::CryptCATAdminEnumCatalogFromHash(void* hCatAdmin, uint8_t* pbHash, uint32_t cbHash, uint32_t dwFlags, void* phPrevCatInfo) {
	debug_log("<wintrust.dll!%s> called..\n", "CryptCATAdminEnumCatalogFromHash");

	return NULL;
}
