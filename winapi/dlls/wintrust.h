#pragma once
#ifndef _WINTRUST_H_
#define _WINTRUST_H_
#include <functional>
#include <windows.h>
#include "../exports.h"

class MockWintrust {
public:
	function<void(void)> set_wintrust_hookaddr = [](void) {
		APIExports::add_hook_info("wintrust.dll", "CryptCATAdminAcquireContext", (void*)MockWintrust::CryptCATAdminAcquireContext);
		APIExports::add_hook_info("wintrust.dll", "CryptCATAdminEnumCatalogFromHash", (void*)MockWintrust::CryptCATAdminEnumCatalogFromHash);
		
	};
	static bool __stdcall MockWintrust::CryptCATAdminAcquireContext(void* phCatAdmin, void* pgSubsystem, unsigned int dwFlags);
	static void* __stdcall MockWintrust::CryptCATAdminEnumCatalogFromHash(void* hCatAdmin, unsigned char* pbHash, unsigned int cbHash, unsigned int dwFlags, void* phPrevCatInfo);
	
};
#endif // !_WINTRUST_H_
