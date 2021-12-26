#if defined(__WINDOWS__)
#pragma once
#endif

#ifndef _WINTRUST_H_
#define _WINTRUST_H_
#include <functional>
#include "../exports.h"

#if defined(__APPLE__) || defined(__LINUX__)
#include "include/windows.h"
#endif

class MockWintrust {
public:
	function<void(void)> set_wintrust_hookaddr = [](void) {
		APIExports::add_hook_info("wintrust.dll", "CryptCATAdminAcquireContext", (void*)CryptCATAdminAcquireContext);
		APIExports::add_hook_info("wintrust.dll", "CryptCATAdminEnumCatalogFromHash", (void*)CryptCATAdminEnumCatalogFromHash);
		
	};
#if defined(__WINDOWS__)
	static bool __stdcall MockWintrust::CryptCATAdminAcquireContext(void* phCatAdmin, void* pgSubsystem, uint32_t dwFlags);
	static void* __stdcall MockWintrust::CryptCATAdminEnumCatalogFromHash(void* hCatAdmin, uint8_t* pbHash, uint32_t cbHash, uint32_t dwFlags, void* phPrevCatInfo);
#else
	static bool __stdcall CryptCATAdminAcquireContext(void* phCatAdmin, void* pgSubsystem, uint32_t dwFlags);
	static void* __stdcall CryptCATAdminEnumCatalogFromHash(void* hCatAdmin, uint8_t* pbHash, uint32_t cbHash, uint32_t dwFlags, void* phPrevCatInfo);
#endif
	
};
#endif // !_WINTRUST_H_
