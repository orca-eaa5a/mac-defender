#pragma once
#ifndef _OLE32_H_
#define _OLE32_H_
#include "../exports.h"
class MockOle32 {
public:
	function<void(void)> set_ole32_hookaddr = [](void) {
		
		APIExports::add_hook_info("ole32.dll", "CoCreateGuid", (void*)CoCreateGuid);
		APIExports::add_hook_info("ole32.dll", "CoCreateInstance", (void*)CoCreateInstance);
		APIExports::add_hook_info("ole32.dll", "CoInitializeEx", (void*)CoInitializeEx);
		APIExports::add_hook_info("ole32.dll", "CoUninitialize", (void*)CoUninitialize);
		APIExports::add_hook_info("ole32.dll", "IIDFromString", (void*)IIDFromString);
		APIExports::add_hook_info("ole32.dll", "CoSetProxyBlanket", (void*)CoSetProxyBlanket);
		
	};
#if defined(__WINDOWS__)
	static uint32_t __stdcall MockOle32::CoCreateGuid(void *pguid);
	static uint32_t __stdcall MockOle32::CoCreateInstance(void* rclsid, void* pUnkOuter, uint32_t dwClsContext, void* riid, void* ppv);
	static uint32_t __stdcall MockOle32::CoInitializeEx(void* pvReserved, uint32_t dwCoInit);
	static void __stdcall MockOle32::CoUninitialize();
	static uint32_t __stdcall MockOle32::IIDFromString(void* lpsz, void* lpiid);
	static uint32_t __stdcall MockOle32::CoSetProxyBlanket(
		void* pProxy,
		uint32_t dwAuthnSvc,
		uint32_t dwAuthzSvc,
		WCHAR* pServerPrincName,
		uint32_t dwAuthnLevel,
		uint32_t dwImpLevel,
		void* pAuthInfo,
		uint32_t dwCapabilities
	);
#else
	static uint32_t __stdcall CoCreateGuid(void *pguid);
	static uint32_t __stdcall CoCreateInstance(void* rclsid, void* pUnkOuter, uint32_t dwClsContext, void* riid, void* ppv);
	static uint32_t __stdcall CoInitializeEx(void* pvReserved, uint32_t dwCoInit);
	static void __stdcall CoUninitialize();
    static uint32_t __stdcall IIDFromString(void* lpsz, void* lpiid);
	static uint32_t __stdcall CoSetProxyBlanket(
		void* pProxy,
		uint32_t dwAuthnSvc,
		uint32_t dwAuthzSvc,
		WCHAR* pServerPrincName,
		uint32_t dwAuthnLevel,
		uint32_t dwImpLevel,
		void* pAuthInfo,
		uint32_t dwCapabilities
	);
#endif // 

};
#endif // _OLE32_H_
