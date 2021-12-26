#pragma once
#ifndef _RPCRT4_H_
#define _RPCRT4_H_
#include "../exports.h"
#if defined(__WINDOWS__)
#include <windows.h>
#else
#include "include/windows.h"
#endif
class MockRpcrt4 {
public:
	function<void(void)> set_rpcrt4_hookaddr = [](void) {
		APIExports::add_hook_info("rpcrt4.dll", "UuidFromStringW", (void*)UuidFromStringW);
		APIExports::add_hook_info("rpcrt4.dll", "RpcBindingFree", (void*)RpcBindingFree);
		APIExports::add_hook_info("rpcrt4.dll", "NdrServerCallAll", (void*)NdrServerCallAll);
		APIExports::add_hook_info("rpcrt4.dll", "NdrClientCall3", (void*)NdrClientCall3);
		
	};
#if defined(__WINDOWS__)
	static uint32_t __stdcall MockRpcrt4::UuidFromStringW(wchar_t* StringUuid, void* Uuid);
	static uint32_t __stdcall MockRpcrt4::RpcBindingFree(void* Binding);
	static void __stdcall MockRpcrt4::NdrServerCallAll(void* pRpcMsg);
	static void* __stdcall MockRpcrt4::NdrClientCall3(void *pProxyInfo, uint32_t nProcNum, void* pReturnValue, ...);
#else
	static uint32_t __stdcall UuidFromStringW(wchar_t* StringUuid, void* Uuid);
	static uint32_t __stdcall RpcBindingFree(void* Binding);
	static void __stdcall NdrServerCallAll(void* pRpcMsg)
	static void* __stdcall NdrClientCall3(void *pProxyInfo, uint32_t nProcNum, void* pReturnValue, ...);
#endif
};
#endif // !_RPCRT4_H_
