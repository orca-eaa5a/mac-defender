#pragma once
#ifndef _ADVAPI_H_
#define _ADVAPI_H_
#include <windows.h>
#include <evntrace.h>
#include <functional>
#include "../exports.h"
#include "../ntoskrnl.h"

class MockAdvapi {
	public:
		function<void(void)> set_advapi_hookaddr = [](void) {
			APIExports::add_hook_info("advapi32.DLL", "RegisterTraceGuidsW", (void*)MockAdvapi::RegisterTraceGuidsW);
			APIExports::add_hook_info("advapi32.DLL", "EventSetInformation", (void*)MockAdvapi::EventSetInformation);
			APIExports::add_hook_info("advapi32.DLL", "LookupPrivilegeValueA", (void*)MockAdvapi::LookupPrivilegeValueA);
			APIExports::add_hook_info("advapi32.DLL", "LookupPrivilegeValueW", (void*)MockAdvapi::LookupPrivilegeValueW);
			APIExports::add_hook_info("advapi32.DLL", "AdjustTokenPrivileges", (void*)MockAdvapi::AdjustTokenPrivileges);
			
			
			APIExports::add_hook_info("advapi32.DLL", "RegCreateKeyExW", (void*)MockAdvapi::RegCreateKeyExW);
			APIExports::add_hook_info("advapi32.DLL", "RegOpenKeyExW", (void*)MockAdvapi::RegOpenKeyExW);
			APIExports::add_hook_info("advapi32.DLL", "RegQueryInfoKeyW", (void*)MockAdvapi::RegQueryInfoKeyW);
			APIExports::add_hook_info("advapi32.DLL", "RegEnumKeyExW", (void*)MockAdvapi::RegEnumKeyExW);
			APIExports::add_hook_info("advapi32.DLL", "RegCloseKey", (void*)MockAdvapi::RegCloseKey);
			APIExports::add_hook_info("advapi32.DLL", "RegQueryValueExW", (void*)MockAdvapi::RegQueryValueExW);
			APIExports::add_hook_info("advapi32.DLL", "RegNotifyChangeKeyValue", (void*)MockAdvapi::RegNotifyChangeKeyValue);
			
			
		};
		static unsigned long __stdcall MockAdvapi::RegisterTraceGuidsW(void* RequestAddress, void* RequestContext, void* ControlGuid, unsigned long GuidCOunt, void* TraceGuidReg, wchar_t* MofImagePath, wchar_t* MofResourceName, void* RegistrationHandle);
		static unsigned long __stdcall MockAdvapi::EventSetInformation(void* RegHandle, unsigned int InformationClass, void* EventInformation, unsigned long InformationLength);
		static bool __stdcall MockAdvapi::LookupPrivilegeValueA(char* lpSystemName, char* lpName, void* lpLuid);
		static bool __stdcall MockAdvapi::LookupPrivilegeValueW(wchar_t* lpSystemName, wchar_t* lpName, void* lpLuid);
		static bool __stdcall MockAdvapi::AdjustTokenPrivileges(void* TokenHandle, bool DisableAllPrivileges, void* NewState, unsigned int BufferLength, void* PreviousState, unsigned int* ReturnLength);
		
		static long __stdcall MockAdvapi::RegCreateKeyExW(
			void* hKey,
			wchar_t* lpSubKey,
			unsigned int Reserved,
			void* lpClass,
			unsigned int dwOptions,
			void* samDesired,
			void* lpSecurityAttributes,
			void* phkResult,
			unsigned int* lpdwDisposition);
		static long __stdcall MockAdvapi::RegOpenKeyExW(void* hKey, wchar_t* lpSubKey, unsigned int ulOptions, unsigned int samDesired, void** phkResult);
		static long __stdcall MockAdvapi::RegCloseKey(void* hKey);
		static long __stdcall MockAdvapi::RegQueryInfoKeyW(
			void* hKey,
			wchar_t* lpClass,
			unsigned int* lpcClass,
			unsigned int* lpReserved,
			unsigned int* lpcSubKeys,
			unsigned int* lpcMaxSubKeyLen,
			unsigned int* lpcMaxClassLen,
			unsigned int* lpcValues,
			unsigned int* lpcMaxValueNameLen,
			unsigned int* lpcMaxValueLen,
			unsigned int* lpcbSecurityDescriptor,
			void* lpftLastWriteTime
		);
		static long __stdcall MockAdvapi::RegQueryValueExW(void* hKey, wchar_t* lpValueName, unsigned int* lpReserved, unsigned int* lpType, unsigned char*  lpData, unsigned int* lpcbData);
		static long __stdcall MockAdvapi::RegEnumKeyExW(void* hkey, unsigned int dwIndex, wchar_t* lpName, unsigned int* lpcchName, void* lpReserved, wchar_t* lpClass, unsigned int* lpcchClass, void* lpftLastWriteTime);
		static long __stdcall MockAdvapi::RegNotifyChangeKeyValue(void* hKey, bool bWatchSubtree, unsigned int dwNotifyFilter, void* hEvent, bool fAsynchronous);
		

};
#endif // !_ADVAPI_H_

