#if defined(__WINDOWS__)
#pragma once
#endif

#ifndef _ADVAPI_H_
#define _ADVAPI_H_

#if defined(__WINDOWS__)
#include <windows.h>
#include <evntrace.h>
#include <evntprov.h>
#else

#endif
#include <functional>
#include "../exports.h"
#include "../ntoskrnl.h"

class MockAdvapi {
	public:
		function<void(void)> set_advapi_hookaddr = [](void) {
			
			APIExports::add_hook_info("advapi32.DLL", "RegisterTraceGuidsW", (void*)RegisterTraceGuidsW);
			APIExports::add_hook_info("advapi32.DLL", "EventSetInformation", (void*)EventSetInformation);
			APIExports::add_hook_info("advapi32.DLL", "LookupPrivilegeValueA", (void*)LookupPrivilegeValueA);
			APIExports::add_hook_info("advapi32.DLL", "LookupPrivilegeValueW", (void*)LookupPrivilegeValueW);
			APIExports::add_hook_info("advapi32.DLL", "AdjustTokenPrivileges", (void*)AdjustTokenPrivileges);
			
			APIExports::add_hook_info("advapi32.DLL", "RegCreateKeyExW", (void*)RegCreateKeyExW);
			APIExports::add_hook_info("advapi32.DLL", "RegOpenKeyExW", (void*)RegOpenKeyExW);
			APIExports::add_hook_info("advapi32.DLL", "RegQueryInfoKeyW", (void*)RegQueryInfoKeyW);
			APIExports::add_hook_info("advapi32.DLL", "RegEnumKeyExW", (void*)RegEnumKeyExW);
			APIExports::add_hook_info("advapi32.DLL", "RegCloseKey", (void*)RegCloseKey);
			APIExports::add_hook_info("advapi32.DLL", "RegQueryValueExW", (void*)RegQueryValueExW);
			APIExports::add_hook_info("advapi32.DLL", "RegNotifyChangeKeyValue", (void*)RegNotifyChangeKeyValue);
			APIExports::add_hook_info("advapi32.DLL", "LsaNtStatusToWinError", (void*)LsaNtStatusToWinError);

			APIExports::add_hook_info("advapi32.DLL", "EventWriteEx", (void*)EventWriteEx);
			APIExports::add_hook_info("advapi32.DLL", "EventWriteTransfer", (void*)EventWriteTransfer);
			APIExports::add_hook_info("advapi32.DLL", "EventActivityIdControl", (void*)MyEventActivityIdControl);
		};

#if defined(__WINDOWS__)
		static uint32_t __stdcall MockAdvapi::RegisterTraceGuidsW(void* RequestAddress, void* RequestContext, void* ControlGuid, uint32_t GuidCOunt, void* TraceGuidReg, wchar_t* MofImagePath, wchar_t* MofResourceName, void* RegistrationHandle);
		static uint32_t __stdcall MockAdvapi::EventSetInformation(void* RegHandle, uint32_t InformationClass, void* EventInformation, uint32_t InformationLength);
		static bool __stdcall MockAdvapi::LookupPrivilegeValueA(char* lpSystemName, char* lpName, void* lpLuid);
		static bool __stdcall MockAdvapi::LookupPrivilegeValueW(wchar_t* lpSystemName, wchar_t* lpName, void* lpLuid);
		static bool __stdcall MockAdvapi::AdjustTokenPrivileges(void* TokenHandle, bool DisableAllPrivileges, void* NewState, uint32_t BufferLength, void* PreviousState, uint32_t* ReturnLength);

		static long __stdcall MockAdvapi::RegCreateKeyExW(
			void* hKey,
			wchar_t* lpSubKey,
			uint32_t Reserved,
			void* lpClass,
			uint32_t dwOptions,
			void* samDesired,
			void* lpSecurityAttributes,
			void* phkResult,
			uint32_t* lpdwDisposition);
		static long __stdcall MockAdvapi::RegOpenKeyExW(void* hKey, wchar_t* lpSubKey, uint32_t ulOptions, uint32_t samDesired, void** phkResult);
		static long __stdcall MockAdvapi::RegCloseKey(void* hKey);
		static long __stdcall MockAdvapi::RegQueryInfoKeyW(
			void* hKey,
			wchar_t* lpClass,
			uint32_t* lpcClass,
			uint32_t* lpReserved,
			uint32_t* lpcSubKeys,
			uint32_t* lpcMaxSubKeyLen,
			uint32_t* lpcMaxClassLen,
			uint32_t* lpcValues,
			uint32_t* lpcMaxValueNameLen,
			uint32_t* lpcMaxValueLen,
			uint32_t* lpcbSecurityDescriptor,
			void* lpftLastWriteTime
		);
		static long __stdcall MockAdvapi::RegQueryValueExW(void* hKey, wchar_t* lpValueName, uint32_t* lpReserved, uint32_t* lpType, uint8_t*  lpData, uint32_t* lpcbData);
		static long __stdcall MockAdvapi::RegEnumKeyExW(void* hkey, uint32_t dwIndex, wchar_t* lpName, uint32_t* lpcchName, void* lpReserved, wchar_t* lpClass, uint32_t* lpcchClass, void* lpftLastWriteTime);
		static long __stdcall MockAdvapi::RegNotifyChangeKeyValue(void* hKey, bool bWatchSubtree, uint32_t dwNotifyFilter, void* hEvent, bool fAsynchronous);

		static uint32_t __stdcall MockAdvapi::LsaNtStatusToWinError(uint32_t Status);
		static uint32_t __stdcall MockAdvapi::EventWriteEx(
			void* EventDescriptor,
			uint64_t Filter,
			uint32_t Flags,
			void* ActivityId,
			void* RelatedActivityId,
			uint32_t UserDataCount,
			void* UserData);
		static uint32_t __stdcall MockAdvapi::EventWriteTransfer(
			void* RegHandle,
			void* EventDescriptor,
			void* ActivityId,
			void* RelatedActivityId,
			uint32_t UserDataCount,
			void* UserData
		);
		static uint32_t __stdcall MockAdvapi::MyEventActivityIdControl(
			uint32_t ControlCode,
			void* ActivityId
		);
#else
		static uint32_t __stdcall RegisterTraceGuidsW(void* RequestAddress, void* RequestContext, void* ControlGuid, uint32_t GuidCOunt, void* TraceGuidReg, wchar_t* MofImagePath, wchar_t* MofResourceName, void* RegistrationHandle);
		static uint32_t __stdcall EventSetInformation(void* RegHandle, uint32_t InformationClass, void* EventInformation, uint32_t InformationLength);
		static bool __stdcall LookupPrivilegeValueA(char* lpSystemName, char* lpName, void* lpLuid);
		static bool __stdcall LookupPrivilegeValueW(wchar_t* lpSystemName, wchar_t* lpName, void* lpLuid);
		static bool __stdcall AdjustTokenPrivileges(void* TokenHandle, bool DisableAllPrivileges, void* NewState, uint32_t BufferLength, void* PreviousState, uint32_t* ReturnLength);
		
		static long __stdcall RegCreateKeyExW(
			void* hKey,
			wchar_t* lpSubKey,
			uint32_t Reserved,
			void* lpClass,
			uint32_t dwOptions,
			void* samDesired,
			void* lpSecurityAttributes,
			void* phkResult,
			uint32_t* lpdwDisposition);
		static long __stdcall RegOpenKeyExW(void* hKey, wchar_t* lpSubKey, uint32_t ulOptions, uint32_t samDesired, void** phkResult);
		static long __stdcall RegCloseKey(void* hKey);
		static long __stdcall RegQueryInfoKeyW(
			void* hKey,
			wchar_t* lpClass,
			uint32_t* lpcClass,
			uint32_t* lpReserved,
			uint32_t* lpcSubKeys,
			uint32_t* lpcMaxSubKeyLen,
			uint32_t* lpcMaxClassLen,
			uint32_t* lpcValues,
			uint32_t* lpcMaxValueNameLen,
			uint32_t* lpcMaxValueLen,
			uint32_t* lpcbSecurityDescriptor,
			void* lpftLastWriteTime
		);
		static long __stdcall RegQueryValueExW(void* hKey, wchar_t* lpValueName, uint32_t* lpReserved, uint32_t* lpType, uint8_t*  lpData, uint32_t* lpcbData);
		static long __stdcall RegEnumKeyExW(void* hkey, uint32_t dwIndex, wchar_t* lpName, uint32_t* lpcchName, void* lpReserved, wchar_t* lpClass, uint32_t* lpcchClass, void* lpftLastWriteTime);
		static long __stdcall RegNotifyChangeKeyValue(void* hKey, bool bWatchSubtree, uint32_t dwNotifyFilter, void* hEvent, bool fAsynchronous);

		static uint32_t __stdcall LsaNtStatusToWinError(uint32_t Status);
		static uint32_t __stdcall EventWriteEx(
			void* EventDescriptor, 
			uint64_t Filter,
			uint32_t Flags,
			void* ActivityId, 
			void* RelatedActivityId,
			uint32_t UserDataCount,
			void* UserData);
		static uint32_t __stdcall EventWriteTransfer(
			void* RegHandle,
			void* EventDescriptor,
			void* ActivityId,
			void* RelatedActivityId,
			uint32_t UserDataCount,
			void* UserData
		);
		static uint32_t __stdcall MyEventActivityIdControl(
			uint32_t ControlCode,
			void* ActivityId
		);
#endif

};
#endif // !_ADVAPI_H_

