#pragma once
#ifndef _ADVAPI_H_
#define _ADVAPI_H_
#include <windows.h>
#include <evntrace.h>
#include <functional>
#include "../exports.h"

class MockAdvapi {
	public:
		function<void(void)> set_advapi_hookaddr = [](void) {
			APIExports::add_hook_info("Advapi32.DLL", "RegisterTraceGuidsW", (void*)MockAdvapi::RegisterTraceGuidsW);
			APIExports::add_hook_info("Advapi32.DLL", "EventSetInformation", (void*)MockAdvapi::EventSetInformation);
			APIExports::add_hook_info("Advapi32.DLL", "LookupPrivilegeValueA", (void*)MockAdvapi::LookupPrivilegeValueA);
			APIExports::add_hook_info("Advapi32.DLL", "LookupPrivilegeValueW", (void*)MockAdvapi::LookupPrivilegeValueW);
			APIExports::add_hook_info("Advapi32.DLL", "AdjustTokenPrivileges", (void*)MockAdvapi::AdjustTokenPrivileges);
		};
		static unsigned long __stdcall MockAdvapi::RegisterTraceGuidsW(void* RequestAddress, void* RequestContext, void* ControlGuid, unsigned long GuidCOunt, void* TraceGuidReg, wchar_t* MofImagePath, wchar_t* MofResourceName, void* RegistrationHandle);
		static unsigned long __stdcall MockAdvapi::EventSetInformation(void* RegHandle, unsigned int InformationClass, void* EventInformation, unsigned long InformationLength);
		static bool __stdcall MockAdvapi::LookupPrivilegeValueA(char* lpSystemName, char* lpName, void* lpLuid);
		static bool __stdcall MockAdvapi::LookupPrivilegeValueW(wchar_t* lpSystemName, wchar_t* lpName, void* lpLuid);
		static bool __stdcall MockAdvapi::AdjustTokenPrivileges(void* TokenHandle, bool DisableAllPrivileges, void* NewState, unsigned int BufferLength, void* PreviousState, unsigned int* ReturnLength);
};
#endif // !_ADVAPI_H_

