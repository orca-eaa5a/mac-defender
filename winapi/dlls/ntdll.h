#pragma once
#ifndef _NT_H_
#define _NT_H_
#include <cstdint>
#include <windows.h>
#include <evntprov.h>
#include <functional>
#include "../exports.h"
typedef struct _IO_STATUS_BLOCK {
	union {
		int Status;
		void*    Pointer;
	};
	__int64 Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

class MockNtdll {
public:
	function<void(void)> set_ntdll_hookaddr = [](void) {
		APIExports::add_hook_info("ntdll.dll", "RtlGetVersion", (void*)MockNtdll::RtlGetVersion);
		APIExports::add_hook_info("ntdll.dll", "EventRegister", (void*)MockNtdll::EtwRegister);
	};
	static NTSTATUS __stdcall MockNtdll::RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
	static NTSTATUS __stdcall MockNtdll::EtwRegister(void* ProviderId, void* EnableCallback, void* CallbackContext, void* RegHandle);
};

#endif
