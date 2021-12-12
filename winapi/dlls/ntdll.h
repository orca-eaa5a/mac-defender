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

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	KeyValueLayerInformation,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
	unsigned long TitleIndex;
	unsigned long Type;
	unsigned long NameLength;
	wchar_t Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
	unsigned long TitleIndex;
	unsigned long Type;
	unsigned long DataLength;
	unsigned char Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _UNICODE_STRING {
	unsigned short Length;
	unsigned short MaximumLength;
	wchar_t*  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

class MockNtdll {
public:
	function<void(void)> set_ntdll_hookaddr = [](void) {
		APIExports::add_hook_info("ntdll.dll", "RtlGetVersion", (void*)MockNtdll::RtlGetVersion);
		APIExports::add_hook_info("ntdll.dll", "EventRegister", (void*)MockNtdll::EtwRegister);
		APIExports::add_hook_info("ntdll.dll", "EventUnRegister", (void*)MockNtdll::EtwUnregister);
		APIExports::add_hook_info("ntdll.dll", "NtEnumerateValueKey", (void*)MockNtdll::NtEnumerateValueKey);
		APIExports::add_hook_info("ntdll.dll", "NtQueryValueKey", (void*)MockNtdll::NtQueryValueKey);
	};
	static NTSTATUS __stdcall MockNtdll::RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
	static NTSTATUS __stdcall MockNtdll::EtwRegister(void* ProviderId, void* EnableCallback, void* CallbackContext, void* RegHandle);
	static NTSTATUS __stdcall MockNtdll::EtwUnregister(void* RegHandle);
	static NTSTATUS __stdcall MockNtdll::NtEnumerateValueKey(void* KeyHandle, unsigned long Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, unsigned long Length, unsigned long* ResultLength);
	static NTSTATUS __stdcall MockNtdll::NtQueryValueKey(void* KeyHandle, void* ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, unsigned long Length, unsigned long* ResultLength);
};

#endif
