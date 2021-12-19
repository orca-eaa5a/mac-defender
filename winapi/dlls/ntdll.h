#pragma once
#ifndef _NT_H_
#define _NT_H_
#include <cstdint>
#include <windows.h>
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
		APIExports::add_hook_info("ntdll.dll", "EventUnregister", (void*)MockNtdll::EtwUnregister);
		APIExports::add_hook_info("ntdll.dll", "NtEnumerateValueKey", (void*)MockNtdll::NtEnumerateValueKey);
		APIExports::add_hook_info("ntdll.dll", "NtQueryValueKey", (void*)MockNtdll::NtQueryValueKey);
		APIExports::add_hook_info("ntdll.dll", "NtOpenSymbolicLinkObject", (void*)MockNtdll::NtOpenSymbolicLinkObject);
		APIExports::add_hook_info("ntdll.dll", "NtQuerySymbolicLinkObject", (void*)MockNtdll::NtQuerySymbolicLinkObject);
		APIExports::add_hook_info("ntdll.dll", "NtQuerySystemInformation", (void*)MockNtdll::NtQuerySystemInformation);
		APIExports::add_hook_info("ntdll.dll", "NtClose", (void*)MockNtdll::NtClose);

		APIExports::add_hook_info("ntdll.dll", "RtlCreateHeap", (void*)MockNtdll::RtlCreateHeap);
		APIExports::add_hook_info("ntdll.dll", "RtlAllocateHeap", (void*)MockNtdll::RtlAllocateHeap);
		APIExports::add_hook_info("ntdll.dll", "RtlInitUnicodeString", (void*)MockNtdll::RtlInitUnicodeString);
		APIExports::add_hook_info("ntdll.dll", "RtlImageNtHeader", (void*)MockNtdll::RtlImageNtHeader);
		APIExports::add_hook_info("ntdll.dll", "RtlImageNtHeaderEx", (void*)MockNtdll::RtlImageNtHeaderEx);
	};
	static NTSTATUS __stdcall MockNtdll::RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
	static NTSTATUS __stdcall MockNtdll::EtwRegister(void* ProviderId, void* EnableCallback, void* CallbackContext, void* RegHandle);
	static NTSTATUS __stdcall MockNtdll::EtwUnregister(void* RegHandle);
	static NTSTATUS __stdcall MockNtdll::NtEnumerateValueKey(void* KeyHandle, unsigned long Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, unsigned long Length, unsigned long* ResultLength);
	static NTSTATUS __stdcall MockNtdll::NtQueryValueKey(void* KeyHandle, void* ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, unsigned long Length, unsigned long* ResultLength);
	static NTSTATUS __stdcall MockNtdll::NtOpenSymbolicLinkObject(void** LinkHandle, unsigned int DesiredAccess, void* ObjectAttributes);
	static NTSTATUS __stdcall MockNtdll::NtQuerySymbolicLinkObject(void* LinkHandle, UNICODE_STRING* LinkTarget, unsigned long* ReturnedLength);
	static NTSTATUS __stdcall MockNtdll::NtClose(void* Handle);
	static NTSTATUS __stdcall MockNtdll::NtQuerySystemInformation(unsigned int SystemInformationClass, void* SystemInformation, unsigned long SystemInformationLength, unsigned long* ReturnLength);
	static void* __stdcall MockNtdll::RtlCreateHeap(unsigned long Flags, void* HeapBase, size_t ReserveSize, size_t CommitSize, void* Lock, void* Parameters);
	static void* __stdcall MockNtdll::RtlAllocateHeap(void* HeapHandle, unsigned long Flags, size_t Size);
	static void __stdcall MockNtdll::RtlInitUnicodeString(PUNICODE_STRING DestinationString, wchar_t* SourceString);
	static void* __stdcall MockNtdll::RtlImageNtHeader(void* ModuleAddress);
	static unsigned int __stdcall MockNtdll::RtlImageNtHeaderEx(unsigned long Flags, void* base, unsigned long long Size, PIMAGE_NT_HEADERS * OutHeaders);
};

#endif
