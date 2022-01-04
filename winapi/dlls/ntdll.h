#if defined(__WINDOWS__)
#pragma once
#endif

#ifndef _NT_H_
#define _NT_H_
#include <cstdint>
#include <functional>
#include <string>
#include "../exports.h"
#if defined(__APPLE__) || defined(__LINUX__)
#include "include/windows.h"
#include <ucontext.h>
#include <mach/mach_init.h>
#include <sys/sysctl.h>
#include <mach/mach_vm.h>

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
	uint32_t BeginAddress;
	uint32_t EndAddress;
    uint32_t UnwindData;
} _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;
typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;
#else
#include <windows.h>

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
	uint32_t TitleIndex;
	uint32_t Type;
	uint32_t NameLength;
	WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;


typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
	uint32_t TitleIndex;
	uint32_t Type;
	uint32_t DataLength;
	uint8_t Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;
#include <subAuth.h>
#endif

#define ALIGN_DOWN_BY(size, align) ((unsigned long long)(size) & ~((unsigned long long)(align) - 1))
#define ALIGN_UP_BY(size, align) (ALIGN_DOWN_BY(((unsigned long long)(size) + align - 1), align))
#define ALIGN_UP_POINTER_BY(ptr, align) ((void*)ALIGN_UP_BY(ptr, align))

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

#define     EXCEPTION_NONCONTINUABLE   0x1
#define     EXCEPTION_UNWINDING   0x2
#define     EXCEPTION_EXIT_UNWIND   0x4
#define     EXCEPTION_STACK_INVALID   0x8
#define     EXCEPTION_NESTED_CALL   0x10
#define     EXCEPTION_TARGET_UNWIND   0x20
#define     EXCEPTION_COLLIDED_UNWIND   0x40
#define     EXCEPTION_UNWIND
#define     IS_UNWINDING(Flag)   ((Flag & EXCEPTION_UNWIND) != 0)
#define     IS_DISPATCHING(Flag)   ((Flag & EXCEPTION_UNWIND) == 0)
#define     IS_TARGET_UNWIND(Flag)   (Flag & EXCEPTION_TARGET_UNWIND)
#define     EXCEPTION_MAXIMUM_PARAMETERS   15

#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#if 0 // These are deprecated / not for x64
#define UWOP_SAVE_XMM 6
#define UWOP_SAVE_XMM_FAR 7
#else
#define UWOP_EPILOG 6
#define UWOP_SPARE_CODE 7
#endif
#define UWOP_SAVE_XMM128 8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10

typedef union _UNWIND_CODE {
	struct {
		unsigned char CodeOffset;
		unsigned char UnwindOp : 4;
		unsigned char OpInfo : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
	unsigned char Version : 3, Flags : 5;          // + 0x00 - Unwind info structure version
	unsigned char SizeOfProlog;         // + 0x01
	unsigned char CountOfCodes;         // + 0x02 - Count of unwind codes
	unsigned char FrameRegister : 4, FrameOffset : 4;    // + 0x03
	UNWIND_CODE UnwindCode[1];  // + 0x04 - Unwind code array
	UNWIND_CODE MoreUnwindCode[1];
	union
	{
		ULONG ExceptionHandler;
		ULONG FunctionEntry;
	};
	ULONG ExceptionData[];

} UNWIND_INFO, *PUNWIND_INFO;


typedef struct _ScopeRecord
{
	ULONG BeginAddress;
	ULONG EndAddress;
	ULONG HandlerAddress;
	ULONG JumpTarget;
} ScopeRecord, *PScopeRecord;

#if defined(__LINUX__) || defined(__APPLE__)
typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    union {
        PM128A FloatingContext[16];
        struct {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    union {
        PULONG64 IntegerContext[16];
        struct {
            PULONG64 Rax;
            PULONG64 Rcx;
            PULONG64 Rdx;
            PULONG64 Rbx;
            PULONG64 Rsp;
            PULONG64 Rbp;
            PULONG64 Rsi;
            PULONG64 Rdi;
            PULONG64 R8;
            PULONG64 R9;
            PULONG64 R10;
            PULONG64 R11;
            PULONG64 R12;
            PULONG64 R13;
            PULONG64 R14;
            PULONG64 R15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME2;
} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;

struct _EXCEPTION_FRAME;

 #define EXCEPTION_MAXIMUM_PARAMETERS   15

typedef enum _EXCEPTION_DISPOSITION{
    ExceptionContinueExecution,
    ExceptionContinueSearch,
    ExceptionNestedException,
    ExceptionCollidedUnwind
}EXCEPTION_DISPOSITION, *PEXCEPTION_DISPOSITION;

typedef struct _EXCEPTION_RECORD {
  DWORD ExceptionCode;
  DWORD ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID ExceptionAddress;
  DWORD NumberParameters;
  ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;


typedef EXCEPTION_DISPOSITION __stdcall EXCEPTION_ROUTINE(
                                                          struct _EXCEPTION_RECORD *ExceptionRecord,
                                                          PVOID EstablisherFrame, struct _CONTEXT *ContextRecord,
                                                          PVOID DispatcherContext);

typedef EXCEPTION_ROUTINE* PEXCEPTION_ROUTINE;

typedef struct _EXCEPTION_REGISTRATION_RECORD
{
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;

typedef EXCEPTION_DISPOSITION(*PEXCEPTION_HANDLER)(
	struct _EXCEPTION_RECORD *ExceptionRecord,
	struct _EXCEPTION_FRAME *EstablisherFrame,
	struct _CONTEXT *ContextRecord,
	struct _EXCEPTION_FRAME **DispatcherContext);

typedef struct _EXCEPTION_FRAME {
	struct _EXCEPTION_FRAME *prev;
	PEXCEPTION_HANDLER handler;
} EXCEPTION_FRAME, *PEXCEPTION_FRAME;

#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
    uint64_t ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE {
    uint32_t Count;
    uint8_t Search;
    uint64_t LowAddress;
    uint64_t HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

typedef struct _DISPATCHER_CONTEXT
{
    uint64_t ControlPc;
    uint64_t ImageBase;
    struct _IMAGE_RUNTIME_FUNCTION_ENTRY *FunctionEntry;
    uint64_t EstablisherFrame;
    uint64_t TargetIp;
    PCONTEXT ContextRecord;
    PEXCEPTION_ROUTINE LanguageHandler;
    void* HandlerData;
    struct _UNWIND_HISTORY_TABLE *HistoryTable;
    uint32_t ScopeIndex;
    uint32_t Fill0;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;
#endif
class MockNtdll {
public:
	function<void(void)> set_ntdll_hookaddr = [](void) {
		
		APIExports::add_hook_info("ntdll.dll", "RtlGetVersion", (void*)RtlGetVersion);
		APIExports::add_hook_info("ntdll.dll", "EventRegister", (void*)EtwRegister);
		APIExports::add_hook_info("ntdll.dll", "EventUnregister", (void*)EtwUnregister);

		APIExports::add_hook_info("ntdll.dll", "NtEnumerateValueKey", (void*)NtEnumerateValueKey);
		APIExports::add_hook_info("ntdll.dll", "NtQueryValueKey", (void*)NtQueryValueKey);
		APIExports::add_hook_info("ntdll.dll", "NtOpenSymbolicLinkObject", (void*)NtOpenSymbolicLinkObject);
		APIExports::add_hook_info("ntdll.dll", "NtQuerySymbolicLinkObject", (void*)NtQuerySymbolicLinkObject);
		APIExports::add_hook_info("ntdll.dll", "NtQuerySystemInformation", (void*)NtQuerySystemInformation);
		
		APIExports::add_hook_info("ntdll.dll", "NtQueryDirectoryFile", (void*)NtQueryDirectoryFile);
		APIExports::add_hook_info("ntdll.dll", "NtQueryInformationProcess", (void*)NtQueryInformationProcess);
		APIExports::add_hook_info("ntdll.dll", "NtQueryInformationThread", (void*)NtQueryInformationThread);
		APIExports::add_hook_info("ntdll.dll", "NtQueryInformationFile", (void*)NtQueryInformationFile);

		APIExports::add_hook_info("ntdll.dll", "NtClose", (void*)NtClose);

		APIExports::add_hook_info("ntdll.dll", "RtlCreateHeap", (void*)RtlCreateHeap);
		APIExports::add_hook_info("ntdll.dll", "RtlAllocateHeap", (void*)RtlAllocateHeap);
		APIExports::add_hook_info("ntdll.dll", "RtlInitUnicodeString", (void*)RtlInitUnicodeString);
		APIExports::add_hook_info("ntdll.dll", "RtlInitUnicodeStringEx", (void*)RtlInitUnicodeString);
		APIExports::add_hook_info("ntdll.dll", "RtlImageNtHeader", (void*)RtlImageNtHeader);
		APIExports::add_hook_info("ntdll.dll", "RtlImageNtHeaderEx", (void*)RtlImageNtHeaderEx);
		

		APIExports::add_hook_info("ntdll.dll", "RtlAddFunctionTable", (void*)RtlAddFunctionTable);
		APIExports::add_hook_info("ntdll.dll", "RtlDeleteFunctionTable", (void*)RtlDeleteFunctionTable);
		APIExports::add_hook_info("ntdll.dll", "RtlLookupFunctionEntry", (void*)RtlLookupFunctionEntry);
		
		APIExports::add_hook_info("ntdll.dll", "RtlpUpcaseUnicodeChar", (void*)RtlpUpcaseUnicodeChar);
		APIExports::add_hook_info("ntdll.dll", "RtlPrefixUnicodeString", (void*)RtlPrefixUnicodeString);
		APIExports::add_hook_info("ntdll.dll", "RtlIpv4AddressToStringW", (void*)RtlIpv4AddressToStringW);
		APIExports::add_hook_info("ntdll.dll", "RtlPcToFileHeader", (void*)RtlPcToFileHeader);
		APIExports::add_hook_info("ntdll.dll", "RtlImageDirectoryEntryToData", (void*)RtlImageDirectoryEntryToData);
		APIExports::add_hook_info("ntdll.dll", "RtlCaptureContext", (void*)MockRtlCaptureContext);
		APIExports::add_hook_info("ntdll.dll", "RtlRestoreContext", (void*)MockRtlRestoreContext);
		APIExports::add_hook_info("ntdll.dll", "RtlUnwind", (void*)MockRtlUnwind);
		APIExports::add_hook_info("ntdll.dll", "RtlUnwindEx", (void*)MockRtlUnwindEx);
		APIExports::add_hook_info("ntdll.dll", "RtlVirtualUnwind", (void*)RtlVirtualUnwind);

		APIExports::add_hook_info("ntdll.dll", "RtlNtStatusToDosError", (void*)RtlNtStatusToDosError);
		

	};
#if defined(__WINDOWS__)
	static NTSTATUS __stdcall MockNtdll::RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
	static NTSTATUS __stdcall MockNtdll::EtwRegister(void* ProviderId, void* EnableCallback, void* CallbackContext, void* RegHandle);
	static NTSTATUS __stdcall MockNtdll::EtwUnregister(void* RegHandle);

	static NTSTATUS __stdcall MockNtdll::NtEnumerateSystemEnvironmentValuesEx(uint32_t InformationClass, void* Buffer, uint32_t* BufferLength);
	static NTSTATUS __stdcall MockNtdll::NtEnumerateValueKey(void* KeyHandle, uint32_t Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, uint32_t Length, uint32_t* ResultLength);
	static NTSTATUS __stdcall MockNtdll::NtQueryValueKey(void* KeyHandle, void* ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, uint32_t Length, uint32_t* ResultLength);
	static NTSTATUS __stdcall MockNtdll::NtOpenSymbolicLinkObject(void** LinkHandle, uint32_t DesiredAccess, void* ObjectAttributes);
	static NTSTATUS __stdcall MockNtdll::NtQuerySymbolicLinkObject(void* LinkHandle, UNICODE_STRING* LinkTarget, uint32_t* ReturnedLength);
	static NTSTATUS __stdcall MockNtdll::NtClose(void* Handle);
	static NTSTATUS __stdcall MockNtdll::NtQueryInformationProcess(void* ProcessHandle, uint32_t ProcessInformationClass, void* ProcessInformation, uint32_t ProcessInformationLength, uint32_t* ReturnLength);
	static NTSTATUS __stdcall MockNtdll::NtQueryInformationThread(void* ThreadHandle, uint32_t ThreadInformationClass, void* ThreadInformation, uint32_t ThreadInformationLength, uint32_t* ReturnLength);
	static NTSTATUS __stdcall MockNtdll::NtQueryInformationFile(void* FileHandle, void* IoStatusBlock, void* FileInformation, uint32_t Length, uint32_t FileInformationClass);
	static NTSTATUS __stdcall MockNtdll::NtQuerySystemInformation(uint32_t SystemInformationClass, void* SystemInformation, uint32_t SystemInformationLength, uint32_t* ReturnLength);
	static NTSTATUS __stdcall MockNtdll::NtQueryDirectoryFile(
		void* FileHandle,
		void* Event,
		void* ApcRoutine,
		void* ApcContext,
		void* IoStatusBlock,
		void* FileInformation,
		uint32_t Length,
		uint32_t FileInformationClass,
		bool ReturnSingleEntry,
		PUNICODE_STRING FileName,
		bool RestartScan
	);
	static void* __stdcall MockNtdll::RtlCreateHeap(uint32_t Flags, void* HeapBase, size_t ReserveSize, size_t CommitSize, void* Lock, void* Parameters);
	static void* __stdcall MockNtdll::RtlAllocateHeap(void* HeapHandle, uint32_t Flags, size_t Size);
	static void __stdcall MockNtdll::RtlInitUnicodeString(PUNICODE_STRING DestinationString, char16_t* SourceString);
	static void* __stdcall MockNtdll::RtlImageNtHeader(void* ModuleAddress);
	static uint32_t __stdcall MockNtdll::RtlImageNtHeaderEx(uint32_t Flags, void* base, uint64_t Size, PIMAGE_NT_HEADERS * OutHeaders);
	static bool __stdcall MockNtdll::RtlAddFunctionTable(void* FunctionTable, uint32_t EntryCount, uint64_t BaseAddress);
	static bool __stdcall MockNtdll::RtlDeleteFunctionTable(void* FunctionTable);
	static PRUNTIME_FUNCTION __stdcall MockNtdll::RtlLookupFunctionEntry(uint64_t ControlPc, uint64_t* ImageBase, void* HistoryTable);
	static PRUNTIME_FUNCTION __stdcall MockNtdll::RtlLookupFunctionTable(uint64_t ControlPc, uint64_t* ImageBase, uint32_t* Length);
	static WCHAR __stdcall MockNtdll::RtlpUpcaseUnicodeChar(WCHAR Source);
	static bool __stdcall MockNtdll::RtlPrefixUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, bool CaseInSensitive);
	static char16_t* __stdcall MockNtdll::RtlIpv4AddressToStringW(in_addr *Addr, char16_t* S);
	static void* __stdcall MockNtdll::RtlPcToFileHeader(void* PcValue, void** BaseOfImage);
	static void* __stdcall MockNtdll::RtlImageDirectoryEntryToData(void* BaseAddress, bool MappedAsImage, uint16_t Directory, uint32_t* Size);
	static void __stdcall MockNtdll::MockRtlCaptureContext(void* ContextRecord);
	static void __stdcall MockNtdll::MockRtlRestoreContext(void* ContextRecord, PEXCEPTION_RECORD ExceptionRecord);
	static void __stdcall MockNtdll::MockRtlUnwind(void* TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue);
	static bool __stdcall MockNtdll::MockRtlUnwindEx(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue, void* ContextRecord, void* HistoryTable);
	static PEXCEPTION_ROUTINE __stdcall MockNtdll::RtlVirtualUnwind(
		uint32_t HandlerType,
		uint64_t ImageBase,
		uint64_t ControlPc,
		PRUNTIME_FUNCTION 	FunctionEntry,
		PCONTEXT 	Context,
		void** HandlerData,
		uint64_t* EstablisherFrame,
		PKNONVOLATILE_CONTEXT_POINTERS 	ContextPointers
	);
	static uint32_t __stdcall MockNtdll::RtlNtStatusToDosError(NTSTATUS Status);

	
#else
	static NTSTATUS __stdcall RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
	static NTSTATUS __stdcall EtwRegister(void* ProviderId, void* EnableCallback, void* CallbackContext, void* RegHandle);
	static NTSTATUS __stdcall EtwUnregister(void* RegHandle);

	static NTSTATUS __stdcall NtEnumerateSystemEnvironmentValuesEx(uint32_t InformationClass, void* Buffer, uint32_t* BufferLength);
	static NTSTATUS __stdcall NtEnumerateValueKey(void* KeyHandle, uint32_t Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, uint32_t Length, uint32_t* ResultLength);
	static NTSTATUS __stdcall NtQueryValueKey(void* KeyHandle, void* ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, uint32_t Length, uint32_t* ResultLength);
	static NTSTATUS __stdcall NtOpenSymbolicLinkObject(void** LinkHandle, uint32_t DesiredAccess, void* ObjectAttributes);
	static NTSTATUS __stdcall NtQuerySymbolicLinkObject(void* LinkHandle, UNICODE_STRING* LinkTarget, uint32_t* ReturnedLength);
	static NTSTATUS __stdcall NtClose(void* Handle);
	static NTSTATUS __stdcall NtQueryInformationProcess(void* ProcessHandle, uint32_t ProcessInformationClass, void* ProcessInformation, uint32_t ProcessInformationLength, uint32_t* ReturnLength);
	static NTSTATUS __stdcall NtQueryInformationThread(void* ThreadHandle, uint32_t ThreadInformationClass, void* ThreadInformation, uint32_t ThreadInformationLength, uint32_t* ReturnLength);
	static NTSTATUS __stdcall NtQueryInformationFile(void* FileHandle, void* IoStatusBlock, void* FileInformation, uint32_t Length, uint32_t FileInformationClass);
	static NTSTATUS __stdcall NtQuerySystemInformation(uint32_t SystemInformationClass, void* SystemInformation, uint32_t SystemInformationLength, uint32_t* ReturnLength);
	static NTSTATUS __stdcall NtQueryDirectoryFile(
		void* FileHandle,
		void* Event,
		void* ApcRoutine,
		void* ApcContext,
		void* IoStatusBlock,
		void* FileInformation,
		uint32_t Length,
		uint32_t FileInformationClass,
		bool ReturnSingleEntry,
		PUNICODE_STRING FileName,
		bool RestartScan
	);
	static void* __stdcall RtlCreateHeap(uint32_t Flags, void* HeapBase, size_t ReserveSize, size_t CommitSize, void* Lock, void* Parameters);
	static void* __stdcall RtlAllocateHeap(void* HeapHandle, uint32_t Flags, size_t Size);
	static void __stdcall RtlInitUnicodeString(PUNICODE_STRING DestinationString, char16_t* SourceString);
	static void* __stdcall RtlImageNtHeader(void* ModuleAddress);
	static uint32_t __stdcall RtlImageNtHeaderEx(uint32_t Flags, void* base, uint64_t Size, PIMAGE_NT_HEADERS * OutHeaders);
	static bool __stdcall RtlAddFunctionTable(void* FunctionTable, uint32_t EntryCount, uint64_t BaseAddress);
	static bool __stdcall RtlDeleteFunctionTable(void* FunctionTable);
	static PRUNTIME_FUNCTION __stdcall RtlLookupFunctionEntry(uint64_t ControlPc, uint64_t* ImageBase, void* HistoryTable);
	static PRUNTIME_FUNCTION __stdcall RtlLookupFunctionTable(uint64_t ControlPc, uint64_t* ImageBase, uint32_t* Length);
	static WCHAR __stdcall RtlpUpcaseUnicodeChar(WCHAR Source);
	static bool __stdcall RtlPrefixUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, bool CaseInSensitive);
	static char16_t* __stdcall RtlIpv4AddressToStringW(in_addr *Addr, char16_t* S);
	static void* __stdcall RtlPcToFileHeader(void* PcValue, void** BaseOfImage);
	static void* __stdcall RtlImageDirectoryEntryToData(void* BaseAddress, bool MappedAsImage, uint16_t Directory, uint32_t* Size);
	static void __stdcall MockRtlCaptureContext(void* ContextRecord);
    static void __stdcall MockRtlRestoreContext(void* ContextRecord, PEXCEPTION_RECORD ExceptionRecord);
    static void __stdcall MockRtlUnwind(void* TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue);
	static bool __stdcall MockRtlUnwindEx(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue, void* ContextRecord, void* HistoryTable);
	static PEXCEPTION_ROUTINE __stdcall RtlVirtualUnwind(
		uint32_t HandlerType,
		uint64_t ImageBase,
		uint64_t ControlPc,
		PRUNTIME_FUNCTION 	FunctionEntry,
		PCONTEXT 	Context,
		void** HandlerData,
		uint64_t* EstablisherFrame,
		PKNONVOLATILE_CONTEXT_POINTERS 	ContextPointers
	);
	static uint32_t __stdcall RtlNtStatusToDosError(NTSTATUS Status);
#endif
};
#endif
