#include "ntdll.h"
#include "../ntoskrnl.h"
#include <cassert>




NTSTATUS __stdcall MockNtdll::RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation) {
	lpVersionInformation->dwMajorVersion = MockNTKrnl::major;
	lpVersionInformation->dwMinorVersion = MockNTKrnl::minor;
	lpVersionInformation->dwBuildNumber = MockNTKrnl::build_version;

	return 0;
}

NTSTATUS __stdcall MockNtdll::EtwRegister(void* ProviderId, void* EnableCallback, void* CallbackContext, void* RegHandle) {
	return 0;
}

NTSTATUS __stdcall MockNtdll::EtwUnregister(void* RegHandle){
	return -1;
}

NTSTATUS __stdcall MockNtdll::NtEnumerateSystemEnvironmentValuesEx(uint32_t InformationClass, void* Buffer, uint32_t* BufferLength) {
	return 0xC0000002; //STATUS_NOT_IMPLEMENTED
}

NTSTATUS __stdcall MockNtdll::NtEnumerateValueKey(void* KeyHandle, uint32_t Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, uint32_t Length, uint32_t* ResultLength) {
	KEY_VALUE_BASIC_INFORMATION* kvinfo = nullptr;

	string hive;
	string key_str;
	Json::Value key;
	memset(KeyValueInformation, 0, Length);
	uintptr_t h = (uintptr_t)KeyHandle;
	tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[h];
	uint32_t idx = 0;
	auto it = key.begin();
	for (; it != key.end(); ++it){
		if (key[it.key().asString()].isObject())
			continue;
		if (idx == Index)
			break;
		idx++;
	}
	if (it == key.end()) {
		/*can't get value of target index*/
		return 0x8000001A; // STATUS_NO_MORE_ENTRIES;
	}

	key_str = it.key().asString();
	auto subkey = key[key_str];
	
	uint32_t regtype = 0;
	if (subkey.isString()) {
		regtype = 0x2; //REG_EXPAND_SZ;

	}
	else if (subkey.isInt64() || subkey.isInt()) {
		regtype = 0x4; //REG_DWORD
	}
	else {
		assert(0);
	}
	uint32_t buf_sz = 0;
	switch (KeyValueInformationClass)
	{
	case KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation:
		kvinfo = (KEY_VALUE_BASIC_INFORMATION*)KeyValueInformation;
		kvinfo->TitleIndex = 0;
		kvinfo->Type = regtype;
		kvinfo->NameLength = 0;
		buf_sz = key_str.length() * sizeof(wchar_t) + sizeof(KEY_VALUE_BASIC_INFORMATION);
		copy_str_to_wstr((char*)key_str.c_str(), kvinfo->Name, key_str.length());
		kvinfo->NameLength = key_str.length() * sizeof(wchar_t);
		*ResultLength = buf_sz;
		if (buf_sz > Length) {
			return 0x80000005; //STATUS_BUFFER_OVERFLOW
		}
		break;
	case KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation:
	case KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformation:
	default:
		assert(0);
		break;
	}

	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQueryValueKey(void* KeyHandle, void* ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, uint32_t Length, uint32_t* ResultLength) {
	string hive;
	string key_str;
	Json::Value key;
	KEY_VALUE_PARTIAL_INFORMATION* kvpi;
	PUNICODE_STRING ustr = (PUNICODE_STRING)ValueName;
	
	tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(uint64_t)KeyHandle];
	wchar_t* wstr = read_widestring(ustr->Buffer, ustr->Length);
	char* subkey_str = str_tolower(convert_wstr_to_str(wstr));
	auto subkey = key[subkey_str];
	delete wstr;
	delete subkey_str;

	if (!subkey) {
		return 0xc0000034; //STATUS_OBJECT_NAME_NOT_FOUND
	}

	uint32_t regtype = 0;
	uint32_t required_sz = 0;

	if (KeyValueInformationClass == KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation) {
		assert(0);
	}
	else if (KeyValueInformationClass == KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation) {
		assert(0);
	}
	else if (KeyValueInformationClass == KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformation) {
		kvpi = (KEY_VALUE_PARTIAL_INFORMATION*)KeyValueInformation;
		if (subkey.isString()) {
			regtype = 0x2;//REG_EXPAND_SZ;
			string subkey_value = subkey.asString();
			size_t value_sz = subkey_value.length();
			required_sz = value_sz + sizeof(KEY_VALUE_PARTIAL_INFORMATION);
			kvpi->TitleIndex = 0;
			kvpi->Type = 0x2;
			kvpi->DataLength = value_sz;
			*ResultLength = required_sz;
			if (required_sz > Length) {
				return 0x80000005; //STATUS_BUFFER_OVERFLOW
			}
			memmove(kvpi->Data, subkey_value.c_str(), value_sz);
		}
		else if (subkey.isInt() || subkey.isInt64()) {
			regtype = 0x4; //REG_DWORD
			uint32_t subkey_value = subkey.asInt();
			uint32_t value_sz = sizeof(uint32_t);
			required_sz = value_sz; +sizeof(KEY_VALUE_PARTIAL_INFORMATION);
			kvpi->TitleIndex = 0;
			kvpi->Type = 0x4;
			kvpi->DataLength = value_sz;
			*ResultLength = required_sz;
			if (required_sz > Length) {
				return 0x80000005; //STATUS_BUFFER_OVERFLOW
			}
			memmove(kvpi->Data, &subkey_value, value_sz);
		}
		else {
			assert(0);
		}
	}
	else {
		assert(0);
	}
	return 0;
}


NTSTATUS __stdcall MockNtdll::NtQueryInformationProcess(void* ProcessHandle, uint32_t ProcessInformationClass, void* ProcessInformation, uint32_t ProcessInformationLength, uint32_t* ReturnLength) {
	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQueryInformationThread(void* ThreadHandle, uint32_t ThreadInformationClass, void* ThreadInformation, uint32_t ThreadInformationLength, uint32_t* ReturnLength) {
	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQueryInformationFile(void* FileHandle, void* IoStatusBlock, void* FileInformation, uint32_t Length, uint32_t FileInformationClass) {
	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQuerySystemInformation(uint32_t SystemInformationClass, void* SystemInformation, uint32_t SystemInformationLength, uint32_t* ReturnLength) {
	return -1;
}

NTSTATUS __stdcall MockNtdll::NtOpenSymbolicLinkObject(void** LinkHandle, uint32_t DesiredAccess, void* ObjectAttributes) {
	// this is unsafe
	*LinkHandle = (void*)'swc';
	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQuerySymbolicLinkObject(void* LinkHandle, UNICODE_STRING* LinkTarget, uint32_t* ReturnedLength) {
	if (LinkHandle == (void*)INVALID_HANDLE_VALUE)
		return 0xC0000008;
	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQueryDirectoryFile(
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
) {
	return 0; // unsafe
}


NTSTATUS __stdcall MockNtdll::NtClose(void* Handle) {
	if (Handle == (void*)INVALID_HANDLE_VALUE)
		return 0xC0000008;
	return 0;
}

void* __stdcall MockNtdll::RtlCreateHeap(uint32_t Flags, void* HeapBase, size_t ReserveSize, size_t CommitSize, void* Lock, void* Parameters) {
	return NULL;
}

void* __stdcall MockNtdll::RtlAllocateHeap(void* HeapHandle, uint32_t Flags, size_t Size) {
	return NULL;
}

void __stdcall MockNtdll::RtlInitUnicodeString(PUNICODE_STRING DestinationString, wchar_t* SourceString) {
	size_t wstr_len = 0;
	for (; SourceString[wstr_len] != '\0'; wstr_len++) {}
	DestinationString->Length = wstr_len * sizeof(wchar_t);
	DestinationString->Buffer = SourceString;
	DestinationString->MaximumLength = (wstr_len + 1) * sizeof(wchar_t);
}


#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK 1

void* __stdcall MockNtdll::RtlImageNtHeader(void* ModuleAddress) {
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	MockNtdll::RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK, ModuleAddress, 0, &NtHeaders);
	return NtHeaders;
}

uint32_t __stdcall MockNtdll::RtlImageNtHeaderEx(uint32_t Flags, void* Base, uint64_t Size, PIMAGE_NT_HEADERS * OutHeaders) {
	PIMAGE_NT_HEADERS NtHeaders = 0;
	ULONG e_lfanew = 0;
	BOOLEAN RangeCheck = 0;
	NTSTATUS Status = 0;
	const ULONG ValidFlags = 1;

	if (OutHeaders != NULL) {
		*OutHeaders = NULL;
	}
	if (OutHeaders == NULL) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}
	if ((Flags & ~ValidFlags) != 0) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}
	if (Base == NULL || Base == (PVOID)(LONG_PTR)-1) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	RangeCheck = ((Flags & RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK) == 0);
	if (RangeCheck) {
		if (Size < sizeof(IMAGE_DOS_HEADER)) {
			Status = 0xC000007B;
			goto Exit;
		}
	}

	//
	// Exception handling is not available in the boot loader, and exceptions
	// were not historically caught here in kernel mode. Drivers are considered
	// trusted, so we can't get an exception here due to a bad file, but we
	// could take an inpage error.
	//
#define EXIT goto Exit
	if (((PIMAGE_DOS_HEADER)Base)->e_magic != IMAGE_DOS_SIGNATURE) {
		Status = 0xC000007B;
		EXIT;
	}
	e_lfanew = ((PIMAGE_DOS_HEADER)Base)->e_lfanew;

	NtHeaders = (PIMAGE_NT_HEADERS)((char*)Base + e_lfanew);

	

	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		Status = 0xC000007B;
		EXIT;
	}
	Status = 0;

Exit:
	if (!Status) {
		*OutHeaders = NtHeaders;
	}
	return Status;
}

bool __stdcall MockNtdll::RtlAddFunctionTable(void* FunctionTable, uint32_t EntryCount, uint64_t BaseAddress) {
	return true;
}

bool __stdcall MockNtdll::RtlDeleteFunctionTable(void* FunctionTable) {
	return true;
}

void* __stdcall MockNtdll::RtlLookupFunctionEntry(uint64_t ControlPc, uint64_t* ImageBase, void* HistoryTable) {
	return NULL;
}


wchar_t __stdcall MockNtdll::RtlpUpcaseUnicodeChar(wchar_t Source){
	uint16_t Offset;

	if (Source < 'a')
		return Source;

	if (Source <= 'z')
		return (Source - ('a' - 'A'));
	
	return towupper(Source); // maybe not work...
}

bool __stdcall MockNtdll::RtlPrefixUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, bool CaseInSensitive) {
	wchar_t* pc1;
	wchar_t* pc2;
	uint32_t  NumChars;

	if (String2->Length < String1->Length)
		return false;

	NumChars = String1->Length / sizeof(wchar_t);
	pc1 = String1->Buffer;
	pc2 = String2->Buffer;

	if (pc1 && pc2){
		if (CaseInSensitive){
			while (NumChars--){
				if (RtlpUpcaseUnicodeChar(*pc1++) != RtlpUpcaseUnicodeChar(*pc2++))
					return false;
			}
		}
		else{
			while (NumChars--){
				if (*pc1++ != *pc2++)
					return false;
			}
		}
		return true;
	}

	return false;
}

wchar_t* __stdcall MockNtdll::RtlIpv4AddressToStringW(in_addr *Addr, wchar_t* S) {
	NTSTATUS Status;
	wchar_t* End;
	uint32_t end_offset = 0;
	if (!S)
		return (PWSTR)~0;
	swprintf(S, 32, L"%u.%u.%u.%u", Addr->S_un.S_un_b.s_b1, Addr->S_un.S_un_b.s_b2, Addr->S_un.S_un_b.s_b3, Addr->S_un.S_un_b.s_b4);
	end_offset = lstrlenW(S);
	End = &S[end_offset];
	
	return End;
}

void __stdcall MockNtdll::RtlCaptureContext(void* ContextRecord) {
#if defined (__WINDOWS__)
#else
	ucontext_t uctx;
	int res = getcontext(&uctx);
#endif
	return;
}

void* __stdcall MockNtdll::RtlVirtualUnwind(uint32_t HandlerType, uint64_t ImageBase, uint64_t ControlPc, void* FunctionEntry, void* ContextRecord, void** HanderData, uint64_t* EstablisherFrame, void* ContextPointers) {
	return NULL;
}
void __stdcall MockNtdll::RtlUnwindEx(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue, void* ContextRecord, void* HistoryTable) {
	return;
}

uint32_t __stdcall MockNtdll::RtlNtStatusToDosError(NTSTATUS Status) {
	return 0x13D; //ERROR_MR_MID_NOT_FOUND
}
