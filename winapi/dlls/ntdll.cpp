#if defined(__WINDOWS__)
#pragma warning(disable: 4996)
#endif

#include <cassert>
#include "ntdll.h"
#include "../ntoskrnl.h"

NTSTATUS __stdcall MockNtdll::RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlGetVersion");
	lpVersionInformation->dwMajorVersion = MockNTKrnl::major;
	lpVersionInformation->dwMinorVersion = MockNTKrnl::minor;
	lpVersionInformation->dwBuildNumber = MockNTKrnl::build_version;

	return 0;
}

NTSTATUS __stdcall MockNtdll::EtwRegister(void* ProviderId, void* EnableCallback, void* CallbackContext, void* RegHandle) {
	debug_log("<ntdll.dll!%s> called..\n", "EtwRegister");
	return 0;
}

NTSTATUS __stdcall MockNtdll::EtwUnregister(void* RegHandle){
	debug_log("<ntdll.dll!%s> called..\n", "EtwUnregister");
	return -1;
}

NTSTATUS __stdcall MockNtdll::NtEnumerateSystemEnvironmentValuesEx(uint32_t InformationClass, void* Buffer, uint32_t* BufferLength) {
	debug_log("<ntdll.dll!%s> called..\n", "NtEnumerateSystemEnvironmentValuesEx");
	return 0xC0000002; //STATUS_NOT_IMPLEMENTED
}

NTSTATUS __stdcall MockNtdll::NtEnumerateValueKey(void* KeyHandle, uint32_t Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, uint32_t Length, uint32_t* ResultLength) {
	KEY_VALUE_BASIC_INFORMATION* kvinfo = nullptr;
	string hive;
	string key_str;
	Json::Value key;
	memset(KeyValueInformation, 0, Length);
	uint64_t h = (uint64_t)KeyHandle;
	tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[h];
	uint32_t idx = 0;
    
    debug_log("<ntdll.dll!%s> called..\n", "NtEnumerateValueKey");
    
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
		buf_sz = key_str.length() * sizeof(WCHAR) + sizeof(KEY_VALUE_BASIC_INFORMATION);
		copy_str_to_wstr((char*)key_str.c_str(), (char16_t*)kvinfo->Name, key_str.length());
		kvinfo->NameLength = key_str.length() * sizeof(WCHAR);
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
	char16_t* wstr = read_widestring(ustr->Buffer, ustr->Length);
	char* subkey_str = str_tolower(convert_wstr_to_str(wstr));

	debug_log("<ntdll.dll!%s> called with %s\n", "NtQueryValueKey", subkey_str);

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
	debug_log("<ntdll.dll!%s> called..\n", "NtQueryInformationProcess");
	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQueryInformationThread(void* ThreadHandle, uint32_t ThreadInformationClass, void* ThreadInformation, uint32_t ThreadInformationLength, uint32_t* ReturnLength) {
	debug_log("<ntdll.dll!%s> called..\n", "NtQueryInformationThread");
	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQueryInformationFile(void* FileHandle, void* IoStatusBlock, void* FileInformation, uint32_t Length, uint32_t FileInformationClass) {
	debug_log("<ntdll.dll!%s> called..\n", "NtQueryInformationFile");
	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQuerySystemInformation(uint32_t SystemInformationClass, void* SystemInformation, uint32_t SystemInformationLength, uint32_t* ReturnLength) {
	debug_log("<ntdll.dll!%s> called..\n", "NtQuerySystemInformation");
	return -1;
}

NTSTATUS __stdcall MockNtdll::NtOpenSymbolicLinkObject(void** LinkHandle, uint32_t DesiredAccess, void* ObjectAttributes) {
	debug_log("<ntdll.dll!%s> called..\n", "NtOpenSymbolicLinkObject");
	// this is unsafe
	*LinkHandle = (void*)'swc';
	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQuerySymbolicLinkObject(void* LinkHandle, UNICODE_STRING* LinkTarget, uint32_t* ReturnedLength) {
	debug_log("<ntdll.dll!%s> called..\n", "NtQuerySymbolicLinkObject");
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
	debug_log("<ntdll.dll!%s> called..\n", "NtQueryDirectoryFile");
	return 0; // unsafe
}


NTSTATUS __stdcall MockNtdll::NtClose(void* Handle) {
	debug_log("<ntdll.dll!%s> called..\n", "NtClose");
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

void __stdcall MockNtdll::RtlInitUnicodeString(PUNICODE_STRING DestinationString, char16_t* SourceString) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlInitUnicodeString");
	size_t wstr_len = 0;
	for (; SourceString[wstr_len] != '\0'; wstr_len++) {}
	DestinationString->Length = wstr_len * sizeof(WCHAR);
#if defined(__WINDOWS__)
	DestinationString->Buffer = (wchar_t*)SourceString;
#else
	DestinationString->Buffer = SourceString;
#endif
	DestinationString->MaximumLength = (wstr_len + 1) * sizeof(WCHAR);
}


#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK 1

void* __stdcall MockNtdll::RtlImageNtHeader(void* ModuleAddress) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlImageNtHeader");
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	MockNtdll::RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK, ModuleAddress, 0, &NtHeaders);
	return NtHeaders;
}

uint32_t __stdcall MockNtdll::RtlImageNtHeaderEx(uint32_t Flags, void* Base, uint64_t Size, PIMAGE_NT_HEADERS * OutHeaders) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlImageNtHeaderEx");
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

PRUNTIME_FUNCTION __stdcall MockNtdll::RtlLookupFunctionTable(uint64_t ControlPc, uint64_t* ImageBase, uint32_t* Length) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlLookupFunctionTable");
	void* Table;
	uint32_t Size;

	/* Find corresponding file header from code address */
	if (!MockNtdll::RtlPcToFileHeader((void*)ControlPc, (void**)ImageBase))
	{
		/* Nothing found */
		return NULL;
	}

	/* Locate the exception directory */
	Table = RtlImageDirectoryEntryToData((void*)*ImageBase, true, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &Size);
	*Length = Size / sizeof(RUNTIME_FUNCTION);
	return (PRUNTIME_FUNCTION)Table;
}

bool __stdcall MockNtdll::RtlAddFunctionTable(void* FunctionTable, uint32_t EntryCount, uint64_t BaseAddress) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlAddFunctionTable");
	return true;
}

bool __stdcall MockNtdll::RtlDeleteFunctionTable(void* FunctionTable) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlDeleteFunctionTable");
	return true;
}

PRUNTIME_FUNCTION __stdcall MockNtdll::RtlLookupFunctionEntry(uint64_t ControlPc, uint64_t* ImageBase, void* HistoryTable) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlLookupFunctionEntry");
	PRUNTIME_FUNCTION FunctionTable, FunctionEntry;
	uint32_t TableLength;
	uint32_t IndexLo, IndexHi, IndexMid;

	FunctionTable = MockNtdll::RtlLookupFunctionTable(ControlPc, ImageBase, &TableLength);

	/* Fail, if no table is found */
	if (!FunctionTable)
	{
		return NULL;
	}

	/* Use relative virtual address */
	ControlPc -= *ImageBase;

	/* Do a binary search */
	IndexLo = 0;
	IndexHi = TableLength;
	while (IndexHi > IndexLo)
	{
		IndexMid = (IndexLo + IndexHi) / 2;
		FunctionEntry = &FunctionTable[IndexMid];

		if (ControlPc < FunctionEntry->BeginAddress)
		{
			/* Continue search in lower half */
			IndexHi = IndexMid;
		}
		else if (ControlPc >= FunctionEntry->EndAddress)
		{
			/* Continue search in upper half */
			IndexLo = IndexMid + 1;
		}
		else
		{
			/* ControlPc is within limits, return entry */
			return FunctionEntry;
		}
	}

	/* Nothing found, return NULL */
	return NULL;
}

WCHAR __stdcall MockNtdll::RtlpUpcaseUnicodeChar(WCHAR Source){
	debug_log("<ntdll.dll!%s> called..\n", "RtlpUpcaseUnicodeChar");
	uint16_t Offset;

	if (Source < 'a')
		return Source;

	if (Source <= 'z')
		return (Source - ('a' - 'A'));
	
	return towupper(Source); // maybe not work...
}

bool __stdcall MockNtdll::RtlPrefixUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, bool CaseInSensitive) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlPrefixUnicodeString");

	char16_t* pc1;
	char16_t* pc2;
	uint32_t  NumChars;

	if (String2->Length < String1->Length)
		return false;

	NumChars = String1->Length / sizeof(WCHAR);
	pc1 = (char16_t*)String1->Buffer;
	pc2 = (char16_t*)String2->Buffer;

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

char16_t* __stdcall MockNtdll::RtlIpv4AddressToStringW(in_addr *Addr, char16_t* S) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlIpv4AddressToStringW");

	NTSTATUS Status;
	char16_t* End;
	uint32_t end_offset = 0;
	char mb_ipaddr[32];
	if (!S)
		return (char16_t*)~0;
	
	sprintf(mb_ipaddr, "%u.%u.%u.%u", Addr->S_un.S_un_b.s_b1, Addr->S_un.S_un_b.s_b2, Addr->S_un.S_un_b.s_b3, Addr->S_un.S_un_b.s_b4);
	S = convert_str_to_wstr(mb_ipaddr);
	end_offset = get_wide_string_length((void*)S);
	End = &S[end_offset];
	
	return End;
}

void* __stdcall MockNtdll::RtlPcToFileHeader(void* PcValue, void** BaseOfImage) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlPcToFileHeader");

	PIMAGE_DOS_HEADER dos_header = nullptr;
	PIMAGE_NT_HEADERS64 nt_header = nullptr;
	PIMAGE_OPTIONAL_HEADER64 opt_header = nullptr;
	uint64_t TargetPC = (uint64_t)PcValue;
	dos_header = (PIMAGE_DOS_HEADER)MockNTKrnl::engine_base;
	nt_header = (PIMAGE_NT_HEADERS64)(MockNTKrnl::engine_base + dos_header->e_lfanew);
	opt_header = (PIMAGE_OPTIONAL_HEADER64)(&nt_header->OptionalHeader);
	
	// there is only two case
	if (MockNTKrnl::engine_base <= TargetPC && TargetPC <= MockNTKrnl::engine_base + opt_header->SizeOfImage)
		*BaseOfImage = (void*)MockNTKrnl::engine_base; // mpengine
	else
#if defined(__WINDOWS__)
		*BaseOfImage = (void*)GetModuleHandle(NULL); //self
#elif defined(__APPLE__)
		*BaseOfImage = NULL; //this is error...
#endif
	return *BaseOfImage;
}

void* __stdcall MockNtdll::RtlImageDirectoryEntryToData(void* BaseAddress, bool MappedAsImage, uint16_t Directory, uint32_t* Size) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlImageDirectoryEntryToData");

	PIMAGE_NT_HEADERS nt_header;
	IMAGE_DOS_HEADER* dos_hdr;
	PIMAGE_OPTIONAL_HEADER64 opt_hdr;
	uint32_t Va;
	uint64_t base_addr = (uint64_t)BaseAddress;
	/* Magic flag for non-mapped images. */
	if ((uint64_t)BaseAddress & 1)
	{
		BaseAddress = (void*)((uint64_t)BaseAddress & ~1);
		MappedAsImage = false;
	}
	dos_hdr = (IMAGE_DOS_HEADER*)base_addr;
	nt_header = (IMAGE_NT_HEADERS64*)(base_addr + dos_hdr->e_lfanew);
	
	if (nt_header == NULL)
		return NULL;

	if (nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		opt_hdr = (PIMAGE_OPTIONAL_HEADER64)&nt_header->OptionalHeader;
		if (Directory >= opt_hdr->NumberOfRvaAndSizes)
			return NULL;
		Va = opt_hdr->DataDirectory[Directory].VirtualAddress;
		if (Va == 0)
			return NULL;
		*Size = opt_hdr->DataDirectory[Directory].Size;
		if (MappedAsImage || Va < opt_hdr->SizeOfHeaders)
			return (void*)(base_addr + Va);
	}
	else {
		assert(0); //unsupported arch
	}

	/* Image mapped as ordinary file, we must find raw pointer */
	return NULL; //RtlImageRvaToVa(NtHeader, BaseAddress, Va, NULL);
}

void __stdcall MockNtdll::MockRtlCaptureContext(void* ContextRecord) {
	debug_log("<ntdll.dll!%s> called..\n", "MockRtlCaptureContext");

#if defined (__WINDOWS__) //testing
	RtlCaptureContext((PCONTEXT)ContextRecord);
#else
	ucontext_t uctx;
	int res = getcontext(&uctx);
#endif
	return;
}

void __stdcall MockNtdll::MockRtlRestoreContext(void* ContextRecord, PEXCEPTION_RECORD ExceptionRecord) {
	debug_log("<ntdll.dll!%s> called..\n", "MockRtlRestoreContext");

#if defined (__WINDOWS__) //testing
	RtlRestoreContext((PCONTEXT)ContextRecord, NULL);
#else
	ucontext_t uctx;
	int res = getcontext(&uctx);
#endif
	return;
}


#if defined(__APPLE__)
bool __stdcall get_pthread_stack_info(void** pBase, void** pLimit)
{
	pthread_t thread = pthread_self();
	void*     pBaseTemp = pthread_get_stackaddr_np(thread);
	size_t    stackSize = pthread_get_stacksize_np(thread);

	if (pBase)
		*pBase = pBaseTemp;
	if (pLimit)
	{
		if (pBaseTemp)
			*pLimit = (void*)((size_t)pBaseTemp - stackSize);
		else
			*pLimit = NULL;
	}

	return (pBaseTemp != NULL);
}
#endif


void* __stdcall GetStackLimit()
{
#if defined (__WINDOWS__)
	NT_TIB64* pTIB = (NT_TIB64*)NtCurrentTeb(); // NtCurrentTeb is defined in <WinNT.h> as an inline call to __readgsqword
	return (void*)pTIB->StackLimit;
#elif defined (__APPLE__)
	void* pLimit;
    if (get_pthread_stack_info(NULL, &pLimit))
		return pLimit;
	void* pStack = __builtin_frame_address(0);
	return (void*)((uintptr_t)pStack & ~4095); // Round down to nearest page.
#else
#endif
}

void* __stdcall GetStackBase()
{

#if defined (__WINDOWS__)
	NT_TIB64* pTIB = (NT_TIB64*)NtCurrentTeb(); // NtCurrentTeb is defined in <WinNT.h> as an inline call to __readgsqword
	return (void*)pTIB->StackBase;
#elif defined(__APPLE__)
	void* pBase;
	if (get_pthread_stack_info(&pBase, NULL))
		return pBase;
	return NULL; // error...
#else
#endif
}


void __stdcall RtlpGetStackLimits(uint64_t* StackBase, uint64_t* StackLimit) {
	*StackBase = (uint64_t)GetStackBase();
	*StackLimit = (uint64_t)GetStackLimit();
}

uint64_t __stdcall GetReg(PCONTEXT Context, uint8_t Reg){
	// ref : https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a9ace9ccebdf63147ae998d2680681b7f
	return ((uint64_t*)(&Context->Rax))[Reg];
}

void __stdcall SetReg(PCONTEXT Context, uint8_t Reg, uint64_t Value){
	// ref : https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a78b2ccd05096b35688393fd4bdc25832
	((uint64_t*)(&Context->Rax))[Reg] = Value;
}

void __stdcall SetXmmReg(PCONTEXT Context, uint8_t Reg, M128A Value) {
	// ref : https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a785da3a689cdb0b585a3e189e239bf46
	((M128A*)(&Context->Xmm0))[Reg] = Value;
}

void __stdcall SetRegFromStackValue(PCONTEXT Context, PKNONVOLATILE_CONTEXT_POINTERS ContextPointers, BYTE Reg, uint64_t* ValuePointer) {
	// ref : https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a80af791c0ec8007aaf5bd7b4b7581021
	SetReg(Context, Reg, *ValuePointer);
	if (ContextPointers != NULL)
#if defined(__WINDOWS__)
		ContextPointers->IntegerContext[Reg] = ValuePointer;
#else
		ContextPointers->DUMMYUNIONNAME2.IntegerContext[Reg] = ValuePointer;
#endif
}


void __stdcall SetXmmRegFromStackValue(PCONTEXT Context, PKNONVOLATILE_CONTEXT_POINTERS ContextPointers, uint8_t Reg, M128A* ValuePointer) {
	// ref : https://doxygen.reactos.org/d8/d2f/unwind_8c.html#abf1d715b64bc14cafc7b227fd9d16f04
	SetXmmReg(Context, Reg, *ValuePointer);
	if (ContextPointers != NULL)
#if defined(__WINDOWS__)
		ContextPointers->FloatingContext[Reg] = ValuePointer;
#else
		ContextPointers->DUMMYUNIONNAME.FloatingContext[Reg] = ValuePointer;
#endif
}

void __stdcall PopReg(PCONTEXT Context, PKNONVOLATILE_CONTEXT_POINTERS ContextPointers, uint8_t Reg){
	// ref : https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a1544fd53fb72c4ac529d9a5b9c0cd28e
	SetRegFromStackValue(Context, ContextPointers, Reg, (uint64_t*)Context->Rsp);
	Context->Rsp += sizeof(uint64_t);
}

uint32_t __stdcall UnwindOpSlots(UNWIND_CODE UnwindCode){
	// ref : https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a966d8765847156957762a8a74b411e06
	uint8_t UnwindOpExtraSlotTable[] = {
		0, // UWOP_PUSH_NONVOL
		1, // UWOP_ALLOC_LARGE (or 3, special cased in lookup code)
		0, // UWOP_ALLOC_SMALL
		0, // UWOP_SET_FPREG
		1, // UWOP_SAVE_NONVOL
		2, // UWOP_SAVE_NONVOL_FAR
		1, // UWOP_EPILOG // previously UWOP_SAVE_XMM
		2, // UWOP_SPARE_CODE // previously UWOP_SAVE_XMM_FAR
		1, // UWOP_SAVE_XMM128
		2, // UWOP_SAVE_XMM128_FAR
		0, // UWOP_PUSH_MACHFRAME
		2, // UWOP_SET_FPREG_LARGE
	};

	if ((UnwindCode.UnwindOp == UWOP_ALLOC_LARGE) && (UnwindCode.OpInfo != 0))
		return 3;
	else
		return UnwindOpExtraSlotTable[UnwindCode.UnwindOp] + 1;
}

uint64_t __stdcall GetEstablisherFrame(PCONTEXT Context, PUNWIND_INFO UnwindInfo, uint64_t CodeOffset) {
	// ref : https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a57ef599c611dcdefb93d5bda32af4819
	uint32_t i;
	if (UnwindInfo->FrameRegister == 0)
		return Context->Rsp;

	if ((CodeOffset >= UnwindInfo->SizeOfProlog) ||
		((UnwindInfo->Flags & UNW_FLAG_CHAININFO) != 0)){
		return GetReg(Context, UnwindInfo->FrameRegister) - UnwindInfo->FrameOffset * 16;
	}
	for (i = 0; i < UnwindInfo->CountOfCodes; i += UnwindOpSlots(UnwindInfo->UnwindCode[i])){
		if (UnwindInfo->UnwindCode[i].UnwindOp == UWOP_SET_FPREG)
			return GetReg(Context, UnwindInfo->FrameRegister) - UnwindInfo->FrameOffset * 16;
	}

	return Context->Rsp;
}

void __stdcall MockNtdll::MockRtlUnwind(void* TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue) {
	// this is wrapper of MockRtlUnwindEx
}

bool __stdcall RtlpTryToUnwindEpilog(PCONTEXT Context, PKNONVOLATILE_CONTEXT_POINTERS ContextPointers, uint64_t ImageBase, PRUNTIME_FUNCTION FunctionEntry) {
	// ref : https://doxygen.reactos.org/d8/d2f/unwind_8c.html#ab1254c449095abb6946019d9f3a00fd7
	CONTEXT LocalContext;
	uint8_t *InstrPtr;
	uint32_t Instr;
	uint8_t Reg, Mod;
	uint64_t EndAddress;

	LocalContext = *Context;
	InstrPtr = (uint8_t*)LocalContext.Rip;
	Instr = *(uint32_t*)InstrPtr;

	if ((Instr & 0x00fffdff) == 0x00c48148){
		if ((Instr & 0x0000ff00) == 0x8300){
			LocalContext.Rsp += Instr >> 24;
			InstrPtr += 4;
		}
		else{
			LocalContext.Rsp += *(uint32_t*)(InstrPtr + 3);
			InstrPtr += 7;
		}
	}
	else if ((Instr & 0x38fffe) == 0x208d48){
		Reg = ((Instr << 8) | (Instr >> 16)) & 0x7;
		LocalContext.Rsp = GetReg(&LocalContext, Reg);
		Mod = (Instr >> 22) & 0x3;
		if (Mod == 0){
			InstrPtr += 3;
		}
		else if (Mod == 1){
			LocalContext.Rsp += Instr >> 24;
			InstrPtr += 4;
		}
		else if (Mod == 2){
			LocalContext.Rsp += *(uint32_t*)(InstrPtr + 3);
			InstrPtr += 7;
		}
	}
	EndAddress = FunctionEntry->EndAddress + ImageBase - 1;
	while ((uint64_t)InstrPtr < EndAddress){
		Instr = *(uint32_t*)InstrPtr;
		if ((Instr & 0xf8) == 0x58){
			Reg = Instr & 0x7;
			PopReg(&LocalContext, ContextPointers, Reg);
			InstrPtr++;
			continue;
		}
		if ((Instr & 0xf8fb) == 0x5841){
			Reg = ((Instr >> 8) & 0x7) + 8;
			PopReg(&LocalContext, ContextPointers, Reg);
			InstrPtr += 2;
			continue;
		}
		return false;
	}
	if ((uint64_t)InstrPtr != EndAddress){
		assert((uint64_t)InstrPtr <= EndAddress);
		return false;
	}
	if (*InstrPtr != 0xc3){
		// continue forcefully
		return false;
	}
	LocalContext.Rip = *(uint64_t*)LocalContext.Rsp;
	LocalContext.Rsp += sizeof(uint64_t);

	*Context = LocalContext;
	return true;
}

PEXCEPTION_ROUTINE __stdcall MockNtdll::RtlVirtualUnwind(
	uint32_t HandlerType,
	uint64_t ImageBase,
	uint64_t ControlPc,
	PRUNTIME_FUNCTION 	FunctionEntry,
	PCONTEXT 	Context,
	void** HandlerData,
	uint64_t* EstablisherFrame,
	PKNONVOLATILE_CONTEXT_POINTERS 	ContextPointers
)
// ref : https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a03c91b6c437066272ebc2c2fff051a4c
	{
	debug_log("<ntdll.dll!%s> called..\n", "RtlVirtualUnwind");

		PUNWIND_INFO UnwindInfo;
		uint64_t CodeOffset;
		uint32_t i, Offset;
		UNWIND_CODE UnwindCode;
		uint8_t Reg;
		uint32_t* LanguageHandler;

		ControlPc -= ImageBase;

		if ((ControlPc < FunctionEntry->BeginAddress) || (ControlPc >= FunctionEntry->EndAddress)){
			return NULL;
		}
		UnwindInfo = (PUNWIND_INFO)(ImageBase + FunctionEntry->UnwindData);
		LanguageHandler = (uint32_t*)ALIGN_UP_POINTER_BY(&UnwindInfo->UnwindCode[UnwindInfo->CountOfCodes], sizeof(uint32_t));
		*HandlerData = (LanguageHandler + 1);
		CodeOffset = ControlPc - FunctionEntry->BeginAddress;

		*EstablisherFrame = GetEstablisherFrame(Context, UnwindInfo, CodeOffset);
		if (CodeOffset > UnwindInfo->SizeOfProlog){
			if (RtlpTryToUnwindEpilog(Context, ContextPointers, ImageBase, FunctionEntry)){
				return NULL;
			}
		}
		i = 0;
		while ((i < UnwindInfo->CountOfCodes) && (UnwindInfo->UnwindCode[i].CodeOffset > CodeOffset)){
			i += UnwindOpSlots(UnwindInfo->UnwindCode[i]);
		}

RepeatChainedInfo:
		while (i < UnwindInfo->CountOfCodes){
			UnwindCode = UnwindInfo->UnwindCode[i];
			switch (UnwindCode.UnwindOp){

			case UWOP_PUSH_NONVOL:
				Reg = UnwindCode.OpInfo;
				PopReg(Context, ContextPointers, Reg);
				i++;
				break;

			case UWOP_ALLOC_LARGE:
				if (UnwindCode.OpInfo){
					Offset = *(uint32_t*)(&UnwindInfo->UnwindCode[i + 1]);
					Context->Rsp += Offset;
					i += 3;
				}
				else{
					Offset = UnwindInfo->UnwindCode[i + 1].FrameOffset;
					Context->Rsp += Offset * 8;
					i += 2;
				}
				break;

			case UWOP_ALLOC_SMALL:
				Context->Rsp += (UnwindCode.OpInfo + 1) * 8;
				i++;
				break;

			case UWOP_SET_FPREG:
				Reg = UnwindInfo->FrameRegister;
				Context->Rsp = GetReg(Context, Reg) - UnwindInfo->FrameOffset * 16;
				i++;
				break;

			case UWOP_SAVE_NONVOL:
				Reg = UnwindCode.OpInfo;
				Offset = *(USHORT*)(&UnwindInfo->UnwindCode[i + 1]);
				SetRegFromStackValue(Context, ContextPointers, Reg, (uint64_t*)Context->Rsp + Offset);
				i += 2;
				break;

			case UWOP_SAVE_NONVOL_FAR:
				Reg = UnwindCode.OpInfo;
				Offset = *(uint32_t*)(&UnwindInfo->UnwindCode[i + 1]);
				SetRegFromStackValue(Context, ContextPointers, Reg, (uint64_t*)Context->Rsp + Offset);
				i += 3;
				break;

			case UWOP_EPILOG:
				i += 1;
				break;

			case UWOP_SPARE_CODE:
				assert(0);
				i += 2;
				break;

			case UWOP_SAVE_XMM128:
				Reg = UnwindCode.OpInfo;
				Offset = *(uint16_t*)(&UnwindInfo->UnwindCode[i + 1]);
				SetXmmRegFromStackValue(Context, ContextPointers, Reg, (M128A*)(Context->Rsp + Offset));
				i += 2;
				break;

			case UWOP_SAVE_XMM128_FAR:
				Reg = UnwindCode.OpInfo;
				Offset = *(uint32_t*)(&UnwindInfo->UnwindCode[i + 1]);
				SetXmmRegFromStackValue(Context, ContextPointers, Reg, (M128A*)(Context->Rsp + Offset));
				i += 3;
				break;

			case UWOP_PUSH_MACHFRAME:
				Context->Rsp += UnwindCode.OpInfo * sizeof(uint64_t);
				Context->Rip = *(uint64_t*)(Context->Rsp + 0x00);
				Context->SegCs = *(uint64_t*)(Context->Rsp + 0x08);
				Context->EFlags = *(uint64_t*)(Context->Rsp + 0x10);
				Context->SegSs = *(uint64_t*)(Context->Rsp + 0x20);
				Context->Rsp = *(uint64_t*)(Context->Rsp + 0x18);
				assert((i + 1) == UnwindInfo->CountOfCodes);
				goto Exit;
			}
		}
		if (UnwindInfo->Flags & UNW_FLAG_CHAININFO){
			/* See https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-160#chained-unwind-info-structures */
			FunctionEntry = (PRUNTIME_FUNCTION)&(UnwindInfo->UnwindCode[(UnwindInfo->CountOfCodes + 1) & ~1]);
			UnwindInfo = (PUNWIND_INFO)(ImageBase + FunctionEntry->UnwindData);
			i = 0;
			goto RepeatChainedInfo;
		}
		if (Context->Rsp != 0){
			Context->Rip = *(uint64_t*)Context->Rsp;
			Context->Rsp += sizeof(uint64_t);
		}

Exit:
		if (UnwindInfo->Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))
			return (PEXCEPTION_ROUTINE)(ImageBase + *LanguageHandler);

		return NULL;
}

void __stdcall RtlpUnwindInternal(
	// ref : https://doxygen.reactos.org/d6/dea/sdk_2lib_2rtl_2amd64_2except_8c.html#abfbd00808c64b2e9fd3b0b63dd181135
	void* 	TargetFrame,
	void* 	TargetIp,
	PEXCEPTION_RECORD 	ExceptionRecord,
	void* 	ReturnValue,
	PCONTEXT 	ContextRecord,
	struct _UNWIND_HISTORY_TABLE * 	HistoryTable,
	uint32_t 	HandlerType
){
	DISPATCHER_CONTEXT DispatcherContext;
	PEXCEPTION_ROUTINE ExceptionRoutine;
	EXCEPTION_DISPOSITION Disposition;
	PRUNTIME_FUNCTION FunctionEntry;
	ULONG_PTR StackLow, StackHigh;
	uint64_t ImageBase, EstablisherFrame;
	CONTEXT UnwindContext;
	RtlpGetStackLimits(&StackLow, &StackHigh);

	if (TargetFrame != NULL){
		StackHigh = (uint64_t)TargetFrame + 1;
	}

	UnwindContext = *ContextRecord;

	DispatcherContext.ContextRecord = ContextRecord;
	DispatcherContext.HistoryTable = HistoryTable;
	DispatcherContext.TargetIp = (uint64_t)TargetIp;

	while (true)
	{
		FunctionEntry = MockNtdll::RtlLookupFunctionEntry(UnwindContext.Rip, &ImageBase, NULL);
		if (FunctionEntry == NULL){
			UnwindContext.Rip = *(uint64_t*)UnwindContext.Rsp;
			UnwindContext.Rsp += sizeof(uint64_t);
			continue;
		}

		/* Do a virtual unwind to get the next frame */
		ExceptionRoutine = MockNtdll::RtlVirtualUnwind(
								HandlerType,
								ImageBase,
								UnwindContext.Rip,
								FunctionEntry,
								&UnwindContext,
								&DispatcherContext.HandlerData,
								&EstablisherFrame,
								NULL
							);

		if ((EstablisherFrame < StackLow) || (EstablisherFrame >= StackHigh) || (EstablisherFrame & 7)){
			if (HandlerType == UNW_FLAG_EHANDLER){
				ExceptionRecord->ExceptionFlags |= EXCEPTION_STACK_INVALID;
				return;
			}
		}

		if (ExceptionRoutine != NULL){
			if (EstablisherFrame == (uint64_t)TargetFrame){
				ExceptionRecord->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
			}

			DispatcherContext.ControlPc = ContextRecord->Rip;
			DispatcherContext.ImageBase = ImageBase;
			DispatcherContext.FunctionEntry = FunctionEntry;
			DispatcherContext.LanguageHandler = ExceptionRoutine;
			DispatcherContext.EstablisherFrame = EstablisherFrame;
			DispatcherContext.ScopeIndex = 0;

			UnwindContext.Rax = (uint64_t)ReturnValue;
			do{
				Disposition = ExceptionRoutine(
									ExceptionRecord,
									(void*)EstablisherFrame,
									&UnwindContext,
									&DispatcherContext
								);

				ExceptionRecord->ExceptionFlags &= ~(EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND);

				if (HandlerType == UNW_FLAG_EHANDLER){
					if (Disposition == ExceptionContinueExecution){
						if (ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE){
							// not ported!!	
						}
						return;
					}
					else if (Disposition == ExceptionNestedException){
						// not ported!!
					}
				}

				if (Disposition == ExceptionCollidedUnwind){
					// not ported!!
				}

				
				if (Disposition != ExceptionContinueSearch){
					// not ported!!
				}
			} while (ExceptionRecord->ExceptionFlags & EXCEPTION_COLLIDED_UNWIND);
		}

		if ((EstablisherFrame < StackLow) ||
			(EstablisherFrame > StackHigh) ||
			(EstablisherFrame & 7)){
			if (UnwindContext.Rip == ContextRecord->Rip){/*not ported!!*/}
			else{/*not ported!!*/ }
		}

		if (EstablisherFrame == (uint64_t)TargetFrame){
			break;
		}
		*ContextRecord = UnwindContext;
	}
	if (ExceptionRecord->ExceptionCode != STATUS_UNWIND_CONSOLIDATE)
	{
		ContextRecord->Rip = (uint64_t)TargetIp;
	}
	ContextRecord->Rax = (uint64_t)ReturnValue;
	//RtlRestoreContext(ContextRecord, ExceptionRecord);
	MockNtdll::MockRtlRestoreContext(ContextRecord, ExceptionRecord);
	return;
}

bool __stdcall MockNtdll::MockRtlUnwindEx(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue, void* ContextRecord, void* HistoryTable) {
	//it is directly called, not called by RtlDispatchException
    debug_log("<ntdll.dll!%s> called..\n", "MockRtlUnwindEx");
    EXCEPTION_RECORD LocalExceptionRecord;
#if defined(__WINDOWS__)
	PCONTEXT ctx = (PCONTEXT)ContextRecord;
	MockNtdll::MockRtlCaptureContext(ctx);
	
#elif defined(__APPLE__)
    #define GET_RSP(sp) __asm__ __volatile__("movq %%rsp,%0": "=r" (sp));
    #define GET_RBP(sp) __asm__ __volatile__("movq %%rbp,%0": "=r" (sp));
    PCONTEXT ctx = (PCONTEXT)ContextRecord;
    void* _rsp;
    void* _rbp;
    uint64_t prev_rbp;
    uint64_t prev_rsp;
    uint64_t ret_val;
    GET_RSP(_rsp);
    GET_RBP(_rbp);
    prev_rsp = (uint64_t)_rsp + 0x1F0;
    prev_rbp = prev_rsp + 0x610;
    ret_val = *(uint64_t*)((uint64_t)_rbp+0x8) - 0x5;
#else
#endif
    if (ExceptionRecord == NULL){
        /* No exception record was passed, so set up a local one */
        LocalExceptionRecord.ExceptionCode = 0xC0000028;
        LocalExceptionRecord.ExceptionAddress = (PVOID)ctx->Rip;
        LocalExceptionRecord.ExceptionRecord = NULL;
        LocalExceptionRecord.NumberParameters = 0;
        ExceptionRecord = &LocalExceptionRecord;
    }
    ctx->Rsp = (uint64_t)prev_rsp;
    ctx->Rbp = (uint64_t)prev_rbp;
    ctx->Rip = ret_val;
    RtlpUnwindInternal(TargetFrame, TargetIp, (EXCEPTION_RECORD*)ExceptionRecord, ReturnValue, (PCONTEXT)ContextRecord, (_UNWIND_HISTORY_TABLE*)HistoryTable, UNW_FLAG_UHANDLER);
	return true;
}

uint32_t __stdcall MockNtdll::RtlNtStatusToDosError(NTSTATUS Status) {
	debug_log("<ntdll.dll!%s> called..\n", "RtlNtStatusToDosError");
    
	return 0x13D; //ERROR_MR_MID_NOT_FOUND
}
