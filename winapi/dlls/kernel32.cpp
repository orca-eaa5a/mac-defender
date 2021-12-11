#pragma warning(disable: 4996)

#include <string>
#include <windows.h>
#include <ctime>
#include <thread>
#include <algorithm>
#include "kernel32.h"
#include "utils.hpp"
using namespace std;

void* MockKernel32::mpengine_base = nullptr;
string MockKernel32::commandline;
wstring MockKernel32::wcommandline;
unsigned long long MockKernel32::ThreadLocalStorage[1024];
PFLS_CALLBACK_FUNCTION MockKernel32::FlsCallbacks[1024];
unsigned int MockKernel32::tls_index = 1;
unsigned int MockKernel32::tick_counter = 0;

void __stdcall MockKernel32::SetLastError(unsigned int dwErrCode) {
	MockNTKrnl::errcode = dwErrCode;
}

unsigned int __stdcall MockKernel32::GetLastError() {
	return MockNTKrnl::errcode;
}

void __stdcall MockKernel32::GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo) {
	//lpStartupInfo->cb = sizeof(STARTUPINFOA);
	return;
}
void __stdcall MockKernel32::GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo) {
	//lpStartupInfo->cb = sizeof(STARTUPINFOW);
	return;
}
/*
void* __stdcall MockKernel32::GetModuleHandleA(char* lpModuleName) {
	if (lpModuleName && memcmp(lpModuleName, "mpengine.dll", strlen("mpengine.dll")) == 0)
		return MockKernel32::mpengine_base;
	else if (lpModuleName && memcmp(lpModuleName, "bcrypt.dll", strlen("bcrypt.dll")) == 0)
		return (void*)'orca';
	else if (lpModuleName && memcmp(lpModuleName, "KERNEL32.DLL", strlen("KERNEL32.DLL")) == 0)
		return (void*)'evil';
	else if (lpModuleName && memcmp(lpModuleName, "kernel32.dll", strlen("kernel32.dll")) == 0)
		return (void*)'mali';
	else if (lpModuleName && memcmp(lpModuleName, "version.dll", strlen("version.dll")) == 0)
		return (void*)'hack';
	else
		return (void*)NULL;
}
*/

void* __stdcall MockKernel32::GetModuleHandleW(wchar_t* lpModuleName)
{
	char *name = convert_wstr_to_str(lpModuleName);
	HANDLE mod = GetModuleHandle(name);
	delete name;
	if (lpModuleName && memcmp(lpModuleName, L"mpengine.dll", sizeof(L"mpengine.dll")) == 0)
		return MockKernel32::mpengine_base;
	else if (lpModuleName && memcmp(lpModuleName, L"bcrypt.dll", sizeof(L"bcrypt.dll")) == 0)
		return (void*)mod;
	else if (lpModuleName && memcmp(lpModuleName, L"KERNEL32.DLL", sizeof(L"KERNEL32.DLL")) == 0)
		return (void*)mod;
	else if (lpModuleName && memcmp(lpModuleName, L"kernel32.dll", sizeof(L"kernel32.dll")) == 0)
		return (void*)mod;
	else if (lpModuleName && memcmp(lpModuleName, L"version.dll", sizeof(L"version.dll")) == 0)
		return (void*)mod;
	else
		return (void*)NULL;
}

bool __stdcall MockKernel32::GetModuleHandleExA(unsigned int dwFlags, char* lpModuleName, void* phModule) {
	char* _phModule = (char*)phModule;
	memset(phModule, (int)0, sizeof(void*));
	return true;
}

bool __stdcall MockKernel32::GetModuleHandleExW(unsigned int dwFlags, wchar_t* lpModuleName, void* phModule) {
	char* str_modname = convert_wstr_to_str(lpModuleName);
	bool ret = false;
	ret = MockKernel32::GetModuleHandleExA(dwFlags, str_modname, phModule);
	delete str_modname;
	return ret;
}

void* __stdcall MockKernel32::MyGetProcAddress(void* hModule, char* lpProcName) {
	for (auto const& mod_name : APIExports::exports) {
		for (auto const& proc_name : APIExports::exports[mod_name.first]) {
			if (strcmp(proc_name.first.c_str(), lpProcName) == 0) {
				return proc_name.second;
			}
		}
	}
	return GetProcAddress((HMODULE)hModule, lpProcName);
}


unsigned int __stdcall MockKernel32::GetModuleFileNameA(void* hModule, char* lpFilename, unsigned int nSize) {
	string mock_file_name = "C:\\orca\\angle.exe";
	size_t str_buf_sz = mock_file_name.length();
	if (hModule == NULL && nSize > str_buf_sz) {
		memmove(lpFilename, mock_file_name.c_str(), str_buf_sz);
		return str_buf_sz;
	}
	return 0; // never reached
}

unsigned int __stdcall MockKernel32::GetModuleFileNameW(void* hModule, wchar_t* lpFileName, unsigned int nSize) {
	wstring mock_file_namew = L"C:\\orca\\angle.exe";
	size_t str_buf_sz = mock_file_namew.length()*sizeof(wchar_t);

	if (hModule == NULL && nSize > str_buf_sz) {
		memmove(lpFileName, mock_file_namew.c_str(), str_buf_sz);
		return str_buf_sz;
	}
	return 0; // never reached
}

void* __stdcall MockKernel32::LoadLibraryExW(wchar_t* lpLibFileName, void* hFile, unsigned int dwFlags) {
	char *name = convert_wstr_to_str(lpLibFileName);
	HINSTANCE mod = LoadLibraryA(name);
	delete name;
	return (void*)mod;
}


void* __stdcall MockKernel32::CreateFileA(char* lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode, void* lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes, void* hTemplateFile) {
	//UNIX
		//while (strchr(filename, '\\'))
		//	*strchr(filename, '\\') = '/';

	FILE *FileHandle;
	FILE* tmp;

#ifdef _WIN64
	//convert_winpath_to_unixpath(lpFileName);
	convert_unixpath_to_winpath(lpFileName);
	switch (dwCreationDisposition) {
	case OPEN_EXISTING:
		FileHandle = fopen(lpFileName, "rb");
		break;
	case CREATE_ALWAYS:
		FileHandle = fopen(lpFileName, "wb");
		break;
	case CREATE_NEW:
		if (tmp = fopen(lpFileName, "rb")) {
			fclose(tmp);
			FileHandle = fopen(lpFileName, "wb");
		}
		else {
			FileHandle = (FILE*)INVALID_HANDLE_VALUE;
		}
		break;
	default:
		abort();
	}
#else
	switch (dwCreationDisposition) {
	case OPEN_EXISTING:
		FileHandle = fopen(filename, "r");
		break;
	case CREATE_ALWAYS:
		FileHandle = fopen("/dev/null", "w");
		break;
	case CREATE_NEW:
		if (strstr(filename, "/faketemp/")) {
			FileHandle = fopen(filename, "w");
			unlink(filename);
		}
		else {
			FileHandle = fopen("/dev/null", "w");
		}
		break;
	default:
		abort();
	}
#endif
	return FileHandle ? FileHandle : INVALID_HANDLE_VALUE;
}

void* __stdcall MockKernel32::CreateFileW(wchar_t* lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode, void* lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes, void* hTemplateFile) {
	char *filename = convert_wstr_to_str(lpFileName);
	void* ret = MockKernel32::CreateFileA(filename, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	delete filename;

	return ret;
}

bool __stdcall MockKernel32::ReadFile(void* hFile, void* lpBuffer, unsigned int nNumberOfBytesToRead, unsigned int* lpNumberOfBytesRead, void* lpOverlapped) {
	*lpNumberOfBytesRead = fread(lpBuffer, 1, nNumberOfBytesToRead, (FILE*)hFile);
	return true;
}

bool __stdcall MockKernel32::WriteFile(void* hFile, void* lpBuffer, unsigned int nNumberOfBytesToWrite, unsigned int* lpNumberOfBytesWritten, void* lpOverlapped) {
	*lpNumberOfBytesWritten = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, (FILE*)hFile);
	return true;
}

bool __stdcall MockKernel32::DeleteFile(char* lpFileName) {
	return remove(lpFileName);
}

bool __stdcall MockKernel32::CloseHandle(void* hObject) {
	return true;
}

unsigned int __stdcall MockKernel32::GetDriveTypeA(char* lpRootPathName) {
	return 3;
}

unsigned int __stdcall MockKernel32::GetDriveTypeW(wchar_t* lpRootPathName) {
	return MockKernel32::GetDriveTypeA(nullptr);
}

unsigned int __stdcall MockKernel32::GetFileSizeEx(void* hFile, PLARGE_INTEGER lpFileSize) {
	long curpos = ftell((FILE*)hFile);
	fseek((FILE*)hFile, 0, SEEK_END);

	lpFileSize->LowPart = ftell((FILE*)hFile);

	fseek((FILE*)hFile, curpos, SEEK_SET);


	return 1;
}

unsigned int __stdcall MockKernel32::SetFilePointer(
	void* hFile,
	long   lDistanceToMove,
	long*  lpDistanceToMoveHigh,
	unsigned int  dwMoveMethod
) {
	int result;
	result = fseek((FILE*)hFile, lDistanceToMove, dwMoveMethod);
	unsigned int pos = ftell((FILE*)hFile);
	if (lpDistanceToMoveHigh) {
		*lpDistanceToMoveHigh = 0;
	}

	return pos;
}

bool __stdcall MockKernel32::SetFilePointerEx(
	void* hFile,
	unsigned long long   liDistanceToMove,
	unsigned long long*  lpNewFilePointer,
	unsigned int  dwMoveMethod
) {
	int result;
	result = fseek((FILE*)hFile, liDistanceToMove, dwMoveMethod);
	if (lpNewFilePointer) {
		*lpNewFilePointer = ftell((FILE*)hFile);
	}

	return true;

}

unsigned int __stdcall MockKernel32::GetFileAttributesW(void* lpFileName){
	//return FILE_ATTRIBUTE_ARCHIVE;
	return FILE_ATTRIBUTE_NORMAL;
}

unsigned int __stdcall MockKernel32::GetFileAttributesExA(char* lpFileName, unsigned int fInfoLevelId, void* lpFileInformation) {
	memset(lpFileInformation, FILE_ATTRIBUTE_NORMAL, sizeof(void*));
	return true;
}

unsigned int __stdcall MockKernel32::GetFileAttributesExW(wchar_t* lpFileName, unsigned int fInfoLevelId, void* lpFileInformation)
{
	return MockKernel32::GetFileAttributesExA(nullptr, fInfoLevelId, lpFileInformation);
}


void __stdcall MockKernel32::GetSystemTimeAsFileTime(PVOID lpSystemTimeAsFileTime)
{
	memset(lpSystemTimeAsFileTime, 0, sizeof(FILETIME));
}

unsigned int __stdcall MockKernel32::GetCurrentThreadID() {
	unsigned int tid = 0;
	
#ifdef _WIN64	
	tid = GetCurrentThreadId();
#else
	tid = gettid();
#endif // _WIN64
	return tid;
}

unsigned int __stdcall MockKernel32::GetCurrentProcessID() {
	unsigned int pid = 0;
#ifdef _WIN64
	pid = GetCurrentProcessId();
#else
	pid = getpid();
#endif
	return pid;
}

bool __stdcall MockKernel32::QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount){
	struct timespec tm;
#ifdef _WIN64
	
	timespec_get(&tm, clock());
#else
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &tm) != 0)
		return false;
#endif // _WIN64
	
	lpPerformanceCount->LowPart = tm.tv_nsec;

	return true;
}

void* __stdcall MockKernel32::GetCommandLineA() {
	return (void*)MockKernel32::commandline.c_str();
}

void* __stdcall MockKernel32::GetCommandLineW() {
	return (void*)MockKernel32::wcommandline.c_str();
}

void* __stdcall MockKernel32::GetStdHandle(uint32_t nStdHandle) {
	void* ret_hndl = nullptr;
	switch (nStdHandle)
	{
	case STD_INPUT_HANDLE:
		ret_hndl = (void*)0;
		break;
	case STD_OUTPUT_HANDLE:
		ret_hndl = (void*)1;
		break;
	case STD_ERROR_HANDLE:
		ret_hndl = (void*)2;
		break;
	default:
		ret_hndl = INVALID_HANDLE_VALUE;
		break;
	}
	return ret_hndl;
}

unsigned int __stdcall MockKernel32::GetFileType(void* hFile) {
	return 0x2; // character file
}

void* __stdcall MockKernel32::DecodePointer(void* ptr) {
	return ptr;
}

void* __stdcall MockKernel32::EncodePointer(void* ptr) {
	return ptr;
}

unsigned int MockKernel32::GetACP() {
	return 65001; //utf-8
}
bool __stdcall MockKernel32::GetCPInfo(int CodePage, LPCPINFO lpCPInfo){
	//codepage is always utf-8
	lpCPInfo->MaxCharSize = 1; // english ver
	lpCPInfo->DefaultChar[0] = '?';
	return true;
}

bool __stdcall MockKernel32::IsValidCodePage(unsigned int CodePage) {
	return true;
}

unsigned int __stdcall MockKernel32::TlsAlloc() {
	if (MockKernel32::tls_index >= _ARRAYSIZE(MockKernel32::ThreadLocalStorage) - 1) {
		return TLS_OUT_OF_INDEXES;
	}
	return MockKernel32::tls_index++;
}

bool __stdcall MockKernel32::TlsSetValue(unsigned int dwTlsIndex, void* lpTlsValue) {
	if (dwTlsIndex < _ARRAYSIZE(MockKernel32::ThreadLocalStorage)) {
		MockKernel32::ThreadLocalStorage[dwTlsIndex] = (unsigned long long)lpTlsValue;
		return true;
	}
	else
		return false;
}

bool __stdcall MockKernel32::TlsFree(unsigned int dwTlsIndex) {
	if (dwTlsIndex < _ARRAYSIZE(MockKernel32::ThreadLocalStorage)) {
		MockKernel32::ThreadLocalStorage[dwTlsIndex] = NULL;
		return true;
	}
	else
		return false;
}

void* __stdcall MockKernel32::TlsGetValue(unsigned int dwTlsIndex) {
	if (dwTlsIndex < _ARRAYSIZE(MockKernel32::ThreadLocalStorage))
		return (void*)MockKernel32::ThreadLocalStorage[dwTlsIndex];
	return 0;
}

unsigned int __stdcall MockKernel32::FlsAlloc(void* lpCallback) {
	unsigned int cur_tls_idx = MockKernel32::TlsAlloc();
	if (cur_tls_idx != TLS_OUT_OF_INDEXES)
		FlsCallbacks[cur_tls_idx] = (PFLS_CALLBACK_FUNCTION)lpCallback;
	return cur_tls_idx;
}

unsigned int __stdcall MockKernel32::FlsSetValue(unsigned int dwFlsIndex, void* lpFlsData) {
	return MockKernel32::TlsSetValue(dwFlsIndex, lpFlsData);
}

void* __stdcall MockKernel32::FlsGetValue(unsigned int dwFlsIndex) {
	return MockKernel32::TlsGetValue(dwFlsIndex);
}

bool MockKernel32::FlsFree(unsigned int dwFlsIndex) {
	if (MockKernel32::FlsCallbacks[dwFlsIndex])
		MockKernel32::FlsCallbacks[dwFlsIndex](MockKernel32::TlsGetValue(dwFlsIndex));
	return MockKernel32::TlsFree(dwFlsIndex);
}

bool __stdcall MockKernel32::GetStringTypeA(unsigned int dwInfoType, char* lpSrcStr, int cchSrc, unsigned short* lpCharType) {
	
	int idx = 0;
	string input_str = string(lpSrcStr);
	if (cchSrc <= 0) {
		cchSrc = input_str.length();
	}
	if (dwInfoType == CT_CTYPE1) {
		for (idx; cchSrc > idx; idx++) {
			uint16_t ct = 0;
			char c = (char)input_str[idx];
			if ((c > 0x20 && c < 0x30) || (c >= 0x3A && c <= 0x40) || \
				(c >= 0x5B && c <= 0x60) || (c >= 0x7B && c <= 0x7E)) {
				ct |= C1_PUNCT;
			}
			if (c < 0x20 || c == 0x7F)
				ct |= C1_CNTRL;
			if (c >= 0x9 && c <= 0xD)
				ct |= C1_SPACE;
			if (c == 0x20)
				ct |= (C1_BLANK | C1_SPACE);
			if (c >= 0x41 && c <= 0x5A)
				ct |= C1_UPPER;
			if (c >= 0x61 && c <= 0x7A)
				ct |= C1_LOWER;
			if (c >= 0x30 && c <= 0x39)
				ct |= C1_DIGIT;
			if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46))
				ct |= C1_XDIGIT;
			if ((ct & C1_UPPER) || (ct & C1_LOWER))
				ct |= C1_ALPHA;
			if (c != 0)
				ct |= C1_DEFINED;

			lpCharType[idx] = ct;
		}
	}
	
	return true;
}

bool __stdcall MockKernel32::GetStringTypeW(unsigned int dwInfoType, wchar_t* lpSrcStr, int cchSrc, unsigned short* lpCharType) {
	
	int idx = 0;
	wstring input_wstr = wstring(lpSrcStr);
	if (cchSrc <= 0) {
		cchSrc = input_wstr.length();
	}
	if (dwInfoType == CT_CTYPE1) {
		for (idx; cchSrc > idx; idx++) {
			uint16_t ct = 0;
			char c = (char)input_wstr[idx];
			if ((c > 0x20 && c < 0x30) || (c >= 0x3A && c <= 0x40) || \
				(c >= 0x5B && c <= 0x60) || (c >= 0x7B && c <= 0x7E)) {
				ct |= C1_PUNCT;
			}
			if (c < 0x20 || c == 0x7F)
				ct |= C1_CNTRL;
			if (c >= 0x9 && c <= 0xD)
				ct |= C1_SPACE;
			if (c == 0x20)
				ct |= (C1_BLANK | C1_SPACE);
			if (c >= 0x41 && c <= 0x5A)
				ct |= C1_UPPER;
			if (c >= 0x61 && c <= 0x7A)
				ct |= C1_LOWER;
			if (c >= 0x30 && c <= 0x39)
				ct |= C1_DIGIT;
			if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46))
				ct |= C1_XDIGIT;
			if ((ct & C1_UPPER) || (ct & C1_LOWER))
				ct |= C1_ALPHA;
			if (c != 0)
				ct |= C1_DEFINED;

			lpCharType[idx] = ct;
		}
	}
	
	return true;
}

int __stdcall MockKernel32::LCMapStringA(LCID Locale, unsigned int dwMapFlags, char* lpSrcStr, int cchSrc, char*  lpDestStr, int cchDest) {
	if (lpDestStr == NULL || cchSrc == NULL)
		return 0;
	if (lpDestStr == NULL || cchDest == NULL)
		return 0;
	memmove(lpDestStr, lpSrcStr, cchSrc*sizeof(wchar_t));
	return string(lpSrcStr).length();
}

int __stdcall MockKernel32::LCMapStringW(LCID Locale, unsigned int dwMapFlags, wchar_t* lpSrcStr, int cchSrc, wchar_t*  lpDestStr, int cchDest) {
	memmove(lpDestStr, lpSrcStr, cchSrc);
	return wstring(lpSrcStr).length();
 }

int __stdcall MockKernel32::LCMapStringEx(wchar_t* lpLocaleName, unsigned int dwMapFlags, wchar_t* lpSrcStr, int cchSrc, wchar_t* lpDestStr, int cchDest, void* lpVersionInformation, void* lpReserved, void* sortHandle) {
	size_t cp_sz = cchDest > cchSrc ? cchSrc : cchDest;
	if (cchSrc == 0)
		return 0;

	if (cchSrc < 0) {
		for (int i = 0; cp_sz > i; i++) {
			cp_sz++;
			if (lpSrcStr[i] == '\0') {
				cp_sz++; // add null term;
				break;
			}
		}
	}
	else {
		cp_sz = cchSrc;
	}

	if (lpDestStr == NULL)
		return cp_sz;

	int i = 0;

	for (; lpSrcStr[i] != '\0' && cp_sz/2 > i; i++) {
		lpDestStr[i] = lpSrcStr[i];
	}
	cp_sz = i;
	
	return cp_sz;
}

int __stdcall MockKernel32::WideCharToMultiByte(unsigned int CodePage, unsigned int dwFlags, void* lpWideCharStr, int cchWideChar, void* lpMultiByteStr, int cbMultiByte, void* lpDefaultChar, void* lpUsedDefaultChar) {
	char *ansi = NULL;
	if (cchWideChar == 0)
		return 0;

	if (cchWideChar != -1) {
		// it is not null terminated
		wchar_t* wstr = read_widestring(lpWideCharStr, cchWideChar);
		ansi = convert_wstr_to_str(wstr);
		delete wstr;
	}
	else {
		ansi = convert_wstr_to_str((wchar_t*)lpWideCharStr);
	}
	if (ansi == NULL) {
		return 0;
	}

	if (lpMultiByteStr && (strlen(ansi) < cbMultiByte)) {
		memmove(lpMultiByteStr, ansi, strlen(ansi)+1);
		//strcpy_s((char*)lpMultiByteStr, strlen(ansi), ansi);
		delete ansi;
		return strlen((char*)lpMultiByteStr) + 1;
	}
	else if (!lpMultiByteStr && cbMultiByte == 0) {
		int len = strlen(ansi) + 1;
		delete ansi;
		return len;
	}

	delete ansi;
	return 0;
}

int __stdcall MockKernel32::MultiByteToWideChar(unsigned int CodePage, unsigned int dwFlags, void* lpMultiByteStr, int cbMultiByte, void* lpWideCharStr, int cchWideChar) {
	size_t i;

	if (cbMultiByte == 0)
		return 0;

	if (cbMultiByte == -1)
		cbMultiByte = strlen((char*)lpMultiByteStr) + 1;

	if (cchWideChar == 0)
		return cbMultiByte;

	if (cbMultiByte > cchWideChar) {
		return 0;
	}
	wchar_t* wstr = (wchar_t*)lpWideCharStr;
	char* str = (char*)lpMultiByteStr;
	for (i = 0; i < cbMultiByte; i++) {
		wstr[i] = str[i];
		if (dwFlags & MB_ERR_INVALID_CHARS) {
			if (!isascii(str[i]) || iscntrl(str[i])) {
				wstr[i] = '?';
			}
		}
	}

	return i;
}


void __stdcall MockKernel32::InitializeSListHead(PSLIST_HEADER ListHead) {
	memset(ListHead, 0, sizeof(unsigned long long) * 2);
}

bool __stdcall MockKernel32::InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, unsigned int dwSpinCount) {
	return true;
}

bool __stdcall MockKernel32::InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	return true;
}

bool __stdcall MockKernel32::InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, unsigned int dwSpinCOunt, unsigned int Flags) {
	return true;
}

void __stdcall MockKernel32::EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	return;
}

void __stdcall MockKernel32::DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	return;
}

void __stdcall MockKernel32::LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	return;
}

void __stdcall MockKernel32::InitializeConditionVariable(PCONDITION_VARIABLE ConditionVariable) {
	return;
}

unsigned int __stdcall MockKernel32::GetEnvironmentVariableA(char* lpName, char* lpBuffer, unsigned int nSize) {
	char *str = lpName;
	bool found = false;
	memset(lpBuffer, 0, nSize);
	for (auto const &v : MockNTKrnl::m_env_variable) {
		if (strcmp(str, v.first.c_str()) == 0) {
			int i = 0;
			for (; v.first.length() > i; i++) {
				lpBuffer[i] = v.first[i];
			}
			return i;
		}
	}
	//SetLastError(ERROR_ENVVAR_NOT_FOUND);
	return 0;
}

unsigned int __stdcall MockKernel32::GetEnvironmentVariableW(wchar_t* lpName, wchar_t* lpBuffer, unsigned int nSize)
{
	char *str = convert_wstr_to_str(lpName);
	bool found = false;
	memset(lpBuffer, 0, nSize);
	for (auto const &v : MockNTKrnl::m_env_variable) {
		if (strcmp(str, v.first.c_str()) == 0) {
			int i = 0;
			for (; v.first.length() > i; i++) {
				lpBuffer[i] = v.first[i];
			}
			delete str;
			return i * sizeof(wchar_t);
		}
	}
	delete str;
	return 0;
}

char* __stdcall MockKernel32::GetEnvironmentStrings() {
	std::string env_str_tmp;
	for (auto const &v : MockNTKrnl::m_env_variable) {
		env_str_tmp += (v.first + std::string("=") + v.second);
		env_str_tmp.push_back('\0');
	}
	env_str_tmp.pop_back();
	char* env_str = new char[env_str_tmp.length()];
	memmove(env_str, env_str_tmp.c_str(), env_str_tmp.length());

	return env_str;
}
wchar_t* __stdcall MockKernel32::GetEnvironmentStringsW() {
	std::wstring env_str_tmp;
	for (auto const &v : MockNTKrnl::m_env_variable) {
		std::wstring key;
		std::wstring value;
		key.assign(v.first.begin(), v.first.end());
		value.assign(v.second.begin(), v.second.end());
		env_str_tmp += (key + std::wstring(L"=")+value);
		env_str_tmp.push_back('\0');
	}
	env_str_tmp.pop_back();
	size_t buf_sz = (env_str_tmp.length() + 1) * 2;
	wchar_t* env_str = new wchar_t[buf_sz];
	memset(env_str, 0, buf_sz);
	memmove(env_str, env_str_tmp.c_str(), buf_sz-2);

	return env_str;
}

unsigned int __stdcall MockKernel32::ExpandEnvironmentStringsW(wchar_t* lpSrc, wchar_t* lpDst, unsigned int nSize) {
	char* str = convert_wstr_to_str(lpSrc);
	std::string src = std::string(str);
	memset(lpDst, 0, nSize);
	for (auto const env : MockNTKrnl::m_env_variable) {
		std::string env_fmt = std::string("%") + env.first + std::string("%");
		std::string src_tmp = src;
		
		std::transform(env_fmt.begin(), env_fmt.end(), env_fmt.begin(), ::tolower);
		std::transform(src.begin(), src.end(), src_tmp.begin(), ::tolower);
		
		size_t req_buf_sz;
		auto idx = src_tmp.find(env_fmt);
		if (idx == std::string::npos) {
			continue;
		}
		src.replace(idx, env_fmt.length(), env.second);
		req_buf_sz = (src.length() + 1) * sizeof(wchar_t);
		if (req_buf_sz > nSize) {
			delete str;
			return req_buf_sz;
		}
		for (int i = 0; req_buf_sz/2 - 1 > i; i++) {
			lpDst[i] = src[i];
		}
		delete str;
		return req_buf_sz;
	}
	size_t sz = (src.length()+1) * sizeof(wchar_t);
	if (sz > nSize) {
		delete str;
		return sz;
	}
	memmove(lpDst, lpSrc, sz);
	delete str;

	return 0;
}
/*
STATIC DWORD WINAPI ExpandEnvironmentStringsW(PWCHAR lpSrc, PWCHAR lpDst, DWORD nSize)
{
	PCHAR AnsiString = CreateAnsiFromWide(lpSrc);
	DWORD Result;
	struct {
		PCHAR   Src;
		PWCHAR  Dst;
	} KnownPaths[] = {
		{ "%ProgramFiles%", L"C:\\Program Files" },
		{ "%AllUsersProfile%", L"C:\\ProgramData" },
		{ "%PATH%", L"C:\\Path" },
		{ "%windir%", L"C:\\Windows" },
		{ "%ProgramFiles(x86)%", L"C:\\Program Files" },
		{ "%WINDIR%\\system32\\drivers", L"C:\\WINDOWS\\system32\\drivers" },
		{ "%windir%\\temp", L"C:\\WINDOWS\\temp" },
		{ "%CommonProgramFiles%", L"C:\\CommonProgramFiles" },
		{ NULL },
	};

	DebugLog("%p [%s], %p, %u", lpSrc, AnsiString, lpDst, nSize);

	for (int i = 0; KnownPaths[i].Src; i++) {
		if (strcmp(AnsiString, KnownPaths[i].Src) == 0) {
			Result = CountWideChars(KnownPaths[i].Dst) + 1;
			if (nSize < Result) {
				goto finish;
			}
			memcpy(lpDst, KnownPaths[i].Dst, Result * 2);
			goto finish;
		}
	}

	free(AnsiString);

	if (nSize < CountWideChars(lpSrc) + 1) {
		return CountWideChars(lpSrc) + 1;
	}

	memcpy(lpDst, lpSrc, (1 + CountWideChars(lpSrc)) * 2);

	return CountWideChars(lpSrc) + 1;

finish:
	free(AnsiString);
	return Result;
}
*/
bool __stdcall MockKernel32::FreeEnvironmentStringsA(char* penv) {
	delete penv;
	return true;
}

bool __stdcall MockKernel32::FreeEnvironmentStringsW(wchar_t* penv) {
	delete penv;
	return true;
}

void __stdcall MockKernel32::AcquireSRWLockExclusive(PSRWLOCK SRWLock) {
	return;
}

void __stdcall MockKernel32::ReleaseSRWLockExclusive(PSRWLOCK SRWLock) {
	return;
}

void __stdcall MockKernel32::InitializeSRWLock(PSRWLOCK SRWLock) {
	return;
}

unsigned int __stdcall MockKernel32::GetTickCount() {
	return ++MockKernel32::tick_counter;
}

unsigned long long __stdcall MockKernel32::GetTickCount64() {
	return ++MockKernel32::tick_counter;
}

unsigned int __stdcall MockKernel32::GetSystemDirectoryA(char* lpBuffer, unsigned int uSize) {
	size_t buf_sz = sizeof("C:\\Windows\\System32");
	char* system_dir = "C:\\Windows\\System32";
	if (uSize == 0)
		return buf_sz + 1;
	memset(lpBuffer, 0, uSize);
	memmove(lpBuffer, system_dir, buf_sz);
	return buf_sz;
}

unsigned int __stdcall MockKernel32::GetSystemDirectoryW(wchar_t* lpBuffer, unsigned int uSize) {
	size_t buf_sz = sizeof(L"C:\\Windows\\System32");
	wchar_t* system_dir = L"C:\\Windows\\System32";
	if (uSize == 0)
		return buf_sz + 1;
	memset(lpBuffer, 0, uSize);
	memmove(lpBuffer, system_dir, buf_sz);
	return buf_sz;
}

unsigned int __stdcall MockKernel32::GetTempPathW(unsigned int nBufferLength, wchar_t* lpBuffer) {
	size_t buf_sz = sizeof(L".\\TEMP");
	wchar_t* temp_dir = L".\\TEMP";
	if (nBufferLength == 0)
		return buf_sz + 1;
	memset(lpBuffer, 0, nBufferLength);
	memmove(lpBuffer, temp_dir, buf_sz);
	return buf_sz;
}

bool __stdcall MockKernel32::VirtualLock(void* lpAddress, unsigned int dwSize) {
	return true;
}

bool __stdcall MockKernel32::VirtualProtect(void* lpAddress, size_t dwSize, unsigned int flNewProtect, void* lpflOldProtect) {
	return true;
}

void* __stdcall MockKernel32::SetThreadpoolTimer(void* pfnti, void* pv, void* pcbe) {
	return (void*)0x90909090;
}

void __stdcall MockKernel32::WaitForThreadpoolTimerCallbacks(void* ptr, bool fCancelPendingCallbacks) {
	return;
}

void* __stdcall MockKernel32::CreateThreadpoolTimer(void* pfnti, void* pv, void* pcbe) {
	return (void*)"roka";
}

void __stdcall MockKernel32::CloseThreadpoolTimer(void* ptr) {
	return;
}

void* __stdcall MockKernel32::CreateThreadpoolWork(void* pfnwk, void* pv, void* pcbe) {
	return (void*)"army";
}

