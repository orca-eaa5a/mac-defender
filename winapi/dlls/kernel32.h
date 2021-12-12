#pragma once
#ifndef _KERNEL32_H_
#define _KERNEL32_H_
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include "../ntoskrnl.h"
#include "../exports.h"

class MockKernel32 {

public:
	static void* mpengine_base;
	static std::string commandline;
	static std::wstring wcommandline;	
	
	static unsigned long long ThreadLocalStorage[1024]; // 64bit
	static PFLS_CALLBACK_FUNCTION FlsCallbacks[1024];
	static unsigned int tls_index;
	static unsigned int tick_counter;

	function<void(void)> set_k32_hookaddr = [](void){
		//APIExports::add_hook_info("KERNEL32.DLL", "SetLastError", (void*)MockKernel32::SetLastError);
		//APIExports::add_hook_info("KERNEL32.DLL", "GetLastError", (void*)MockKernel32::GetLastError);
		APIExports::add_hook_info("KERNEL32.DLL", "GetStartupInfoA", (void*)MockKernel32::GetStartupInfoA);
		APIExports::add_hook_info("KERNEL32.DLL", "GetStartupInfoW", (void*)MockKernel32::GetStartupInfoW);
		APIExports::add_hook_info("KERNEL32.DLL", "GetStringTypeA", (void*)MockKernel32::GetStringTypeA);
		APIExports::add_hook_info("KERNEL32.DLL", "GetStringTypeW", (void*)MockKernel32::GetStringTypeW);
		APIExports::add_hook_info("KERNEL32.DLL", "GetModuleFileNameA", (void*)MockKernel32::GetModuleFileNameA);

		APIExports::add_hook_info("KERNEL32.DLL", "GetStdHandle", (void*)MockKernel32::GetStdHandle);
		APIExports::add_hook_info("KERNEL32.DLL", "LoadLibraryExW", (void*)MockKernel32::LoadLibraryExW);
		//APIExports::add_hook_info("KERNEL32.DLL", "GetModuleHandleA", (void*)MockKernel32::GetModuleHandleA);
		APIExports::add_hook_info("KERNEL32.DLL", "GetModuleHandleW", (void*)MockKernel32::GetModuleHandleW);
		APIExports::add_hook_info("KERNEL32.DLL", "GetModuleHandleExW", (void*)MockKernel32::GetModuleHandleExW);
		APIExports::add_hook_info("KERNEL32.DLL", "CloseHandle", (void*)MockKernel32::MyCloseHandle);
		APIExports::add_hook_info("KERNEL32.DLL", "GetProcAddress", (void*)MockKernel32::MyGetProcAddress);

		APIExports::add_hook_info("KERNEL32.DLL", "EncodePointer", (void*)MockKernel32::EncodePointer);
		APIExports::add_hook_info("KERNEL32.DLL", "DecodePointer", (void*)MockKernel32::DecodePointer);
		
		APIExports::add_hook_info("KERNEL32.DLL", "GetFileType", (void*)MockKernel32::GetFileType);
		APIExports::add_hook_info("KERNEL32.DLL", "GetDriveTypeW", (void*)MockKernel32::GetDriveTypeW);
		APIExports::add_hook_info("KERNEL32.DLL", "GetDriveTypeA", (void*)MockKernel32::GetDriveTypeA);
		APIExports::add_hook_info("KERNEL32.DLL", "GetLogicalDrives", (void*)MockKernel32::GetLogicalDrives);

		APIExports::add_hook_info("KERNEL32.DLL", "GetProductInfo", (void*)MockKernel32::GetProductInfo);
		APIExports::add_hook_info("KERNEL32.DLL", "GetSystemInfo", (void*)MockKernel32::GetSystemInfo);
		APIExports::add_hook_info("KERNEL32.DLL", "GetCurrentProcessID", (void*)MockKernel32::GetCurrentProcessID);
		APIExports::add_hook_info("KERNEL32.DLL", "GetCurrentThreadID", (void*)MockKernel32::GetCurrentThreadID);

		APIExports::add_hook_info("KERNEL32.DLL", "GetSystemTimeAsFileTime", (void*)MockKernel32::GetSystemTimeAsFileTime);
		APIExports::add_hook_info("KERNEL32.DLL", "GetSystemTimePreciseAsFileTime", (void*)MockKernel32::GetSystemTimePreciseAsFileTime);
		APIExports::add_hook_info("KERNEL32.DLL", "QueryPerformanceCounter", (void*)MockKernel32::QueryPerformanceCounter);
		APIExports::add_hook_info("KERNEL32.DLL", "GetTickCount", (void*)MockKernel32::GetTickCount);
		APIExports::add_hook_info("KERNEL32.DLL", "GetTickCount64", (void*)MockKernel32::GetTickCount64);

		APIExports::add_hook_info("KERNEL32.DLL", "DeviceIoControl", (void*)MockKernel32::DeviceIoControl);

		APIExports::add_hook_info("KERNEL32.DLL", "GetCommandLineA", (void*)MockKernel32::GetCommandLineA);
		APIExports::add_hook_info("KERNEL32.DLL", "GetCommandLineW", (void*)MockKernel32::GetCommandLineW);

		APIExports::add_hook_info("KERNEL32.DLL", "GetACP", (void*)MockKernel32::GetACP);
		APIExports::add_hook_info("KERNEL32.DLL", "IsValidCodePage", (void*)MockKernel32::IsValidCodePage);
		APIExports::add_hook_info("KERNEL32.DLL", "GetCPInfo", (void*)MockKernel32::GetCPInfo);

		APIExports::add_hook_info("KERNEL32.DLL", "TlsAlloc", (void*)MockKernel32::TlsAlloc);
		APIExports::add_hook_info("KERNEL32.DLL", "TlsGetValue", (void*)MockKernel32::TlsGetValue);
		APIExports::add_hook_info("KERNEL32.DLL", "TlsSetValue", (void*)MockKernel32::TlsSetValue);
		APIExports::add_hook_info("KERNEL32.DLL", "TlsFree", (void*)MockKernel32::TlsFree);
		APIExports::add_hook_info("KERNEL32.DLL", "FlsAlloc", (void*)MockKernel32::FlsAlloc);
		APIExports::add_hook_info("KERNEL32.DLL", "FlsGetValue", (void*)MockKernel32::FlsGetValue);
		APIExports::add_hook_info("KERNEL32.DLL", "FlsSetValue", (void*)MockKernel32::FlsSetValue);
		APIExports::add_hook_info("KERNEL32.DLL", "FlsFree", (void*)MockKernel32::FlsFree);

		APIExports::add_hook_info("KERNEL32.DLL", "LCMapStringA", (void*)MockKernel32::LCMapStringA);
		APIExports::add_hook_info("KERNEL32.DLL", "LCMapStringW", (void*)MockKernel32::LCMapStringW);
		APIExports::add_hook_info("KERNEL32.DLL", "LCMapStringEx", (void*)MockKernel32::LCMapStringEx);

		APIExports::add_hook_info("KERNEL32.DLL", "MultiByteToWideChar", (void*)MockKernel32::MultiByteToWideChar);
		APIExports::add_hook_info("KERNEL32.DLL", "WideCharToMultiByte", (void*)MockKernel32::WideCharToMultiByte);
		
		APIExports::add_hook_info("KERNEL32.DLL", "InitializeSListHead", (void*)MockKernel32::InitializeSListHead);
		APIExports::add_hook_info("KERNEL32.DLL", "InitializeConditionVariable", (void*)MockKernel32::InitializeConditionVariable);

		APIExports::add_hook_info("KERNEL32.DLL", "InitializeCriticalSection", (void*)MockKernel32::InitializeCriticalSection);
		APIExports::add_hook_info("KERNEL32.DLL", "InitializeCriticalSectionEx", (void*)MockKernel32::InitializeCriticalSectionEx);
		APIExports::add_hook_info("KERNEL32.DLL", "InitializeCriticalSectionAndSpinCount", (void*)MockKernel32::InitializeCriticalSectionAndSpinCount);
		APIExports::add_hook_info("KERNEL32.DLL", "EnterCriticalSection", (void*)MockKernel32::EnterCriticalSection);
		APIExports::add_hook_info("KERNEL32.DLL", "LeaveCriticalSection", (void*)MockKernel32::LeaveCriticalSection);
		APIExports::add_hook_info("KERNEL32.DLL", "DeleteCriticalSection", (void*)MockKernel32::DeleteCriticalSection);


		APIExports::add_hook_info("KERNEL32.DLL", "ExpandEnvironmentStringsW", (void*)MockKernel32::ExpandEnvironmentStringsW);
		APIExports::add_hook_info("KERNEL32.DLL", "GetEnvironmentVariableA", (void*)MockKernel32::GetEnvironmentVariableA);
		APIExports::add_hook_info("KERNEL32.DLL", "GetEnvironmentVariableW", (void*)MockKernel32::GetEnvironmentVariableW);
		APIExports::add_hook_info("KERNEL32.DLL", "GetEnvironmentStrings", (void*)MockKernel32::GetEnvironmentStrings);
		APIExports::add_hook_info("KERNEL32.DLL", "GetEnvironmentStringsW", (void*)MockKernel32::GetEnvironmentStringsW);
		APIExports::add_hook_info("KERNEL32.DLL", "FreeEnvironmentStringsA", (void*)MockKernel32::FreeEnvironmentStringsA);
		APIExports::add_hook_info("KERNEL32.DLL", "FreeEnvironmentStringsW", (void*)MockKernel32::FreeEnvironmentStringsW);

		APIExports::add_hook_info("KERNEL32.DLL", "AcquireSRWLockExclusive", (void*)MockKernel32::AcquireSRWLockExclusive);
		APIExports::add_hook_info("KERNEL32.DLL", "ReleaseSRWLockExclusive", (void*)MockKernel32::ReleaseSRWLockExclusive);
		APIExports::add_hook_info("KERNEL32.DLL", "InitializeSRWLock", (void*)MockKernel32::InitializeSRWLock);

		APIExports::add_hook_info("KERNEL32.DLL", "VirtualLock", (void*)MockKernel32::VirtualLock);
		APIExports::add_hook_info("KERNEL32.DLL", "VirtualProtect", (void*)MockKernel32::VirtualProtect);

		APIExports::add_hook_info("KERNEL32.DLL", "GetFileAttributesW", (void*)MockKernel32::GetFileAttributesW);
		APIExports::add_hook_info("KERNEL32.DLL", "GetFileAttributesExA", (void*)MockKernel32::GetFileAttributesExA);
		APIExports::add_hook_info("KERNEL32.DLL", "GetFileAttributesExW", (void*)MockKernel32::GetFileAttributesExW);

		APIExports::add_hook_info("KERNEL32.DLL", "GetSystemDirectoryA", (void*)MockKernel32::GetSystemDirectoryA);
		APIExports::add_hook_info("KERNEL32.DLL", "GetSystemDirectoryW", (void*)MockKernel32::GetSystemDirectoryW);
		APIExports::add_hook_info("KERNEL32.DLL", "GetTempPathW", (void*)MockKernel32::GetTempPathW);
		APIExports::add_hook_info("KERNEL32.DLL", "GetFullPathNameW", (void*)MockKernel32::GetFullPathNameW);
		APIExports::add_hook_info("KERNEL32.DLL", "QueryDosDeviceA", (void*)MockKernel32::QueryDosDeviceA);
		APIExports::add_hook_info("KERNEL32.DLL", "QueryDosDeviceW", (void*)MockKernel32::QueryDosDeviceW);

		APIExports::add_hook_info("KERNEL32.DLL", "CreateThreadpoolTimer", (void*)MockKernel32::CreateThreadpoolTimer);
		APIExports::add_hook_info("KERNEL32.DLL", "SetThreadpoolTimer", (void*)MockKernel32::SetThreadpoolTimer);
		APIExports::add_hook_info("KERNEL32.DLL", "WaitForThreadpoolTimerCallbacks", (void*)MockKernel32::WaitForThreadpoolTimerCallbacks);
		APIExports::add_hook_info("KERNEL32.DLL", "CloseThreadpoolTimer", (void*)MockKernel32::CloseThreadpoolTimer);
		APIExports::add_hook_info("KERNEL32.DLL", "CreateThreadpoolWork", (void*)MockKernel32::CreateThreadpoolWork);

		APIExports::add_hook_info("KERNEL32.DLL", "CreateEventW", (void*)MockKernel32::CreateEventW);
		APIExports::add_hook_info("KERNEL32.DLL", "SetEvent", (void*)MockKernel32::SetEvent);
		APIExports::add_hook_info("KERNEL32.DLL", "ReSetEvent", (void*)MockKernel32::ReSetEvent);
		APIExports::add_hook_info("KERNEL32.DLL", "RegisterWaitForSingleObject", (void*)MockKernel32::RegisterWaitForSingleObject);
		APIExports::add_hook_info("KERNEL32.DLL", "WaitForSingleObject", (void*)MockKernel32::WaitForSingleObject);
	};
	static void __stdcall MockKernel32::SetLastError(unsigned int dwErrCode);
	static unsigned int __stdcall MockKernel32::GetLastError();

	static void __stdcall MockKernel32::GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo);
	static void __stdcall MockKernel32::GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo);
	
	static void* __stdcall MockKernel32::GetStdHandle(uint32_t nStdHandle);
	//static void* __stdcall MockKernel32::GetModuleHandleA(char* lpModuleName);
	static void* __stdcall MockKernel32::GetModuleHandleW(wchar_t* lpModuleName);
	static bool __stdcall MockKernel32::GetModuleHandleExA(unsigned int dwFlags, char* lpModuleName, void* phModule);
	static bool __stdcall MockKernel32::GetModuleHandleExW(unsigned int dwFlags, wchar_t* lpModuleName, void* phModule);
	static void* __stdcall MockKernel32::MyGetProcAddress(void* hModule, char* lpProcName);
	static unsigned int __stdcall MockKernel32::GetModuleFileNameA(void* hModule, char* lpFilename, unsigned int nSize);
	static unsigned int __stdcall MockKernel32::GetModuleFileNameW(void* hModule, wchar_t* lpFilename, unsigned int nSize);
	static void* __stdcall MockKernel32::LoadLibraryExW(wchar_t* lpLibFileName, void* hFile, unsigned int dwFlags);
	
	static unsigned int __stdcall MockKernel32::SetFilePointer(void* hFile, long lDistanceToMove, long* lpDistanceToMoveHigh, unsigned int dwMoveMethod);
	static bool __stdcall MockKernel32::SetFilePointerEx(void* hFile, unsigned long long liDistanceToMove, unsigned long long* lpNewFilePointer, unsigned int dwMoveMethod);
	static unsigned int __stdcall MockKernel32::GetFileAttributesW(void* lpFileName);
	static unsigned int __stdcall MockKernel32::GetFileAttributesExA(char* lpFileName, unsigned int fInfoLevelId, void* lpFileInformation);
	static unsigned int __stdcall MockKernel32::GetFileAttributesExW(wchar_t* lpFileName, unsigned int fInfoLevelId, void* lpFileInformation);
	static void* __stdcall MockKernel32::CreateFileA(char* lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode, void* lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes, void* hTemplateFile);
	static void* __stdcall MockKernel32::CreateFileW(wchar_t* lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode, void* lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes, void* hTemplateFile);
	static bool __stdcall MockKernel32::ReadFile(void* hFile, void* lpBuffer, unsigned int nNumberOfBytesToRead, unsigned int* lpNumberOfBytesRead, void* lpOverlapped);
	static bool __stdcall MockKernel32::WriteFile(void* hFile, void* lpBuffer, unsigned int nNumberOfBytesToWrite, unsigned int* lpNumberOfBytesWritten, void* lpOverlapped);
	static bool __stdcall MockKernel32::DeleteFile(char* lpFileName);
	static bool __stdcall MockKernel32::MyCloseHandle(void* hObject);

	static unsigned int __stdcall GetFileType(void* hFile);
	static unsigned int __stdcall MockKernel32::GetDriveTypeA(char* lpRootPathName);
	static unsigned int __stdcall MockKernel32::GetDriveTypeW(wchar_t* lpRootPathName);
	static unsigned int __stdcall MockKernel32::GetLogicalDrives();
	static unsigned int __stdcall MockKernel32::GetFileSizeEx(void* hFile, PLARGE_INTEGER lpFileSize);
	static bool __stdcall MockKernel32::GetProductInfo(unsigned int dwOSMajorVersion, unsigned int dwOSMinorVersion, unsigned int dwSpMajorVersion, unsigned int dwSpMinorVersion, unsigned int * pdwReturnedProductType);
	static void __stdcall MockKernel32::GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
	static unsigned int __stdcall MockKernel32::GetCurrentThreadID();
	static unsigned int __stdcall MockKernel32::GetCurrentProcessID();
	
	static void __stdcall MockKernel32::GetSystemTimeAsFileTime(void* lpSystemTimeAsFileTime);
	static void __stdcall MockKernel32::GetSystemTimePreciseAsFileTime(void* lpSystemTimeAsFileTime);
	static bool __stdcall MockKernel32::QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
	static unsigned int __stdcall MockKernel32::GetTickCount();
	static unsigned long long __stdcall MockKernel32::GetTickCount64();

	static bool __stdcall MockKernel32::DeviceIoControl(
		void* hDevice,
		unsigned int dwIoControlCode,
		void* lpInBuffer,
		unsigned int nInBufferSize,
		void* lpOutBufferm,
		unsigned int nOutBufferSize,
		unsigned int* lpBytesReturend,
		void* lpOverlapped
	);

	static void* __stdcall MockKernel32::GetCommandLineA();
	static void* __stdcall MockKernel32::GetCommandLineW();
	
	static void* __stdcall MockKernel32::DecodePointer(void* ptr);
	static void* __stdcall MockKernel32::EncodePointer(void* ptr);
	
	static unsigned int __stdcall MockKernel32::GetACP();
	static bool __stdcall IsValidCodePage(unsigned int CodePage);
	static bool __stdcall MockKernel32::GetCPInfo(int CodePage, LPCPINFO lpCPInfo);
	
	static unsigned int __stdcall MockKernel32::TlsAlloc();
	static bool __stdcall MockKernel32::TlsSetValue(unsigned int dwTlsIndex, void* lpTlsValue);
	static void* __stdcall MockKernel32::TlsGetValue(unsigned int dwTlsIndex);
	static bool __stdcall MockKernel32::TlsFree(unsigned int dwTlsIndex);
	static unsigned __stdcall MockKernel32::FlsAlloc(void* lpCallback);
	static unsigned int __stdcall MockKernel32::FlsSetValue(unsigned int dwFlsIndex, void* lpFlsData);
	static void* __stdcall MockKernel32::FlsGetValue(unsigned int dwFlsIndex);
	static bool __stdcall MockKernel32::FlsFree(unsigned int dwFlsIndex);
	
	static bool __stdcall MockKernel32::GetStringTypeA(unsigned int dwInfoType, char* lpSrcStr, int cchSrc, unsigned short* lpCharType);
	static bool __stdcall MockKernel32::GetStringTypeW(unsigned int dwInfoType, wchar_t* lpSrcStr, int cchSrc, unsigned short* lpCharType);
	static int __stdcall MockKernel32::LCMapStringA(LCID Locale, unsigned int dwMapFlags, char* lpSrcStr, int cchSrc, char*  lpDestStr, int cchDest);
	static int __stdcall MockKernel32::LCMapStringW(LCID Locale, unsigned int dwMapFlags, wchar_t* lpSrcStr, int cchSrc, wchar_t*  lpDestStr, int cchDest);
	static int __stdcall MockKernel32::LCMapStringEx(wchar_t* lpLocaleName, unsigned int dwMapFlags, wchar_t* lpSrcStr, int cchSrc, wchar_t* lpDestStr, int cchDest, void* lpVersionInformation, void* lpReserved, void* sortHandle);
	
	static int __stdcall MockKernel32::WideCharToMultiByte(unsigned int CodePage, unsigned int dwFlags, void* lpWideCharStr, int cchWideChar, void* lpMultiByteStr, int cbMultiByte, void* lpDefaultChar, void* lpUsedDefaultChar);
	static int __stdcall MockKernel32::MultiByteToWideChar(unsigned int CodePage, unsigned int dwFlags, void* lpMultiByteStr, int cbMultiByte, void* lpWideCHarStr, int cchWideChar);
	
	static void __stdcall MockKernel32::InitializeSListHead(PSLIST_HEADER ListHead);
	static void __stdcall MockKernel32::InitializeConditionVariable(PCONDITION_VARIABLE ConditionVariable);
	
	static bool __stdcall MockKernel32::InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, unsigned int dwSpinCount);
	static bool __stdcall MockKernel32::InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
	static bool __stdcall MockKernel32::InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, unsigned int dwSpinCOunt, unsigned int Flags);
	static void __stdcall MockKernel32::EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
	static void __stdcall MockKernel32::DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
	static void __stdcall MockKernel32::LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection);

	static unsigned int __stdcall MockKernel32::ExpandEnvironmentStringsW(wchar_t* lpSrc, wchar_t* lpDst, unsigned int nSize);
	static unsigned int __stdcall MockKernel32::GetEnvironmentVariableA(char* lpName, char* lpBuffer, unsigned int nSize);
	static unsigned int __stdcall MockKernel32::GetEnvironmentVariableW(wchar_t* lpName, wchar_t* lpBuffer, unsigned int nSize);
	static char* __stdcall MockKernel32::GetEnvironmentStrings();
	static wchar_t* __stdcall MockKernel32::GetEnvironmentStringsW();
	static bool __stdcall MockKernel32::FreeEnvironmentStringsA(char* penv);
	static bool __stdcall MockKernel32::FreeEnvironmentStringsW(wchar_t* penv);

	static void __stdcall MockKernel32::AcquireSRWLockExclusive(PSRWLOCK SRWLock);
	static void __stdcall MockKernel32::ReleaseSRWLockExclusive(PSRWLOCK SRWLock);
	static void __stdcall MockKernel32::InitializeSRWLock(PSRWLOCK SRWLock);

	static unsigned int __stdcall MockKernel32::GetSystemDirectoryA(char* lpBuffer, unsigned int uSize);
	static unsigned int __stdcall MockKernel32::GetSystemDirectoryW(wchar_t* lpBuffer, unsigned int uSize);
	static unsigned int __stdcall MockKernel32::GetFullPathNameW(wchar_t* lpFileName, unsigned int nBufferLength, wchar_t* lpBuffer, wchar_t** lpFilePart);
	static unsigned int __stdcall MockKernel32::GetTempPathW(unsigned int nBufferLength, wchar_t* lpBuffer);
	static unsigned int __stdcall MockKernel32::QueryDosDeviceA(void* lpDeviceName, void* lpTargetPath, unsigned int ucchMax);
	static unsigned int __stdcall MockKernel32::QueryDosDeviceW(void* lpDeviceName, void* lpTargetPath, unsigned int ucchMax);

	static bool __stdcall MockKernel32::VirtualProtect(void* lpAddress, size_t dwSize, unsigned int flNewProtect, void* lpflOldProtect);
	static bool __stdcall MockKernel32::VirtualLock(void* lpAddress, unsigned int dwSize);
	
	static void* __stdcall MockKernel32::CreateThreadpoolTimer(void* pfnti, void* pv, void* pcbe);
	static void __stdcall MockKernel32::SetThreadpoolTimer(void* pfnti, void* pv, unsigned int msPeriod, unsigned int msWindowLength);
	static void __stdcall MockKernel32::WaitForThreadpoolTimerCallbacks(void* ptr, bool fCancelPendingCallbacks);
	static void __stdcall MockKernel32::CloseThreadpoolTimer(void* pti);
	static void* __stdcall MockKernel32::CreateThreadpoolWork(void* pfnwk, void* pv, void* pcbe);

	static void* __stdcall MockKernel32::CreateSemaphoreW(void* lpSemaphoreAttributes, long lInitialCount, long lMaximumCount, wchar_t* lpName);
	static void* __stdcall MockKernel32::CreateEventW(void* lpEventAttributes, bool bManualReset, bool bInitialState, wchar_t* lpName);
	static bool __stdcall MockKernel32::SetEvent(void* hEvent);
	static bool __stdcall MockKernel32::ReSetEvent(void* hEvent);
	static bool __stdcall MockKernel32::RegisterWaitForSingleObject(void** phNewWaitObject, void* hObject, void* Callback, void* Context, unsigned long dwMilliseconds, unsigned long dwFlags);
	static unsigned int __stdcall MockKernel32::WaitForSingleObject(void* hHandle, unsigned int dwMilliseconds);
};
#endif // !_KERNEL32_H_
