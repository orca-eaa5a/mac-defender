#if defined(__WINDOWS__)
#pragma once
#endif

#ifndef _KERNEL32_H_
#define _KERNEL32_H_
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include "../ntoskrnl.h"
#include "../exports.h"

#if defined(__WINDOWS__)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
	#if defined(__APPLE__)
	#include <sys/types.h>
	#include <malloc/malloc.h>
	#endif
#include "include/windows.h"
#endif

#define MAXIMUM_TLS_SLOTS 1088

typedef void (__stdcall *PFLS_CALLBACK_FUNCTION) (void*);

class MockKernel32 {

public:
	static std::string commandline;
	static std::u16string wcommandline;	
	
	static uint64_t ThreadLocalStorage[1024]; // 64bit
	//static uint64_t* ThreadLocalStorage;
	static PFLS_CALLBACK_FUNCTION FlsCallbacks[1024];
	static uint32_t tls_index;
	static uint32_t tick_counter;

	function<void(void)> set_k32_hookaddr = [](void){
		APIExports::add_hook_info("kernel32.dll", "GetModuleHandleA", (void*)MockGetModuleHandleA);
		APIExports::add_hook_info("kernel32.dll", "GetModuleHandleW", (void*)GetModuleHandleW);
		APIExports::add_hook_info("kernel32.dll", "GetModuleHandleExW", (void*)GetModuleHandleExW);
		APIExports::add_hook_info("kernel32.dll", "CloseHandle", (void*)CloseHandle);
		APIExports::add_hook_info("kernel32.dll", "DuplicateHandle", (void*)DuplicateHandle);

		APIExports::add_hook_info("kernel32.dll", "GetProcAddress", (void*)MockGetProcAddress);
		
		APIExports::add_hook_info("kernel32.dll", "SetLastError", (void*)SetLastError);
		APIExports::add_hook_info("kernel32.dll", "GetLastError", (void*)GetLastError);
		
		APIExports::add_hook_info("kernel32.dll", "GetStartupInfoA", (void*)GetStartupInfoA);
		APIExports::add_hook_info("kernel32.dll", "GetStartupInfoW", (void*)GetStartupInfoW);
		APIExports::add_hook_info("kernel32.dll", "GetStringTypeA", (void*)GetStringTypeA);
		APIExports::add_hook_info("kernel32.dll", "GetStringTypeW", (void*)GetStringTypeW);
		APIExports::add_hook_info("kernel32.dll", "GetModuleFileNameA", (void*)GetModuleFileNameA);
		APIExports::add_hook_info("kernel32.dll", "GetModuleFileNameW", (void*)GetModuleFileNameW);

		APIExports::add_hook_info("kernel32.dll", "GetStdHandle", (void*)GetStdHandle);
		//APIExports::add_hook_info("kernel32.dll", "LoadLibraryA", (void*)LoadLibraryA);
		APIExports::add_hook_info("kernel32.dll", "LoadLibraryW", (void*)LoadLibraryW);
		APIExports::add_hook_info("kernel32.dll", "LoadLibraryExW", (void*)LoadLibraryExW);
		APIExports::add_hook_info("kernel32.dll", "FreeLibrary", (void*)FreeLibrary);
		
		APIExports::add_hook_info("kernel32.dll", "CreateFileA", (void*)CreateFileA);
		APIExports::add_hook_info("kernel32.dll", "CreateFileW", (void*)CreateFileW);
		APIExports::add_hook_info("kernel32.dll", "ReadFile", (void*)ReadFile);
		APIExports::add_hook_info("kernel32.dll", "WriteFile", (void*)WriteFile);
		APIExports::add_hook_info("kernel32.dll", "DeleteFileA", (void*)DeleteFileA);
		APIExports::add_hook_info("kernel32.dll", "DeleteFileW", (void*)DeleteFileW);
		APIExports::add_hook_info("kernel32.dll", "FindFirstFileW", (void*)FindFirstFileW);


		APIExports::add_hook_info("kernel32.dll", "GetFileSizeEx", (void*)GetFileSizeEx);
		APIExports::add_hook_info("kernel32.dll", "GetFileSGetFileAttributesWizeEx", (void*)GetFileAttributesW);
		APIExports::add_hook_info("kernel32.dll", "GetFileAttributesExA", (void*)GetFileAttributesExA);
		APIExports::add_hook_info("kernel32.dll", "GetFileAttributesExW", (void*)GetFileAttributesExW);
		APIExports::add_hook_info("kernel32.dll", "SetFilePointer", (void*)SetFilePointer);
		APIExports::add_hook_info("kernel32.dll", "SetFilePointerEx", (void*)SetFilePointerEx);
		
		APIExports::add_hook_info("kernel32.dll", "EncodePointer", (void*)EncodePointer);
		APIExports::add_hook_info("kernel32.dll", "DecodePointer", (void*)DecodePointer);
		
		APIExports::add_hook_info("kernel32.dll", "GetFileType", (void*)GetFileType);
		APIExports::add_hook_info("kernel32.dll", "GetDriveTypeW", (void*)GetDriveTypeW);
		APIExports::add_hook_info("kernel32.dll", "GetDriveTypeA", (void*)GetDriveTypeA);
		APIExports::add_hook_info("kernel32.dll", "GetLogicalDrives", (void*)GetLogicalDrives);
		APIExports::add_hook_info("kernel32.dll", "GetSystemDefaultLCID", (void*)GetSystemDefaultLCID);

		APIExports::add_hook_info("kernel32.dll", "GetProductInfo", (void*)GetProductInfo);
		APIExports::add_hook_info("kernel32.dll", "GetSystemInfo", (void*)GetSystemInfo);
		APIExports::add_hook_info("kernel32.dll", "GetCurrentProcessId", (void*)GetCurrentProcessID);
		APIExports::add_hook_info("kernel32.dll", "GetCurrentThreadId", (void*)GetCurrentThreadID);
		APIExports::add_hook_info("kernel32.dll", "SetProcessInformation", (void*)SetProcessInformation);

		APIExports::add_hook_info("kernel32.dll", "GetThreadTimes", (void*)GetThreadTimes);
		APIExports::add_hook_info("kernel32.dll", "CreateTimerQueueTimer", (void*)CreateTimerQueueTimer);
		APIExports::add_hook_info("kernel32.dll", "GetSystemTime", (void*)GetSystemTime);
		APIExports::add_hook_info("kernel32.dll", "SystemTimeToFileTime", (void*)SystemTimeToFileTime);
		APIExports::add_hook_info("kernel32.dll", "GetSystemTimeAsFileTime", (void*)GetSystemTimeAsFileTime);
		APIExports::add_hook_info("kernel32.dll", "GetSystemTimePreciseAsFileTime", (void*)GetSystemTimePreciseAsFileTime);
		APIExports::add_hook_info("kernel32.dll", "QueryPerformanceFrequency", (void*)QueryPerformanceFrequency);
		APIExports::add_hook_info("kernel32.dll", "QueryPerformanceCounter", (void*)QueryPerformanceCounter);
		APIExports::add_hook_info("kernel32.dll", "GetTickCount", (void*)GetTickCount);
		APIExports::add_hook_info("kernel32.dll", "GetTickCount64", (void*)GetTickCount64);
		
		APIExports::add_hook_info("kernel32.dll", "DeviceIoControl", (void*)DeviceIoControl);

		APIExports::add_hook_info("kernel32.dll", "GetCommandLineA", (void*)GetCommandLineA);
		APIExports::add_hook_info("kernel32.dll", "GetCommandLineW", (void*)GetCommandLineW);

		APIExports::add_hook_info("kernel32.dll", "GetACP", (void*)GetACP);
		APIExports::add_hook_info("kernel32.dll", "IsValidCodePage", (void*)IsValidCodePage);
		APIExports::add_hook_info("kernel32.dll", "GetCPInfo", (void*)GetCPInfo);
		
		APIExports::add_hook_info("kernel32.dll", "TlsAlloc", (void*)TlsAlloc);
		APIExports::add_hook_info("kernel32.dll", "TlsGetValue", (void*)TlsGetValue);
		APIExports::add_hook_info("kernel32.dll", "TlsSetValue", (void*)TlsSetValue);
		APIExports::add_hook_info("kernel32.dll", "TlsFree", (void*)TlsFree);
		APIExports::add_hook_info("kernel32.dll", "FlsAlloc", (void*)FlsAlloc);
		APIExports::add_hook_info("kernel32.dll", "FlsGetValue", (void*)FlsGetValue);
		APIExports::add_hook_info("kernel32.dll", "FlsSetValue", (void*)FlsSetValue);
		APIExports::add_hook_info("kernel32.dll", "FlsFree", (void*)FlsFree);
		
		APIExports::add_hook_info("kernel32.dll", "LCMapStringA", (void*)LCMapStringA);
		APIExports::add_hook_info("kernel32.dll", "LCMapStringW", (void*)LCMapStringW);
		APIExports::add_hook_info("kernel32.dll", "LCMapStringEx", (void*)LCMapStringEx);

		APIExports::add_hook_info("kernel32.dll", "MultiByteToWideChar", (void*)MultiByteToWideChar);
		APIExports::add_hook_info("kernel32.dll", "WideCharToMultiByte", (void*)WideCharToMultiByte);
		
		APIExports::add_hook_info("kernel32.dll", "InitializeSListHead", (void*)InitializeSListHead);
		APIExports::add_hook_info("kernel32.dll", "InitializeConditionVariable", (void*)InitializeConditionVariable);

		APIExports::add_hook_info("kernel32.dll", "InitializeCriticalSection", (void*)InitializeCriticalSection);
		APIExports::add_hook_info("kernel32.dll", "InitializeCriticalSectionEx", (void*)InitializeCriticalSectionEx);
		APIExports::add_hook_info("kernel32.dll", "InitializeCriticalSectionAndSpinCount", (void*)InitializeCriticalSectionAndSpinCount);
		APIExports::add_hook_info("kernel32.dll", "EnterCriticalSection", (void*)EnterCriticalSection);
		APIExports::add_hook_info("kernel32.dll", "LeaveCriticalSection", (void*)LeaveCriticalSection);
		APIExports::add_hook_info("kernel32.dll", "DeleteCriticalSection", (void*)DeleteCriticalSection);

		
		APIExports::add_hook_info("kernel32.dll", "ExpandEnvironmentStringsW", (void*)ExpandEnvironmentStringsW);
		APIExports::add_hook_info("kernel32.dll", "GetEnvironmentVariableA", (void*)GetEnvironmentVariableA);
		APIExports::add_hook_info("kernel32.dll", "GetEnvironmentVariableW", (void*)GetEnvironmentVariableW);
		APIExports::add_hook_info("kernel32.dll", "GetEnvironmentStrings", (void*)GetEnvironmentStrings);
		APIExports::add_hook_info("kernel32.dll", "GetEnvironmentStringsW", (void*)GetEnvironmentStringsW);
		APIExports::add_hook_info("kernel32.dll", "FreeEnvironmentStringsA", (void*)FreeEnvironmentStringsA);
		APIExports::add_hook_info("kernel32.dll", "FreeEnvironmentStringsW", (void*)FreeEnvironmentStringsW);
		
		APIExports::add_hook_info("kernel32.dll", "AcquireSRWLockExclusive", (void*)AcquireSRWLockExclusive);
		APIExports::add_hook_info("kernel32.dll", "ReleaseSRWLockExclusive", (void*)ReleaseSRWLockExclusive);
		APIExports::add_hook_info("kernel32.dll", "InitializeSRWLock", (void*)InitializeSRWLock);
		
		APIExports::add_hook_info("kernel32.dll", "VirtualAlloc", (void*)VirtualAlloc);
		APIExports::add_hook_info("kernel32.dll", "VirtualFree", (void*)VirtualFree);
		APIExports::add_hook_info("kernel32.dll", "VirtualLock", (void*)VirtualLock);
		APIExports::add_hook_info("kernel32.dll", "VirtualUnlock", (void*)VirtualUnlock);
		APIExports::add_hook_info("kernel32.dll", "VirtualProtect", (void*)MockVirtualProtect);
		
		
		APIExports::add_hook_info("kernel32.dll", "GetFileAttributesW", (void*)GetFileAttributesW);
		APIExports::add_hook_info("kernel32.dll", "GetFileAttributesExA", (void*)GetFileAttributesExA);
		APIExports::add_hook_info("kernel32.dll", "GetFileAttributesExW", (void*)GetFileAttributesExW);
		
		APIExports::add_hook_info("kernel32.dll", "GetCurrentProcess", (void*)GetCurrentProcess);
		APIExports::add_hook_info("kernel32.dll", "GetCurrentThread", (void*)GetCurrentThread);
		APIExports::add_hook_info("kernel32.dll", "GetSystemWindowsDirectoryW", (void*)GetSystemWindowsDirectoryW);
		APIExports::add_hook_info("kernel32.dll", "GetSystemWow64DirectoryW", (void*)GetSystemWow64DirectoryW);
		APIExports::add_hook_info("kernel32.dll", "GetSystemDirectoryA", (void*)GetSystemDirectoryA);
		APIExports::add_hook_info("kernel32.dll", "GetSystemDirectoryW", (void*)GetSystemDirectoryW);
		APIExports::add_hook_info("kernel32.dll", "GetTempPathW", (void*)GetTempPathW);
		APIExports::add_hook_info("kernel32.dll", "GetFullPathNameW", (void*)GetFullPathNameW);
		APIExports::add_hook_info("kernel32.dll", "GetComputerNameExW", (void*)GetComputerNameExW);
		APIExports::add_hook_info("kernel32.dll", "ProcessIdToSessionId", (void*)ProcessIdToSessionId);
		APIExports::add_hook_info("kernel32.dll", "GetProcessTimes", (void*)GetProcessTimes);
		APIExports::add_hook_info("kernel32.dll", "QueryDosDeviceA", (void*)QueryDosDeviceA);
		APIExports::add_hook_info("kernel32.dll", "QueryDosDeviceW", (void*)QueryDosDeviceW);
		
		
		APIExports::add_hook_info("kernel32.dll", "CreateThreadpoolTimer", (void*)CreateThreadpoolTimer);
		APIExports::add_hook_info("kernel32.dll", "SetThreadpoolTimer", (void*)SetThreadpoolTimer);
		APIExports::add_hook_info("kernel32.dll", "WaitForThreadpoolTimerCallbacks", (void*)WaitForThreadpoolTimerCallbacks);
		APIExports::add_hook_info("kernel32.dll", "CloseThreadpoolTimer", (void*)CloseThreadpoolTimer);
		APIExports::add_hook_info("kernel32.dll", "CreateThreadpoolWork", (void*)CreateThreadpoolWork);
		APIExports::add_hook_info("kernel32.dll", "WaitForThreadpoolWorkCallbacks", (void*)WaitForThreadpoolWorkCallbacks);
		
		APIExports::add_hook_info("kernel32.dll", "CreateSemaphoreW", (void*)CreateSemaphoreW);
		APIExports::add_hook_info("kernel32.dll", "CreateEventW", (void*)CreateEventW);
		APIExports::add_hook_info("kernel32.dll", "SetEvent", (void*)SetEvent);
		APIExports::add_hook_info("kernel32.dll", "ResetEvent", (void*)ReSetEvent);
		APIExports::add_hook_info("kernel32.dll", "RegisterWaitForSingleObject", (void*)RegisterWaitForSingleObject);
		APIExports::add_hook_info("kernel32.dll", "WaitForSingleObject", (void*)WaitForSingleObject);
		
		APIExports::add_hook_info("kernel32.dll", "GetProcessHeap", (void*)GetProcessHeap);
		APIExports::add_hook_info("kernel32.dll", "HeapCreate", (void*)HeapCreate);
		APIExports::add_hook_info("kernel32.dll", "HeapAlloc", (void*)HeapAlloc);
		APIExports::add_hook_info("kernel32.dll", "HeapReAlloc", (void*)HeapReAlloc);
		APIExports::add_hook_info("kernel32.dll", "HeapFree", (void*)HeapFree);
		APIExports::add_hook_info("kernel32.dll", "HeapDestroy", (void*)HeapDestroy);
		APIExports::add_hook_info("kernel32.dll", "HeapSize", (void*)HeapSize);
		
		APIExports::add_hook_info("kernel32.dll", "LocalAlloc", (void*)LocalAlloc);
		APIExports::add_hook_info("kernel32.dll", "LocalFree", (void*)LocalFree);
		APIExports::add_hook_info("kernel32.dll", "GlobalAlloc", (void*)LocalAlloc);
		APIExports::add_hook_info("kernel32.dll", "GlobalFree", (void*)LocalFree);
		
		APIExports::add_hook_info("kernel32.dll", "CompareStringOrdinal", (void*)CompareStringOrdinal);
		APIExports::add_hook_info("kernel32.dll", "RaiseException", (void*)RaiseException);
		APIExports::add_hook_info("kernel32.dll", "IsProcessorFeaturePresent", (void*)MockIsProcessorFeaturePresent);
		APIExports::add_hook_info("kernel32.dll", "IsDebuggerPresent", (void*)IsDebuggerPresent);
	};
#if defined(__WINDOWS__)
	static void __stdcall MockKernel32::SetLastError(uint32_t dwErrCode);
	static uint32_t __stdcall MockKernel32::GetLastError();

	static void __stdcall MockKernel32::GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo);
	static void __stdcall MockKernel32::GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo);
	
	static void* __stdcall MockKernel32::GetStdHandle(uint32_t nStdHandle);
	//static void* __stdcall MockKernel32::LoadLibraryA(char* lpLibFileName);
	static void* __stdcall MockKernel32::LoadLibraryW(char16_t* lpLibFileName);
	static void* __stdcall MockKernel32::LoadLibraryExW(char16_t* lpLibFileName, void* hFile, uint32_t dwFlags);
	static bool __stdcall MockKernel32::FreeLibrary(void* hLibModule);
	static void* __stdcall MockKernel32::MockGetModuleHandleA(char* lpModuleName);
	static void* __stdcall MockKernel32::GetModuleHandleW(char16_t* lpModuleName);
	static bool __stdcall MockKernel32::GetModuleHandleExA(uint32_t dwFlags, char* lpModuleName, void* phModule);
	static bool __stdcall MockKernel32::GetModuleHandleExW(uint32_t dwFlags, char16_t* lpModuleName, void* phModule);
	static void* __stdcall MockKernel32::MockGetProcAddress(void* hModule, char* lpProcName);
	static uint32_t __stdcall MockKernel32::GetModuleFileNameA(void* hModule, char* lpFilename, uint32_t nSize);
	static uint32_t __stdcall MockKernel32::GetModuleFileNameW(void* hModule, char16_t* lpFilename, uint32_t nSize);
	
	static uint32_t __stdcall MockKernel32::SetFilePointer(void* hFile, long lDistanceToMove, long* lpDistanceToMoveHigh, uint32_t dwMoveMethod);
	static bool __stdcall MockKernel32::SetFilePointerEx(void* hFile, uint64_t liDistanceToMove, uint64_t* lpNewFilePointer, uint32_t dwMoveMethod);
	static uint32_t __stdcall MockKernel32::GetFileAttributesW(void* lpFileName);
	static uint32_t __stdcall MockKernel32::GetFileAttributesExA(char* lpFileName, uint32_t fInfoLevelId, void* lpFileInformation);
	static uint32_t __stdcall MockKernel32::GetFileAttributesExW(char16_t* lpFileName, uint32_t fInfoLevelId, void* lpFileInformation);
	static void* __stdcall MockKernel32::CreateFileA(char* lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, void* lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, void* hTemplateFile);
	static void* __stdcall MockKernel32::CreateFileW(char16_t* lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, void* lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, void* hTemplateFile);
	static bool __stdcall MockKernel32::ReadFile(void* hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead, uint32_t* lpNumberOfBytesRead, void* lpOverlapped);
	static bool __stdcall MockKernel32::WriteFile(void* hFile, void* lpBuffer, uint32_t nNumberOfBytesToWrite, uint32_t* lpNumberOfBytesWritten, void* lpOverlapped);
	static bool __stdcall MockKernel32::DeleteFileA(char* lpFileName);
	static bool __stdcall MockKernel32::DeleteFileW(char16_t* lpFileName);
	static bool __stdcall MockKernel32::CloseHandle(void* hObject);
	static void* __stdcall MockKernel32::FindFirstFileW(char16_t* lpFileName, void* lpFindFileData);

	static bool __stdcall MockKernel32::DuplicateHandle(void* hSourceProcessHandle, void* hSourceHandle, void* hTargetProcessHandle, void** lpTargetHandle, uint32_t dwDesiredAccess, bool bInheritHandle, uint32_t dwOptions);
	static uint32_t __stdcall MockKernel32::GetFileType(void* hFile);
	static uint32_t __stdcall MockKernel32::GetDriveTypeA(char* lpRootPathName);
	static uint32_t __stdcall MockKernel32::GetDriveTypeW(char16_t* lpRootPathName);
	static uint32_t __stdcall MockKernel32::GetLogicalDrives();
	static uint32_t __stdcall MockKernel32::GetSystemDefaultLCID();
	static uint32_t __stdcall MockKernel32::GetFileSizeEx(void* hFile, PLARGE_INTEGER lpFileSize);
	static bool __stdcall MockKernel32::GetProductInfo(uint32_t dwOSMajorVersion, uint32_t dwOSMinorVersion, uint32_t dwSpMajorVersion, uint32_t dwSpMinorVersion, uint32_t * pdwReturnedProductType);
	static void __stdcall MockKernel32::GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
	static uint32_t __stdcall MockKernel32::GetCurrentThreadID();
	static uint32_t __stdcall MockKernel32::GetCurrentProcessID();
	static bool __stdcall MockKernel32::SetProcessInformation(void* hProces, PROCESS_INFORMATION_CLASS ProcessInformationClass, void* ProcessInformation, uint32_t ProcessInformationSize);

	static bool __stdcall MockKernel32::CreateTimerQueueTimer(void** phNewTimer, void* TimerQueue, void* Callback, void* Parameter, uint32_t DueTime, uint32_t Period, uint32_t Flags);
	static void __stdcall MockKernel32::GetSystemTime(PSYSTEMTIME lpSystemTime);
	static bool __stdcall MockKernel32::SystemTimeToFileTime(SYSTEMTIME *lpSystemTime, PFILETIME lpFileTime);
	static void __stdcall MockKernel32::GetSystemTimeAsFileTime(void* lpSystemTimeAsFileTime);
	static void __stdcall MockKernel32::GetSystemTimePreciseAsFileTime(void* lpSystemTimeAsFileTime);
	
	static bool __stdcall MockKernel32::QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
	static bool __stdcall MockKernel32::QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
	static uint32_t __stdcall MockKernel32::GetTickCount();
	static uint64_t __stdcall MockKernel32::GetTickCount64();

	static bool __stdcall MockKernel32::DeviceIoControl(
		void* hDevice,
		uint32_t dwIoControlCode,
		void* lpInBuffer,
		uint32_t nInBufferSize,
		void* lpOutBufferm,
		uint32_t nOutBufferSize,
		uint32_t* lpBytesReturend,
		void* lpOverlapped
	);

	static void* __stdcall MockKernel32::GetCommandLineA();
	static void* __stdcall MockKernel32::GetCommandLineW();
	
	static void* __stdcall MockKernel32::DecodePointer(void* ptr);
	static void* __stdcall MockKernel32::EncodePointer(void* ptr);
	
	static uint32_t __stdcall MockKernel32::GetACP();
	static bool __stdcall MockKernel32::IsValidCodePage(uint32_t CodePage);
	static bool __stdcall MockKernel32::GetCPInfo(int CodePage, LPCPINFO lpCPInfo);
	
	static uint32_t __stdcall MockKernel32::TlsAlloc();
	static bool __stdcall MockKernel32::TlsSetValue(uint32_t dwTlsIndex, void* lpTlsValue);
	static void* __stdcall MockKernel32::TlsGetValue(uint32_t dwTlsIndex);
	static bool __stdcall MockKernel32::TlsFree(uint32_t dwTlsIndex);
	static uint32_t __stdcall MockKernel32::FlsAlloc(void* lpCallback);
	static uint32_t __stdcall MockKernel32::FlsSetValue(uint32_t dwFlsIndex, void* lpFlsData);
	static void* __stdcall MockKernel32::FlsGetValue(uint32_t dwFlsIndex);
	static bool __stdcall MockKernel32::FlsFree(uint32_t dwFlsIndex);
	
	static bool __stdcall MockKernel32::GetStringTypeA(uint32_t dwInfoType, char* lpSrcStr, int cchSrc, uint16_t* lpCharType);
	static bool __stdcall MockKernel32::GetStringTypeW(uint32_t dwInfoType, char16_t* lpSrcStr, int cchSrc, uint16_t* lpCharType);
	static int __stdcall MockKernel32::LCMapStringA(LCID Locale, uint32_t dwMapFlags, char* lpSrcStr, int cchSrc, char*  lpDestStr, int cchDest);
	static int __stdcall MockKernel32::LCMapStringW(LCID Locale, uint32_t dwMapFlags, char16_t* lpSrcStr, int cchSrc, char16_t*  lpDestStr, int cchDest);
	static int __stdcall MockKernel32::LCMapStringEx(char16_t* lpLocaleName, uint32_t dwMapFlags, char16_t* lpSrcStr, int cchSrc, char16_t* lpDestStr, int cchDest, void* lpVersionInformation, void* lpReserved, void* sortHandle);
	
	static int __stdcall MockKernel32::WideCharToMultiByte(uint32_t CodePage, uint32_t dwFlags, void* lpWideCharStr, int cchWideChar, void* lpMultiByteStr, int cbMultiByte, void* lpDefaultChar, void* lpUsedDefaultChar);
	static int __stdcall MockKernel32::MultiByteToWideChar(uint32_t CodePage, uint32_t dwFlags, void* lpMultiByteStr, int cbMultiByte, void* lpWideCHarStr, int cchWideChar);
	
	static void __stdcall MockKernel32::InitializeSListHead(PSLIST_HEADER ListHead);
	static void __stdcall MockKernel32::InitializeConditionVariable(void* ConditionVariable);
	
	static bool __stdcall MockKernel32::InitializeCriticalSectionAndSpinCount(void* lpCriticalSection, uint32_t dwSpinCount);
	static bool __stdcall MockKernel32::InitializeCriticalSection(void* lpCriticalSection);
	static bool __stdcall MockKernel32::InitializeCriticalSectionEx(void* lpCriticalSection, uint32_t dwSpinCOunt, uint32_t Flags);
	static void __stdcall MockKernel32::EnterCriticalSection(void* lpCriticalSection);
	static void __stdcall MockKernel32::DeleteCriticalSection(void* lpCriticalSection);
	static void __stdcall MockKernel32::LeaveCriticalSection(void* lpCriticalSection);

	static uint32_t __stdcall MockKernel32::ExpandEnvironmentStringsW(char16_t* lpSrc, char16_t* lpDst, uint32_t nSize);
	static uint32_t __stdcall MockKernel32::GetEnvironmentVariableA(char* lpName, char* lpBuffer, uint32_t nSize);
	static uint32_t __stdcall MockKernel32::GetEnvironmentVariableW(char16_t* lpName, char16_t* lpBuffer, uint32_t nSize);
	static char* __stdcall MockKernel32::GetEnvironmentStrings();
	static char16_t* __stdcall MockKernel32::GetEnvironmentStringsW();
	static bool __stdcall MockKernel32::FreeEnvironmentStringsA(char* penv);
	static bool __stdcall MockKernel32::FreeEnvironmentStringsW(char16_t* penv);

	static void __stdcall MockKernel32::AcquireSRWLockExclusive(PSRWLOCK SRWLock);
	static void __stdcall MockKernel32::ReleaseSRWLockExclusive(PSRWLOCK SRWLock);
	static void __stdcall MockKernel32::InitializeSRWLock(PSRWLOCK SRWLock);

	static void* __stdcall MockKernel32::GetCurrentProcess();
	static void* __stdcall MockKernel32::GetCurrentThread();

	static bool __stdcall MockKernel32::GetDiskFreeSpaceExW(char16_t* lpDirectoryName, void* lpFreeBytesAvailableToCaller, void* lpTotalNumberOfBytes, void* lpTotalNumberOfFreeBytes);
	static uint32_t __stdcall MockKernel32::GetSystemWindowsDirectoryW(char16_t* lpBuffer, uint32_t uSize);
	static uint32_t __stdcall MockKernel32::GetSystemWow64DirectoryW(char16_t* lpBuffer, uint32_t uSize);
	static uint32_t __stdcall MockKernel32::GetSystemDirectoryA(char* lpBuffer, uint32_t uSize);
	static uint32_t __stdcall MockKernel32::GetSystemDirectoryW(char16_t* lpBuffer, uint32_t uSize);
	static uint32_t __stdcall MockKernel32::GetFullPathNameW(char16_t* lpFileName, uint32_t nBufferLength, char16_t* lpBuffer, char16_t** lpFilePart);
	static uint32_t __stdcall MockKernel32::GetTempPathW(uint32_t nBufferLength, char16_t* lpBuffer);
	static bool __stdcall MockKernel32::GetComputerNameExW(uint32_t NameType, char16_t* lpBuffer, uint32_t* lpnSize);
	static bool __stdcall MockKernel32::ProcessIdToSessionId(uint32_t dwProcessId, uint32_t* pSessionId);
	static bool __stdcall MockKernel32::GetProcessTimes(void* hProcess, void* lpCreationTime, void* lpExitTime, void* lpKernelTime, void* lpUserTime);
	static uint32_t __stdcall MockKernel32::QueryDosDeviceA(void* lpDeviceName, void* lpTargetPath, uint32_t ucchMax);
	static uint32_t __stdcall MockKernel32::QueryDosDeviceW(void* lpDeviceName, void* lpTargetPath, uint32_t ucchMax);

	static void* __stdcall MockKernel32::VirtualAlloc(void* lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect);
	static bool __stdcall MockKernel32::MockVirtualProtect(void* lpAddress, size_t dwSize, uint32_t flNewProtect, void* lpflOldProtect);
	static bool __stdcall MockKernel32::VirtualLock(void* lpAddress, size_t dwSize);
	static bool __stdcall MockKernel32::VirtualUnlock(void* lpAddress, size_t dwSize);
	static bool __stdcall MockKernel32::VirtualFree(void* lpAddress, size_t dwSize, uint32_t dwFreeType);
	
	static void* __stdcall MockKernel32::CreateThreadpoolTimer(void* pfnti, void* pv, void* pcbe);
	static bool __stdcall MockKernel32::GetThreadTimes(void* hThread, void* lpCreationTime, void* lpExitTime, void* lpKernelTime, void* lpUserTime);
	static void __stdcall MockKernel32::SetThreadpoolTimer(void* pfnti, void* pv, uint32_t msPeriod, uint32_t msWindowLength);
	static void __stdcall MockKernel32::WaitForThreadpoolTimerCallbacks(void* ptr, bool fCancelPendingCallbacks);
	static void __stdcall MockKernel32::CloseThreadpoolTimer(void* pti);
	static void* __stdcall MockKernel32::CreateThreadpoolWork(void* pfnwk, void* pv, void* pcbe);
	static void __stdcall MockKernel32::CloseThreadpoolWork(void* pfnwk);
	static void __stdcall MockKernel32::WaitForThreadpoolWorkCallbacks(void* pwk, bool fCancelPendingCallbacks);

	static void* __stdcall MockKernel32::CreateSemaphoreW(void* lpSemaphoreAttributes, long lInitialCount, long lMaximumCount, char16_t* lpName);
	static void* __stdcall MockKernel32::CreateEventW(void* lpEventAttributes, bool bManualReset, bool bInitialState, char16_t* lpName);
	static bool __stdcall MockKernel32::SetEvent(void* hEvent);
	static bool __stdcall MockKernel32::ReSetEvent(void* hEvent);
	static bool __stdcall MockKernel32::RegisterWaitForSingleObject(void** phNewWaitObject, void* hObject, void* Callback, void* Context, uint32_t dwMilliseconds, uint32_t dwFlags);
	static uint32_t __stdcall MockKernel32::WaitForSingleObject(void* hHandle, uint32_t dwMilliseconds);

	static void* __stdcall MockKernel32::GetProcessHeap();
	static void* __stdcall MockKernel32::HeapCreate(uint32_t flOptions, size_t dwInitialSize, size_t dwMaximumSize);
	static void* __stdcall MockKernel32::HeapAlloc(void* hHeap, uint32_t dwFlags, size_t dwBytes);
	static void* __stdcall MockKernel32::HeapReAlloc(void* hHeap, uint32_t dwFlags, void* lpMem, size_t dwBytes);
	static bool __stdcall MockKernel32::HeapFree(void* hHeap, uint32_t dwFlags, void* lpMem);
	static bool __stdcall MockKernel32::HeapDestroy(void* hHeap);
	static size_t __stdcall MockKernel32::HeapSize(void* hHeap, uint32_t dwFlags, void* lpMem);

	static void* __stdcall MockKernel32::LocalAlloc(uint32_t uFlags, size_t uBytes);
	static void* __stdcall MockKernel32::LocalFree(void* hMem);

	static int __stdcall MockKernel32::CompareStringOrdinal(void* lpString1, int cchCount1, void* lpString2, int cchCount2, bool bIgnoreCase);

	static void* __stdcall MockKernel32::RaiseException(uint32_t dwExceptionCode, uint32_t dwExceptionFlags, uint32_t nNumberOfArguments, void* Arguments);
	static bool __stdcall MockKernel32::MockIsProcessorFeaturePresent(uint32_t ProcessorFeature);
	static bool __stdcall MockKernel32::IsDebuggerPresent();
#else
	static void __stdcall SetLastError(uint32_t dwErrCode);
	static uint32_t __stdcall GetLastError();

	static void __stdcall GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo);
	static void __stdcall GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo);

	static void* __stdcall GetStdHandle(uint32_t nStdHandle);
	//static void* __stdcall LoadLibraryA(char* lpLibFileName);
	static void* __stdcall LoadLibraryW(char16_t* lpLibFileName);
	static void* __stdcall LoadLibraryExW(char16_t* lpLibFileName, void* hFile, uint32_t dwFlags);
	static bool __stdcall FreeLibrary(void* hLibModule);
	static void* __stdcall MockGetModuleHandleA(char* lpModuleName);
	static void* __stdcall GetModuleHandleW(char16_t* lpModuleName);
	static bool __stdcall GetModuleHandleExA(uint32_t dwFlags, char* lpModuleName, void* phModule);
	static bool __stdcall GetModuleHandleExW(uint32_t dwFlags, char16_t* lpModuleName, void* phModule);
	static void* __stdcall MockGetProcAddress(void* hModule, char* lpProcName);
	static uint32_t __stdcall GetModuleFileNameA(void* hModule, char* lpFilename, uint32_t nSize);
	static uint32_t __stdcall GetModuleFileNameW(void* hModule, char16_t* lpFilename, uint32_t nSize);

	static uint32_t __stdcall SetFilePointer(void* hFile, long lDistanceToMove, long* lpDistanceToMoveHigh, uint32_t dwMoveMethod);
	static bool __stdcall SetFilePointerEx(void* hFile, uint64_t liDistanceToMove, uint64_t* lpNewFilePointer, uint32_t dwMoveMethod);
	static uint32_t __stdcall GetFileAttributesW(void* lpFileName);
	static uint32_t __stdcall GetFileAttributesExA(char* lpFileName, uint32_t fInfoLevelId, void* lpFileInformation);
	static uint32_t __stdcall GetFileAttributesExW(char16_t* lpFileName, uint32_t fInfoLevelId, void* lpFileInformation);
	static void* __stdcall CreateFileA(char* lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, void* lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, void* hTemplateFile);
	static void* __stdcall CreateFileW(char16_t* lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, void* lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, void* hTemplateFile);
	static bool __stdcall ReadFile(void* hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead, uint32_t* lpNumberOfBytesRead, void* lpOverlapped);
	static bool __stdcall WriteFile(void* hFile, void* lpBuffer, uint32_t nNumberOfBytesToWrite, uint32_t* lpNumberOfBytesWritten, void* lpOverlapped);
	static bool __stdcall DeleteFileA(char* lpFileName);
	static bool __stdcall DeleteFileW(char16_t* lpFileName);
	static void* __stdcall FindFirstFileW(char16_t* lpFileName, void* lpFindFileData);

	static bool __stdcall CloseHandle(void* hObject);
	static bool __stdcall DuplicateHandle(void* hSourceProcessHandle, void* hSourceHandle, void* hTargetProcessHandle, void** lpTargetHandle, uint32_t dwDesiredAccess, bool bInheritHandle, uint32_t dwOptions);
	
	static uint32_t __stdcall GetFileType(void* hFile);
	static uint32_t __stdcall GetDriveTypeA(char* lpRootPathName);
	static uint32_t __stdcall GetDriveTypeW(char16_t* lpRootPathName);
	static uint32_t __stdcall GetLogicalDrives();
	static uint32_t __stdcall GetSystemDefaultLCID();
	static uint32_t __stdcall GetFileSizeEx(void* hFile, PLARGE_INTEGER lpFileSize);
	static bool __stdcall GetProductInfo(uint32_t dwOSMajorVersion, uint32_t dwOSMinorVersion, uint32_t dwSpMajorVersion, uint32_t dwSpMinorVersion, uint32_t * pdwReturnedProductType);
	static void __stdcall GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
	static uint32_t __stdcall GetCurrentThreadID();
	static uint32_t __stdcall GetCurrentProcessID();

	static bool __stdcall GetThreadTimes(void* hThread, void* lpCreationTime, void* lpExitTime, void* lpKernelTime, void* lpUserTime);
	static bool __stdcall CreateTimerQueueTimer(void** phNewTimer, void* TimerQueue, void* Callback, void* Parameter, uint32_t DueTime, uint32_t Period, uint32_t Flags);
	static bool __stdcall SetProcessInformation(void* hProces, PROCESS_INFORMATION_CLASS ProcessInformationClass, void* ProcessInformation, uint32_t ProcessInformationSize);
	static void __stdcall GetSystemTime(PSYSTEMTIME lpSystemTime);
	static bool __stdcall SystemTimeToFileTime(SYSTEMTIME *lpSystemTime, PFILETIME lpFileTime);
	static void __stdcall GetSystemTimeAsFileTime(void* lpSystemTimeAsFileTime);
	static void __stdcall GetSystemTimePreciseAsFileTime(void* lpSystemTimeAsFileTime);
	static bool __stdcall QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
	static bool __stdcall QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
	static uint32_t __stdcall GetTickCount();
	static uint64_t __stdcall GetTickCount64();

	static bool __stdcall DeviceIoControl(
		void* hDevice,
		uint32_t dwIoControlCode,
		void* lpInBuffer,
		uint32_t nInBufferSize,
		void* lpOutBufferm,
		uint32_t nOutBufferSize,
		uint32_t* lpBytesReturend,
		void* lpOverlapped
	);

	static void* __stdcall GetCommandLineA();
	static void* __stdcall GetCommandLineW();

	static void* __stdcall DecodePointer(void* ptr);
	static void* __stdcall EncodePointer(void* ptr);

	static uint32_t __stdcall GetACP();
	static bool __stdcall IsValidCodePage(uint32_t CodePage);
	static bool __stdcall GetCPInfo(int CodePage, LPCPINFO lpCPInfo);

	static uint32_t __stdcall TlsAlloc();
	static bool __stdcall TlsSetValue(uint32_t dwTlsIndex, void* lpTlsValue);
	static void* __stdcall TlsGetValue(uint32_t dwTlsIndex);
	static bool __stdcall TlsFree(uint32_t dwTlsIndex);
	static uint32_t __stdcall FlsAlloc(void* lpCallback);
	static uint32_t __stdcall FlsSetValue(uint32_t dwFlsIndex, void* lpFlsData);
	static void* __stdcall FlsGetValue(uint32_t dwFlsIndex);
	static bool __stdcall FlsFree(uint32_t dwFlsIndex);

	static bool __stdcall GetStringTypeA(uint32_t dwInfoType, char* lpSrcStr, int cchSrc, uint16_t* lpCharType);
	static bool __stdcall GetStringTypeW(uint32_t dwInfoType, char16_t* lpSrcStr, int cchSrc, uint16_t* lpCharType);
	static int __stdcall LCMapStringA(LCID Locale, uint32_t dwMapFlags, char* lpSrcStr, int cchSrc, char*  lpDestStr, int cchDest);
	static int __stdcall LCMapStringW(LCID Locale, uint32_t dwMapFlags, char16_t* lpSrcStr, int cchSrc, char16_t*  lpDestStr, int cchDest);
	static int __stdcall LCMapStringEx(char16_t* lpLocaleName, uint32_t dwMapFlags, char16_t* lpSrcStr, int cchSrc, char16_t* lpDestStr, int cchDest, void* lpVersionInformation, void* lpReserved, void* sortHandle);

	static int __stdcall WideCharToMultiByte(uint32_t CodePage, uint32_t dwFlags, void* lpWideCharStr, int cchWideChar, void* lpMultiByteStr, int cbMultiByte, void* lpDefaultChar, void* lpUsedDefaultChar);
	static int __stdcall MultiByteToWideChar(uint32_t CodePage, uint32_t dwFlags, void* lpMultiByteStr, int cbMultiByte, void* lpWideCHarStr, int cchWideChar);

	static void __stdcall InitializeSListHead(PSLIST_HEADER ListHead);
	static void __stdcall InitializeConditionVariable(void* ConditionVariable);

	static bool __stdcall InitializeCriticalSectionAndSpinCount(void* lpCriticalSection, uint32_t dwSpinCount);
	static bool __stdcall InitializeCriticalSection(void* lpCriticalSection);
	static bool __stdcall InitializeCriticalSectionEx(void* lpCriticalSection, uint32_t dwSpinCOunt, uint32_t Flags);
	static void __stdcall EnterCriticalSection(void* lpCriticalSection);
	static void __stdcall DeleteCriticalSection(void* lpCriticalSection);
	static void __stdcall LeaveCriticalSection(void* lpCriticalSection);

	static uint32_t __stdcall ExpandEnvironmentStringsW(char16_t* lpSrc, char16_t* lpDst, uint32_t nSize);
	static uint32_t __stdcall GetEnvironmentVariableA(char* lpName, char* lpBuffer, uint32_t nSize);
	static uint32_t __stdcall GetEnvironmentVariableW(char16_t* lpName, char16_t* lpBuffer, uint32_t nSize);
	static char* __stdcall GetEnvironmentStrings();
	static char16_t* __stdcall GetEnvironmentStringsW();
	static bool __stdcall FreeEnvironmentStringsA(char* penv);
	static bool __stdcall FreeEnvironmentStringsW(char16_t* penv);

	static void __stdcall AcquireSRWLockExclusive(PSRWLOCK SRWLock);
	static void __stdcall ReleaseSRWLockExclusive(PSRWLOCK SRWLock);
	static void __stdcall InitializeSRWLock(PSRWLOCK SRWLock);

	static void* __stdcall GetCurrentProcess();
	static void* __stdcall GetCurrentThread();

	static bool __stdcall GetDiskFreeSpaceExW(char16_t* lpDirectoryName, void* lpFreeBytesAvailableToCaller, void* lpTotalNumberOfBytes, void* lpTotalNumberOfFreeBytes);
	static uint32_t __stdcall GetSystemWindowsDirectoryW(char16_t* lpBuffer, uint32_t uSize);
	static uint32_t __stdcall GetSystemWow64DirectoryW(char16_t* lpBuffer, uint32_t uSize);
	static uint32_t __stdcall GetSystemDirectoryA(char* lpBuffer, uint32_t uSize);
	static uint32_t __stdcall GetSystemDirectoryW(char16_t* lpBuffer, uint32_t uSize);
	static uint32_t __stdcall GetFullPathNameW(char16_t* lpFileName, uint32_t nBufferLength, char16_t* lpBuffer, char16_t** lpFilePart);
	static uint32_t __stdcall GetTempPathW(uint32_t nBufferLength, char16_t* lpBuffer);
	static bool __stdcall GetComputerNameExW(uint32_t NameType, char16_t* lpBuffer, uint32_t* lpnSize);
	static bool __stdcall ProcessIdToSessionId(uint32_t dwProcessId, uint32_t* pSessionId);
	static bool __stdcall GetProcessTimes(void* hProcess, void* lpCreationTime, void* lpExitTime, void* lpKernelTime, void* lpUserTime);
	static uint32_t __stdcall QueryDosDeviceA(void* lpDeviceName, void* lpTargetPath, uint32_t ucchMax);
	static uint32_t __stdcall QueryDosDeviceW(void* lpDeviceName, void* lpTargetPath, uint32_t ucchMax);

	static void* __stdcall VirtualAlloc(void* lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect);
	static bool __stdcall MockVirtualProtect(void* lpAddress, size_t dwSize, uint32_t flNewProtect, void* lpflOldProtect);
	static bool __stdcall VirtualLock(void* lpAddress, size_t dwSize);
	static bool __stdcall VirtualUnlock(void* lpAddress, size_t dwSize);
	static bool __stdcall VirtualFree(void* lpAddress, size_t dwSize, uint32_t dwFreeType);

	static void* __stdcall CreateThreadpoolTimer(void* pfnti, void* pv, void* pcbe);
	static void __stdcall SetThreadpoolTimer(void* pfnti, void* pv, uint32_t msPeriod, uint32_t msWindowLength);
	static void __stdcall WaitForThreadpoolTimerCallbacks(void* ptr, bool fCancelPendingCallbacks);
	static void __stdcall CloseThreadpoolTimer(void* pti);
	static void* __stdcall CreateThreadpoolWork(void* pfnwk, void* pv, void* pcbe);
	static void __stdcall CloseThreadpoolWork(void* pfnwk);
	static void __stdcall WaitForThreadpoolWorkCallbacks(void* pwk, bool fCancelPendingCallbacks);

	static void* __stdcall CreateSemaphoreW(void* lpSemaphoreAttributes, long lInitialCount, long lMaximumCount, char16_t* lpName);
	static void* __stdcall CreateEventW(void* lpEventAttributes, bool bManualReset, bool bInitialState, char16_t* lpName);
	static bool __stdcall SetEvent(void* hEvent);
	static bool __stdcall ReSetEvent(void* hEvent);
	static bool __stdcall RegisterWaitForSingleObject(void** phNewWaitObject, void* hObject, void* Callback, void* Context, uint32_t dwMilliseconds, uint32_t dwFlags);
	static uint32_t __stdcall WaitForSingleObject(void* hHandle, uint32_t dwMilliseconds);

	static void* __stdcall GetProcessHeap();
	static void* __stdcall HeapCreate(uint32_t flOptions, size_t dwInitialSize, size_t dwMaximumSize);
	static void* __stdcall HeapAlloc(void* hHeap, uint32_t dwFlags, size_t dwBytes);
	static void* __stdcall HeapReAlloc(void* hHeap, uint32_t dwFlags, void* lpMem, size_t dwBytes);
	static bool __stdcall HeapFree(void* hHeap, uint32_t dwFlags, void* lpMem);
	static bool __stdcall HeapDestroy(void* hHeap);
	static size_t __stdcall HeapSize(void* hHeap, uint32_t dwFlags, void* lpMem);

	static void* __stdcall LocalAlloc(uint32_t uFlags, size_t uBytes);
	static void* __stdcall LocalFree(void* hMem);

	static int __stdcall CompareStringOrdinal(void* lpString1, int cchCount1, void* lpString2, int cchCount2, bool bIgnoreCase);

	static void* __stdcall RaiseException(uint32_t dwExceptionCode, uint32_t dwExceptionFlags, uint32_t nNumberOfArguments, void* Arguments);
	static bool __stdcall MockIsProcessorFeaturePresent(uint32_t ProcessorFeature);
	static bool __stdcall IsDebuggerPresent();
#endif
};
#endif // !_KERNEL32_H_
