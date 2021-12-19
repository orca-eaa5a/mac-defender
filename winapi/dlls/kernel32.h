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
		
		
		APIExports::add_hook_info("kernel32.dll", "SetLastError", (void*)MockKernel32::MySetLastError);
		APIExports::add_hook_info("kernel32.dll", "GetLastError", (void*)MockKernel32::MyGetLastError);
		
		APIExports::add_hook_info("kernel32.dll", "GetStartupInfoA", (void*)MockKernel32::GetStartupInfoA);
		APIExports::add_hook_info("kernel32.dll", "GetStartupInfoW", (void*)MockKernel32::GetStartupInfoW);
		APIExports::add_hook_info("kernel32.dll", "GetStringTypeA", (void*)MockKernel32::GetStringTypeA);
		APIExports::add_hook_info("kernel32.dll", "GetStringTypeW", (void*)MockKernel32::GetStringTypeW);
		APIExports::add_hook_info("kernel32.dll", "GetModuleFileNameA", (void*)MockKernel32::GetModuleFileNameA);

		APIExports::add_hook_info("kernel32.dll", "GetStdHandle", (void*)MockKernel32::GetStdHandle);
		//APIExports::add_hook_info("kernel32.dll", "LoadLibraryA", (void*)MockKernel32::LoadLibraryA);
		APIExports::add_hook_info("kernel32.dll", "LoadLibraryW", (void*)MockKernel32::LoadLibraryW);
		APIExports::add_hook_info("kernel32.dll", "LoadLibraryExW", (void*)MockKernel32::LoadLibraryExW);
		APIExports::add_hook_info("kernel32.dll", "FreeLibrary", (void*)MockKernel32::FreeLibrary);

		APIExports::add_hook_info("kernel32.dll", "CreateFileA", (void*)MockKernel32::CreateFileA);
		APIExports::add_hook_info("kernel32.dll", "CreateFileW", (void*)MockKernel32::CreateFileW);
		APIExports::add_hook_info("kernel32.dll", "ReadFile", (void*)MockKernel32::ReadFile);
		APIExports::add_hook_info("kernel32.dll", "WriteFile", (void*)MockKernel32::WriteFile);
		APIExports::add_hook_info("kernel32.dll", "GetFileSizeEx", (void*)MockKernel32::GetFileSizeEx);
		APIExports::add_hook_info("kernel32.dll", "GetFileSGetFileAttributesWizeEx", (void*)MockKernel32::GetFileAttributesW);
		APIExports::add_hook_info("kernel32.dll", "GetFileAttributesExA", (void*)MockKernel32::GetFileAttributesExA);
		APIExports::add_hook_info("kernel32.dll", "GetFileAttributesExW", (void*)MockKernel32::GetFileAttributesExW);
		APIExports::add_hook_info("kernel32.dll", "SetFilePointer", (void*)MockKernel32::SetFilePointer);
		APIExports::add_hook_info("kernel32.dll", "SetFilePointerEx", (void*)MockKernel32::SetFilePointerEx);


		APIExports::add_hook_info("kernel32.dll", "GetModuleHandleA", (void*)MockKernel32::MyGetModuleHandleA);
		APIExports::add_hook_info("kernel32.dll", "GetModuleHandleW", (void*)MockKernel32::GetModuleHandleW);
		APIExports::add_hook_info("kernel32.dll", "GetModuleHandleExW", (void*)MockKernel32::GetModuleHandleExW);
		APIExports::add_hook_info("kernel32.dll", "CloseHandle", (void*)MockKernel32::MyCloseHandle);
		APIExports::add_hook_info("kernel32.dll", "GetProcAddress", (void*)MockKernel32::MyGetProcAddress);

		APIExports::add_hook_info("kernel32.dll", "EncodePointer", (void*)MockKernel32::EncodePointer);
		APIExports::add_hook_info("kernel32.dll", "DecodePointer", (void*)MockKernel32::DecodePointer);
		
		APIExports::add_hook_info("kernel32.dll", "GetFileType", (void*)MockKernel32::GetFileType);
		APIExports::add_hook_info("kernel32.dll", "GetDriveTypeW", (void*)MockKernel32::GetDriveTypeW);
		APIExports::add_hook_info("kernel32.dll", "GetDriveTypeA", (void*)MockKernel32::GetDriveTypeA);
		APIExports::add_hook_info("kernel32.dll", "GetLogicalDrives", (void*)MockKernel32::GetLogicalDrives);
		APIExports::add_hook_info("kernel32.dll", "GetSystemDefaultLCID", (void*)MockKernel32::GetSystemDefaultLCID);

		APIExports::add_hook_info("kernel32.dll", "GetProductInfo", (void*)MockKernel32::GetProductInfo);
		APIExports::add_hook_info("kernel32.dll", "GetSystemInfo", (void*)MockKernel32::GetSystemInfo);
		APIExports::add_hook_info("kernel32.dll", "GetCurrentProcessID", (void*)MockKernel32::GetCurrentProcessID);
		APIExports::add_hook_info("kernel32.dll", "GetCurrentThreadID", (void*)MockKernel32::GetCurrentThreadID);

		APIExports::add_hook_info("kernel32.dll", "SetProcessInformation", (void*)MockKernel32::MySetProcessInformation);
		APIExports::add_hook_info("kernel32.dll", "GetSystemTimeAsFileTime", (void*)MockKernel32::GetSystemTimeAsFileTime);
		APIExports::add_hook_info("kernel32.dll", "GetSystemTimePreciseAsFileTime", (void*)MockKernel32::GetSystemTimePreciseAsFileTime);
		APIExports::add_hook_info("kernel32.dll", "QueryPerformanceFrequency", (void*)MockKernel32::QueryPerformanceFrequency);
		APIExports::add_hook_info("kernel32.dll", "QueryPerformanceCounter", (void*)MockKernel32::QueryPerformanceCounter);
		APIExports::add_hook_info("kernel32.dll", "GetTickCount", (void*)MockKernel32::GetTickCount);
		APIExports::add_hook_info("kernel32.dll", "GetTickCount64", (void*)MockKernel32::GetTickCount64);
		
		APIExports::add_hook_info("kernel32.dll", "DeviceIoControl", (void*)MockKernel32::DeviceIoControl);

		APIExports::add_hook_info("kernel32.dll", "GetCommandLineA", (void*)MockKernel32::GetCommandLineA);
		APIExports::add_hook_info("kernel32.dll", "GetCommandLineW", (void*)MockKernel32::GetCommandLineW);

		APIExports::add_hook_info("kernel32.dll", "GetACP", (void*)MockKernel32::GetACP);
		APIExports::add_hook_info("kernel32.dll", "IsValidCodePage", (void*)MockKernel32::IsValidCodePage);
		APIExports::add_hook_info("kernel32.dll", "GetCPInfo", (void*)MockKernel32::GetCPInfo);

		APIExports::add_hook_info("kernel32.dll", "TlsAlloc", (void*)MockKernel32::TlsAlloc);
		APIExports::add_hook_info("kernel32.dll", "TlsGetValue", (void*)MockKernel32::TlsGetValue);
		APIExports::add_hook_info("kernel32.dll", "TlsSetValue", (void*)MockKernel32::TlsSetValue);
		APIExports::add_hook_info("kernel32.dll", "TlsFree", (void*)MockKernel32::TlsFree);
		APIExports::add_hook_info("kernel32.dll", "FlsAlloc", (void*)MockKernel32::FlsAlloc);
		APIExports::add_hook_info("kernel32.dll", "FlsGetValue", (void*)MockKernel32::FlsGetValue);
		APIExports::add_hook_info("kernel32.dll", "FlsSetValue", (void*)MockKernel32::FlsSetValue);
		APIExports::add_hook_info("kernel32.dll", "FlsFree", (void*)MockKernel32::FlsFree);

		APIExports::add_hook_info("kernel32.dll", "LCMapStringA", (void*)MockKernel32::LCMapStringA);
		APIExports::add_hook_info("kernel32.dll", "LCMapStringW", (void*)MockKernel32::LCMapStringW);
		APIExports::add_hook_info("kernel32.dll", "LCMapStringEx", (void*)MockKernel32::LCMapStringEx);

		APIExports::add_hook_info("kernel32.dll", "MultiByteToWideChar", (void*)MockKernel32::MultiByteToWideChar);
		APIExports::add_hook_info("kernel32.dll", "WideCharToMultiByte", (void*)MockKernel32::WideCharToMultiByte);
		
		APIExports::add_hook_info("kernel32.dll", "InitializeSListHead", (void*)MockKernel32::InitializeSListHead);
		APIExports::add_hook_info("kernel32.dll", "InitializeConditionVariable", (void*)MockKernel32::InitializeConditionVariable);

		APIExports::add_hook_info("kernel32.dll", "InitializeCriticalSection", (void*)MockKernel32::InitializeCriticalSection);
		APIExports::add_hook_info("kernel32.dll", "InitializeCriticalSectionEx", (void*)MockKernel32::InitializeCriticalSectionEx);
		APIExports::add_hook_info("kernel32.dll", "InitializeCriticalSectionAndSpinCount", (void*)MockKernel32::InitializeCriticalSectionAndSpinCount);
		APIExports::add_hook_info("kernel32.dll", "EnterCriticalSection", (void*)MockKernel32::EnterCriticalSection);
		APIExports::add_hook_info("kernel32.dll", "LeaveCriticalSection", (void*)MockKernel32::LeaveCriticalSection);
		APIExports::add_hook_info("kernel32.dll", "DeleteCriticalSection", (void*)MockKernel32::DeleteCriticalSection);

		
		APIExports::add_hook_info("kernel32.dll", "ExpandEnvironmentStringsW", (void*)MockKernel32::ExpandEnvironmentStringsW);
		APIExports::add_hook_info("kernel32.dll", "GetEnvironmentVariableA", (void*)MockKernel32::GetEnvironmentVariableA);
		APIExports::add_hook_info("kernel32.dll", "GetEnvironmentVariableW", (void*)MockKernel32::GetEnvironmentVariableW);
		APIExports::add_hook_info("kernel32.dll", "GetEnvironmentStrings", (void*)MockKernel32::GetEnvironmentStrings);
		APIExports::add_hook_info("kernel32.dll", "GetEnvironmentStringsW", (void*)MockKernel32::GetEnvironmentStringsW);
		APIExports::add_hook_info("kernel32.dll", "FreeEnvironmentStringsA", (void*)MockKernel32::FreeEnvironmentStringsA);
		APIExports::add_hook_info("kernel32.dll", "FreeEnvironmentStringsW", (void*)MockKernel32::FreeEnvironmentStringsW);
		
		APIExports::add_hook_info("kernel32.dll", "AcquireSRWLockExclusive", (void*)MockKernel32::AcquireSRWLockExclusive);
		APIExports::add_hook_info("kernel32.dll", "ReleaseSRWLockExclusive", (void*)MockKernel32::ReleaseSRWLockExclusive);
		APIExports::add_hook_info("kernel32.dll", "InitializeSRWLock", (void*)MockKernel32::InitializeSRWLock);
		
		APIExports::add_hook_info("kernel32.dll", "VirtualAlloc", (void*)MockKernel32::VirtualAlloc);
		APIExports::add_hook_info("kernel32.dll", "VirtualLock", (void*)MockKernel32::VirtualLock);
		APIExports::add_hook_info("kernel32.dll", "VirtualProtect", (void*)MockKernel32::MyVirtualProtect);
		
		
		APIExports::add_hook_info("kernel32.dll", "GetFileAttributesW", (void*)MockKernel32::GetFileAttributesW);
		APIExports::add_hook_info("kernel32.dll", "GetFileAttributesExA", (void*)MockKernel32::GetFileAttributesExA);
		APIExports::add_hook_info("kernel32.dll", "GetFileAttributesExW", (void*)MockKernel32::GetFileAttributesExW);
		
		
		APIExports::add_hook_info("kernel32.dll", "GetSystemWindowsDirectoryW", (void*)MockKernel32::GetSystemWindowsDirectoryW);
		APIExports::add_hook_info("kernel32.dll", "GetSystemWow64DirectoryW", (void*)MockKernel32::GetSystemWow64DirectoryW);
		APIExports::add_hook_info("kernel32.dll", "GetSystemDirectoryA", (void*)MockKernel32::GetSystemDirectoryA);
		APIExports::add_hook_info("kernel32.dll", "GetSystemDirectoryW", (void*)MockKernel32::GetSystemDirectoryW);
		APIExports::add_hook_info("kernel32.dll", "GetTempPathW", (void*)MockKernel32::GetTempPathW);
		APIExports::add_hook_info("kernel32.dll", "GetFullPathNameW", (void*)MockKernel32::GetFullPathNameW);
		APIExports::add_hook_info("kernel32.dll", "GetComputerNameExW", (void*)MockKernel32::GetComputerNameExW);
		APIExports::add_hook_info("kernel32.dll", "GetProcessTimes", (void*)MockKernel32::GetProcessTimes);
		APIExports::add_hook_info("kernel32.dll", "QueryDosDeviceA", (void*)MockKernel32::QueryDosDeviceA);
		APIExports::add_hook_info("kernel32.dll", "QueryDosDeviceW", (void*)MockKernel32::QueryDosDeviceW);
		
		
		APIExports::add_hook_info("kernel32.dll", "CreateThreadpoolTimer", (void*)MockKernel32::CreateThreadpoolTimer);
		APIExports::add_hook_info("kernel32.dll", "SetThreadpoolTimer", (void*)MockKernel32::SetThreadpoolTimer);
		APIExports::add_hook_info("kernel32.dll", "WaitForThreadpoolTimerCallbacks", (void*)MockKernel32::WaitForThreadpoolTimerCallbacks);
		APIExports::add_hook_info("kernel32.dll", "CloseThreadpoolTimer", (void*)MockKernel32::CloseThreadpoolTimer);
		APIExports::add_hook_info("kernel32.dll", "CloseThreadpoolWork", (void*)MockKernel32::CloseThreadpoolWork);
		APIExports::add_hook_info("kernel32.dll", "CreateThreadpoolWork", (void*)MockKernel32::CreateThreadpoolWork);
		APIExports::add_hook_info("kernel32.dll", "WaitForThreadpoolWorkCallbacks", (void*)MockKernel32::WaitForThreadpoolWorkCallbacks);
		
		APIExports::add_hook_info("kernel32.dll", "CreateSemaphoreW", (void*)MockKernel32::CreateSemaphoreW);
		APIExports::add_hook_info("kernel32.dll", "CreateEventW", (void*)MockKernel32::CreateEventW);
		APIExports::add_hook_info("kernel32.dll", "SetEvent", (void*)MockKernel32::SetEvent);
		APIExports::add_hook_info("kernel32.dll", "ReSetEvent", (void*)MockKernel32::ReSetEvent);
		APIExports::add_hook_info("kernel32.dll", "RegisterWaitForSingleObject", (void*)MockKernel32::RegisterWaitForSingleObject);
		APIExports::add_hook_info("kernel32.dll", "WaitForSingleObject", (void*)MockKernel32::WaitForSingleObject);
		
		
		APIExports::add_hook_info("kernel32.dll", "GetProcessHeap", (void*)MockKernel32::GetProcessHeap);
		APIExports::add_hook_info("kernel32.dll", "HeapCreate", (void*)MockKernel32::HeapCreate);
		APIExports::add_hook_info("kernel32.dll", "HeapAlloc", (void*)MockKernel32::HeapAlloc);
		APIExports::add_hook_info("kernel32.dll", "HeapReAlloc", (void*)MockKernel32::HeapReAlloc);
		APIExports::add_hook_info("kernel32.dll", "HeapFree", (void*)MockKernel32::HeapFree);
		APIExports::add_hook_info("kernel32.dll", "HeapDestroy", (void*)MockKernel32::HeapDestroy);
		APIExports::add_hook_info("kernel32.dll", "HeapSize", (void*)MockKernel32::HeapSize);
		
		APIExports::add_hook_info("kernel32.dll", "LocalAlloc", (void*)MockKernel32::LocalAlloc);
		APIExports::add_hook_info("kernel32.dll", "LocalFree", (void*)MockKernel32::LocalFree);
		APIExports::add_hook_info("kernel32.dll", "GlobalAlloc", (void*)MockKernel32::LocalAlloc);
		APIExports::add_hook_info("kernel32.dll", "GlobalFree", (void*)MockKernel32::LocalFree);
		
		APIExports::add_hook_info("kernel32.dll", "CompareStringOrdinal", (void*)MockKernel32::CompareStringOrdinal);
		
	};

	static void __stdcall MockKernel32::MySetLastError(unsigned int dwErrCode);
	static unsigned int __stdcall MockKernel32::MyGetLastError();

	static void __stdcall MockKernel32::GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo);
	static void __stdcall MockKernel32::GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo);
	
	static void* __stdcall MockKernel32::GetStdHandle(uint32_t nStdHandle);
	//static void* __stdcall MockKernel32::LoadLibraryA(char* lpLibFileName);
	static void* __stdcall MockKernel32::LoadLibraryW(wchar_t* lpLibFileName);
	static void* __stdcall MockKernel32::LoadLibraryExW(wchar_t* lpLibFileName, void* hFile, unsigned int dwFlags);
	static bool __stdcall MockKernel32::FreeLibrary(void* hLibModule);
	static void* __stdcall MockKernel32::MyGetModuleHandleA(char* lpModuleName);
	static void* __stdcall MockKernel32::GetModuleHandleW(wchar_t* lpModuleName);
	static bool __stdcall MockKernel32::GetModuleHandleExA(unsigned int dwFlags, char* lpModuleName, void* phModule);
	static bool __stdcall MockKernel32::GetModuleHandleExW(unsigned int dwFlags, wchar_t* lpModuleName, void* phModule);
	static void* __stdcall MockKernel32::MyGetProcAddress(void* hModule, char* lpProcName);
	static unsigned int __stdcall MockKernel32::GetModuleFileNameA(void* hModule, char* lpFilename, unsigned int nSize);
	static unsigned int __stdcall MockKernel32::GetModuleFileNameW(void* hModule, wchar_t* lpFilename, unsigned int nSize);
	
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
	static unsigned int __stdcall MockKernel32::GetSystemDefaultLCID();
	static unsigned int __stdcall MockKernel32::GetFileSizeEx(void* hFile, PLARGE_INTEGER lpFileSize);
	static bool __stdcall MockKernel32::GetProductInfo(unsigned int dwOSMajorVersion, unsigned int dwOSMinorVersion, unsigned int dwSpMajorVersion, unsigned int dwSpMinorVersion, unsigned int * pdwReturnedProductType);
	static void __stdcall MockKernel32::GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
	static unsigned int __stdcall MockKernel32::GetCurrentThreadID();
	static unsigned int __stdcall MockKernel32::GetCurrentProcessID();
	
	static bool __stdcall MockKernel32::MySetProcessInformation(void* hProces, PROCESS_INFORMATION_CLASS ProcessInformationClass, void* ProcessInformation, unsigned int ProcessInformationSize);
	static void __stdcall MockKernel32::GetSystemTimeAsFileTime(void* lpSystemTimeAsFileTime);
	static void __stdcall MockKernel32::GetSystemTimePreciseAsFileTime(void* lpSystemTimeAsFileTime);
	static bool __stdcall MockKernel32::QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
	static bool __stdcall MockKernel32::QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
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

	static unsigned int __stdcall MockKernel32::GetSystemWindowsDirectoryW(wchar_t* lpBuffer, unsigned int uSize);
	static unsigned int __stdcall MockKernel32::GetSystemWow64DirectoryW(wchar_t* lpBuffer, unsigned int uSize);
	static unsigned int __stdcall MockKernel32::GetSystemDirectoryA(char* lpBuffer, unsigned int uSize);
	static unsigned int __stdcall MockKernel32::GetSystemDirectoryW(wchar_t* lpBuffer, unsigned int uSize);
	static unsigned int __stdcall MockKernel32::GetFullPathNameW(wchar_t* lpFileName, unsigned int nBufferLength, wchar_t* lpBuffer, wchar_t** lpFilePart);
	static unsigned int __stdcall MockKernel32::GetTempPathW(unsigned int nBufferLength, wchar_t* lpBuffer);
	static bool __stdcall MockKernel32::GetComputerNameExW(unsigned int NameType, wchar_t* lpBuffer, unsigned int* lpnSize);
	static bool __stdcall MockKernel32::GetProcessTimes(void* hProcess, void* lpCreationTime, void* lpExitTime, void* lpKernelTime, void* lpUserTime);
	static unsigned int __stdcall MockKernel32::QueryDosDeviceA(void* lpDeviceName, void* lpTargetPath, unsigned int ucchMax);
	static unsigned int __stdcall MockKernel32::QueryDosDeviceW(void* lpDeviceName, void* lpTargetPath, unsigned int ucchMax);

	static void* __stdcall MockKernel32::VirtualAlloc(void* lpAddress, size_t dwSize, unsigned int flAllocationType, unsigned int flProtect);
	static bool __stdcall MockKernel32::MyVirtualProtect(void* lpAddress, size_t dwSize, unsigned int flNewProtect, void* lpflOldProtect);
	static bool __stdcall MockKernel32::VirtualLock(void* lpAddress, unsigned int dwSize);
	
	static void* __stdcall MockKernel32::CreateThreadpoolTimer(void* pfnti, void* pv, void* pcbe);
	static void __stdcall MockKernel32::SetThreadpoolTimer(void* pfnti, void* pv, unsigned int msPeriod, unsigned int msWindowLength);
	static void __stdcall MockKernel32::WaitForThreadpoolTimerCallbacks(void* ptr, bool fCancelPendingCallbacks);
	static void __stdcall MockKernel32::CloseThreadpoolTimer(void* pti);
	static void* __stdcall MockKernel32::CreateThreadpoolWork(void* pfnwk, void* pv, void* pcbe);
	static void __stdcall MockKernel32::CloseThreadpoolWork(void* pfnwk);
	static void __stdcall MockKernel32::WaitForThreadpoolWorkCallbacks(void* pwk, bool fCancelPendingCallbacks);

	static void* __stdcall MockKernel32::CreateSemaphoreW(void* lpSemaphoreAttributes, long lInitialCount, long lMaximumCount, wchar_t* lpName);
	static void* __stdcall MockKernel32::CreateEventW(void* lpEventAttributes, bool bManualReset, bool bInitialState, wchar_t* lpName);
	static bool __stdcall MockKernel32::SetEvent(void* hEvent);
	static bool __stdcall MockKernel32::ReSetEvent(void* hEvent);
	static bool __stdcall MockKernel32::RegisterWaitForSingleObject(void** phNewWaitObject, void* hObject, void* Callback, void* Context, unsigned long dwMilliseconds, unsigned long dwFlags);
	static unsigned int __stdcall MockKernel32::WaitForSingleObject(void* hHandle, unsigned int dwMilliseconds);

	static void* __stdcall MockKernel32::GetProcessHeap();
	static void* __stdcall MockKernel32::HeapCreate(unsigned int flOptions, size_t dwInitialSize, size_t dwMaximumSize);
	static void* __stdcall MockKernel32::HeapAlloc(void* hHeap, unsigned int dwFlags, size_t dwBytes);
	static void* __stdcall MockKernel32::HeapReAlloc(void* hHeap, unsigned int dwFlags, void* lpMem, size_t dwBytes);
	static bool __stdcall MockKernel32::HeapFree(void* hHeap, unsigned int dwFlags, void* lpMem);
	static bool __stdcall MockKernel32::HeapDestroy(void* hHeap);
	static size_t __stdcall MockKernel32::HeapSize(void* hHeap, unsigned int dwFlags, void* lpMem);

	static void* __stdcall MockKernel32::LocalAlloc(unsigned int uFlags, size_t uBytes);
	static void* __stdcall MockKernel32::LocalFree(void* hMem);

	static int __stdcall MockKernel32::CompareStringOrdinal(void* lpString1, int cchCount1, void* lpString2, int cchCount2, bool bIgnoreCase);
};
#endif // !_KERNEL32_H_
