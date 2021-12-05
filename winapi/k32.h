#pragma once
#ifndef _KERNEL32_H_
#define _KERNEL32_H_
#include <cstdint>

extern void* __stdcall MockGetModuleHandleW(wchar_t* lpModuleName);
extern void* __stdcall MockLoadLibraryExW(wchar_t* lpLibFileName, void* hFile, unsigned int dwFlags);
extern unsigned int __stdcall MockSetFilePointer(void* hFile, long lDistanceToMove, long* lpDistanceToMoveHigh, unsigned int dwMoveMethod);
extern void* __stdcall MockCreateFileA(char* lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode, void* lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes, void* hTemplateFile);
extern void* __stdcall MockCreateFileW(wchar_t* lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode, void* lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes, void* hTemplateFile);
extern bool __stdcall MockReadFile(void* hFile, void* lpBuffer, unsigned int nNumberOfBytesToRead, unsigned int* lpNumberOfBytesRead, void* lpOverlapped);
extern bool __stdcall MockWriteFile(void* hFile, void* lpBuffer, unsigned int nNumberOfBytesToWrite, unsigned int* lpNumberOfBytesWritten, void* lpOverlapped);
extern bool __stdcall MockDeleteFile(char* lpFileName);
extern bool __stdcall MockCloseHandle(void* hObject);
extern unsigned int __stdcall MockGetDriveTypeA(char* lpRootPathName);
extern unsigned int __stdcall MockGetDriveTypeW(wchar_t* lpRootPathName);
extern unsigned int __stdcall MockGetFileSizeEx(void* hFile, PLARGE_INTEGER lpFileSize);
extern unsigned int __stdcall MockSetFilePointer(void* hFile, long lDistanceToMove, long* lpDistanceToMoveHigh, unsigned int dwMoveMethod);
extern bool __stdcall MockSetFilePointerEx(void* hFile, unsigned long long liDistanceToMove, unsigned long long* lpNewFilePointer, unsigned int dwMoveMethod);
#endif // !_KERNEL32_H_
