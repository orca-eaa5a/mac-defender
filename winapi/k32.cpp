#pragma warning(disable: 4996)

#include <string>
#include <windows.h>
#include "k32.h"
#include "../global.h"
#include "utils.hpp"
using namespace std;

void* __stdcall MockGetModuleHandleW(wchar_t* lpModuleName)
{
	char *name = convert_wstr_to_str(lpModuleName);
	HANDLE mod = GetModuleHandle(name);
	delete name;
	if (lpModuleName && memcmp(lpModuleName, L"mpengine.dll", sizeof(L"mpengine.dll")) == 0)
		return (void*)engine_base;
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

void* __stdcall MockLoadLibraryExW(wchar_t* lpLibFileName, void* hFile, unsigned int) {
	char *name = convert_wstr_to_str(lpLibFileName);
	HINSTANCE mod = LoadLibraryA(name);
	delete name;
	return (void*)mod;
}


void* __stdcall MockCreateFileA(char* lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode, void* lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes, void* hTemplateFile) {
	/* UNIX
	while (strchr(filename, '\\'))
		*strchr(filename, '\\') = '/';
	*/
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

void* __stdcall MockCreateFileW(wchar_t* lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode, void* lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes, void* hTemplateFile) {
	char *filename = convert_wstr_to_str(lpFileName);
	void* ret = MockCreateFileA(filename, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	delete filename;

	return ret;
}

bool __stdcall MockReadFile(void* hFile, void* lpBuffer, unsigned int nNumberOfBytesToRead, unsigned int* lpNumberOfBytesRead, void* lpOverlapped) {
	*lpNumberOfBytesRead = fread(lpBuffer, 1, nNumberOfBytesToRead, (FILE*)hFile);
	return true;
}

bool __stdcall MockWriteFile(void* hFile, void* lpBuffer, unsigned int nNumberOfBytesToWrite, unsigned int* lpNumberOfBytesWritten, void* lpOverlapped) {
	*lpNumberOfBytesWritten = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, (FILE*)hFile);
	return true;
}

bool __stdcall MockDeleteFile(char* lpFileName) {
	return remove(lpFileName);
}

bool __stdcall MockCloseHandle(void* hObject) {
	return true;
}

unsigned int __stdcall MockGetDriveTypeA(char* lpRootPathName) {
	return 3;
}

unsigned int __stdcall MockGetDriveTypeW(wchar_t* lpRootPathName) {
	return MockGetDriveTypeA(nullptr);
}

unsigned int __stdcall MockGetFileSizeEx(void* hFile, PLARGE_INTEGER lpFileSize) {
	long curpos = ftell((FILE*)hFile);
	fseek((FILE*)hFile, 0, SEEK_END);

	lpFileSize->LowPart = ftell((FILE*)hFile);

	fseek((FILE*)hFile, curpos, SEEK_SET);


	return 1;
}

unsigned int __stdcall MockSetFilePointer(
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

bool __stdcall MockSetFilePointerEx(
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