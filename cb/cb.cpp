
#include <cstdint>
#include <io.h>
#include <windows.h>
#include <string>
#include "cb.h"

#ifdef _X86

uint32_t BufferSize = 0;

uint32_t FullScanNotifyCallback(PSCAN_REPLY Scan)
{
	void* _this = NULL;

	if (Scan->Flags & SCAN_FILENAME) {
		printf("[%s]  Scanning \"%s\"...\n", "INFO", Scan->FileName);
	}
	if (Scan->Flags & SCAN_PACKERSTART) {
		printf("[%s]  Maybe packed using %s...\n", "INFO", Scan->FileName);
	}
	if (Scan->Flags & SCAN_ENCRYPTED) {
		printf("File is encrypted\n");
	}
	if (Scan->Flags & SCAN_CORRUPT) {
		printf("File may be corrupt\n");
	}
	if (Scan->Flags & SCAN_FILETYPE) {
		printf("[%s]  %s identified at %s\n", Scan->VirusName, Scan->FileName);
	}
	if (Scan->Flags & 0x08000022) {
		printf("[%s]  %s detected!\n", "INFO", Scan->VirusName);
	}

	if (Scan->Flags & SCAN_NORESULT) {
		printf("No Threat identified");
	}

	return 0;
}

uint32_t ReadStreamCb(uint32_t fd, unsigned long long Offset, void* Buffer, uint32_t Size, uint32_t* SizeRead)
{
	_lseek(fd, Offset, SEEK_SET);
	*SizeRead = _read(fd, Buffer, Size);
	return 1;
}

uint32_t GetStreamSizeCb(uint32_t fd, uint32_t* FileSize)
{
	_lseek(fd, 0, SEEK_END);
	*FileSize = _lseek(fd, 0, SEEK_CUR);
	return 1;
}

uint32_t GetIncremBufferSizeCb(void* buf, uint32_t* BufSize) {
	BufferSize += 0x1000;
	*BufSize = BufferSize;

	return 1;
}

uint32_t ReadBufferCb(void* src, unsigned long long Offset, void* Buffer, uint32_t Size, uint32_t* SizeRead) {
	memcpy(Buffer, (void*)((uint8_t*)src + Offset), Size);
	*SizeRead = Size;
	return 1;
}

#elif _X64

uint64_t BufferSize = 0;

uint64_t FullScanNotifyCallback(PSCAN_REPLY Scan)
{
	void* _this = NULL;

	if (Scan->Flags & SCAN_FILENAME) {
		printf("[%s]  Scanning \"%s\"...\n", "INFO", Scan->FileName);
	}
	if (Scan->Flags & SCAN_PACKERSTART) {
		printf("[%s]  Maybe packed using %s...\n", "INFO", Scan->FileName);
	}
	if (Scan->Flags & SCAN_ENCRYPTED) {
		printf("File is encrypted\n");
	}
	if (Scan->Flags & SCAN_CORRUPT) {
		printf("File may be corrupt\n");
	}
	if (Scan->Flags & SCAN_FILETYPE) {
		printf("[%s]  %s identified at %s\n", Scan->VirusName, Scan->FileName);
	}
	if (Scan->Flags & 0x08000022) {
		printf("[%s]  %s detected!\n", "INFO", Scan->VirusName);
	}

	if (Scan->Flags & SCAN_NORESULT) {
		printf("No Threat identified");
	}

	return 0;
}

uint64_t ReadStreamCb(uint64_t fd, uint64_t Offset, void* Buffer, uint64_t Size, uint64_t* SizeRead)
{
	_lseek(fd, Offset, SEEK_SET);
	*SizeRead = _read(fd, (uint8_t*)Buffer, Size);

	return 1;
}

uint64_t GetStreamSizeCb(uint64_t fd, uint64_t* FileSize)
{
	_lseek(fd, 0, SEEK_END);
	*FileSize = _lseek(fd, 0, SEEK_CUR);
	return 1;
}

uint64_t GetIncremBufferSizeCb(void* buf, uint64_t* BufSize) {
	BufferSize += 0x1000;
	*BufSize = BufferSize;

	return 1;
}

uint64_t ReadBufferCb(void* src, uint64_t Offset, void* Buffer, uint32_t Size, uint32_t* SizeRead) {
	memcpy(Buffer, (void*)((uint8_t*)src + Offset), Size);
	*SizeRead = Size;
	return 1;
}
#endif // _X86

const wchar_t* GetStreamNameCb(void* self) {
	HANDLE hFile = (HANDLE)_get_osfhandle((uint32_t)self);
	wchar_t* fname = new wchar_t[260];
	memset(fname, '\0', MAX_PATH);
	GetFinalPathNameByHandleW(hFile, (wchar_t*)fname, MAX_PATH, VOLUME_NAME_DOS);
	std::wstring target_path(fname);
	if (target_path.substr(0, 8).compare(L"\\\\?\\UNC\\") == 0)
	{
		// In case of a network path, replace `\\?\UNC\` with `\\`.
		target_path = L"\\" + target_path.substr(7);
	}
	else if (target_path.substr(0, 4).compare(L"\\\\?\\") == 0)
	{
		// In case of a local path, crop `\\?\`.
		target_path = target_path.substr(4);
	}
	lstrcpyW(fname, target_path.c_str());

	return fname;
}