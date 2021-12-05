#include "ntdll.h"

long __stdcall MockNtSetInformationFile(
	void* FileHandle,
	void* IoStatusBlock,
	void* FileInformation,
	unsigned long Length,
	unsigned int FileInformationClass
) {
	PIO_STATUS_BLOCK isb = (PIO_STATUS_BLOCK)IoStatusBlock;
	return 0;
}