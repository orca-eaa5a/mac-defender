#pragma once
#ifndef _NT_H_
#define _NT_H_
#include <cstdint>
typedef struct _IO_STATUS_BLOCK {
	union {
		int Status;
		void*    Pointer;
	};
	__int64 Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

extern long __stdcall MockNtSetInformationFile(
	void* FileHandle,
	void* IoStatusBlock,
	void* FileInformation,
	unsigned long Length,
	unsigned int FileInformationClass
);
#endif // !_NT_H_
