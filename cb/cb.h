#pragma once
#ifndef _CB_H_
#define _CB_H_

#include <stdio.h>
#include <cstring>
#include <cstdint>

#include "../mpcore/scanreply.h"
#include "../winapi/dlls/include/wintype.h"

#ifdef _X86

uint32_t FullScanNotifyCallback(PSCAN_REPLY Scan);
uint32_t ReadStreamCb(uint32_t fd, unsigned long long Offset, void* Buffer, uint32_t Size, uint32_t* SizeRead);
uint32_t GetStreamSizeCb(uint32_t fd, uint32_t* FileSize);
uint32_t GetIncremBufferSizeCb(uint32_t buf, uint32_t* BufSize);
uint32_t ReadBufferCb(void* src, unsigned long long Offset, void* Buffer, uint32_t Size, uint32_t* SizeRead);
const char16_t* GetStreamNameCb(void* self);

#elif _X64

uint64_t __stdcall FullScanNotifyCallback(PSCAN_REPLY Scan);
uint64_t __stdcall ReadStreamCb(uint64_t fd, uint64_t Offset, void* Buffer, uint64_t Size, uint64_t* SizeRead);
uint64_t __stdcall GetStreamSizeCb(uint64_t fd, uint64_t* FileSize);
uint64_t __stdcall GetIncremBufferSizeCb(void* buf, uint64_t* BufSize);
uint64_t __stdcall ReadBufferCb(void* src, uint64_t Offset, void* Buffer, uint32_t* Size, uint32_t* SizeRead);

#endif // _X86
char16_t* __stdcall GetStreamNameCb(void* self);

#endif
