#pragma once
#ifndef _MPCORE_H_
#define _MPCORE_H_
#include "scanreply.h"
#include <cstdint>
typedef struct _pe_vars_t {
	SCAN_REPLY* pScanReply;
	void* unk1;
	char pe_signature[4];
	/*
	v--------------unknown-----------
	*/
}pe_vars_t;

typedef struct _vdll_data_t32 {
	uint32_t vftable;
	uint32_t unk[0x1d];
	uint32_t vdll_base;
}vdll_data_t32;

typedef struct _vdll_data_t64 {
	void* vftable;
	uint64_t unk[0x1c];
	uint32_t vdll_base;
}vdll_data_t64;

typedef struct _IL_X64_Context {
	uint64_t* vftable;
	uint64_t rax;  // 0x8
	uint64_t rbx;  // 0x10
	uint64_t rcx;  // 0x18
	uint64_t rdx;  // 0x20
	uint64_t rsp;  // 0x28
	uint64_t rbp;  // 0x30
	uint64_t rsi;  // 0x38
	uint64_t rdi;  // 0x40
	uint64_t unk1[8];  // 0x48
	uint32_t sig1; // 0x88
	uint32_t sig2; // 0x8C
	uint32_t sig3; // 0x90
	uint32_t unk2; // 0x94
	void* callee;  // 0x98
	uint32_t emu_eip; // 0xA0
	uint8_t unk3[0x1384]; //0xA4
	uint64_t mp_stack_base;
	uint64_t stack_base;
	/*
	v--------------unknown-----------
	*/

}IL_X64_Context, *PIL_X64_Context;

typedef struct _IL_X86_Context {
	uint32_t* vftable;	//0x0
	uint32_t reserved;	//0x4
	uint32_t eax;		//0x8
	uint32_t ebx;		//0xC
	uint32_t ecx;		//0x10
	uint32_t edx;		//0x14
	uint32_t esp;		//0x18
	uint32_t ebp;		//0x1C
	uint32_t esi;		//0x20
	uint32_t edi;		//0x24
	uint32_t sig1;		//0x28
	uint32_t sig2;		//0x2C
	uint32_t sig3;		//0x30
	void* callee;	//0x34
	uint32_t unk1;		//0x38
	uint32_t emu_eip;		//0x3C
	uint32_t unk2[0x4FA];	// 0x40 ~ 0x1424
	uint32_t mp_stack_base; //0x1428
	uint32_t reserved2;
	uint32_t stack_base; //0x1430
	uint32_t reserved3;
	/*
	v--------------unknown-----------
	*/
}IL_X86_Context, *PIL_X86_Context;
#endif // !_MPCORE_H_

