#pragma once
#include <windows.h>
#include <string>
#include <fstream>
#include <cstdint>

#include "log.hpp"
#ifndef _LOADER_H_
#define _LOADER_H_
using namespace std;

typedef enum {
	UNKNOWN_PLATFORM = 0,
	X86_PLATFORM,
	X64_PLATFORM
}PLATFORM;

auto check_valid_pe = [](uint8_t* pe_bin) -> uint16_t {
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)pe_bin;
	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(pe_bin + dos_header->e_lfanew);

	if ((dos_header->e_magic ^ 0x5A4D) == 0) {
		if ((nt_header->Signature ^ 0x4550) == 0)
			return true;
	}
	return false;

};

auto check_platform = [](uint8_t* pe_bin) -> uint16_t {
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)pe_bin;
	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(pe_bin + dos_header->e_lfanew);
	if (!check_valid_pe(pe_bin)) {
		return 0x0;
	}
	else { // has valid pe
		if (nt_header->OptionalHeader.Magic == 0x10b)
			return PLATFORM::X86_PLATFORM;
		else if (nt_header->OptionalHeader.Magic == 0x20b)
			return PLATFORM::X64_PLATFORM;
		else
			return PLATFORM::UNKNOWN_PLATFORM;

	}
};

auto load_temp = [](string lib_name) -> void* {
	HANDLE hMap = nullptr;
	HANDLE hFile = nullptr;
	void* img_base = nullptr;

	hFile = CreateFileA(lib_name.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (hFile == INVALID_HANDLE_VALUE)
		printf("sibal");
	hMap = CreateFileMappingA(
		hFile, // paging file
		nullptr, SEC_IMAGE | PAGE_READONLY, 0,
		0, nullptr);

	img_base = MapViewOfFile(
		hMap, FILE_MAP_READ,
		0, 0, 0
	);
	return img_base;
};

auto call_dllmain = [](void* imgbase) -> bool {
	typedef bool(*dllMain)(void*, uint32_t, uint32_t);
	uint16_t platform = 0xffff;
	dllMain d_main = nullptr;
	uint8_t* _imgbase = (uint8_t*)imgbase;
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)_imgbase;
	platform = check_platform((uint8_t*)_imgbase);
	if (platform == PLATFORM::X86_PLATFORM) {
		IMAGE_NT_HEADERS32* nt_header = (IMAGE_NT_HEADERS32*)(_imgbase + dos_header->e_lfanew);
		d_main = (dllMain)(_imgbase + nt_header->OptionalHeader.AddressOfEntryPoint);
	}
	else if (platform == PLATFORM::X64_PLATFORM) {
		IMAGE_NT_HEADERS64* nt_header = (IMAGE_NT_HEADERS64*)(_imgbase + dos_header->e_lfanew);
		d_main = (dllMain)(_imgbase + nt_header->OptionalHeader.AddressOfEntryPoint);
	}
	else {
		exit(-1);
	}
	return d_main(imgbase, 1, 0);
};

auto of_getprocaddress = [](void* imgbase, string proc_name) {
	uint16_t platform = 0xffff;
	uint8_t* _imgbase = (uint8_t*)imgbase;
	uint32_t exp_dir_va;
	uint32_t exp_dir_sz;
	platform = check_platform((uint8_t*)_imgbase);
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)_imgbase;
	IMAGE_EXPORT_DIRECTORY* exp_dir = nullptr;
	if (platform == PLATFORM::X86_PLATFORM) {
		IMAGE_NT_HEADERS32* nt_header = (IMAGE_NT_HEADERS32*)(_imgbase + dos_header->e_lfanew);
		exp_dir_va = nt_header->OptionalHeader.DataDirectory[0].VirtualAddress;
		exp_dir_sz = nt_header->OptionalHeader.DataDirectory[0].Size;
		exp_dir = (IMAGE_EXPORT_DIRECTORY*)(_imgbase + exp_dir_va);

	}
	else if (platform == PLATFORM::X64_PLATFORM) {
		IMAGE_NT_HEADERS64* nt_header = (IMAGE_NT_HEADERS64*)(_imgbase + dos_header->e_lfanew);
		exp_dir_va = nt_header->OptionalHeader.DataDirectory[0].VirtualAddress;
		exp_dir_sz = nt_header->OptionalHeader.DataDirectory[0].Size;
		exp_dir = (IMAGE_EXPORT_DIRECTORY*)(_imgbase + exp_dir_va);
	}
	else {
		exit(-1);
	}
	unsigned int *name_rva = (unsigned int*)(_imgbase + exp_dir->AddressOfNames);
	for (int i = 0; i < exp_dir->NumberOfNames; i++) {
		char* name = (char*)(_imgbase + name_rva[i]);
		if (proc_name.compare(name) == 0) {
			unsigned short name_ordin = ((unsigned short*)(_imgbase + exp_dir->AddressOfNameOrdinals))[i];
			unsigned int addr = ((unsigned int*)(_imgbase + exp_dir->AddressOfFunctions))[name_ordin];
			if (addr > exp_dir_va && addr < exp_dir_va + exp_dir_sz) {
				return (void*)0;
			}
			else {
				return (void*)(_imgbase + addr);
			}
		}
	}
	return (void*)0;
};




auto of_rewrite_iat = [](void* imgbase) {
	uint16_t platform = 0xffff;
	uint8_t* _imgbase = (uint8_t*)imgbase;
	uint32_t imp_dir_va;
	uint32_t imp_dir_sz;
	platform = check_platform((uint8_t*)_imgbase);
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)_imgbase;
	IMAGE_IMPORT_DESCRIPTOR* imp_descriptor = nullptr;
	if (platform == PLATFORM::X86_PLATFORM) {
		IMAGE_NT_HEADERS32* nt_header = (IMAGE_NT_HEADERS32*)(_imgbase + dos_header->e_lfanew);
		IMAGE_THUNK_DATA32* name_tab = nullptr;
		IMAGE_THUNK_DATA32* addr_tab = nullptr;

		imp_dir_va = nt_header->OptionalHeader.DataDirectory[1].VirtualAddress;
		imp_dir_sz = nt_header->OptionalHeader.DataDirectory[1].Size;
		imp_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(_imgbase + imp_dir_va);
		char* mod_name = nullptr;
		while (imp_descriptor->Name != 0)
		{
			mod_name = (char*)(_imgbase + imp_descriptor->Name);
			HMODULE hMod = LoadLibraryA(mod_name);
			name_tab = (IMAGE_THUNK_DATA32*)(_imgbase + imp_descriptor->FirstThunk);
			addr_tab = (IMAGE_THUNK_DATA32*)(_imgbase + imp_descriptor->OriginalFirstThunk);

			while (addr_tab->u1.Function != 0)
			{
				IMAGE_IMPORT_BY_NAME* imp_by_name = (IMAGE_IMPORT_BY_NAME*)(_imgbase + name_tab->u1.AddressOfData);
				uint64_t target_addr = (uint64_t)GetProcAddress(hMod, (char*)imp_by_name->Name);
				uint32_t old_prot;
				bool res;
				res = VirtualProtect(&addr_tab->u1.Function, sizeof(void*), PAGE_READWRITE, (PDWORD)&old_prot);
				memmove(&addr_tab->u1.Function, &target_addr, sizeof(void*));
				addr_tab++;
				name_tab++;
			}
			imp_descriptor++;
		}

	}
	else if (platform == PLATFORM::X64_PLATFORM) {
		IMAGE_NT_HEADERS64* nt_header = (IMAGE_NT_HEADERS64*)(_imgbase + dos_header->e_lfanew);
		IMAGE_THUNK_DATA64* name_tab = nullptr;
		IMAGE_THUNK_DATA64* addr_tab = nullptr;

		imp_dir_va = nt_header->OptionalHeader.DataDirectory[1].VirtualAddress;
		imp_dir_sz = nt_header->OptionalHeader.DataDirectory[1].Size;
		imp_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(_imgbase + imp_dir_va);

		char* mod_name = nullptr;
		if (imp_dir_sz) {
			while (imp_descriptor->Name) {
				mod_name = (char*)(_imgbase + imp_descriptor->Name);
				HMODULE hMod = LoadLibraryA(mod_name);

				unsigned long long* pThunkRef = reinterpret_cast<unsigned long long*>(_imgbase + imp_descriptor->OriginalFirstThunk);
				unsigned long long* pFuncRef = reinterpret_cast<unsigned long long*>(_imgbase + imp_descriptor->FirstThunk);
				if (!pThunkRef)
					pThunkRef = pFuncRef;
				for (; *pThunkRef; pThunkRef++, pFuncRef++) {
					if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
						uint32_t old_prot;
						bool res;
						res = VirtualProtect(pFuncRef, sizeof(void*), PAGE_READWRITE, (PDWORD)&old_prot);
						*pFuncRef = (ULONG_PTR)GetProcAddress(hMod, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
					}
					else {
						IMAGE_IMPORT_BY_NAME* imp_by_name = (IMAGE_IMPORT_BY_NAME*)(_imgbase + *pThunkRef);
						uint64_t target_addr = (uint64_t)GetProcAddress(hMod, (char*)imp_by_name->Name);
						uint32_t old_prot;
						bool res;
						res = VirtualProtect(pFuncRef, sizeof(void*), PAGE_READWRITE, (PDWORD)&old_prot);
						*pFuncRef = target_addr;
					}
				}
				imp_descriptor++;
			}
		}
		
	}
	else {
		exit(-1);
	}
};

auto of_rewrite_mp_iat = [](void* imgbase, char* targ_module, char* targ_api, void* rewrite_addr) {
	uint16_t platform = 0xffff;
	uint8_t* _imgbase = (uint8_t*)imgbase;
	uint32_t imp_dir_va;
	uint32_t imp_dir_sz;
	platform = check_platform((uint8_t*)_imgbase);
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)_imgbase;
	IMAGE_IMPORT_DESCRIPTOR* imp_descriptor = nullptr;
	if (platform == PLATFORM::X86_PLATFORM) {
		printf("unsupport..\n");
	}

	else if (platform == PLATFORM::X64_PLATFORM) {
		IMAGE_NT_HEADERS64* nt_header = (IMAGE_NT_HEADERS64*)(_imgbase + dos_header->e_lfanew);
		IMAGE_THUNK_DATA64* name_tab = nullptr;
		IMAGE_THUNK_DATA64* addr_tab = nullptr;

		imp_dir_va = nt_header->OptionalHeader.DataDirectory[1].VirtualAddress;
		imp_dir_sz = nt_header->OptionalHeader.DataDirectory[1].Size;
		imp_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(_imgbase + imp_dir_va);

		char* mod_name = nullptr;
		if (imp_dir_sz) {
			while (imp_descriptor->Name) {
				mod_name = (char*)(_imgbase + imp_descriptor->Name);
				if (stricmp(targ_module, mod_name) != 0) {
					imp_descriptor++;
					continue;
				}
				unsigned long long* pThunkRef = reinterpret_cast<unsigned long long*>(_imgbase + imp_descriptor->OriginalFirstThunk);
				unsigned long long* pFuncRef = reinterpret_cast<unsigned long long*>(_imgbase + imp_descriptor->FirstThunk);
				if (!pThunkRef)
					pThunkRef = pFuncRef;
				for (; *pThunkRef; pThunkRef++, pFuncRef++) {
					IMAGE_IMPORT_BY_NAME* imp_by_name = (IMAGE_IMPORT_BY_NAME*)(_imgbase + *pThunkRef);
					if (stricmp(imp_by_name->Name, targ_api) == 0) {
						*pFuncRef = (unsigned long long)rewrite_addr;
						return;
					}
				}
				imp_descriptor++;
			}
		}

	}
	else {
		exit(-1);
	}
};

auto of_set_seh = [](void* imgbase) {
	uint8_t* _imgbase = (uint8_t*)imgbase;
	uint16_t platform = 0xffff;
	uint32_t seh_dir_va;
	uint32_t seh_dir_sz;
	platform = check_platform((uint8_t*)_imgbase);
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)_imgbase;
	if (platform == PLATFORM::X64_PLATFORM) {
		IMAGE_NT_HEADERS64* nt_header = (IMAGE_NT_HEADERS64*)(_imgbase + dos_header->e_lfanew);
		seh_dir_sz = nt_header->OptionalHeader.DataDirectory[3].Size;
		seh_dir_va = nt_header->OptionalHeader.DataDirectory[3].VirtualAddress;
		if (seh_dir_sz) {
			RtlAddFunctionTable(
				(RUNTIME_FUNCTION*)(_imgbase + seh_dir_va),
				seh_dir_sz / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
				(uint64_t)imgbase
			);
		}
	}
};

auto load_x86_pe = [](uint8_t* pe_bin) {
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)pe_bin;
	IMAGE_NT_HEADERS32* nt_header_x64 = (IMAGE_NT_HEADERS32*)(pe_bin + dos_header->e_lfanew);
};

auto load_x64_pe = [](uint8_t* pe_bin) {
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)pe_bin;
	IMAGE_NT_HEADERS64* nt_header_x64 = (IMAGE_NT_HEADERS64*)(pe_bin + dos_header->e_lfanew);
};

auto of_loadlibrary = [](string libname) {
	// Testing LoadLibrary with MMF
	HANDLE hMap = nullptr;
	uint32_t file_sz = 0;
	uint8_t* f_buf = nullptr;
	uint16_t platform = 0xffff;
	IMAGE_DOS_HEADER* dos_header = nullptr;
	IMAGE_NT_HEADERS* nt_header = nullptr;

	ifstream _stream(libname, ios::binary | ios::in);
	_stream.seekg(0, ios::beg);
	_stream.seekg(0, ios::end);
	file_sz = _stream.tellg();
	_stream.seekg(0, ios::beg);
	f_buf = new uint8_t[file_sz];
	_stream.read((char*)f_buf, file_sz);

	platform = check_platform(f_buf);

	switch (platform)
	{
	case PLATFORM::X86_PLATFORM:

		break;

	case PLATFORM::X64_PLATFORM:

		break;
	default:
		console_log(MSGTYPE::CRIT, "Invalid PE file");
		break;
	}

	/*

	hMap = CreateFileMappingA(
		INVALID_HANDLE_VALUE, // paging file
		nullptr,
		PAGE_EXECUTE_READWRITE,
		0,

	)
	*/
};
#endif