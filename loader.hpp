
#ifndef _LOADER_H_
#define _LOADER_H_
#include <string>
#include <fstream>
#include <cstdint>
#if defined(__APPLE__) || defined(__LINUX__)
#include <sys/mman.h>
#include "winapi/dlls/include/windows.h"
#else
#include <windows.h>
#endif 
#include "log.hpp"
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

auto call_dllmain = [](void* imgbase) -> bool {
#if defined(__APPLE__)
	typedef __attribute__((ms_abi)) bool(*dllMain)(void*, uint32_t, uint32_t);
#elif defined(__LINUX__)
#else
	typedef bool(*dllMain)(void*, uint32_t, uint32_t);
#endif
	uint16_t platform = 0xffff;
	dllMain d_main = nullptr;
	uint8_t* _imgbase = (uint8_t*)imgbase;
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)_imgbase;
	platform = check_platform((uint8_t*)_imgbase);
	if (platform == PLATFORM::X64_PLATFORM) {
		IMAGE_NT_HEADERS64* nt_header = (IMAGE_NT_HEADERS64*)(_imgbase + dos_header->e_lfanew);
		d_main = (dllMain)(_imgbase + nt_header->OptionalHeader.AddressOfEntryPoint);
	}
	else {
		console_log(MSGTYPE::CRIT, "target module is unsupported platform binary");
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
	uint32_t *name_rva = (uint32_t*)(_imgbase + exp_dir->AddressOfNames);
	for (int i = 0; i < exp_dir->NumberOfNames; i++) {
		char* name = (char*)(_imgbase + name_rva[i]);
		if (proc_name.compare(name) == 0) {
			uint16_t name_ordin = ((uint16_t*)(_imgbase + exp_dir->AddressOfNameOrdinals))[i];
			uint32_t addr = ((uint32_t*)(_imgbase + exp_dir->AddressOfFunctions))[name_ordin];
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
auto of_readfile = [](string filename, size_t* dwread) {
	size_t file_sz = 0;
	uint8_t* fbuf = nullptr;
	FILE* fp = nullptr;
	errno_t err;
	ifstream _stream(filename, ios::binary | ios::in);
	_stream.seekg(0, ios::beg);
	_stream.seekg(0, ios::end);
	file_sz = _stream.tellg();
	_stream.close();

	fbuf = new uint8_t[file_sz];
#if defined(__WINDOWS__)
	err = fopen_s(&fp, filename.c_str(), "rb");
	if (err) {
		console_log(MSGTYPE::CRIT, "fopen_s error");
	}
	fread_s(fbuf, file_sz, sizeof(uint8_t), file_sz, fp);
#else
	fp = fopen(filename.c_str(), "rb");
	if(!fp)
		console_log(MSGTYPE::CRIT, "fopen error");
	fread(fbuf, file_sz, sizeof(uint8_t), fp);
#endif
	fclose(fp);

	*dwread = file_sz;

	return fbuf;
};

auto get_imagebase = [](uint8_t* pe_bin) {
	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)pe_bin;
	IMAGE_NT_HEADERS64* nt_hdr = (IMAGE_NT_HEADERS64*)(pe_bin + dos_hdr->e_lfanew);

	return nt_hdr->OptionalHeader.ImageBase;
};

auto get_entrypoint = [](uint8_t* pe_bin) {
	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)pe_bin;
	IMAGE_NT_HEADERS64* nt_hdr = (IMAGE_NT_HEADERS64*)(pe_bin + dos_hdr->e_lfanew);

	return nt_hdr->OptionalHeader.AddressOfEntryPoint;
};

auto get_ntheader = [](uint8_t* pe_bin) -> IMAGE_NT_HEADERS64* {
	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)pe_bin;
	IMAGE_NT_HEADERS64* nt_hdr = (IMAGE_NT_HEADERS64*)(pe_bin + dos_hdr->e_lfanew);
	
	return nt_hdr;
};

auto get_optheader = [](uint8_t* pe_bin) {
	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)pe_bin;
	IMAGE_NT_HEADERS64* nt_hdr = (IMAGE_NT_HEADERS64*)(pe_bin + dos_hdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER64* opt_header = &nt_hdr->OptionalHeader;

	return opt_header;
};

auto map_as_iamge = [](uint8_t* pe_bin, void* _image_base) {
	uint8_t* image_base = (uint8_t*)_image_base;
	IMAGE_NT_HEADERS64* nt_header = (IMAGE_NT_HEADERS64*)get_ntheader(pe_bin);
	IMAGE_FILE_HEADER* file_header = &nt_header->FileHeader;
	IMAGE_SECTION_HEADER* section_header = nullptr;
	section_header = IMAGE_FIRST_SECTION(nt_header);
#if defined(__WINDOWS__)
	memmove_s(image_base, nt_header->OptionalHeader.SizeOfHeaders, pe_bin, nt_header->OptionalHeader.SizeOfHeaders);
#else
	memmove(image_base, pe_bin, nt_header->OptionalHeader.SizeOfHeaders);
#endif

	for (int i = 0; file_header->NumberOfSections > i; i++) {
#if defined(__WINDOWS__)
		memmove_s((image_base + section_header->VirtualAddress), section_header->SizeOfRawData, (pe_bin + section_header->PointerToRawData), section_header->SizeOfRawData);
#else
		memmove((image_base + section_header->VirtualAddress), (pe_bin + section_header->PointerToRawData), section_header->SizeOfRawData);
#endif
		section_header = (IMAGE_SECTION_HEADER*)((uint8_t*)section_header + sizeof(IMAGE_SECTION_HEADER));
	}
};

auto reloc_pe_image = [](void* _image_base) {
	uint8_t* image_base = (uint8_t*)_image_base;
	IMAGE_OPTIONAL_HEADER64* opt_header = (IMAGE_OPTIONAL_HEADER64*)get_optheader(image_base);
	uint64_t delta = (uint64_t)image_base - (uint64_t)opt_header->ImageBase;
	uint32_t reloc_dir_size = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	uint64_t reloc_dir_va = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (delta) {
		if (reloc_dir_size) {
			IMAGE_BASE_RELOCATION* cur_reloc_dir = (IMAGE_BASE_RELOCATION*)(image_base + reloc_dir_va);
			IMAGE_BASE_RELOCATION* reloc_dir_end = (IMAGE_BASE_RELOCATION*)((uint8_t*)cur_reloc_dir + reloc_dir_size);
			while (cur_reloc_dir < reloc_dir_end && cur_reloc_dir->SizeOfBlock) {
				uint32_t number_of_etry = (cur_reloc_dir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
				uint16_t* info = (uint16_t*)(cur_reloc_dir + 1);
				for (int i = 0; number_of_etry > i; i++, info++) {
					if ((*info >> 0xC) == IMAGE_REL_BASED_DIR64) {
						uint64_t* addr = (uint64_t*)(image_base + cur_reloc_dir->VirtualAddress + ((*info) & 0xfff));
						*addr += delta;
					}
				}
				cur_reloc_dir = (IMAGE_BASE_RELOCATION*)((uint8_t*)cur_reloc_dir + cur_reloc_dir->SizeOfBlock);
			}
		}
	}
};

auto set_all_priv = [](void* image_base, size_t image_sz) {
#if defined(__WINDOWS__)
	uint32_t dwOldProt;
	VirtualProtect(image_base, image_sz, PAGE_EXECUTE_READWRITE, (DWORD*)&dwOldProt);
#else
	mprotect(image_base, image_sz, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
};

#if defined(__WINDOWS__)
auto of_rewrite_iat = [](void* imgbase) {
	uint16_t platform = 0xffff;
	uint8_t* _imgbase = (uint8_t*)imgbase;
	uint32_t imp_dir_va;
	uint32_t imp_dir_sz;
	platform = check_platform((uint8_t*)_imgbase);
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)_imgbase;
	IMAGE_IMPORT_DESCRIPTOR* imp_descriptor = nullptr;
	if (platform == PLATFORM::X64_PLATFORM) {
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

				uint64_t* pThunkRef = reinterpret_cast<uint64_t*>(_imgbase + imp_descriptor->OriginalFirstThunk);
				uint64_t* pFuncRef = reinterpret_cast<uint64_t*>(_imgbase + imp_descriptor->FirstThunk);
				if (!pThunkRef)
					pThunkRef = pFuncRef;
				for (; *pThunkRef; pThunkRef++, pFuncRef++) {
					if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
						uint32_t old_prot;
						bool res;
						res = VirtualProtect(pFuncRef, sizeof(void*), PAGE_EXECUTE_READWRITE, (PDWORD)&old_prot);
						*pFuncRef = (ULONG_PTR)GetProcAddress(hMod, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
					}
					else {
						IMAGE_IMPORT_BY_NAME* imp_by_name = (IMAGE_IMPORT_BY_NAME*)(_imgbase + *pThunkRef);
						uint64_t target_addr = (uint64_t)GetProcAddress(hMod, (char*)imp_by_name->Name);
						uint32_t old_prot;
						bool res;
						res = VirtualProtect(pFuncRef, sizeof(void*), PAGE_EXECUTE_READWRITE, (PDWORD)&old_prot);
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


auto of_get_runtime_function_AMD = [](RUNTIME_FUNCTION *func, uint64_t addr) {
	return func->EndAddress;
};

auto of_RtlAddFunctionTable = [](RUNTIME_FUNCTION *table, uint32_t count, uint64_t addr) {
	struct list
	{
		struct list *next;
		struct list *prev;
	};

	struct dynamic_unwind_entry
	{
		struct list entry;
		uint64_t base;
		uint64_t end;
		RUNTIME_FUNCTION *table;
		uint32_t count;
		uint32_t max_count;
		void* callback;
		void* context;
	};
	struct dynamic_unwind_entry *entry;

	entry = (dynamic_unwind_entry*)calloc(sizeof(dynamic_unwind_entry), sizeof(uint8_t));
	if (!entry)
		return false;
	entry->base = addr;
	entry->end = addr + (count ? of_get_runtime_function_AMD(&table[count - 1], addr) : 0);
	entry->table = table;
	entry->count = count;
	entry->max_count = 0;
	entry->callback = NULL;
	entry->context = NULL;

	//list_add_tail(&dynamic_unwind_list, &entry->entry);
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

auto winmap = [](string lib_name) -> void* {
	HANDLE hMap = nullptr;
	HANDLE hFile = nullptr;
	void* img_base = nullptr;
	IMAGE_OPTIONAL_HEADER64* opt_header;
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
	
	img_base = MapViewOfFileEx(hMap, FILE_MAP_READ, 0, 0, 0, (void*)0x75a100000);
	opt_header = (IMAGE_OPTIONAL_HEADER64*)get_optheader((uint8_t*)img_base);
	set_all_priv(img_base, opt_header->SizeOfImage);
	reloc_pe_image(img_base);
	return img_base;
};
#endif

auto of_loadlibraryX64 = [](string libname) {
	uint8_t* raw = nullptr;
	void* image_base = nullptr;
	size_t file_sz = 0;
	int fd = 0;
	uint16_t platform = 0xffff;
	IMAGE_NT_HEADERS64* nt_header = nullptr;
	raw = of_readfile(libname, &file_sz);
	platform = check_platform(raw);

	switch (platform)
	{
	case PLATFORM::X64_PLATFORM:
#if defined(__WINDOWS__)
		image_base = winmap(libname);
		of_set_seh(image_base);
#else
		if (!check_valid_pe(raw)) {
			console_log(MSGTYPE::CRIT, "target module is not valid pe");
		}
		if (check_platform(raw) != PLATFORM::X64_PLATFORM) {
			console_log(MSGTYPE::CRIT, "target module is unsupported platform binary");
		}
		nt_header = (IMAGE_NT_HEADERS64*)get_ntheader(raw);
		
		image_base = mmap((void*)(nt_header->OptionalHeader.ImageBase),
			nt_header->OptionalHeader. SizeOfImage, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_ANONYMOUS | MAP_PRIVATE,
			-1,
			0);
		if (image_base == MAP_FAILED) {
			console_log(MSGTYPE::CRIT, "fail to map windll");
		}
		set_all_priv(image_base, nt_header->OptionalHeader.SizeOfImage);
		map_as_iamge(raw, image_base);
		reloc_pe_image(image_base);
#endif // _WIN64

		break;
	default:
		console_log(MSGTYPE::CRIT, "unsupported PE platform");
		break;
	}
	delete raw;
	return image_base;
};
#endif
