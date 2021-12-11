#include <windows.h>
#include "exports.h"

map<string, map<string, void*>> APIExports::exports;
void APIExports::add_hook_info(string mod_name, string func_name, void* addr) {
	if (APIExports::exports.count(mod_name)) {
		if (!APIExports::exports[mod_name].count(func_name)) {
			APIExports::exports[mod_name][func_name] = addr;
		}
	}
	else {
		APIExports::exports[mod_name];
		APIExports::exports[mod_name][func_name] = addr;
	}
}

bool APIExports::hook_as_ported_api(void* imgbase, char* targ_module, char* targ_api, void* hook_addr) {
	uint16_t platform = 0xffff;
	uint8_t* _imgbase = (uint8_t*)imgbase;
	uint32_t imp_dir_va;
	uint32_t imp_dir_sz;

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)_imgbase;
	IMAGE_IMPORT_DESCRIPTOR* imp_descriptor = nullptr;

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
			if (_stricmp(targ_module, mod_name) != 0) {
				imp_descriptor++;
				continue;
			}
			unsigned long long* pThunkRef = reinterpret_cast<unsigned long long*>(_imgbase + imp_descriptor->OriginalFirstThunk);
			unsigned long long* pFuncRef = reinterpret_cast<unsigned long long*>(_imgbase + imp_descriptor->FirstThunk);
			if (!pThunkRef)
				pThunkRef = pFuncRef;
			for (; *pThunkRef; pThunkRef++, pFuncRef++) {
				IMAGE_IMPORT_BY_NAME* imp_by_name = (IMAGE_IMPORT_BY_NAME*)(_imgbase + *pThunkRef);
				if (_stricmp(imp_by_name->Name, targ_api) == 0) {
					*pFuncRef = (unsigned long long)hook_addr;
					return true;
				}
			}
			imp_descriptor++;
		}
	}
	return false;
}

void APIExports::hook_api_bulk(void* image_base) {
	auto iter = APIExports::exports.begin();
	for (auto const& mod_name : APIExports::exports) {
		for (auto const& proc_name : APIExports::exports[mod_name.first]) {
			APIExports::hook_as_ported_api(
				image_base,
				(char*)mod_name.first.c_str(),
				(char*)proc_name.first.c_str(),
				(void*)proc_name.second
			);
		}
	}
}