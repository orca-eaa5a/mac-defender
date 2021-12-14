#include "imports.h"

void ImportDLLs::setup_dlls() {
	this->kernel32.set_k32_hookaddr();
	this->ntdll.set_ntdll_hookaddr();
	this->advapi.set_advapi_hookaddr();
	this->bcrypt.set_bcrypt_hookaddr();
}

void ImportDLLs::set_ported_apis(void) {
	APIExports::hook_api_bulk(this->engine_base);
}