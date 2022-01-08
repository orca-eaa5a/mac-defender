#include "imports.h"

void ImportDLLs::setup_dlls() {
	this->kernel32.set_k32_hookaddr();
	this->ntdll.set_ntdll_hookaddr();
	this->advapi.set_advapi_hookaddr();
	this->bcrypt.set_bcrypt_hookaddr();
	this->version.set_version_hookaddr();
	this->crypt32.set_crypt32_hookaddr();
	this->wofutil.set_wofutil_hookaddr();
	this->wintrust.set_wintrust_hookaddr();
	this->ole32.set_ole32_hookaddr();
	this->rpcrt4.set_rpcrt4_hookaddr();
	//this->dxgi.set_dxgi_hookaddr();
}

void ImportDLLs::set_ported_apis(void) {
	APIExports::hook_api_bulk(this->engine_base);
}
