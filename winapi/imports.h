#pragma once
#ifndef _IMP_H_
#define _IMP_H_

#include "dlls/ntoskrnl.h"
#include "dlls/kernel32.h"
#include "dlls/ntdll.h"
#include "dlls/advapi32.h"
#include "exports.h"

class ImportDLLs {
public:
	void ImportDLLs::setup_dlls(void);

	ImportDLLs() {
		this->setup_dlls();
	}
	
	ImportDLLs(void* engine_base) {
		this->engine_base = engine_base;
		this->setup_dlls();
	}

	void ImportDLLs::set_ported_apis(void);


private:
	MockKernel32 kernel32;
	MockNtdll ntdll;
	MockAdvapi advapi;
	void* engine_base;

};

#endif // !_IMP_H_