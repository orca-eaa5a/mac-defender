#if defined(__WINDOWS__)
#pragma once
#endif
#ifndef _IMP_H_
#define _IMP_H_


#include "dlls/kernel32.h"
#include "dlls/ntdll.h"
#include "dlls/advapi32.h"
#include "dlls/bcrypt.h"
#include "dlls/version.h"
#include "dlls/crypt32.h"
#include "dlls/wofutil.h"
#include "dlls/wintrust.h"
#include "dlls/ole32.h"
#include "dlls/rpcrt4.h"
#include "dlls/dxgi.h"
#include "ntoskrnl.h"
#include "exports.h"

class ImportDLLs {
public:
	void setup_dlls(void);

	ImportDLLs() {
		this->setup_dlls();
	}
	
	ImportDLLs(void* engine_base) {
		this->engine_base = engine_base;
		this->setup_dlls();
	}

	void set_ported_apis(void);


private:
	MockKernel32 kernel32;
	MockNtdll ntdll;
	MockAdvapi advapi;
	MockBcrypt bcrypt;
	MockVersion version;
	MockCrypt32 crypt32;
	MockWofUtil wofutil;
	MockWintrust wintrust;
	MockOle32 ole32;
	MockRpcrt4 rpcrt4;
	MockDxgi dxgi;
	
	void* engine_base;

};

#endif // !_IMP_H_