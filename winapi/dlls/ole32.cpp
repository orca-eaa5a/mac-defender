#include "ole32.h"


uint32_t __stdcall MockOle32::CoCreateGuid(void* pguid) {
	struct WinGUID {
		uint32_t  Data1;
		uint16_t Data2;
		uint16_t Data3;
		uint8_t  Data4[8];
	};
	WinGUID* guid = new WinGUID;
	debug_log("<ole32.dll!%s> called..\n", "CoCreateGuid");

	pguid = (void*)guid;
	return 0;
}

uint32_t __stdcall MockOle32::CoCreateInstance(void* rclsid, void* pUnkOuter, uint32_t dwClsContext, void* riid, void* ppv) {
	debug_log("<ole32.dll!%s> called..\n", "CoCreateInstance");

	return 0xffffffff;
}

uint32_t __stdcall MockOle32::CoInitializeEx(void* pvReserved, uint32_t dwCoInit) {
	debug_log("<ole32.dll!%s> called..\n", "CoInitializeEx");

	return 0xffffffff;
}

void __stdcall MockOle32::CoUninitialize() {
	debug_log("<ole32.dll!%s> called..\n", "CoUninitialize");

	return;
}

uint32_t __stdcall MockOle32::IIDFromString(void* lpsz, void* lpiid) {
	debug_log("<ole32.dll!%s> called..\n", "IIDFromString");

	return 0xffffffff;
}
uint32_t __stdcall MockOle32::CoSetProxyBlanket(
	void* pProxy,
	uint32_t dwAuthnSvc,
	uint32_t dwAuthzSvc,
	char16_t* pServerPrincName,
	uint32_t dwAuthnLevel,
	uint32_t dwImpLevel,
	void* pAuthInfo,
	uint32_t dwCapabilities
) {
	debug_log("<ole32.dll!%s> called..\n", "CoSetProxyBlanket");

	return 0xffffffff;
}
