#include "rpcrt4.h"

uint32_t __stdcall MockRpcrt4::UuidFromStringW(char16_t* StringUuid, void* Uuid)
{
    typedef struct _GUID {
      uint32_t  Data1;
      uint16_t Data2;
      uint16_t Data3;
      uint8_t  Data4[8];
    } GUID;
	debug_log("<rpcrt4.dll!%s> called..\n", "UuidFromStringW");

	memset(Uuid, 'mock', sizeof(GUID));
	/*
	for (i = 0; i < 16; i++) {
		memset((uint64_t*)Uuid + i, 'mock', sizeof(void*));
	}
	*/
	return 0;
}

uint32_t __stdcall MockRpcrt4::RpcBindingFree(void* Binding) {
	debug_log("<rpcrt4.dll!%s> called..\n", "RpcBindingFree");

	return 1702; //RPC_S_INVALID_BINDING
}


void __stdcall MockRpcrt4::NdrServerCallAll(void* pRpcMsg) {
	debug_log("<rpcrt4.dll!%s> called..\n", "NdrServerCallAll");

	return;
}

void* __stdcall MockRpcrt4::NdrClientCall3(void *pProxyInfo, uint32_t nProcNum, void* pReturnValue, ...) {
	debug_log("<rpcrt4.dll!%s> called..\n", "NdrClientCall3");

	return NULL;
}

