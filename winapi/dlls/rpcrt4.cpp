#include "rpcrt4.h"

uint32_t __stdcall MockRpcrt4::UuidFromStringW(WCHAR* StringUuid, void* Uuid)
{
    typedef struct _GUID {
      uint32_t  Data1;
      uint16_t Data2;
      uint16_t Data3;
      uint8_t  Data4[8];
    } GUID;
	memset(Uuid, 'mock', sizeof(GUID));
	/*
	for (i = 0; i < 16; i++) {
		memset((uint64_t*)Uuid + i, 'mock', sizeof(void*));
	}
	*/
	return 0;
}

uint32_t __stdcall MockRpcrt4::RpcBindingFree(void* Binding) {
	return 1702; //RPC_S_INVALID_BINDING
}


void __stdcall MockRpcrt4::NdrServerCallAll(void* pRpcMsg) {
	return;
}

void* __stdcall MockRpcrt4::NdrClientCall3(void *pProxyInfo, uint32_t nProcNum, void* pReturnValue, ...) {
	return NULL;
}

