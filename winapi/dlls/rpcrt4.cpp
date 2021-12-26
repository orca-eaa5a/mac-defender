#include "rpcrt4.h"

uint32_t __stdcall MockRpcrt4::UuidFromStringW(wchar_t* StringUuid, void* Uuid) {
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

