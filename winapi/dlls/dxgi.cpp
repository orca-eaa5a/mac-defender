#include "dxgi.h"
#include <dxgi.h>


typedef bool(*enumAdapter)(void*, uint32_t, void*);
typedef bool(*releaseAdapter)(void*);
static int EnumAdapter(void* self, uint32_t a, void* b) {
	return 0x887A0002; //DXGI_ERROR_NOT_FOUND
};

static void AdapterRelease(void* self) {
	delete self;
}

typedef struct MockIDXGIFactoryElem {
	uint8_t unk[0x10];
	releaseAdapter _releaseAdapter;
	uint8_t unk2[0x20];
	enumAdapter _enumAdapter;
}MockIDXGIFactoryElem;

typedef struct MockIDXGIFactory {
	MockIDXGIFactoryElem* elem;
};

uint32_t __stdcall MockDxgi::CreateDXGIFactory(void* riid, void**ppFactory) {
	/*
	DXGI_ERROR_NOT_CURRENTLY_AVAILABLE
	0x887A0022
	*/
	MockIDXGIFactory* factory = new MockIDXGIFactory;
	MockIDXGIFactoryElem* elem = new MockIDXGIFactoryElem;
	//memset(factory, 0, sizeof(MockIDXGIFactory));
	factory->elem = elem;
	elem->_enumAdapter = (enumAdapter)EnumAdapter;
	elem->_releaseAdapter = (releaseAdapter)AdapterRelease;
	
	*ppFactory = (void*)factory;

	return 0; //DXGI_ERROR_NOT_FOUND
}

