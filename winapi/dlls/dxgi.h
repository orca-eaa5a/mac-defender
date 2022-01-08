#if defined(__WINDOWS__)
#pragma once
#endif

#ifndef _DXGI_H_
#define _DXGI_H_
#include <functional>
#include "../exports.h"
//#include "../strutils.hpp"

#if defined(__APPLE__) || defined(__LINUX__)
#include "include/windows.h"
#endif

class MockDxgi {
public:
	function<void(void)> set_dxgi_hookaddr = [](void) {
		//APIExports::add_hook_info("dxgi.dll", "CreateDXGIFactory", (void*)CreateDXGIFactory);
		APIExports::add_hook_info("dxgi.dll", "CreateDXGIFactory1", (void*)CreateDXGIFactory);
	};
#if defined(__WINDOWS__)
	static uint32_t __stdcall MockDxgi::CreateDXGIFactory(void* riid, void**ppFactory);
	
#else
    static uint32_t __stdcall CreateDXGIFactory(void* riid, void**ppFactory);
	
#endif

};
#endif // !_DXGI_H_
