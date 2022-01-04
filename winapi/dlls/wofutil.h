#if defined(__WINDOWS__)
#pragma once
#endif

#ifndef _WOFUTIL_H_
#define _WOFUTIL_H_
#include <functional>
#include "../exports.h"

#if defined(__APPLE__) || defined(__LINUX__)
#include "include/windows.h"
#endif

class MockWofUtil {
public:
	function<void(void)> set_wofutil_hookaddr = [](void) {
		APIExports::add_hook_info("wofutil.dll", "WofShouldCompressBinaries", (void*)WofShouldCompressBinaries);

	};
#if defined(__WINDOWS__)
	static bool __stdcall MockWofUtil::WofShouldCompressBinaries(char16_t* Volume, uint32_t* Algorithm);
#else
	static bool __stdcall WofShouldCompressBinaries(char16_t* Volume, uint32_t* Algorithm);
#endif
};
#endif // !_WOFUTIL_H_
