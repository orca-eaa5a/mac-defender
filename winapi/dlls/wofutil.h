#pragma once
#ifndef _WOFUTIL_H_
#define _WOFUTIL_H_
#include <functional>
#include <windows.h>
#include "../exports.h"

class MockWofUtil {
public:
	function<void(void)> set_wofutil_hookaddr = [](void) {
		APIExports::add_hook_info("wofutil.dll", "WofShouldCompressBinaries", (void*)MockWofUtil::WofShouldCompressBinaries);

	};
	static void* __stdcall MockWofUtil::WofShouldCompressBinaries(wchar_t* Volume, unsigned long* Algorithm);
};
#endif // !_WOFUTIL_H_
