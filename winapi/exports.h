#ifndef _API_H_
#define _API_H_
#include <string>
#include <map>
#include <functional>

#if defined(__APPLE__) || defined(__LINUX__)
#include "dlls/include/windows.h"
#else
#include <windows.h>
#endif

using namespace std;
class APIExports {
public:
	static map<string, map<string, void*>> exports;
	static void add_hook_info(string mod_name, string func_name, void* addr);
	static bool hook_as_ported_api(void* imgbase, char* targ_module, char* targ_api, void* hook_addr);
	static void hook_api_bulk(void* image_base);
};

#endif // !_API_H_
