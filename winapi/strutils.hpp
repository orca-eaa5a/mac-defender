#if defined(__WINDOWS__)
#pragma once
#endif

#ifndef _WINAPI_UTILS_H_
#define _WINAPI_UTILS_H_
#include <functional>
#include <string>
#include <codecvt>
#include <string.h>
#include <vector>

#if defined(__APPLE__) || defined(__LINUX__)
#include "dlls/include/wintype.h"
#else
#include <windows.h>
#endif

using namespace std;

extern char* convert_wstr_to_str(char16_t* wstr);
extern char16_t* convert_str_to_wstr(char* str);
extern char* convert_winpath_to_unixpath(char* winpath);
extern char* convert_unixpath_to_winpath(char* unixpath);
extern char* str_tolower(char* str);
extern char* read_multibyte(void* ptr, size_t buf_sz);
extern char16_t* read_widestring(void* ptr, size_t buf_sz);
extern vector<string> split_string(char* str, char delim);
extern uint32_t copy_str_to_wstr(char* src, char16_t* dst, uint32_t str_len);
extern int compare_wstr(char16_t* targ1, char16_t* targ2);
extern uint32_t copy_wstr_to_str(char16_t* src, char* dst, uint32_t max_len);
extern size_t get_wide_string_length(void* ptr);
extern void debug_log(const char* fmt, ...);
#endif // !_WINAPI_UTILS_H_

