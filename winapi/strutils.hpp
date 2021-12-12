#pragma once
#ifndef _WINAPI_UTILS_H_
#define _WINAPI_UTILS_H_
#include <functional>
#include <string>
#include <string.h>
#include <vector>

using namespace std;

extern char* convert_wstr_to_str(wchar_t* wstr);
extern wchar_t* convert_str_to_wstr(char* str);
extern char* convert_winpath_to_unixpath(char* winpath);
extern char* convert_unixpath_to_winpath(char* unixpath);
extern char* str_tolower(char* str);
extern char* read_multibyte(void* ptr, size_t buf_sz);
extern wchar_t* read_widestring(void* ptr, size_t buf_sz);
extern vector<string> split_string(char* str, char delim);
extern unsigned int copy_str_to_wstr(char* src, wchar_t* dst, unsigned int str_len);
extern unsigned int copy_wstr_to_str(wchar_t* src, char* dst, unsigned int max_len);
#endif // !_WINAPI_UTILS_H_

