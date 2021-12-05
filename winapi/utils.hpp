#pragma once
#ifndef _WINAPI_UTILS_H_
#define _WINAPI_UTILS_H_
#include <functional>
#include <string>
#include <string.h>
using namespace std;

function<char*(wchar_t*)> convert_wstr_to_str = [](wchar_t* wstr)->char* {
	wstring std_wstr = wstring(wstr);
	string std_str;
	std_str.assign(std_wstr.begin(), std_wstr.end());
	char* new_str = new char[std_str.length()+1];
	unsigned long long max_len = std_str.length() + 1;
	strcpy_s(new_str, max_len, std_str.c_str());

	return new_str;
};

function<char*(char*)> convert_winpath_to_unixpath = [](char* winpath)->char* {
	while (strchr(winpath, '\\'))
		*strchr(winpath, '\\') = '/';
	return winpath;
};

function<char*(char*)> convert_unixpath_to_winpath = [](char* unixpath)->char* {
	while (strchr(unixpath, '/'))
		*strchr(unixpath, '/') = '\\';
	return unixpath;
};

function<char*(char*)> str_tolower = [](char* str)->char* {
	for (char *t = str; *t; t++)
		*t = tolower(*t);
	return str;
};
#endif // !_WINAPI_UTILS_H_

