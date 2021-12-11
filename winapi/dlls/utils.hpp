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

function<wchar_t*(char*)> convert_str_to_wstr = [](char* str)->wchar_t* {
	string std_str = string(str);
	wstring std_wstr;
	std_wstr.assign(std_str.begin(), std_str.end());
	wchar_t* new_wstr = new wchar_t[std_wstr.length()+1];
	unsigned long long max_len = (std_str.length() + 1)*sizeof(wchar_t);
	memmove(new_wstr, std_wstr.c_str(), max_len);

	return new_wstr;
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

function<char*(void*, size_t)> read_multibyte = [](void* ptr, size_t buf_sz)->char* {
	char* _str = (char*)ptr;
	char* new_str = nullptr;
	size_t l = 0;
	if(buf_sz != 0)
		for (; (_str[l] != '\0' && buf_sz > l); l++);
	else
		for (; (_str[l] != '\0'); l++);
	new_str = new char[l+1];
	memset(new_str, 0, (l + 1) * sizeof(char));
	memmove(new_str, _str, l);

	return new_str;
};

function<wchar_t*(void*, size_t)> read_widestring = [](void* ptr, size_t buf_sz)->wchar_t* {
	wchar_t* _str = (wchar_t*)ptr;
	uint8_t* new_str = nullptr;
	size_t l = 0;
	if(buf_sz != 0)
		for (; (_str[l] != '\0' && buf_sz > l); l++);
	else
		for (; (_str[l] != '\0'); l++);
	new_str = new uint8_t[l+1];
	memset(new_str, 0, (l + 1));
	memmove(new_str, _str, l);
	
	return (wchar_t*)new_str;
};
#endif // !_WINAPI_UTILS_H_

