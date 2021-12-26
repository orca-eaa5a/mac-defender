#if defined(__WINDOWS__)
#pragma warning(disable: 4996)
#endif
#include "strutils.hpp"

char* convert_wstr_to_str(wchar_t* wstr){
	wstring std_wstr = wstring(wstr);
	string std_str;
	std_str.assign(std_wstr.begin(), std_wstr.end());
	char* new_str = new char[std_str.length() + 1];
	uint64_t max_len = std_str.length() + 1;
	strcpy(new_str, std_str.c_str());

	return new_str;
}

wchar_t* convert_str_to_wstr(char* str) {
	string std_str = string(str);
	wstring std_wstr;
	std_wstr.assign(std_str.begin(), std_str.end());
	wchar_t* new_wstr = new wchar_t[std_wstr.length() + 1];
	uint64_t max_len = (std_str.length() + 1) * sizeof(wchar_t);
	memmove(new_wstr, std_wstr.c_str(), max_len);

	return new_wstr;
}

char* convert_winpath_to_unixpath(char* winpath) {
	while (strchr(winpath, '\\'))
		*strchr(winpath, '\\') = '/';
	return winpath;
}

char* convert_unixpath_to_winpath(char* unixpath) {
	while (strchr(unixpath, '/'))
		*strchr(unixpath, '/') = '\\';
	return unixpath;
}

char* str_tolower(char* str) {
	for (char *t = str; *t; t++)
		*t = tolower(*t);
	return str;
}

char* read_multibyte(void* ptr, size_t buf_sz) {
	char* _str = (char*)ptr;
	char* new_str = nullptr;
	size_t l = 0;
	if (buf_sz != 0)
		for (; (_str[l] != '\0' && buf_sz > l); l++);
	else
		for (; (_str[l] != '\0'); l++);
	new_str = new char[l + 1];
	memset(new_str, 0, (l + 1) * sizeof(char));
	memmove(new_str, _str, l);

	return new_str;
}

wchar_t* read_widestring(void* ptr, size_t buf_sz) {
	wchar_t* _str = (wchar_t*)ptr;
	uint8_t* new_str = nullptr;
	size_t l = 0;
	if (buf_sz != 0)
		for (; (_str[l] != '\0' && buf_sz > l); l++);
	else
		for (; (_str[l] != '\0'); l++);
	l = l * sizeof(wchar_t);
	new_str = new uint8_t[l + 2];
	memset(new_str, 0, (l + 2));
	memmove(new_str, _str, l);

	return (wchar_t*)new_str;
}

vector<string> split_string(char* str, char delimiter) {
	vector<string> v;
	string str_tmp = string(str);
	int sp = 0;
	int pos = 0;

	for (pos; str_tmp.length() > pos; pos++) {
		char c = str_tmp[pos];
		if (c == delimiter) {
			v.push_back(str_tmp.substr(sp, pos-sp));
			sp = pos + 1;
		}
	}
	v.push_back(str_tmp.substr(sp, pos - sp));

	return v;
}

uint32_t copy_str_to_wstr(char* src, wchar_t* dst, uint32_t str_len) {
	/*src is null-terminated string*/
	int i = 0;
	for (i = 0; src[i] != '\0' && str_len > i; i++) {
		dst[i] = src[i];
	}
	dst[i++] = '\0';
	return i;
}

uint32_t copy_wstr_to_str(wchar_t* src, char* dst, uint32_t max_len) {
	/*src is null-terminated string*/
	int i = 0;
	for (i = 0; src[i] != '\0' && max_len > i; i++) {
		dst[i] = (char)src[i];
	}
	dst[i++] = '\0';
	return i;
}

size_t get_wide_string_length(void* ptr) {
	size_t i = 0;
	wchar_t *p = (wchar_t*)ptr;

	if (!p) return 0;

	while (*p++)
		i++;

	return i;
}
