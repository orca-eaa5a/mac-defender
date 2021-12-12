#include "ntdll.h"
#include "../ntoskrnl.h"
#include <cassert>

NTSTATUS __stdcall MockNtdll::RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation) {
	lpVersionInformation->dwMajorVersion = MockNTKrnl::major;
	lpVersionInformation->dwMinorVersion = MockNTKrnl::minor;
	lpVersionInformation->dwBuildNumber = MockNTKrnl::build_version;

	return 0;
}

NTSTATUS __stdcall MockNtdll::EtwRegister(void* ProviderId, void* EnableCallback, void* CallbackContext, void* RegHandle) {
	return 0;
}

NTSTATUS __stdcall MockNtdll::EtwUnregister(void* RegHandle){
	return -1;
}

NTSTATUS __stdcall MockNtdll::NtEnumerateValueKey(void* KeyHandle, unsigned long Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, unsigned long Length, unsigned long* ResultLength) {
	KEY_VALUE_BASIC_INFORMATION* kvinfo = nullptr;

	string hive;
	string key_str;
	Json::Value key;
	memset(KeyValueInformation, 0, Length);

	tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(unsigned int)KeyHandle];
	unsigned int idx = 0;
	auto it = key.begin();
	for (; it != key.end(); ++it){
		if (key[it.key().asString()].isObject())
			continue;
		if (idx == Index)
			break;
		idx++;
	}
	if (it == key.end()) {
		/*can't get value of target index*/
		return 0x8000001A; // STATUS_NO_MORE_ENTRIES;
	}

	key_str = it.key().asString();
	auto subkey = key[key_str];
	
	unsigned int regtype = 0;
	if (subkey.isString()) {
		regtype = 0x2; //REG_EXPAND_SZ;

	}
	else if (subkey.isInt64() || subkey.isInt()) {
		regtype = 0x4; //REG_DWORD
	}
	else {
		assert(0);
	}
	unsigned int buf_sz = 0;
	switch (KeyValueInformationClass)
	{
	case KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation:
		kvinfo = (KEY_VALUE_BASIC_INFORMATION*)KeyValueInformation;
		kvinfo->TitleIndex = 0;
		kvinfo->Type = regtype;
		kvinfo->NameLength = 0;
		buf_sz = key_str.length() * sizeof(wchar_t) + sizeof(KEY_VALUE_BASIC_INFORMATION);
		copy_str_to_wstr((char*)key_str.c_str(), kvinfo->Name, key_str.length());
		kvinfo->NameLength = key_str.length() * sizeof(wchar_t);
		*ResultLength = buf_sz;
		if (buf_sz > Length) {
			return 0x80000005; //STATUS_BUFFER_OVERFLOW
		}
		break;
	case KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation:
	case KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformation:
	default:
		assert(0);
		break;
	}

	return 0;
}

NTSTATUS __stdcall MockNtdll::NtQueryValueKey(void* KeyHandle, void* ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation, unsigned long Length, unsigned long* ResultLength) {
	string hive;
	string key_str;
	Json::Value key;
	KEY_VALUE_PARTIAL_INFORMATION* kvpi;
	PUNICODE_STRING ustr = (PUNICODE_STRING)ValueName;
	
	tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(unsigned int)KeyHandle];
	wchar_t* wstr = read_widestring(ustr->Buffer, ustr->Length);
	char* subkey_str = str_tolower(convert_wstr_to_str(wstr));
	auto subkey = key[subkey_str];
	delete wstr;
	delete subkey_str;

	if (!subkey) {
		return 0xc0000034; //STATUS_OBJECT_NAME_NOT_FOUND
	}

	unsigned int regtype = 0;
	unsigned int required_sz = 0;

	if (KeyValueInformationClass == KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation) {
		assert(0);
	}
	else if (KeyValueInformationClass == KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation) {
		assert(0);
	}
	else if (KeyValueInformationClass == KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformation) {
		kvpi = (KEY_VALUE_PARTIAL_INFORMATION*)KeyValueInformation;
		if (subkey.isString()) {
			regtype = 0x2;//REG_EXPAND_SZ;
			string subkey_value = subkey.asString();
			unsigned int value_sz = subkey_value.length();
			required_sz = value_sz + sizeof(KEY_VALUE_PARTIAL_INFORMATION);
			kvpi->TitleIndex = 0;
			kvpi->Type = 0x2;
			kvpi->DataLength = value_sz;
			*ResultLength = required_sz;
			if (required_sz > Length) {
				return 0x80000005; //STATUS_BUFFER_OVERFLOW
			}
			memmove(kvpi->Data, subkey_value.c_str(), value_sz);
		}
		else if (subkey.isInt() || subkey.isInt64()) {
			regtype = 0x4; //REG_DWORD
			unsigned int subkey_value = subkey.asInt();
			unsigned int value_sz = sizeof(unsigned int);
			required_sz = value_sz; +sizeof(KEY_VALUE_PARTIAL_INFORMATION);
			kvpi->TitleIndex = 0;
			kvpi->Type = 0x4;
			kvpi->DataLength = value_sz;
			*ResultLength = required_sz;
			if (required_sz > Length) {
				return 0x80000005; //STATUS_BUFFER_OVERFLOW
			}
			memmove(kvpi->Data, &subkey_value, value_sz);
		}
		else {
			assert(0);
		}
	}
	else {
		assert(0);
	}
	return 0;
}

