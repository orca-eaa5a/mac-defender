#include "advapi32.h"
#include <string>
#include <cassert>

using namespace std;

uint32_t __stdcall MockAdvapi::RegisterTraceGuidsW(void* RequestAddress, void* RequestContext, void* ControlGuid, uint32_t GuidCOunt, void* TraceGuidReg, char16_t* MofImagePath, char16_t* MofResourceName, void* RegistrationHandle) {
	debug_log("<advapi.dll!%s> called..\n", "RegisterTraceGuidsW");

	return 0;
}

uint32_t __stdcall MockAdvapi::EventSetInformation(void* RegHandle, uint32_t InformationClass, void* EventInformation, uint32_t InformationLength) {
	debug_log("<advapi.dll!%s> called..\n", "EventSetInformation");

	return 0;
}

bool __stdcall MockAdvapi::LookupPrivilegeValueA(char* lpSystemName, char* lpName, void* lpLuid) {
	debug_log("<advapi.dll!%s> called with %s:%s\n", "LookupPrivilegeValueA", lpSystemName, lpName);

	if (lpSystemName != NULL)
		return false;
	char* prv1 = "SeDebugPrivilege";
	char* prv2 = "SeBackupPrivilege";
	char* prv3 = "SeRestorePrivilege";
	if (strcmp(prv1, lpName) == 0 || strcmp(prv2, lpName) == 0 || strcmp(prv3, lpName) == 0) {
		return false;
	}
	return true;
}

bool __stdcall MockAdvapi::LookupPrivilegeValueW(char16_t* lpSystemName, char16_t* lpName, void* lpLuid) {
	char* system_name = nullptr;
	char* name = nullptr;
	if (!lpName)
		return false;
	if(lpSystemName)
		system_name = convert_wstr_to_str(lpSystemName);

	name = convert_wstr_to_str(lpName);

	bool ret = LookupPrivilegeValueA(system_name, name, lpLuid);
	delete name;
	delete system_name;
	return ret;
}

bool __stdcall MockAdvapi::AdjustTokenPrivileges(void* TokenHandle, bool DisableAllPrivileges, void* NewState, uint32_t BufferLength, void* PreviousState, uint32_t* ReturnLength) {
	debug_log("<advapi.dll!%s> called..\n", "AdjustTokenPrivileges");
	return true;
}

long __stdcall MockAdvapi::RegCreateKeyExW(
	/*
	Creates the specified registry key.
	If the key already exists, the function opens it. 
	Note that key names are not case sensitive.
	*/
	void* hKey, 
	char16_t* lpSubKey,
	uint32_t Reserved,
	void* lpClass, 
	uint32_t dwOptions,
	void* samDesired, 
	void* lpSecurityAttributes, 
	void* phkResult, 
	uint32_t* lpdwDisposition) {
	u16string wstr = u16string(lpSubKey);
	string hive;
	string sub_key_str;
	string key_str;
	Json::Value key;

	sub_key_str.assign(wstr.begin(), wstr.end());
	switch ((uint64_t)hKey)
	{
	case HKEY_LOCAL_MACHINE:
		hive = "hklm";
		key = MockNTKrnl::mock_reg[hive];
		break;
	case HKEY_CLASSES_ROOT:
	case HKEY_CURRENT_CONFIG:
	case HKEY_CURRENT_USER:
	case HKEY_USERS:
		hive = "not imp";
		break;
	default:
		tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(uintptr_t)hKey];
		break;
	}
	vector<string> splitted = split_string((char*)sub_key_str.c_str(), '\\');
	//Json::Value key = MockNTKrnl::mock_reg[hive];
	if (!key) {
		debug_log("<advapi.dll!%s> called with ERROR_FILE_NOT_FOUND\n", "RegOpenKeyExW");
		return ERROR_FILE_NOT_FOUND;
	}

	bool exist= true;
	for (auto const subk : splitted) { // check key exist
		string s = str_tolower((char*)subk.c_str());
		key = key[s];
		if (key.isObject())
			continue;
		if (!key) {
			key[subk] = Json::objectValue;
		}
	}
	
	debug_log("<advapi.dll!%s> called with %s/%s\n", "RegCreateKeyExW", hive.c_str(), sub_key_str.c_str());

	uint64_t new_k = MockNTKrnl::CreateNewRegHandle(hive, sub_key_str, key);
	memmove(phkResult, &new_k, sizeof(new_k));

	return 0;
}

long __stdcall MockAdvapi::RegOpenKeyExW(void* hKey, char16_t* lpSubKey, uint32_t ulOptions, uint32_t samDesired, void** phkResult) {
	u16string wstr = u16string(lpSubKey);
	string hive;
	string sub_key_str;
	string key_str;
	sub_key_str.assign(wstr.begin(), wstr.end());
	Json::Value key;
	switch ((uint64_t)hKey)
	{
	case HKEY_LOCAL_MACHINE:
		hive = "hklm";
		key = MockNTKrnl::mock_reg[hive];
		break;
	case HKEY_CLASSES_ROOT:
	case HKEY_CURRENT_CONFIG:
	case HKEY_CURRENT_USER:
	case HKEY_USERS:
		hive = "not imp";
		break;
	default:
		tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(uintptr_t)hKey];
		break;
	}
	vector<string> splitted = split_string((char*)sub_key_str.c_str(), '\\');
	
	if (!key) {
		debug_log("<advapi.dll!%s> called with ERROR_FILE_NOT_FOUND\n", "RegOpenKeyExW");
		return ERROR_FILE_NOT_FOUND;
	}

	for (auto const subk : splitted) { // check key exist
		string s = str_tolower((char*)subk.c_str());
		key = key[s];
		if (key.isObject())
			continue;
		if (!key) {
			debug_log("<advapi.dll!%s> called with ERROR_FILE_NOT_FOUND\n", "RegOpenKeyExW");
			return ERROR_FILE_NOT_FOUND;
		}
	}
	debug_log("<advapi.dll!%s> called with %s>%s\n", "RegOpenKeyExW", hive.c_str(), sub_key_str.c_str());
	uint64_t new_k = MockNTKrnl::CreateNewRegHandle(hive, sub_key_str, key);
	memmove(phkResult, &new_k, sizeof(new_k));
	
	return 0;
}

long __stdcall MockAdvapi::RegQueryInfoKeyW(
	void* hKey,
	char16_t* lpClass,
	uint32_t* lpcClass,
	uint32_t* lpReserved,
	uint32_t* lpcSubKeys,
	uint32_t* lpcMaxSubKeyLen,
	uint32_t* lpcMaxClassLen,
	uint32_t* lpcValues,
	uint32_t* lpcMaxValueNameLen,
	uint32_t* lpcMaxValueLen,
	uint32_t* lpcbSecurityDescriptor,
	void* lpftLastWriteTime
) {
	debug_log("<advapi.dll!%s> called..\n", "RegQueryInfoKeyW");

	string hive;
	string key_str;
	Json::Value key;
	tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(uintptr_t)hKey];
	uint32_t subkeys = 0;
	uint32_t key_values = 0;
	uint32_t max_valuename_len = 0;
	uint32_t max_subkey_len = 0;
	for (auto it = key.begin(); it != key.end(); ++it)
	{
		string subkey_str = it.key().asString();
		size_t subkey_str_len = subkey_str.length();
		if (key[it.key().asString()].isObject()){
			if (subkey_str_len > max_subkey_len)
				max_subkey_len = subkey_str_len;
			subkeys++;
		}
		else {
			if (subkey_str_len > max_valuename_len)
				max_valuename_len = subkey_str_len;
			key_values++;
		}
	}
	if (lpClass) {
		assert(0); // not implemented yet
	}
	if (lpcClass) {
		assert(0); // not implemented yet
	}
	if (lpcSubKeys) {
		*lpcSubKeys = subkeys;
	}
	if (lpcMaxSubKeyLen) {
		*lpcMaxSubKeyLen = max_subkey_len;
	}
	if (lpcMaxClassLen) {
		assert(0); // not implemented yet
	}
	if (lpcValues) {
		/*number of values in key*/
		*lpcValues = key_values;
	}
	 
	if (lpcMaxValueNameLen) {
		*lpcMaxValueNameLen = max_valuename_len;
	}
	if (lpcMaxValueLen) {
		assert(0); // not implemented yet
	}
	if (lpcbSecurityDescriptor) {
		assert(0); // not implemented yet
	}

	return 0;
}

long __stdcall MockAdvapi::RegQueryValueExW(void* hKey, char16_t* lpValueName, uint32_t* lpReserved, uint32_t* lpType, uint8_t*  lpData, uint32_t* lpcbData) {
	string hive;
	string key_str;
	Json::Value key;
	string value;
	u16string value_w = u16string(lpValueName);
	value.assign(value_w.begin(), value_w.end());

	debug_log("<advapi.dll!%s> called with %s\n", "RegQueryValueExW", value.c_str());

	switch ((uint64_t)hKey)
	{
	case HKEY_LOCAL_MACHINE:
		hive = "hklm";
		key = MockNTKrnl::mock_reg[hive];
		break;
	case HKEY_CLASSES_ROOT:
	case HKEY_CURRENT_CONFIG:
	case HKEY_CURRENT_USER:
	case HKEY_USERS:
		hive = "not imp";
		break;
	default:
		tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(uintptr_t)hKey];
		break;
	}

	if (key.isMember(value)) {
		auto subkey = key[value];
		uint32_t regtype;
		size_t data_sz = 0;
		
		if (subkey.isString()) {
			regtype = 0x2; //REG_EXPAND_SZ;
			u16string value;
			data_sz = subkey.asString().length();
			
			value.assign(subkey.asString().begin(), subkey.asString().end());
			if (data_sz > *lpcbData) {
				*lpcbData = data_sz;
				return 234; //ERROR_MORE_DATA
			}
			memmove(lpData, value.c_str(), (data_sz+1)*sizeof(WCHAR));
			
			*lpcbData = (data_sz + 1) * sizeof(WCHAR);
		}
		else if (subkey.isInt64() || subkey.isInt()) {
			regtype = 0x4; //REG_DWORD
			data_sz = 4;
		}
		*lpType = regtype;
		
	}
	else {
		debug_log("<advapi.dll!%s> called with ERROR_FILE_NOT_FOUND\n", "RegQueryValueExW");
		return ERROR_FILE_NOT_FOUND;
	}
	return 0;
}

long __stdcall MockAdvapi::RegEnumKeyExW(void* hKey, uint32_t dwIndex, char16_t* lpName, uint32_t* lpcchName, void* lpReserved, char16_t* lpClass, uint32_t* lpcchClass, void* lpftLastWriteTime) {
	string hive;
	string key_str;
	Json::Value key;
	tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(uintptr_t)hKey];
	
	debug_log("<advapi.dll!%s> called..\n", "RegEnumKeyExW");


	uint32_t idx = 0;
	auto it = key.begin();
	for (; it != key.end(); ++it) {
		if (!key[it.key().asString()].isObject())
			continue;
		if (idx == dwIndex)
			break;
		idx++;
	}

	key_str = it.key().asString();
	auto subkey = key[key_str];

	if (it == key.end()) {
		/*can't get value of target index*/
		return 0x80070103; // ERROR_NO_MORE_ITEMS;
	}
	
	if (lpName) {
		copy_str_to_wstr((char*)key_str.c_str(), lpName, key_str.length());
	}
	if (lpcchName) {
		*lpcchName = key_str.length();
	}
	if (lpClass) {
		assert(0); // not impemented yet
	}
	if (lpcchClass) {
		assert(0); // not impemented yet
	}


	return 0;
}


long __stdcall MockAdvapi::RegCloseKey(void* hKey) {
	debug_log("<advapi.dll!%s> called..\n", "RegCloseKey");

	uintptr_t k = (uintptr_t)hKey;
	MockNTKrnl::RemoveRegHandle(k);
	return 0;
}

long __stdcall MockAdvapi::RegNotifyChangeKeyValue(void* hKey, bool bWatchSubtree, uint32_t dwNotifyFilter, void* hEvent, bool fAsynchronous) {
	debug_log("<advapi.dll!%s> called..\n", "RegNotifyChangeKeyValue");

	return 0;
}

uint32_t __stdcall MockAdvapi::LsaNtStatusToWinError(uint32_t Status) {
	debug_log("<advapi.dll!%s> called..\n", "LsaNtStatusToWinError");

	return Status;
}

uint32_t __stdcall MockAdvapi::EventWriteEx(
	void* EventDescriptor,
	uint64_t Filter,
	uint32_t Flags,
	void* ActivityId,
	void* RelatedActivityId,
	uint32_t UserDataCount,
	void* UserData) {
	debug_log("<advapi.dll!%s> called..\n", "EventWriteEx");

	return 0;
}

uint32_t __stdcall MockAdvapi::EventWriteTransfer(
	void* RegHandle,
	void* EventDescriptor,
	void* ActivityId,
	void* RelatedActivityId,
	uint32_t UserDataCount,
	void* UserData
) {
	debug_log("<advapi.dll!%s> called..\n", "EventWriteTransfer");

	return 0;
}

uint32_t __stdcall MockAdvapi::MyEventActivityIdControl(
	uint32_t ControlCode,
	void* ActivityId
) {
	debug_log("<advapi.dll!%s> called..\n", "MyEventActivityIdControl");

	return 0;
	//return 0;
}
