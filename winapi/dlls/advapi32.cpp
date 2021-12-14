#include "advapi32.h"
#include <string>
#include <cassert>

using namespace std;

unsigned long __stdcall MockAdvapi::RegisterTraceGuidsW(void* RequestAddress, void* RequestContext, void* ControlGuid, unsigned long GuidCOunt, void* TraceGuidReg, wchar_t* MofImagePath, wchar_t* MofResourceName, void* RegistrationHandle) {
	return 0;
}

unsigned long __stdcall MockAdvapi::EventSetInformation(void* RegHandle, unsigned int InformationClass, void* EventInformation, unsigned long InformationLength) {
	return 0;
}

bool __stdcall MockAdvapi::LookupPrivilegeValueA(char* lpSystemName, char* lpName, void* lpLuid) {
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

bool __stdcall MockAdvapi::LookupPrivilegeValueW(wchar_t* lpSystemName, wchar_t* lpName, void* lpLuid) {
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

bool __stdcall MockAdvapi::AdjustTokenPrivileges(void* TokenHandle, bool DisableAllPrivileges, void* NewState, unsigned int BufferLength, void* PreviousState, unsigned int* ReturnLength) {
	return true;
}

long __stdcall MockAdvapi::RegCreateKeyExW(
	/*
	Creates the specified registry key.
	If the key already exists, the function opens it. 
	Note that key names are not case sensitive.
	*/
	void* hKey, 
	wchar_t* lpSubKey, 
	unsigned int Reserved, 
	void* lpClass, 
	unsigned int dwOptions, 
	void* samDesired, 
	void* lpSecurityAttributes, 
	void* phkResult, 
	unsigned int* lpdwDisposition) {
	wstring wstr = wstring(lpSubKey);
	string hive;
	string sub_key_str;
	string key_str;
	Json::Value key;

	sub_key_str.assign(wstr.begin(), wstr.end());
	switch ((unsigned long long)hKey)
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
		tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(unsigned int)hKey];
		break;
	}
	vector<string> splitted = split_string((char*)sub_key_str.c_str(), '\\');
	//Json::Value key = MockNTKrnl::mock_reg[hive];
	if (!key) {
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
	
	unsigned long long new_k = MockNTKrnl::CreateNewRegHandle(hive, sub_key_str, key);
	memmove(phkResult, &new_k, sizeof(new_k));
	

	return 0;
}

long __stdcall MockAdvapi::RegOpenKeyExW(void* hKey, wchar_t* lpSubKey, unsigned int ulOptions, unsigned int samDesired, void** phkResult) {
	wstring wstr = wstring(lpSubKey);
	string hive;
	string sub_key_str;
	string key_str;
	sub_key_str.assign(wstr.begin(), wstr.end());
	Json::Value key;
	switch ((unsigned long long)hKey)
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
		tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(unsigned int)hKey];
		break;
	}
	vector<string> splitted = split_string((char*)sub_key_str.c_str(), '\\');
	
	if (!key) {
		return ERROR_FILE_NOT_FOUND;
	}

	for (auto const subk : splitted) { // check key exist
		string s = str_tolower((char*)subk.c_str());
		key = key[s];
		if (key.isObject())
			continue;
		if (!key) {
			return ERROR_FILE_NOT_FOUND;
		}
	}
	
	unsigned long long new_k = MockNTKrnl::CreateNewRegHandle(hive, sub_key_str, key);
	memmove(phkResult, &new_k, sizeof(new_k));
	
	return 0;
}

long __stdcall MockAdvapi::RegQueryInfoKeyW(
	void* hKey,
	wchar_t* lpClass,
	unsigned int* lpcClass,
	unsigned int* lpReserved,
	unsigned int* lpcSubKeys,
	unsigned int* lpcMaxSubKeyLen,
	unsigned int* lpcMaxClassLen,
	unsigned int* lpcValues,
	unsigned int* lpcMaxValueNameLen,
	unsigned int* lpcMaxValueLen,
	unsigned int* lpcbSecurityDescriptor,
	void* lpftLastWriteTime
) {
	string hive;
	string key_str;
	Json::Value key;
	tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(unsigned int)hKey];
	unsigned int subkeys = 0;
	unsigned int key_values = 0;
	unsigned int max_valuename_len = 0;
	unsigned int max_subkey_len = 0;
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

long __stdcall MockAdvapi::RegQueryValueExW(void* hKey, wchar_t* lpValueName, unsigned int* lpReserved, unsigned int* lpType, unsigned char*  lpData, unsigned int* lpcbData) {
	string hive;
	string key_str;
	Json::Value key;
	string value;
	wstring value_w = wstring(lpValueName);
	value.assign(value_w.begin(), value_w.end());

	switch ((unsigned long long)hKey)
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
		tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(unsigned int)hKey];
		break;
	}

	if (key.isMember(value)) {
		auto subkey = key[value];
		unsigned int regtype;
		size_t data_sz = 0;
		
		if (subkey.isString()) {
			regtype = 0x2; //REG_EXPAND_SZ;
			wstring value;
			data_sz = subkey.asString().length();
			
			value.assign(subkey.asString().begin(), subkey.asString().end());
			if (data_sz > *lpcbData) {
				*lpcbData = data_sz;
				return 234; //ERROR_MORE_DATA
			}
			memmove(lpData, value.c_str(), (data_sz+1)*sizeof(wchar_t));
			
			*lpcbData = (data_sz + 1) * sizeof(wchar_t);
		}
		else if (subkey.isInt64() || subkey.isInt()) {
			regtype = 0x4; //REG_DWORD
			data_sz = 4;
		}
		*lpType = regtype;
		
	}
	else {
		return ERROR_FILE_NOT_FOUND;
	}
	return 0;
}

long __stdcall MockAdvapi::RegEnumKeyExW(void* hKey, unsigned int dwIndex, wchar_t* lpName, unsigned int* lpcchName, void* lpReserved, wchar_t* lpClass, unsigned int* lpcchClass, void* lpftLastWriteTime) {
	string hive;
	string key_str;
	Json::Value key;
	tie(hive, key_str, key) = MockNTKrnl::m_reg_handle[(unsigned int)hKey];
	
	unsigned int idx = 0;
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
	unsigned int k = (unsigned int)hKey;
	MockNTKrnl::RemoveRegHandle(k);
	return 0;
}

long __stdcall MockAdvapi::RegNotifyChangeKeyValue(void* hKey, bool bWatchSubtree, unsigned int dwNotifyFilter, void* hEvent, bool fAsynchronous) {
	return 0;
}