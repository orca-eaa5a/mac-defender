#include "advapi32.h"
#include <string>

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
	auto convert_wstr_to_str = [](wchar_t* wstr)->char* {
		wstring std_wstr = wstring(wstr);
		string std_str;
		std_str.assign(std_wstr.begin(), std_wstr.end());
		char* new_str = new char[std_str.length() + 1];
		unsigned long long max_len = std_str.length() + 1;
		strcpy_s(new_str, max_len, std_str.c_str());

		return new_str;
	};
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