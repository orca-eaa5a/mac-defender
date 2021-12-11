#include "ntdll.h"
#include "ntoskrnl.h"

NTSTATUS __stdcall MockNtdll::RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation) {
	lpVersionInformation->dwMajorVersion = MockNTKrnl::major;
	lpVersionInformation->dwMinorVersion = MockNTKrnl::minor;
	lpVersionInformation->dwBuildNumber = MockNTKrnl::build_version;

	return 0;
}

NTSTATUS __stdcall MockNtdll::EtwRegister(void* ProviderId, void* EnableCallback, void* CallbackContext, void* RegHandle) {
	return 0;
}

