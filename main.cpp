#pragma warning(disable: 4996)

#include <stdio.h>
#include <cstdint>
#include <string>
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include "loader.hpp"
#include "log.hpp"
#include "mpcore/engineboot.h"
#include "mpcore/mpcore.h"
#include "mpcore/openscan.h"
#include "mpcore/rsignal.h"
#include "mpcore/scanreply.h"
#include "mpcore/streambuffer.h"
#include "wrapper.hpp"
#include "global.h"
#include "winapi/k32.h"

#ifndef open
#define open _open
#endif // !open

using namespace std;
string engine_path;

void* engine_base = nullptr;

int main(int argc, char** argv) {
	int fd = 0;
	uint8_t* image = nullptr;
	char cur_dir[260];
	GetCurrentDirectory(
		MAX_PATH,
		cur_dir
	);
	engine_path = string(cur_dir) + "\\engine\\mpengine.dll";
	printf("%s\n", engine_path.c_str());
	fd = open((char*)argv[1], _O_RDONLY);
	if (fd < 0) {
		console_log(MSGTYPE::ERR, "Fail to open file");
		exit(-1);
	}

	engine_base = load_temp(engine_path.c_str());

	if (!engine_base) {
		console_log(MSGTYPE::CRIT, "Unable to load mpengine.dll");
	}
	of_rewrite_iat(engine_base);
	of_set_seh(engine_base);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "GetModuleHandleW", (void*)MockGetModuleHandleW);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "GetDriveTypeW", (void*)MockGetDriveTypeW);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "GetDriveTypeA", (void*)MockGetDriveTypeA);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "CreateFileA", (void*)MockCreateFileA);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "CreateFileW", (void*)MockCreateFileW);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "ReadFile", (void*)MockReadFile);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "WriteFile", (void*)MockWriteFile);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "CloseHandle", (void*)MockCloseHandle);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "GetFileSizeEx", (void*)MockGetFileSizeEx);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "SetFilePointerEx", (void*)MockSetFilePointerEx);
	of_rewrite_mp_iat(engine_base, "KERNEL32.DLL", "SetFilePointer", (void*)MockSetFilePointer);
	
	call_dllmain(engine_base);
	void* rsig_addr = (void*)of_getprocaddress((HMODULE)engine_base, (char*)"__rsignal");

	RsignalWrapper* rsignal_wrapper;
	rsignal_wrapper = new RsignalWrapper();
	rsignal_wrapper->set_rsignal(rsig_addr);
	rsignal_wrapper->set_notify_cb((void*)FullScanNotifyCallback);
	rsignal_wrapper->set_vdm_location("./engine");
	rsignal_wrapper->rsig_boot_engine();
	rsignal_wrapper->rsig_scan_stream(fd);
}