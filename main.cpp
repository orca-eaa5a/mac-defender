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
#include "winapi/imports.h"

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
	string cmdline;
	ImportDLLs* dlls;

	if (argc < 2)
		console_log(MSGTYPE::CRIT, "Please input target file");

	for (int i = 0; argc - 1 > i; i++)
		cmdline += string(argv[i]) + string(" ") + string(argv[i + 1]);		

	GetCurrentDirectory(
		MAX_PATH,
		cur_dir
	);

	engine_path = string(cur_dir) + "\\engine\\mpengine.dll";
	engine_base = of_loadlibraryX64(engine_path);
	MockKernel32::mpengine_base = engine_base;
	MockKernel32::commandline = cmdline;
	MockKernel32::wcommandline.assign(cmdline.begin(), cmdline.end());

	if (!engine_base) {
		console_log(MSGTYPE::CRIT, "Unable to load mpengine.dll");
	}
	of_rewrite_iat(engine_base);
	dlls = new ImportDLLs(engine_base);
	dlls->set_ported_apis();
	call_dllmain(engine_base);
	void* rsig_addr = (void*)of_getprocaddress((HMODULE)engine_base, (char*)"__rsignal");

	fd = open((char*)argv[1], _O_RDONLY);
	if (fd < 0) {
		console_log(MSGTYPE::ERR, "Fail to open file");
		exit(-1);
	}

	RsignalWrapper* rsignal_wrapper;
	rsignal_wrapper = new RsignalWrapper();
	rsignal_wrapper->set_notify_cb((void*)FullScanNotifyCallback);
	rsignal_wrapper->set_rsignal(rsig_addr);
	rsignal_wrapper->set_vdm_location("./engine");
	rsignal_wrapper->rsig_boot_engine();
	rsignal_wrapper->rsig_scan_stream(fd);
	system("pause");
}