#if defined(__WINDOWS__)
#pragma warning(disable: 4996)
#endif

#include <stdio.h>
#include <cstdint>
#include <string>
#if defined(__WINDOWS__) || defined(__LINUX__)
#include <io.h>
#elif defined(__APPLE__)
#include <sys/uio.h>
#include <unistd.h>
#endif
#include <fcntl.h>
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
#include "winapi/ntoskrnl.h"

#if defined(__WINDOWS__)
#ifndef open
#define open _open
#endif // !open
#endif

using namespace std;
string engine_path;
void* engine_base = nullptr;

int main(int argc, char** argv) {
	int fd = 0;
	char cur_dir[260];
	string cmdline;
	ImportDLLs* dlls;
	MockNTKrnl mtosknl;

	if (argc < 2)
		console_log(MSGTYPE::CRIT, "Please input target file");

	for (int i = 0; argc - 1 > i; i++)
		cmdline += string(argv[i]) + string(" ") + string(argv[i + 1]);
#if defined(__WINDOWS__)
	GetCurrentDirectory(
		MAX_PATH,
		cur_dir
	);
	engine_path = string(cur_dir) + "\\engine\\mpengine.dll";
#else
	getcwd(cur_dir, sizeof(cur_dir));
	engine_path = string(cur_dir) + "/engine/mpengine.dll";
#endif

	engine_base = of_loadlibraryX64(engine_path);
	MockNTKrnl::engine_base = (uint64_t)engine_base;
	MockKernel32::commandline = cmdline;
	MockKernel32::wcommandline.assign(cmdline.begin(), cmdline.end());
	if (!engine_base) {
		console_log(MSGTYPE::CRIT, "Unable to load mpengine.dll");
	}

	dlls = new ImportDLLs(engine_base);
	dlls->set_ported_apis();
	bool res = call_dllmain(engine_base);
	void* rsig_addr = (void*)of_getprocaddress(engine_base, (char*)"__rsignal");

	//engine_base = LoadLibrary(engine_path.c_str());
	//void* rsig_addr = (void*)GetProcAddress((HMODULE)engine_base, "__rsignal");
#if defined(__WINDOWS__)
	fd = open((char*)argv[1], _O_BINARY | _O_RDONLY, _S_IREAD);
#else
	fd = open((char*)argv[1], O_RDONLY, S_IREAD);
#endif
	if (fd < 0) {
		console_log(MSGTYPE::ERR, "Fail to open file");
		exit(-1);
	}

	RsignalWrapper* rsignal_wrapper;
	rsignal_wrapper = new RsignalWrapper();
	rsignal_wrapper->set_notify_cb((void*)FullScanNotifyCallback);
	rsignal_wrapper->set_rsignal(rsig_addr);
	rsignal_wrapper->set_vdm_location(string(cur_dir) + "/engine");
	rsignal_wrapper->rsig_boot_engine();
	rsignal_wrapper->rsig_scan_stream(fd);

    console_log(MSGTYPE::INFO, "bye~!");
}
