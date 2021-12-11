#include "ntoskrnl.h"
unsigned short MockNTKrnl::major = 10;
unsigned short MockNTKrnl::minor = 0;
unsigned int MockNTKrnl::build_version = 19042;
int MockNTKrnl::errcode = 0;
std::map<std::string, string> MockNTKrnl::m_env_variable = {
	{"AllUsersProfile", "C:\\ProgramData"},
	{"APPDATA", "C:\\Users\\orca\\AppData\\Roaming"},
	{"LocalAppData", "C:\\Users\\dlfgu\\AppData\\Local"},
	{"SYSTEMROOT", "C:\\Windows"},
	{"TEMP", ".\\TEMP"},
	{"UserProfile", "C:\\Users\orca"},
	{"windir", "C:\\Windows"},
	{"CommonProgramFiles", "C:\\Program Files\\Common Files"},
	{"ProgramFiles", "C:\\Program Files"},
	{"ProgramFiles(x86)", "C:\\Program Files (x86)"},
	{"Public", "C:\\Users\\Public"},
	{"SYSTEMDRIVE", "C:"},
};
