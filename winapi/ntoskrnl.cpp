#include <cassert>
#include "ntoskrnl.h"

unsigned short MockNTKrnl::major = 10;
unsigned short MockNTKrnl::minor = 0;
unsigned int MockNTKrnl::build_version = 19042;
int MockNTKrnl::errcode = 0;
unsigned int MockNTKrnl::handle_count = 0x0188;
Json::Value MockNTKrnl::mock_reg;

map<unsigned int, tuple<string, string, Json::Value>> MockNTKrnl::m_reg_handle;
std::map<std::string, string> MockNTKrnl::m_env_variable = {
	{"AllUsersProfile", "C:\\ProgramData"},
	{"APPDATA", "C:\\Users\\orca\\AppData\\Roaming"},
	{"LocalAppData", "C:\\Users\\dlfgu\\AppData\\Local"},
	{"SYSTEMROOT", "C:\\Windows"},
	{"TEMP", ".\\TEMP"},
	{"UserProfile", "C:\\Users\\orca"},
	{"windir", "C:\\Windows"},
	{"CommonProgramFiles", "C:\\Program Files\\Common Files"},
	{"ProgramFiles", "C:\\Program Files"},
	{"ProgramFiles(x86)", "C:\\Program Files (x86)"},
	{"Public", "C:\\Users\\Public"},
	{"SYSTEMDRIVE", "C:"},
};

void MockNTKrnl::parse_mock_reg_info() {
	Json::Value _json;
	Json::CharReaderBuilder reader;
	ifstream json_stream;

	json_stream.open(this->mock_reg_path, ifstream::binary);
	if (!json_stream.is_open()) {
		assert(0);
	}
	auto bret = Json::parseFromStream(reader, json_stream, &_json, nullptr);
	if (bret == false) {
		assert(0);
	}
	this->mock_reg = _json;
}

unsigned int MockNTKrnl::CreateNewRegHandle(string hive, string key, Json::Value v) {
	if (!MockNTKrnl::mock_reg) {
		return 0xFFFFFFFF;
	}
	unsigned int hv = MockNTKrnl::handle_count += 4;
	MockNTKrnl::m_reg_handle[hv] = make_tuple(hive, key, v);

	return hv;
}

void MockNTKrnl::RemoveRegHandle(unsigned int hKey) {
	MockNTKrnl::m_reg_handle.erase(hKey);
}