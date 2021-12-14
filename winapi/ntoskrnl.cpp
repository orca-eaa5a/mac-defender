#include <cassert>
#include "ntoskrnl.h"

unsigned short MockNTKrnl::major = 10;
unsigned short MockNTKrnl::minor = 0;
unsigned int MockNTKrnl::build_version = 19042;
int MockNTKrnl::errcode = 0;
unsigned int MockNTKrnl::handle_count = 0x0188;
Json::Value MockNTKrnl::mock_reg;

map<unsigned int, tuple<string, string, Json::Value>> MockNTKrnl::m_reg_handle;
map<unsigned int,
	tuple<
		unsigned int,
		unsigned int,
		unsigned int,
		vector<
			tuple<
				unsigned long long,
				unsigned int
			>
		>
	>
> MockNTKrnl::m_heap_handle;
unsigned int MockNTKrnl::process_heap_handle;

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

#define INIT_SZ 0
#define MAX_SZ 1
#define CUR_SZ 2
#define HEAP_LIST 3 

unsigned int MockNTKrnl::CreateNewHeapHandle(size_t init_sz, size_t max_sz) {
	/*
	"handle":{
		"init_sz": ??,
		"max_sz": ??,
		"cur_sz"
		[("base_addr", "size"), ... ("base_addr", "size")]
	}
	if max_sz != 0
		heap is not fixed
	*/
	
	unsigned long long membase = (unsigned long long)malloc(init_sz);
	unsigned int hv = MockNTKrnl::handle_count += 4;
	vector<tuple<unsigned long long, unsigned int>> v;
	v.push_back({ membase, init_sz });
	MockNTKrnl::m_heap_handle[hv] = {init_sz, max_sz, 0, v};

	return hv;
}

void* MockNTKrnl::AllocHeapMemory(unsigned int heap_handle, bool zeroize, size_t mem_size) {
	tuple<unsigned int, unsigned int, unsigned int, vector<tuple<unsigned long long, unsigned int>>> handle_info;
	handle_info = MockNTKrnl::m_heap_handle[heap_handle];
	unsigned int init_sz = std::get<INIT_SZ>(handle_info);
	unsigned int max_sz = std::get<MAX_SZ>(handle_info);
	unsigned int cur_sz = std::get<CUR_SZ>(handle_info);

	unsigned long long mem_ptr;
	if (zeroize) {
		mem_ptr = (unsigned long long)calloc(mem_size, 1);
	}
	else {
		mem_ptr = (unsigned long long)malloc(mem_size);
	}

	if (max_sz != 0) {
		// fixed heap
		unsigned int after_heap_sz = cur_sz + mem_size;
		if (after_heap_sz > max_sz) {
			return NULL;
		}
	}
	else {
		// flexible heap
		std::get<CUR_SZ>(MockNTKrnl::m_heap_handle[heap_handle]) += mem_size;
		std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle]).push_back({ mem_ptr, mem_size });
	}

	return (void*)mem_ptr;
}

void* MockNTKrnl::ResizeHeap(unsigned int heap_handle, bool zeroize, void* heap_base, size_t mem_size) {
	tuple<unsigned int, unsigned int, unsigned int, vector<tuple<unsigned long long, unsigned int>>> handle_info;
	handle_info = MockNTKrnl::m_heap_handle[heap_handle];

	auto beg = std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle]).begin();
	unsigned int idx = 0;
	unsigned long long mem_ptr = 0;
	unsigned int mem_sz;
	for (auto m : std::get<HEAP_LIST>(handle_info)) {
		tie(mem_ptr, mem_sz) = m;
		if ((void*)mem_ptr == heap_base) {
			break;
		}
		idx++;
	}
	if ((void*)mem_ptr != heap_base) {
		return NULL;
	}

	mem_ptr = (unsigned long long)realloc((void*)mem_ptr, mem_size);
	if (zeroize)
		memset((void*)mem_ptr, 0, mem_size);
	int delta = mem_size - mem_sz;
	std::get<CUR_SZ>(MockNTKrnl::m_heap_handle[heap_handle]) += delta;
	std::get<0>(std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle])[idx]) = mem_ptr;
	std::get<1>(std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle])[idx]) = mem_size;

	return (void*)mem_ptr;
}

bool MockNTKrnl::FreeHeap(unsigned int heap_handle, void* heap_base) {
	tuple<unsigned int, unsigned int, unsigned int, vector<tuple<unsigned long long, unsigned int>>> handle_info;
	handle_info = MockNTKrnl::m_heap_handle[heap_handle];

	auto beg = std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle]).begin();
	unsigned int idx = 0;
	unsigned long long mem_ptr = 0;
	unsigned int mem_sz;
	for (auto m : std::get<HEAP_LIST>(handle_info)) {
		tie(mem_ptr, mem_sz) = m;
		if ((void*)mem_ptr == heap_base) {
			break;
		}
		idx++;
	}
	if ((void*)mem_ptr != heap_base) {
		return false;
	}
	free(heap_base);
	std::get<CUR_SZ>(MockNTKrnl::m_heap_handle[heap_handle]) -= mem_sz;
	std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle]).erase(beg + idx);

	return true;
}

bool MockNTKrnl::DestroyHeap(unsigned int heap_handle) {
	tuple<unsigned int, unsigned int, unsigned int, vector<tuple<unsigned long long, unsigned int>>> handle_info;
	handle_info = MockNTKrnl::m_heap_handle[heap_handle];

	unsigned long long mem_ptr = 0;
	unsigned int mem_sz;
	for (auto m : std::get<HEAP_LIST>(handle_info)) {
		tie(mem_ptr, mem_sz) = m;
		free((void*)mem_ptr);
	}

	MockNTKrnl::m_heap_handle.erase(heap_handle);

	return true;
}