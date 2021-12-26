#include <cassert>
#include "ntoskrnl.h"

uint16_t MockNTKrnl::major = 10;
uint16_t MockNTKrnl::minor = 0;
uint32_t MockNTKrnl::build_version = 19042;
uint64_t MockNTKrnl::handle_count = 0x0188;
uint64_t MockNTKrnl::engine_base = 0;
Json::Value MockNTKrnl::mock_reg;
uint32_t MockNTKrnl::page_alignment = 0x1000;


map<uint64_t, tuple<string, string, Json::Value>> MockNTKrnl::m_reg_handle;
map<uint64_t,
	tuple<
		size_t,
		size_t,
		size_t,
		map<
			uint64_t,
			size_t
		>
	>
> MockNTKrnl::m_heap_handle;
uint32_t MockNTKrnl::process_heap_handle;

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

	json_stream.open(this->mock_reg_path);
	if (!json_stream.is_open()) {
		assert(0);
	}
	auto bret = Json::parseFromStream(reader, json_stream, &_json, nullptr);
	if (bret == false) {
		assert(0);
	}
	this->mock_reg = _json;
}

uint64_t MockNTKrnl::CreateNewRegHandle(string hive, string key, Json::Value v) {
	if (!MockNTKrnl::mock_reg) {
		return 0xFFFFFFFF;
	}
	uint64_t hv = MockNTKrnl::handle_count += 4;
	MockNTKrnl::m_reg_handle[hv] = make_tuple(hive, key, v);

	return hv;
}

void MockNTKrnl::RemoveRegHandle(uint32_t hKey) {
	MockNTKrnl::m_reg_handle.erase(hKey);
}

#define INIT_SZ 0
#define MAX_SZ 1
#define CUR_SZ 2
#define HEAP_LIST 3 

uint64_t MockNTKrnl::CreateNewHeapHandle(size_t init_sz, size_t max_sz) {
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
	
	//uint64_t membase = (uint64_t)malloc(init_sz);
	uint64_t hv = MockNTKrnl::handle_count += 4;
	map<uint64_t, size_t> m;
	tuple<size_t, size_t, size_t, map<uint64_t, size_t>> new_t = {init_sz, max_sz, 0, m};
	MockNTKrnl::m_heap_handle[hv] = new_t;

	return hv;
}

void* MockNTKrnl::AllocHeapMemory(uint64_t heap_handle, bool zeroize, size_t mem_size) {
	tuple<size_t, size_t, size_t, map<uint64_t, size_t>> handle_info;
	handle_info = MockNTKrnl::m_heap_handle[heap_handle];
	size_t init_sz = std::get<INIT_SZ>(handle_info);
	size_t max_sz = std::get<MAX_SZ>(handle_info);
	size_t cur_sz = std::get<CUR_SZ>(handle_info);

	uint64_t mem_ptr;
	if (zeroize) {
		mem_ptr = (uint64_t)calloc(mem_size, 1);
	}
	else {
		mem_ptr = (uint64_t)malloc(mem_size);
	}

	if (max_sz != 0) {
		// fixed heap
		size_t after_heap_sz = cur_sz + mem_size;
		if (after_heap_sz > max_sz) {
			return NULL;
		}
	}
	else {
		// flexible heap
		std::get<CUR_SZ>(MockNTKrnl::m_heap_handle[heap_handle]) += mem_size;
		std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle])[mem_ptr] = mem_size;
	}

	return (void*)mem_ptr;
}

void* MockNTKrnl::ResizeHeap(uint64_t heap_handle, bool zeroize, void* heap_base, size_t mem_size) {
	uint64_t mem_ptr = (uint64_t)heap_base;
	size_t mem_sz = 0;

	if (std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle]).find(mem_ptr)
		== std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle]).end()) {
		return NULL; // undefined...
	}

	mem_sz = std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle])[mem_ptr];
	std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle]).erase(mem_ptr);

	mem_ptr = (uint64_t)realloc(heap_base, mem_size);

	if (zeroize)
		memset((void*)mem_ptr, 0, mem_size);

	size_t delta = mem_size - mem_sz;
	std::get<CUR_SZ>(MockNTKrnl::m_heap_handle[heap_handle]) += delta;
	std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle])[mem_ptr] = mem_size;

	return (void*)mem_ptr;
}

bool MockNTKrnl::FreeHeap(uint64_t heap_handle, void* heap_base) {
	tuple<size_t, size_t, size_t, map<uint64_t, size_t>> handle_info;
	handle_info = MockNTKrnl::m_heap_handle[heap_handle];

	uint64_t mem_ptr = (uint64_t)heap_base;
	size_t mem_sz = 0;
	if (std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle]).find(mem_ptr)
		== std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle]).end()) {
		return false;
	}
	mem_sz = std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle])[mem_ptr];
	std::get<CUR_SZ>(MockNTKrnl::m_heap_handle[heap_handle]) -= mem_sz;
	std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle]).erase(mem_ptr);
	free(heap_base);

	return true;
}

bool MockNTKrnl::DestroyHeap(uint64_t heap_handle) {
	void* heap_base = nullptr;
	for (const auto &m : std::get<HEAP_LIST>(MockNTKrnl::m_heap_handle[heap_handle])) {
		heap_base = (void*)m.first;
		free(heap_base);
	}

	MockNTKrnl::m_heap_handle.erase(heap_handle);

	return true;
}
