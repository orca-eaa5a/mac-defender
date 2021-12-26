
#ifndef _NTOSKRNL_H_
#define _NTOSKRNL_H_
#include <map>
#include <tuple>
#include <string>
#include <fstream>
#include "../include/jsoncpp/json/json.h"
#include "strutils.hpp"
using namespace std;

class MockNTKrnl {
public:
	static uint16_t major;
	static uint16_t minor;
	static uint32_t build_version;
	static uint64_t engine_base;
	//static int errcode;
	static map<std::string, string> m_env_variable;
	static map<uint64_t, tuple<string, string, Json::Value>> m_reg_handle; //hKey is void*
	static map<uint64_t,
				tuple<
					size_t,
					size_t,
					size_t,
					map<
						uint64_t,
						size_t
					>
				> 
			>m_heap_handle;
	static uint32_t process_heap_handle;
	static Json::Value mock_reg;
	static uint64_t handle_count;
	static uint32_t page_alignment;

#ifdef _WIN64
	string mock_reg_path = ".\\reg\\mock_reg.json";
#else
	string mock_reg_path = "./reg/mock_reg.json";
#endif // _WIN64
	MockNTKrnl() {
		this->parse_mock_reg_info();
	}
#if defined(__WINDOWS__)
	static uint64_t MockNTKrnl::CreateNewRegHandle(string hive, string key, Json::Value v);
	static void MockNTKrnl::RemoveRegHandle(uint32_t hKey);
	static uint64_t MockNTKrnl::CreateNewHeapHandle(size_t init_sz, size_t max_sz);
	static void* MockNTKrnl::AllocHeapMemory(uint64_t heap_handle, bool zeroize, size_t mem_size);
	static void* MockNTKrnl::ResizeHeap(uint64_t heap_handle, bool zeroize, void* heap_base, size_t mem_size);
	static bool MockNTKrnl::FreeHeap(uint64_t heap_handle, void* heap_base);
	static bool MockNTKrnl::DestroyHeap(uint64_t heap_handle);
#else
	static uint64_t CreateNewRegHandle(string hive, string key, Json::Value v);
	static void RemoveRegHandle(uint32_t hKey);
	static uint64_t CreateNewHeapHandle(size_t init_sz, size_t max_sz);
	static void* AllocHeapMemory(uint64_t heap_handle, bool zeroize, size_t mem_size);
	static void* ResizeHeap(uint64_t heap_handle, bool zeroize, void* heap_base, size_t mem_size);
	static bool FreeHeap(uint64_t heap_handle, void* heap_base);
	static bool DestroyHeap(uint64_t heap_handle);
#endif

private:
#if defined(__WINDOWS__)
	void MockNTKrnl::parse_mock_reg_info();
#else
	void parse_mock_reg_info();
#endif
	
};
#endif // !_NTOSKRNL_H_

