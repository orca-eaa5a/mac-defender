#pragma once
#ifndef _NTOSKRNL_H_
#define _NTOSKRNL_H_
#include <windows.h>
#include <map>
#include <tuple>
#include <string>
#include <fstream>
#include "../include/jsoncpp/json/json.h"
#include "strutils.hpp"
using namespace std;

class MockNTKrnl {
public:
	static unsigned short major;
	static unsigned short minor;
	static unsigned int build_version;
	static int errcode;
	static map<std::string, string> m_env_variable;
	static map<unsigned int, tuple<string, string, Json::Value>> m_reg_handle;
	static map<unsigned int,
				tuple<
					unsigned int,
					unsigned int,
					unsigned int,
					map<
						unsigned long long,
						unsigned int
					>
				> 
			>m_heap_handle;
	static unsigned int process_heap_handle;
	static Json::Value mock_reg;
	static unsigned int handle_count;

#ifdef _WIN64
	string mock_reg_path = ".\\reg\\mock_reg.json";
#else
	string mock_reg_path = "./reg/mock_reg.json";
#endif // _WIN64
	MockNTKrnl() {
		this->parse_mock_reg_info();
	}
	static unsigned int MockNTKrnl::CreateNewRegHandle(string hive, string key, Json::Value v);
	static void MockNTKrnl::RemoveRegHandle(unsigned int hKey);
	static unsigned int MockNTKrnl::CreateNewHeapHandle(size_t init_sz, size_t max_sz);
	static void* MockNTKrnl::AllocHeapMemory(unsigned int heap_handle, bool zeroize, size_t mem_size);
	static void* MockNTKrnl::ResizeHeap(unsigned int heap_handle, bool zeroize, void* heap_base, size_t mem_size);
	static bool MockNTKrnl::FreeHeap(unsigned int heap_handle, void* heap_base);
	static bool MockNTKrnl::DestroyHeap(unsigned int heap_handle);

private:
	void MockNTKrnl::parse_mock_reg_info();
	
};
#endif // !_NTOSKRNL_H_

