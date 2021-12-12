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

private:
	void MockNTKrnl::parse_mock_reg_info();
	
};
#endif // !_NTOSKRNL_H_

