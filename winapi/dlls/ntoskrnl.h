#pragma once
#ifndef _NTOSKRNL_H_
#define _NTOSKRNL_H_
#include <windows.h>
#include <map>

using namespace std;

class MockNTKrnl {
public:
	static unsigned short major;
	static unsigned short minor;
	static unsigned int build_version;
	static int errcode;
	static std::map<std::string, string> m_env_variable;
};
#endif // !_NTOSKRNL_H_

