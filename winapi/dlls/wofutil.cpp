#include "wofutil.h"

void* __stdcall MockWofUtil::WofShouldCompressBinaries(wchar_t* Volume, unsigned long* Algorithm) {
	return false;
}