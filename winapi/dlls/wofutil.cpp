#include "wofutil.h"

bool __stdcall MockWofUtil::WofShouldCompressBinaries(WCHAR* Volume, uint32_t* Algorithm) {
	return false;
}
