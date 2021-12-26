#include "wofutil.h"

bool __stdcall MockWofUtil::WofShouldCompressBinaries(wchar_t* Volume, uint32_t* Algorithm) {
	return false;
}
