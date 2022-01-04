#include "wofutil.h"

bool __stdcall MockWofUtil::WofShouldCompressBinaries(char16_t* Volume, uint32_t* Algorithm) {
	return false;
}
