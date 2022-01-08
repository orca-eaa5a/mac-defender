#include "wofutil.h"

bool __stdcall MockWofUtil::WofShouldCompressBinaries(char16_t* Volume, uint32_t* Algorithm) {
	debug_log("<wofutil.dll!%s> called..\n", "WofShouldCompressBinaries");

	return false;
}
