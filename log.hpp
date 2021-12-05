#pragma once
#ifndef _LOG_H_
#include <cassert>
#include <stdio.h>

enum MSGTYPE {
	INFO = 1,
	ERR,
	CRIT,
};
auto console_log = [](MSGTYPE msg_type, const char* msg) {

	switch (msg_type)
	{
	case INFO:
		printf("[%s]  %s\n", "INFO", msg);
		break;
	case ERR:
		printf("[%s]  %s", "ERROR", msg);
		assert(0);
		break;
	case CRIT:
		printf("[%s]  %s\n", "CRIT", msg);
		exit(-1);
	default:
		printf("Unknown Message Type\n");
		exit(-1);
	}
};
#endif