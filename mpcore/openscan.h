#if defined(__WINDOWS__)
#pragma once
#endif
#ifndef __OPENSCAN_H
#define __OPENSCAN_H


#if defined(__WINDOWS__)
#include <guiddef.h>
#else
typedef struct _GUID {
  uint32_t  Data1;
  uint16_t Data2;
  uint16_t Data3;
  uint8_t  Data4[8];
} GUID;
#endif


#define OPENSCAN_VERSION 0x2C6D


enum {
	SCANSOURCE_NOTASOURCE = 0,
	SCANSOURCE_SCHEDULED = 1,
	SCANSOURCE_ONDEMAND = 2,
	SCANSOURCE_RTP = 3,
	SCANSOURCE_IOAV_WEB = 4,
	SCANSOURCE_IOAV_FILE = 5,
	SCANSOURCE_CLEAN = 6,
	SCANSOURCE_UCL = 7,
	SCANSOURCE_RTSIG = 8,
	SCANSOURCE_SPYNETREQUEST = 9,
	SCANSOURCE_INFECTIONRESCAN = 0x0A,
	SCANSOURCE_CACHE = 0x0B,
	SCANSOURCE_UNK_TELEMETRY = 0x0C,
	SCANSOURCE_IEPROTECT = 0x0D,
	SCANSOURCE_ELAM = 0x0E,
	SCANSOURCE_LOCAL_ATTESTATION = 0x0F,
	SCANSOURCE_REMOTE_ATTESTATION = 0x10,
	SCANSOURCE_HEARTBEAT = 0x11,
	SCANSOURCE_MAINTENANCE = 0x12,
	SCANSOURCE_MPUT = 0x13,
	SCANSOURCE_AMSI = 0x14,
	SCANSOURCE_STARTUP = 0x15,
	SCANSOURCE_ADDITIONAL_ACTIONS = 0x16,
	SCANSOURCE_AMSI_UAC = 0x17,
	SCANSOURCE_GENSTREAM = 0x18,
	SCANSOURCE_REPORTLOWFI = 0x19,
	SCANSOURCE_REPORTINTERNALDETECTION = 0x19,
	SCANSOURCE_SENSE = 0x1A,
	SCANSOURCE_XBAC = 0x1B,
};
#ifdef _X86
typedef struct _OPENSCAN_PARAMS {
	uint32_t   Version;
	uint32_t   ScanSource;
	uint32_t   Flags;
	uint32_t   field_C;
	uint32_t   field_10;
	uint32_t   field_14;
	uint32_t   field_18;
	uint32_t   field_1C;
	GUID    ScanID;
	uint32_t   field_30;
	uint32_t   field_34;
	uint32_t   field_38;
	uint32_t   field_3C;
	uint32_t   field_40;
	uint32_t   field_44;
} OPENSCAN_PARAMS, *POPENSCAN_PARAMS;
#elif _X64
typedef struct _OPENSCAN_PARAMS {
	uint64_t   Version;
	uint64_t   ScanSource;
	uint64_t   Flags;
	uint64_t   field_C;
	uint64_t   field_10;
	uint64_t   field_14;
	uint64_t   field_18;
	uint64_t   field_1C;
	GUID    ScanID;
	uint64_t   field_30;
	uint64_t   field_34;
	uint64_t   field_38;
	uint64_t   field_3C;
	uint64_t   field_40;
	uint64_t   field_44;
} OPENSCAN_PARAMS, *POPENSCAN_PARAMS;
#endif

#pragma pack(pop)
#endif // __OPENSCAN_H
