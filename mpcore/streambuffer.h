#if defined(__WINDOWS__)
#pragma once
#endif
#include "scanreply.h"

#ifndef __STREAMBUFFER_H
#define __STREAMBUFFER_H


enum {
	STREAM_ATTRIBUTE_INVALID = 0,
	STREAM_ATTRIBUTE_SKIPBMNOTIFICATION = 1,
	STREAM_ATTRIBUTE_BMDATA = 2,
	STREAM_ATTRIBUTE_FILECOPYPERFHINT = 3,
	STREAM_ATTRIBUTE_FILECOPYSOURCEPATH = 4,
	STREAM_ATTRIBUTE_FILECHANGEPERFHINT = 5,
	STREAM_ATTRIBUTE_FILEOPPROCESSID = 6,
	STREAM_ATTRIBUTE_FILEBACKUPWRITEPERFHINT = 7,
	STREAM_ATTRIBUTE_DONOTCACHESCANRESULT = 8,
	STREAM_ATTRIBUTE_SCANREASON = 9,
	STREAM_ATTRIBUTE_FILEID = 10,
	STREAM_ATTRIBUTE_FILEVOLUMESERIALNUMBER = 11,
	STREAM_ATTRIBUTE_FILEUSN = 12,
	STREAM_ATTRIBUTE_SCRIPTTYPE = 13,
	STREAM_ATTRIBUTE_PRIVATE = 14,
	STREAM_ATTRIBUTE_URL = 15,
	STREAM_ATTRIBUTE_REFERRALURL = 16,
	STREAM_ATTRIBUTE_SCRIPTID = 17,
	STREAM_ATTRIBUTE_HOSTAPPVERSION = 18,
	STREAM_ATTRIBUTE_THREAT_ID = 19,
	STREAM_ATTRIBUTE_THREAT_STATUS = 21,
	STREAM_ATTRIBUTE_LOFI = 22,
	STREAM_ATTRIBUTE_THREAT_RESOURCES = 25,
	STREAM_ATTRIBUTE_LOFI_RESOURCES = 26,
	STREAM_ATTRIBUTE_VOLATILE = 29,
	STREAM_ATTRIBUTE_REFERRERURL = 30,
	STREAM_ATTRIBUTE_REQUESTORMODE = 31,
	STREAM_ATTRIBUTE_CI_EA = 33,
	STREAM_ATTRIBUTE_CURRENT_FILEUSN = 34,
	STREAM_ATTRIBUTE_AVAILABLE_DSS_THREADS = 35,
	STREAM_ATTRIBUTE_IO_STATUS_BLOCK_FOR_NEW_FILE = 36,
	STREAM_ATTRIBUTE_DESIRED_ACCESS = 37,
	STREAM_ATTRIBUTE_FILEOPPROCESSNAME = 38,
	STREAM_ATTRIBUTE_DETAILED_SCAN_NEEDED = 39,
	STREAM_ATTRIBUTE_URL_HAS_GOOD_REPUTATION = 40,
	STREAM_ATTRIBUTE_SITE_HAS_GOOD_REPUTATION = 41,
	STREAM_ATTRIBUTE_URL_ZONE = 42,
	STREAM_ATTRIBUTE_CONTROL_GUID = 43,
	STREAM_ATTRIBUTE_CONTROL_VERSION = 44,
	STREAM_ATTRIBUTE_CONTROL_PATH = 45,
	STREAM_ATTRIBUTE_CONTROL_HTML = 46,
	STREAM_ATTRIBUTE_PAGE_CONTEXT = 47,
	STREAM_ATTRIBUTE_FRAME_URL = 48,
	STREAM_ATTRIBUTE_FRAME_HTML = 49,
	STREAM_ATTRIBUTE_ACTION_IE_BLOCK_PAGE = 50,
	STREAM_ATTRIBUTE_ACTION_IE_BLOCK_CONTROL = 51,
	STREAM_ATTRIBUTE_SHARE_ACCESS = 52,
	STREAM_ATTRIBUTE_OPEN_OPTIONS = 53,
	STREAM_ATTRIBUTE_DEVICE_CHARACTERISTICS = 54,
	STREAM_ATTRIBUTE_FILE_ATTRIBUTES = 55,
	STREAM_ATTRIBUTE_HAS_MOTW_ADS = 56,
	STREAM_ATTRIBUTE_SE_SIGNING_LEVEL = 57,
	STREAM_ATTRIBUTE_SESSION_ID = 58,
	STREAM_ATTRIBUTE_AMSI_APP_ID = 59,
	STREAM_ATTRIBUTE_AMSI_SESSION_ID = 60,
	STREAM_ATTRIBUTE_FILE_OPERATION_PPID = 61,
	STREAM_ATTRIBUTE_SECTOR_NUMBER = 62,
	STREAM_ATTRIBUTE_AMSI_CONTENT_NAME = 63,
	STREAM_ATTRIBUTE_AMSI_UAC_REQUEST_CONTEXT = 64,
	STREAM_ATTRIBUTE_RESOURCE_CONTEXT = 65,
	STREAM_ATTRIBUTE_OPEN_CREATEPROCESS_HINT = 66,
	STREAM_ATTRIBUTE_GENSTREAM_APP_NAME = 67,
	STREAM_ATTRIBUTE_GENSTREAM_SESSION_ID = 68,
	STREAM_ATTRIBUTE_GENSTREAM_CONTENT_NAME = 69,
	STREAM_ATTRIBUTE_OPEN_ACCESS_STATE_FLAGS = 70,
	STREAM_ATTRIBUTE_GENSTREAM_EXTERN_GUID = 71,
	STREAM_ATTRIBUTE_IS_CONTAINER_FILE = 72,
	STREAM_ATTRIBUTE_AMSI_REDIRECT_CHAIN = 75,
};

enum {
	SCANREASON_UNKNOWN = 0,
	SCANREASON_ONMOUNT = 1,
	SCANREASON_ONOPEN = 2,
	SCANREASON_ONFIRSTREAD = 3,
	SCANREASON_ONWRITE = 4,
	SCANREASON_ONMODIFIEDHANDLECLOSE = 5,
	SCANREASON_INMEMORY = 8,
	SCANREASON_VALIDATION_PRESCAN = 9,
	SCANREASON_VALIDATION_CONTENTSCAN = 0x0A,
	SCANREASON_ONVOLUMECLEANUP = 0x0B,
	SCANREASON_AMSI = 0x0C,
	SCANREASON_AMSI_UAC = 0x0D,
	SCANREASON_GENERICSTREAM = 0x0E,
	SCANREASON_IOAVSTREAM = 0x0F,
};

#ifdef _X86
typedef struct _USERDEFINED_STREAMBUFFER_DESCRIPTOR { // size of StreamBufferDescriptor is 0x80
	uint32_t  UserPtr;
	uint32_t(*Read)(uint32_t fd, unsigned long long Offset, void* Buffer, uint32_t Size, uint32_t* SizeRead);
	uint32_t(*Write)(uint32_t fd, uint32_t Offset, void* Buffer, uint32_t Size, uint32_t* TotalWritten);
	uint32_t(*GetSize)(uint32_t fd, uint32_t *FileSize);
	uint32_t(*SetSize)(uint32_t fd, uint32_t *FileSize);
	const WCHAR*(*GetName)(void* streambuffer_disc);
	uint32_t(*SetAttributes)(uint32_t fd, uint32_t Attribute, void* Data, uint32_t DataSize);
	uint32_t(*GetAttributes)(uint32_t fd, uint32_t Attribute, void* Data, uint32_t DataSize, uint32_t* DataSizeWritten);
} StreamBufferDescriptor, *PStreamBufferDescriptor;
#elif _X64
typedef struct _USERDEFINED_STREAMBUFFER_DESCRIPTOR { // size of StreamBufferDescriptor is 0x80
	uint64_t  UserPtr;
	uint64_t(*Read)(uint64_t fd, uint64_t Offset, void* Buffer, uint64_t Size, uint64_t* SizeRead);
	uint64_t(*Write)(uint64_t fd, uint64_t Offset, void* Buffer, uint64_t Size, uint64_t* TotalWritten);
	uint64_t(*GetSize)(uint64_t fd, uint64_t *FileSize);
	uint64_t(*SetSize)(uint64_t fd, uint64_t *FileSize);
	const WCHAR*(*GetName)(void* streambuffer_disc);
	uint64_t(*SetAttributes)(uint64_t fd, uint64_t Attribute, void* Data, uint64_t DataSize);
	uint64_t(*GetAttributes)(uint64_t fd, uint64_t Attribute, void* Data, uint64_t DataSize, uint64_t* DataSizeWritten);
} StreamBufferDescriptor, *PStreamBufferDescriptor;
#endif // _X86

#ifdef _X86
typedef struct _StreamBufferScanData {
	PStreamBufferDescriptor Descriptor;
	PCCftScanState ScanState;
	uint32_t UnknownB;
	void* UfsClientRequest; // New Created durring running
} StreamBufferScanData, *PStreamBufferScanData;
#elif _X64
typedef struct _StreamBufferScanData {
	PStreamBufferDescriptor    Descriptor;
	PCCftScanState              ScanState;
	uint64_t                       UnknownB;
	void*                       UfsClientRequest; // New Created durring running
} StreamBufferScanData, *PStreamBufferScanData;
#endif // _X86

#ifdef _X86
typedef struct _STREAMBUFFER_DESCRIPTOR_INTERNAL {
	void* vftable;
	uint32_t RESERVED;
	uint32_t(*VfzReadDefaultCb)();
	uint32_t(*VfzWriteDefaultCb)();
	uint32_t(*VfzGetSizeDefaultCb)();
	uint32_t(*VfzSetSizeDefaultCb)();
	PStreamBufferDescriptor* streambuffer_disc;
	void* ReadStream;
	void* WriteStream;
	void* GetSize;
	void* SetSize;
	void* GetName;
	void* SetAttributes;
	void* GetAttributes;
	uint32_t Reserved1;
	uint32_t Unknown1;
	uint32_t Reserved2;
	uint32_t Reserved3;
	uint32_t Unknown2;
	uint32_t Unknown3;
	uint32_t Unknown4;
	uint32_t Unknown5;
	uint32_t Reserved4;
	uint32_t Reserved5;
	uint32_t Reserved6;
	uint32_t Reserved7;
	uint32_t Reserved8;
	uint32_t Unknown6;
	uint32_t Unknown7;
	uint32_t Unknown8;
	uint32_t Unknown9;
	uint32_t Unknown10;
	uint32_t Unknown11;
	uint32_t Unknown12;
	uint32_t Unknown13;
	uint32_t Unknown14;
	uint32_t Reserved9;
};
#elif _X64
typedef struct _STREAMBUFFER_DESCRIPTOR_INTERNAL {
	void* vftable;
	uint64_t RESERVED;
	uint64_t(*VfzReadDefaultCb)();
	uint64_t(*VfzWriteDefaultCb)();
	uint64_t(*VfzGetSizeDefaultCb)();
	uint64_t(*VfzSetSizeDefaultCb)();
	PStreamBufferDescriptor* streambuffer_disc;
	void* ReadStream;
	void* WriteStream;
	void* GetSize;
	void* SetSize;
	void* GetName;
	void* SetAttributes;
	void* GetAttributes;
	uint64_t Reserved1;
	uint64_t Unknown1;
	uint64_t Reserved2;
	uint64_t Reserved3;
	uint64_t Unknown2;
	uint64_t Unknown3;
	uint64_t Unknown4;
	uint64_t Unknown5;
	uint64_t Reserved4;
	uint64_t Reserved5;
	uint64_t Reserved6;
	uint64_t Reserved7;
	uint64_t Reserved8;
	uint64_t Unknown6;
	uint64_t Unknown7;
	uint64_t Unknown8;
	uint64_t Unknown9;
	uint64_t Unknown10;
	uint64_t Unknown11;
	uint64_t Unknown12;
	uint64_t Unknown13;
	uint64_t Unknown14;
	uint64_t Reserved9;
}STREAMBUFFER_DESCRIPTOR_INTERNAL;
#endif

#pragma pack(pop)
#endif // __STREAMBUFFER_H
