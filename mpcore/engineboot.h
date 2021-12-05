#ifndef __ENGINEBOOT_H
#define __ENGINEBOOT_H
#pragma once
#pragma pack(push, 1)
#include <cstdint>
#ifdef _X86
#define BOOTENGINE_PARAMS_VERSION 0x8E00
#elif _X64
#define BOOTENGINE_PARAMS_VERSION 0x8B00
#endif // _X86


enum {
	BOOT_CACHEENABLED = 1 << 0,
	BOOT_NOFILECHANGES = 1 << 3,
	BOOT_ENABLECALLISTO = 1 << 6,
	BOOT_REALTIMESIGS = 1 << 8,
	BOOT_DISABLENOTIFICATION = 1 << 9,
	BOOT_CLOUDBHEAVIORBLOCK = 1 << 10,
	BOOT_ENABLELOGGING = 1 << 12,
	BOOT_ENABLEBETA = 1 << 16,
	BOOT_ENABLEIEV = 1 << 17,
	BOOT_ENABLEMANAGED = 1 << 19,
};

enum {
	BOOT_ATTR_NORMAL = 1 << 0,
	BOOT_ATTR_ISXBAC = 1 << 2,
};

enum {
	ENGINE_UNPACK = 1 << 1,  // 2
	ENGINE_HEURISTICS = 1 << 3,  // 8
	ENGINE_DISABLETHROTTLING = 1 << 11, // 0x800
	ENGINE_PARANOID = 1 << 12, // 0x1000
	ENGINE_DISABLEANTISPYWARE = 1 << 15, // if this flag set, mpengine will not load mpasbase.vdm
	ENGINE_DISABLEANTIVIRUS = 1 << 16, // if this flag set, mpengine will not load mpavbase.vdm
	ENGINE_DISABLENETWORKDRIVES = 1 << 20,
};

typedef struct _ENGINE_INFO {
	unsigned int field_0;
	unsigned int field_4;    // Possibly Signature UNIX time?
	unsigned int field_8;
	unsigned int field_C;
} ENGINE_INFO, *PENGINE_INFO;

typedef struct _ENGINE_CONFIG {
	unsigned int EngineFlags;
	wchar_t* Inclusions;      // Example, "*.zip"
	void* Exceptions;
	wchar_t* UnknownString2;
	wchar_t* QuarantineLocation;
	unsigned int field_14;
	unsigned int field_18;
	unsigned int TempPath;
	unsigned int OfflinePath;
	unsigned int field_24;
	unsigned int field_28;
	unsigned int field_2C;         // Setting this seems to cause packer to be reported.
	unsigned int field_30;
	unsigned int field_34;
	char* UnknownAnsiString1;
	char* UnknownAnsiString2;
} ENGINE_CONFIG, *PENGINE_CONFIG;

typedef struct _ENGINE_CONTEXT {
	unsigned int   field_0;
} ENGINE_CONTEXT, *PENGINE_CONTEXT;

#ifdef _X86
typedef struct _BOOTENGINE_PARAMS {
	/*0x0*/     uint32_t           ClientVersion;
	/*0x4*/     wchar_t*          SignatureLocation;
	/*0x8*/     void*           SpynetSource; // maybe 16byte structure & not important
	/*0xC*/     PENGINE_CONFIG  EngineConfig;
	/*0x10*/    PENGINE_INFO    EngineInfo;
	/*0x14*/    wchar_t*          ScanReportLocation;
	/*0x18*/    uint32_t           BootFlags;
	/*0x1C*/    wchar_t*          LocalCopyDirectory;
	/*0x20*/    wchar_t*          OfflineTargetOS;
	/*0x24*/    char            ProductString[16]; // not important
	/*0x34*/    uint32_t           field_34;
	/*0x38*/    void*           GlobalCallback;
	/*0x3C*/    PENGINE_CONTEXT EngineContext;
	/*0x40*/    uint32_t           AvgCpuLoadFactor;
	/*0x44*/    char            field_44[16]; // maybe product string 2
	/*0x54*/    wchar_t*          SpynetReportingGUID;
	/*0x58*/    wchar_t*          SpynetVersion;
	/*0x5C*/    wchar_t*          NISEngineVersion;
	/*0x60*/    wchar_t*          NISSignatureVersion;
	/*0x64*/    uint32_t           FlightingEnabled;
	/*0x68*/    uint32_t           FlightingLevel;
	/*0x6C*/    void*           DynamicConfig; // 20byte structure
	/*0x70*/    uint32_t           AutoSampleSubmission;
	/*0x74*/    uint32_t           EnableThreatLogging;
	/*0x78*/    wchar_t*          ProductName;
	/*0x7C*/    uint32_t           PassiveMode;
	/*0x80*/    uint32_t           SenseEnabled;
	/*0x84*/    wchar_t*          SenseOrgId;
	/*0x88*/    uint32_t           Attributes;
	/*0x8C*/    uint32_t           BlockAtFirstSeen;
	/*0x90*/    uint32_t           PUAProtection;
	/*0x94*/    uint32_t           SideBySidePassiveMode;
} BOOTENGINE_PARAMS, *PBOOTENGINE_PARAMS;

#elif _X64
typedef struct _BOOTENGINE_PARAMS {
	/*0x0*/     uint64_t           ClientVersion;
	/*0x4*/     wchar_t*          SignatureLocation;
	/*0xC*/     void*           SpynetSource; // maybe 16byte structure & not important
	/*0x14*/    PENGINE_CONFIG  EngineConfig;
	/*0x1C*/    PENGINE_INFO    EngineInfo;
	/*0x24*/    wchar_t*          ScanReportLocation;
	/*0x2C*/    unsigned int           BootFlags;
	/*0x30*/    wchar_t*          LocalCopyDirectory;
	/*0x38*/    wchar_t*          OfflineTargetOS;
	/*0x40*/    char            ProductString[16]; // not important
	/*0x50*/    unsigned int           field_34;
	/*0x64*/    void*           GlobalCallback;
	/*0x6C*/    PENGINE_CONTEXT EngineContext;
	/*0x74*/    unsigned int           AvgCpuLoadFactor;
	/*0x78*/    char            field_44[16]; // maybe product string 2
	/*0x88*/    wchar_t*          SpynetReportingGUID;
	/*0x90*/    wchar_t*          SpynetVersion;
	/*0x98*/    wchar_t*          NISEngineVersion;
	/*0x100*/    wchar_t*          NISSignatureVersion;
	/*0x108*/    unsigned int           FlightingEnabled;
	/*0x10C*/    unsigned int           FlightingLevel;
	/*0x110*/    void*           DynamicConfig; // 20byte structure
	/*0x118*/    unsigned int           AutoSampleSubmission;
	/*0x11C*/    unsigned int           EnableThreatLogging;
	/*0x120*/    wchar_t*          ProductName;
	/*0x128*/    unsigned int           PassiveMode;
	/*0x12C*/    unsigned int           SenseEnabled;
	/*0x130*/    wchar_t*          SenseOrgId;
	/*0x138*/    unsigned int           Attributes;
	/*0x13C*/    unsigned int           BlockAtFirstSeen;
	/*0x140*/    unsigned int           PUAProtection;
	/*0x14C*/    unsigned int           SideBySidePassiveMode;
} BOOTENGINE_PARAMS, *PBOOTENGINE_PARAMS;
#endif

#pragma pack(pop)
#endif // __ENGINEBOOT_H
