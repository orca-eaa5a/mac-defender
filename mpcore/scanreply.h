#pragma once

#ifndef __SCANREPLY_H
#define __SCANREPLY_H
#include <cstdint>
#include "engineboot.h"

#pragma pack(push, 1)

// These are just guesses based on observed behaviour.
enum {
	SCAN_ENCRYPTED = 1 << 6,
	SCAN_MEMBERNAME = 1 << 7,
	SCAN_FILENAME = 1 << 8,
	SCAN_FILETYPE = 1 << 9,
	SCAN_PACKEREND = 1 << 12,
	SCAN_CORRUPT = 1 << 13,
	SCAN_UNKNOWN = 1 << 15, // I dunno what this means
	SCAN_ISARCHIVE = 1 << 16,
	SCAN_TOPLEVEL = 1 << 18,
	SCAN_PACKERSTART = 1 << 19,
	SCAN_NORESULT = 1 << 20,
	SCAN_VIRUSFOUND = 1 << 27,
};

#ifdef _X86

typedef struct _SCAN_REPLY { // very very important structure!!
	/*0x0*/    uint32_t field_0; // 0xB6B7B8B9
	/*0x4*/    uint32_t Flags;
	/*0x8*/    char* FileName;
	/*0xC*/    char  VirusName[28];
	/*0x28*/    uint32_t field_28;
	/*0x2C*/    uint32_t field_2C;
	/*0x30*/    uint32_t field_30;
	/*0x34*/    uint32_t field_34;
	/*0x38*/    uint32_t field_38;
	/*0x3C*/    uint32_t field_3C;
	/*0x40*/    uint32_t field_40;
	/*0x44*/    uint32_t field_44; // this was originally reserved field
	/*0x48*/    uint32_t field_48;
	/*0x4C*/    uint32_t field_4C;
	/*0x50*/    uint32_t FileSize;
	/*0x54*/    uint32_t field_54; // if this fild is not 0, pefile_scan_mp is not working
	/*0x58*/    uint32_t UserPtr;
	/*0x5C*/    uint32_t field_5C;
	/*0x60*/    char* MaybeFileName2;
	/*0x64*/    wchar_t* StreamName1;
	/*0x68*/    wchar_t* StreamName2;
	/*0x6C*/    uint32_t field_6C;
	/*0x70*/    uint32_t ThreatId;             // Can be passed back to GetThreatInfo
	/*0x74*/    uint32_t Reserved1;
	/*0x78*/    uint32_t Reserved2;
	/*0x7C*/    uint32_t Reserved3;
	/*0x80*/    uint32_t Reserved4;
	/*0x84*/    uint32_t Reserved5;
	/*0x88*/    uint32_t NullSHA1[5];
	/*0x9C*/    uint32_t Reserved7;
	/*0xA0*/    PENGINE_CONFIG engine_config_t;
	/*0xA4*/    uint32_t Reserved8;
	/*0xA8*/    uint32_t Reserved9;
	/*0xAC*/    uint32_t Reserved10;
	/*0xB0*/    uint32_t Reserved11;
	/*0xB4*/    uint32_t Reserved12;
	/*0xB8*/    uint32_t Reserved13;
	/*0xBC*/    uint32_t Reserved14;
	/*0xC0*/    uint8_t Header[0x1000]; // First 0x1000 bytes of target file
	/*0x10C0*/  uint8_t Footer[0x1000]; // Last 0x1000 bytes of target file
	/*0x20C0*/  void* UfsPluginBase;
	/*0x20C4*/  void* UfsClientRequest; //PUFSCLIENT_REQUEST
	/*0x20C8*/  uint32_t Reserved15;
	/*0x20CC*/  void* scan_variable; // pe_var_t*
	/*0x20D0*/  void* UFSClientRequest;
	uint32_t UNK[0x7D0];
	/*0x28A0*/  uint32_t Unknown20000000; //0x20000000
	/*0x28D0*/  uint32_t End_Signautre;//str::NONE
	/*0x28D4*/  uint32_t WTF1;
	/*0x2948*/  uint32_t WTF2;
	/*0x294C*/  uint32_t WTF3;
	/*0x2950*/  uint32_t WTF4;
	/*too big...*/
} SCAN_REPLY, *PSCAN_REPLY;

#elif _X64

typedef struct _SCAN_REPLY { // very very important structure!!
	/*0x0*/    uint32_t signature; // 0xB6B7B8B9
	/*0x4*/    uint32_t Flags;
	/*0x8*/    char* FileName;
	/*0x10*/    char  VirusName[28];
	/*0x2C*/    uint32_t field_28;
	/*0x30*/    uint32_t field_2C;
	/*0x34*/    uint32_t field_30;
	/*0x38*/    uint32_t field_34;
	/*0x3C*/    uint32_t field_38;
	/*0x40*/    uint32_t field_3C;
	/*0x44*/    uint32_t field_40;
	/*0x48*/    uint32_t field_44; // this was originally reserved field
	/*0x4C*/    uint32_t field_48;
	/*0x50*/    uint32_t FileSize;
	/*0x54*/    uint32_t field_50;
	/*0x58*/    uint32_t field_54; // if this fild is not 0, pefile_scan_mp is not working
	/*0x5C*/    void* UserPtr;
	/*0x64*/    uint32_t field_5C;
	/*0x68*/    char* MaybeFileName2;
	/*0x70*/    wchar_t* StreamName1;
	/*0x78*/    wchar_t* StreamName2;
	/*0x80*/    uint32_t field_6C;
	/*0x84*/    uint32_t ThreatId;             // Can be passed back to GetThreatInfo
	/*0x88*/    uint32_t Reserved1;
	/*0x8C*/    uint32_t Reserved2;
	/*0x90*/    uint32_t Reserved3;
	/*0x94*/    uint32_t Reserved4;
	/*0x98*/    void* Reserved5;
	/*0xA0*/    uint32_t NullSHA1[5];
	/*0xB4*/    uint32_t Reserved6;
	/*0xB8*/    PENGINE_CONFIG engine_config_t;
	/*0xC0*/    uint8_t Header[0x1000]; // First 0x1000 bytes of target file
	/*0x10C0*/  uint8_t Footer[0x1000]; // Last 0x1000 bytes of target file
	/*0x20C0*/  void* UfsPluginBase;
	/*0x20C4*/  void* UfsClientRequest; //PUFSCLIENT_REQUEST
	/*0x20CC*/  void* pe_var_t; // pe_var_t*
	/*0x20D0*/  void* UFSClientRequest;
	uint32_t UNK[0x7D0];
	/*0x28A0*/  uint32_t Unknown20000000; //0x20000000
	/*0x28D0*/  uint8_t End_Signautre[4];//str::NONE
	/*0x28D4*/  uint32_t WTF1[0x1000];
	/*too big...*/
} SCAN_REPLY, *PSCAN_REPLY;
#endif // _X86

#ifdef _X86
typedef struct CCftScanState {
	uint32_t(*ClientNotifyCallback)(PSCAN_REPLY arg);
	uint32_t   field_4;
	void*   UserPtr;
	uint32_t   ScanFlag;
} CCftScanState, *PCCftScanState;
#elif _X64
typedef struct CCftScanState {
	uint64_t(*ClientNotifyCallback)(PSCAN_REPLY arg);
	uint64_t   field_4;
	uint64_t   UserPtr;
	uint64_t   ScanFlag;
} CCftScanState, *PCCftScanState;
#endif // _X86

#pragma pack(pop)
#endif // __SCANREPLY_H

