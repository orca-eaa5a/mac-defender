#ifndef _WINDOWS_H_
#define _WINDOWS_H_
#if defined(__APPLE__)
#define __stdcall __attribute__((__stdcall__)) __attribute__((__force_align_arg_pointer__))
#define __cdecl __attribute__((__cdecl__)) __attribute__((__force_align_arg_pointer__))
#include "ntstatus.h"
#include "wintype.h"
#elif defined(__LINUX__)
#define __stdcall __attribute__((__stdcall__))
#define __cdecl __attribute__((__cdecl__))
#endif

#if defined(__APPLE__) || defined(__LINUX__)

typedef struct _SINGLE_LIST_ENTRY
{
  _SINGLE_LIST_ENTRY* Next;
}SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

typedef struct _SLIST_HEADER
{
	 union
	 {
		  UINT64 Alignment;
		  struct
		  {
			   SINGLE_LIST_ENTRY Next;
			   WORD Depth;
			   WORD Sequence;
		  };
	 };
} SLIST_HEADER, *PSLIST_HEADER;

typedef struct _RTL_SRWLOCK {
  PVOID Ptr;
} RTL_SRWLOCK, *PRTL_SRWLOCK;
typedef RTL_SRWLOCK SRWLOCK, *PSRWLOCK;
#define MAX_DEFAULTCHAR 2
#define MAX_LEADBYTES 12
typedef struct _cpinfo {
  UINT MaxCharSize;
  BYTE DefaultChar[MAX_DEFAULTCHAR];
  BYTE LeadByte[MAX_LEADBYTES];
} CPINFO, *LPCPINFO;

typedef struct _IO_STATUS_BLOCK{
	union {
		int Status;
		void*    Pointer;
	};
	
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _PROCESS_INFORMATION_CLASS {
  ProcessMemoryPriority,
  ProcessMemoryExhaustionInfo,
  ProcessAppMemoryInfo,
  ProcessInPrivateInfo,
  ProcessPowerThrottling,
  ProcessReservedValue1,
  ProcessTelemetryCoverageInfo,
  ProcessProtectionLevelInfo,
  ProcessLeapSecondInfo,
  ProcessMachineTypeInfo,
  ProcessInformationClassMax
} PROCESS_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS{
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	KeyValueLayerInformation,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
	unsigned long TitleIndex;
	unsigned long Type;
	unsigned long NameLength;
	wchar_t Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
	unsigned long TitleIndex;
	unsigned long Type;
	unsigned long DataLength;
	unsigned char Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _UNICODE_STRING {
	unsigned short Length;
	unsigned short MaximumLength;
	wchar_t*  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OSVERSIONINFOW {
  unsigned long dwOSVersionInfoSize;
  unsigned long dwMajorVersion;
  unsigned long dwMinorVersion;
  unsigned long dwBuildNumber;
  unsigned long dwPlatformId;
  wchar_t szCSDVersion[128];
} OSVERSIONINFOW, *POSVERSIONINFOW, *LPOSVERSIONINFOW, RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;

typedef struct _IMAGE_DOS_HEADER {
	WORD  e_magic;      /* 00: MZ Header signature */
	WORD  e_cblp;       /* 02: Bytes on last page of file */
	WORD  e_cp;         /* 04: Pages in file */
	WORD  e_crlc;       /* 06: Relocations */
	WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
	WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
	WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
	WORD  e_ss;         /* 0e: Initial (relative) SS value */
	WORD  e_sp;         /* 10: Initial SP value */
	WORD  e_csum;       /* 12: Checksum */
	WORD  e_ip;         /* 14: Initial IP value */
	WORD  e_cs;         /* 16: Initial (relative) CS value */
	WORD  e_lfarlc;     /* 18: File address of relocation table */
	WORD  e_ovno;       /* 1a: Overlay number */
	WORD  e_res[4];     /* 1c: Reserved words */
	WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
	WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
	WORD  e_res2[10];   /* 28: Reserved words */
	DWORD e_lfanew;     /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
/* Wine extension */
#define IMAGE_DOS_SIGNATURE    0x5A4D     /* MZ   */
#define IMAGE_NT_SIGNATURE     0x00004550 /* PE00 */
#define	IMAGE_FILE_MACHINE_ARM64	0x01c5

#define	IMAGE_SIZEOF_FILE_HEADER		20
#define IMAGE_SIZEOF_ROM_OPTIONAL_HEADER	56
#define IMAGE_SIZEOF_STD_OPTIONAL_HEADER	28
#define IMAGE_SIZEOF_NT_OPTIONAL32_HEADER 	224
#define IMAGE_SIZEOF_NT_OPTIONAL64_HEADER 	240
#define IMAGE_SIZEOF_SHORT_NAME 		8
#define IMAGE_SIZEOF_SECTION_HEADER 		40
#define IMAGE_SIZEOF_SYMBOL 			18
#define IMAGE_SIZEOF_AUX_SYMBOL 		18
#define IMAGE_SIZEOF_RELOCATION 		10
#define IMAGE_SIZEOF_BASE_RELOCATION 		8
#define IMAGE_SIZEOF_LINENUMBER 		6
#define IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR 	60

/* Possible Magic values */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

#ifdef _X64
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
#define IMAGE_NT_OPTIONAL_HDR_MAGIC     IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
#define IMAGE_NT_OPTIONAL_HDR_MAGIC     IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif

/* Directory Entries, indices into the DataDirectory array */

#define	IMAGE_DIRECTORY_ENTRY_EXPORT		0
#define	IMAGE_DIRECTORY_ENTRY_IMPORT		1
#define	IMAGE_DIRECTORY_ENTRY_RESOURCE		2
#define	IMAGE_DIRECTORY_ENTRY_EXCEPTION		3
#define	IMAGE_DIRECTORY_ENTRY_SECURITY		4
#define	IMAGE_DIRECTORY_ENTRY_BASERELOC		5
#define	IMAGE_DIRECTORY_ENTRY_DEBUG		6
#define	IMAGE_DIRECTORY_ENTRY_COPYRIGHT		7
#define	IMAGE_DIRECTORY_ENTRY_GLOBALPTR		8   /* (MIPS GP) */
#define	IMAGE_DIRECTORY_ENTRY_TLS		9
#define	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG	10
#define	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT	11
#define	IMAGE_DIRECTORY_ENTRY_IAT		12  /* Import Address Table */
#define	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT	13
#define	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	14


typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD  Magic; /* 0x20b */
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  ULONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_OPTIONAL_HEADER {

  /* Standard fields */

  WORD  Magic; /* 0x10b or 0x107 */	/* 0x00 */
  BYTE  MajorLinkerVersion;
  BYTE  MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;		/* 0x10 */
  DWORD BaseOfCode;
  DWORD BaseOfData;

  /* NT additional fields */

  DWORD ImageBase;
  DWORD SectionAlignment;		/* 0x20 */
  DWORD FileAlignment;
  WORD  MajorOperatingSystemVersion;
  WORD  MinorOperatingSystemVersion;
  WORD  MajorImageVersion;
  WORD  MinorImageVersion;
  WORD  MajorSubsystemVersion;		/* 0x30 */
  WORD  MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;			/* 0x40 */
  WORD  Subsystem;
  WORD  DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;		/* 0x50 */
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; /* 0x60 */
  /* 0xE0 */
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
  DWORD Signature; /* "PE"\0\0 */	/* 0x00 */
  IMAGE_FILE_HEADER FileHeader;		/* 0x04 */
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;	/* 0x18 */
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

#ifdef _X64
typedef IMAGE_NT_HEADERS64  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#else
typedef IMAGE_NT_HEADERS32  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#endif

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
	DWORD PhysicalAddress;
	DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define	IMAGE_SIZEOF_SECTION_HEADER 40

#define IMAGE_FIRST_SECTION(ntheader) \
  ((PIMAGE_SECTION_HEADER)(ULONG_PTR)((const BYTE *)&((const IMAGE_NT_HEADERS *)(ntheader))->OptionalHeader + \
						   ((const IMAGE_NT_HEADERS *)(ntheader))->FileHeader.SizeOfOptionalHeader))

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD	Characteristics;
	DWORD	TimeDateStamp;
	WORD	MajorVersion;
	WORD	MinorVersion;
	DWORD	Name;
	DWORD	Base;
	DWORD	NumberOfFunctions;
	DWORD	NumberOfNames;
	DWORD	AddressOfFunctions;
	DWORD	AddressOfNames;
	DWORD	AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

/* Import name entry */
typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD	Hint;
	BYTE	Name[1];
} IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
	union {
		ULONGLONG ForwarderString;
		ULONGLONG Function;
		ULONGLONG Ordinal;
		ULONGLONG AddressOfData;
	} u1;
} IMAGE_THUNK_DATA64,*PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_THUNK_DATA32 {
	union {
		DWORD ForwarderString;
		DWORD Function;
		DWORD Ordinal;
		DWORD AddressOfData;
	} u1;
} IMAGE_THUNK_DATA32,*PIMAGE_THUNK_DATA32;

/* Import module directory */

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD	Characteristics; /* 0 for terminating null import descriptor  */
		DWORD	OriginalFirstThunk;	/* RVA to original unbound IAT */
	} DUMMYUNIONNAME;
	DWORD	TimeDateStamp;	/* 0 if not bound,
				 * -1 if bound, and real date\time stamp
				 *    in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
				 * (new BIND)
				 * otherwise date/time stamp of DLL bound to
				 * (Old BIND)
				 */
	DWORD	ForwarderChain;	/* -1 if no forwarders */
	DWORD	Name;
	/* RVA to IAT (if bound this IAT has actual addresses) */
	DWORD	FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;

#define IMAGE_ORDINAL_FLAG64             (((ULONGLONG)0x80000000 << 32) | 0x00000000)
#define IMAGE_ORDINAL_FLAG32             0x80000000
#define IMAGE_SNAP_BY_ORDINAL64(ordinal) (((ordinal) & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(ordinal) (((ordinal) & IMAGE_ORDINAL_FLAG32) != 0)
#define IMAGE_ORDINAL64(ordinal)         ((ordinal) & 0xffff)
#define IMAGE_ORDINAL32(ordinal)         ((ordinal) & 0xffff)

#ifdef _X64
#define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG64
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL64(Ordinal)
#define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL64(Ordinal)
typedef IMAGE_THUNK_DATA64              IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA64             PIMAGE_THUNK_DATA;
#else
#define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG32
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL32(Ordinal)
#define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL32(Ordinal)
typedef IMAGE_THUNK_DATA32              IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA32             PIMAGE_THUNK_DATA;
#endif

typedef struct _IMAGE_BASE_RELOCATION
{
	DWORD	VirtualAddress;
	DWORD	SizeOfBlock;
	/* WORD	TypeOffset[1]; */
} IMAGE_BASE_RELOCATION,*PIMAGE_BASE_RELOCATION;


typedef struct _IMAGE_RELOCATION
{
	union {
		DWORD   VirtualAddress;
		DWORD   RelocCount;
	} DUMMYUNIONNAME;
	DWORD   SymbolTableIndex;
	WORD    Type;
} IMAGE_RELOCATION, *PIMAGE_RELOCATION;

#define IMAGE_SIZEOF_RELOCATION 10
#define IMAGE_REL_BASED_DIR64			10


#define CREATE_NEW 1
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define OPEN_ALWAYS 4
#define TRUNCATE_EXISTING 5

#define INVALID_HANDLE_VALUE ((HANDLE)(ULONG_PTR)-1)
#define ERROR_FILE_NOT_FOUND 2

#define SECTION_QUERY              0x0001
#define SECTION_MAP_WRITE          0x0002
#define SECTION_MAP_READ           0x0004
#define SECTION_MAP_EXECUTE        0x0008
#define SECTION_EXTEND_SIZE        0x0010
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020
#define SECTION_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED|0x01f)

#define FILE_READ_DATA            0x0001    /* file & pipe */
#define FILE_LIST_DIRECTORY       0x0001    /* directory */
#define FILE_WRITE_DATA           0x0002    /* file & pipe */
#define FILE_ADD_FILE             0x0002    /* directory */
#define FILE_APPEND_DATA          0x0004    /* file */
#define FILE_ADD_SUBDIRECTORY     0x0004    /* directory */
#define FILE_CREATE_PIPE_INSTANCE 0x0004    /* named pipe */
#define FILE_READ_EA              0x0008    /* file & directory */
#define FILE_READ_PROPERTIES      FILE_READ_EA
#define FILE_WRITE_EA             0x0010    /* file & directory */
#define FILE_WRITE_PROPERTIES     FILE_WRITE_EA
#define FILE_EXECUTE              0x0020    /* file */
#define FILE_TRAVERSE             0x0020    /* directory */
#define FILE_DELETE_CHILD         0x0040    /* directory */
#define FILE_READ_ATTRIBUTES      0x0080    /* all */
#define FILE_WRITE_ATTRIBUTES     0x0100    /* all */
#define FILE_ALL_ACCESS           (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x1ff)

#define FILE_GENERIC_READ         (STANDARD_RIGHTS_READ | FILE_READ_DATA | \
								   FILE_READ_ATTRIBUTES | FILE_READ_EA | \
								   SYNCHRONIZE)
#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | \
								   FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | \
								   FILE_APPEND_DATA | SYNCHRONIZE)
#define FILE_GENERIC_EXECUTE      (STANDARD_RIGHTS_EXECUTE | FILE_EXECUTE | \
								   FILE_READ_ATTRIBUTES | SYNCHRONIZE)

#define DUPLICATE_CLOSE_SOURCE     0x00000001
#define DUPLICATE_SAME_ACCESS      0x00000002

/* File attribute flags */
#define FILE_SHARE_READ                    0x00000001
#define FILE_SHARE_WRITE                   0x00000002
#define FILE_SHARE_DELETE                  0x00000004

#define FILE_ATTRIBUTE_READONLY            0x00000001
#define FILE_ATTRIBUTE_HIDDEN              0x00000002
#define FILE_ATTRIBUTE_SYSTEM              0x00000004
#define FILE_ATTRIBUTE_DIRECTORY           0x00000010
#define FILE_ATTRIBUTE_ARCHIVE             0x00000020
#define FILE_ATTRIBUTE_DEVICE              0x00000040
#define FILE_ATTRIBUTE_NORMAL              0x00000080
#define FILE_ATTRIBUTE_TEMPORARY           0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE         0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT       0x00000400
#define FILE_ATTRIBUTE_COMPRESSED          0x00000800
#define FILE_ATTRIBUTE_OFFLINE             0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED           0x00004000

typedef struct _FILETIME {
  unsigned int dwLowDateTime;
  unsigned int dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

typedef struct _STARTUPINFOA {
  unsigned int  cb;
  char*  lpReserved;
  char*  lpDesktop;
  char*  lpTitle;
  unsigned int  dwX;
  unsigned int  dwY;
  unsigned int  dwXSize;
  unsigned int  dwYSize;
  unsigned int  dwXCountChars;
  unsigned int  dwYCountChars;
  unsigned int  dwFillAttribute;
  unsigned int  dwFlags;
  unsigned short   wShowWindow;
  unsigned short   cbReserved2;
  unsigned char* lpReserved2;
  void* hStdInput;
  void* hStdOutput;
  void* hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _STARTUPINFOW {
  unsigned int  cb;
  wchar_t*  lpReserved;
  wchar_t*  lpDesktop;
  wchar_t*  lpTitle;
  unsigned int  dwX;
  unsigned int  dwY;
  unsigned int  dwXSize;
  unsigned int  dwYSize;
  unsigned int  dwXCountChars;
  unsigned int  dwYCountChars;
  unsigned int  dwFillAttribute;
  unsigned int  dwFlags;
  unsigned short   wShowWindow;
  unsigned short   cbReserved2;
  unsigned char* lpReserved2;
  void* hStdInput;
  void* hStdOutput;
  void* hStdError;
} STARTUPINFOW, *LPSTARTUPINFOW;

typedef union _LARGE_INTEGER {
  struct {
	unsigned int LowPart;
	long  HighPart;
  } DUMMYSTRUCTNAME;
  struct {
	unsigned int LowPart;
	long  HighPart;
  } u;
  long long QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _SYSTEM_INFO {
  union {
	unsigned int dwOemId;
	struct {
	  unsigned short wProcessorArchitecture;
	  unsigned short wReserved;
	} DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
  unsigned int     dwPageSize;
  void*    lpMinimumApplicationAddress;
  void*    lpMaximumApplicationAddress;
  unsigned int* dwActiveProcessorMask;
  unsigned int     dwNumberOfProcessors;
  unsigned int     dwProcessorType;
  unsigned int     dwAllocationGranularity;
  unsigned short      wProcessorLevel;
  unsigned short      wProcessorRevision;
} SYSTEM_INFO, *LPSYSTEM_INFO;

#define STD_INPUT_HANDLE ((unsigned int)-10)
#define STD_OUTPUT_HANDLE ((unsigned int)-11)
#define STD_ERROR_HANDLE ((unsigned int)-12)

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#define _ARRAYSIZE ARRAY_SIZE

#ifndef TLS_OUT_OF_INDEXES
#define TLS_OUT_OF_INDEXES          ((DWORD)0xFFFFFFFF)
#endif
#ifndef FLS_OUT_OF_INDEXES
#define FLS_OUT_OF_INDEXES          ((DWORD)0xFFFFFFFF)
#endif

#define CP_UTF8 65001
#define CT_CTYPE1 1
#define CT_CTYPE2 2
#define CT_CTYPE3 4
#define C1_UPPER 1
#define C1_LOWER 2
#define C1_DIGIT 4
#define C1_SPACE 8
#define C1_PUNCT 16
#define C1_CNTRL 32
#define C1_BLANK 64
#define C1_XDIGIT 128
#define C1_ALPHA 256
#define C1_DEFINED 0x0200

#define MB_ERR_INVALID_CHARS 8
#define ERROR_ENVVAR_NOT_FOUND 0x800700cb
#define LMEM_ZEROINIT 0x0040

#define CSTR_LESS_THAN 1
#define CSTR_EQUAL 2
#define CSTR_GREATER_THAN 3

#define PF_FLOATING_POINT_PRECISION_ERRATA       0   
#define PF_FLOATING_POINT_EMULATED               1   
#define PF_COMPARE_EXCHANGE_DOUBLE               2   
#define PF_MMX_INSTRUCTIONS_AVAILABLE            3   
#define PF_PPC_MOVEMEM_64BIT_OK                  4   
#define PF_ALPHA_BYTE_INSTRUCTIONS               5   
#define PF_XMMI_INSTRUCTIONS_AVAILABLE           6   
#define PF_3DNOW_INSTRUCTIONS_AVAILABLE          7   
#define PF_RDTSC_INSTRUCTION_AVAILABLE           8   
#define PF_PAE_ENABLED                           9   
#define PF_XMMI64_INSTRUCTIONS_AVAILABLE        10   
#define PF_SSE_DAZ_MODE_AVAILABLE               11   
#define PF_NX_ENABLED                           12   
#define PF_SSE3_INSTRUCTIONS_AVAILABLE          13   
#define PF_COMPARE_EXCHANGE128                  14   
#define PF_COMPARE64_EXCHANGE128                15   
#define PF_CHANNELS_ENABLED                     16   
#define PF_XSAVE_ENABLED                        17   
#define PF_ARM_VFP_32_REGISTERS_AVAILABLE       18   
#define PF_ARM_NEON_INSTRUCTIONS_AVAILABLE      19   
#define PF_SECOND_LEVEL_ADDRESS_TRANSLATION     20   
#define PF_VIRT_FIRMWARE_ENABLED                21   
#define PF_RDWRFSGSBASE_AVAILABLE               22   
#define PF_FASTFAIL_AVAILABLE                   23   
#define PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE     24   
#define PF_ARM_64BIT_LOADSTORE_ATOMIC           25   
#define PF_ARM_EXTERNAL_CACHE_AVAILABLE         26   
#define PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE      27   
#define PF_RDRAND_INSTRUCTION_AVAILABLE         28   
#define PF_ARM_V8_INSTRUCTIONS_AVAILABLE        29   
#define PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE 30   
#define PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE  31   
#define PF_RDTSCP_INSTRUCTION_AVAILABLE         32   
#define PF_RDPID_INSTRUCTION_AVAILABLE          33

/* Heap flags */
#define HEAP_NO_SERIALIZE               0x00000001
#define HEAP_GROWABLE                   0x00000002
#define HEAP_GENERATE_EXCEPTIONS        0x00000004
#define HEAP_ZERO_MEMORY                0x00000008
#define HEAP_REALLOC_IN_PLACE_ONLY      0x00000010
#define HEAP_TAIL_CHECKING_ENABLED      0x00000020
#define HEAP_FREE_CHECKING_ENABLED      0x00000040
#define HEAP_DISABLE_COALESCE_ON_FREE   0x00000080
#define HEAP_CREATE_ALIGN_16            0x00010000
#define HEAP_CREATE_ENABLE_TRACING      0x00020000
#define HEAP_CREATE_ENABLE_EXECUTE      0x00040000

#define HKEY_CLASSES_ROOT       0x80000000
#define HKEY_CURRENT_USER       0x80000001
#define HKEY_LOCAL_MACHINE      0x80000002
#define HKEY_USERS              0x80000003
#define HKEY_PERFORMANCE_DATA   0x80000004
#define HKEY_CURRENT_CONFIG     0x80000005

#ifndef s_addr
typedef struct in_addr {
	union {
		struct { UCHAR s_b1, s_b2, s_b3, s_b4; } S_un_b;
		struct { USHORT s_w1, s_w2; } S_un_w;
		ULONG S_addr;
	} S_un;
#define s_addr  S_un.S_addr /* can be used for most tcp & ip code */
#define s_host  S_un.S_un_b.s_b2    // host on imp
#define s_net   S_un.S_un_b.s_b1    // network
#define s_imp   S_un.S_un_w.s_w2    // imp
#define s_impno S_un.S_un_b.s_b4    // imp #
#define s_lh    S_un.S_un_b.s_b3    // logical host
} IN_ADDR, *PIN_ADDR, FAR *LPIN_ADDR;
#endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP | WINAPI_PARTITION_SYSTEM) */

#define DECLSPEC_ALIGN(x)   __declspec(align(x))

typedef struct DECLSPEC_ALIGN(16) _M128A {
	ULONGLONG Low;
	LONGLONG High;
} M128A, *PM128A;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT {

	//
	// Register parameter home addresses.
	//
	// N.B. These fields are for convience - they could be used to extend the
	//      context record in the future.
	//

	DWORD64 P1Home;
	DWORD64 P2Home;
	DWORD64 P3Home;
	DWORD64 P4Home;
	DWORD64 P5Home;
	DWORD64 P6Home;

	//
	// Control flags.
	//

	DWORD ContextFlags;
	DWORD MxCsr;

	//
	// Segment Registers and processor flags.
	//

	WORD   SegCs;
	WORD   SegDs;
	WORD   SegEs;
	WORD   SegFs;
	WORD   SegGs;
	WORD   SegSs;
	DWORD EFlags;

	//
	// Debug registers
	//

	DWORD64 Dr0;
	DWORD64 Dr1;
	DWORD64 Dr2;
	DWORD64 Dr3;
	DWORD64 Dr6;
	DWORD64 Dr7;

	//
	// Integer registers.
	//

	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;

	//
	// Program counter.
	//

	DWORD64 Rip;

	//
	// Floating point state.
	//

	union {
		XMM_SAVE_AREA32 FltSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	//
	// Vector registers.
	//

	M128A VectorRegister[26];
	DWORD64 VectorControl;

	//
	// Special debug control registers.
	//

	DWORD64 DebugControl;
	DWORD64 LastBranchToRip;
	DWORD64 LastBranchFromRip;
	DWORD64 LastExceptionToRip;
	DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

typedef struct _SYSTEMTIME {
	uint16_t wYear;
	uint16_t wMonth;
	uint16_t wDayOfWeek;
	uint16_t wDay;
	uint16_t wHour;
	uint16_t wMinute;
	uint16_t wSecond;
	uint16_t wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

typedef struct _FILETIME {
	DWORD dwLowDateTime;
	DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

typedef struct DECLSPEC_ALIGN(16) _M128A {
	ULONGLONG Low;
	LONGLONG High;
} M128A, *PM128A;

#endif
#endif