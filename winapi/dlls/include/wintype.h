#if defined(__APPLE__) || defined(__LINUX__)
typedef uint8_t BYTE;
typedef int16_t WCHAR;
typedef uint32_t DWORD;
typedef bool BOOL;
typedef BOOL *PBOOL,*LPBOOL;
typedef uint16_t WORD;
typedef float FLOAT;
typedef FLOAT *PFLOAT;
typedef BYTE *PBYTE,*LPBYTE;
typedef BYTE BOOLEAN;
typedef int32_t *PINT,*LPINT;
typedef WORD *PWORD,*LPWORD;
typedef uint8_t UCHAR;
typedef uint16_t USHORT;
typedef int32_t *LPLONG;
typedef DWORD *PDWORD,*LPDWORD;
typedef uint64_t DWORD64;
typedef void *PVOID,*LPVOID;
typedef const void *PCVOID,*LPCVOID;
typedef int32_t INT;
typedef uint32_t UINT,*PUINT,*LPUINT;
typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;
typedef uint32_t ULONG; // x86_64 OSX
typedef LONGLONG LONG_PTR;
typedef DWORD LCID, *PLCID;
typedef uint64_t UINT64;
typedef uint64_t* PULONG64;
typedef WCHAR* PWSTR;
#ifdef _X64
 typedef uint32_t UHALF_PTR;
 typedef uint64_t UINT_PTR;
 typedef uint64_t ULONG_PTR;
#else
 typedef uint16_t UHALF_PTR;
 typedef uint32_t UINT_PTR;
 typedef uint32_t ULONG_PTR;
#endif

typedef PVOID HANDLE;
#endif

