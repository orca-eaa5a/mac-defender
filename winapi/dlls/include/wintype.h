#if defined(__APPLE__) || defined(__LINUX__)
typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef bool BOOL;
typedef BOOL *PBOOL,*LPBOOL;
typedef unsigned short WORD;
typedef float FLOAT;
typedef FLOAT *PFLOAT;
typedef BYTE *PBYTE,*LPBYTE;
typedef BYTE BOOLEAN;
typedef int *PINT,*LPINT;
typedef WORD *PWORD,*LPWORD;
typedef long *LPLONG;
typedef DWORD *PDWORD,*LPDWORD;
typedef uint64_t DWORD64;
typedef void *PVOID,*LPVOID;
typedef const void *PCVOID,*LPCVOID;
typedef int INT;
typedef unsigned int UINT,*PUINT,*LPUINT;
typedef unsigned long long ULONGLONG;
typedef long long LONGLONG;
typedef unsigned int ULONG; // x86_64 OSX
typedef LONGLONG LONG_PTR;
typedef DWORD LCID, *PLCID;
typedef unsigned long long UINT64;
#ifdef _X64
 typedef unsigned int UHALF_PTR;
 typedef unsigned long long UINT_PTR;
 typedef unsigned long long ULONG_PTR;
#else
 typedef unsigned short UHALF_PTR;
 typedef unsigned int UINT_PTR;
 typedef unsigned int ULONG_PTR;
#endif

typedef PVOID HANDLE;
#endif

