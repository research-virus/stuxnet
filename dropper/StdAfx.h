#include <windows.h>

#define _QWORD UINT64
#define _DWORD UINT32
#define _WORD  USHORT
#define _BYTE  UCHAR
#define bool   BOOL

#define __usercall _cdecl
#define __thiscall _cdecl // (?)

#define NTSTATUS                     ULONG
#define STATUS_SUCCESS               0x00000000
#define STATUS_INFO_LENGTH_MISMATCH  0xC0000004
#define STATUS_ACCESS_DENIED         0xC0000022
#define STATUS_BUFFER_OVERFLOW       0x80000005
#define STATUS_CONFLICTING_ADDRESSES 0xC0000018
