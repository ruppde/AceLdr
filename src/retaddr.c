//
// https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html
//


#include "include.h"

SECTION( E ) PVOID SpoofRetAddr( QWORD ArgCount, PVOID function, HANDLE module, ULONG size, PVOID a, PVOID b, PVOID c, PVOID d, PVOID e, PVOID f, PVOID g, PVOID h, PVOID i, PVOID j, PVOID k, PVOID l, PVOID m )
{
    PVOID   Trampoline;
    PRM     param      = { 0 };
    ULONG   SizeBackup = 0; 

    // If no specified module, grab something from kernel32
    if( !module || !size )
    {
        module = FindModule( H_LIB_KERNEL32, NULL, &SizeBackup );
        size = SizeBackup;
    }
    if( function != NULL )
    {
            PrepSpoof( &param, module, size );
            return Spoof( a, b, c, d, &param, function, C_PTR( ArgCount ), e, f, g, h, i, j, k, l, m );
    };

    return NULL;
};
