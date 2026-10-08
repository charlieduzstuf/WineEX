/*
 * xboxkrnl.exe - fastcall wrappers for xboxkrnl ordinals implemented elsewhere.
 *
 * THIS FILE IS GENERATED in the sense that the ordinal table it covers comes
 * from Cxbx-Reloaded's src/core/kernel/exports/KernelThunk.cpp and the
 * per-function signatures in src/core/kernel/common/*.h. Each
 * DEFINE_FASTCALL_WRAPPER below emits the stdcall->fastcall-glue for a real
 * implementation living in keirql_misc.c (Ex*/Kf*/Ki*) or hal_ob_stubs.c
 * (Hal*/Iof*/Obf*); the wrappers themselves carry no behaviour. Ordinals
 * with no honest usermode equivalent remain FIXME stubs in hal_ob_stubs.c /
 * misc.c / xc_crypto.c / sync_io.c — see those files.
 *
 * See dlls/xboxkrnl/main.c for the subset of ordinals that DO have a real,
 * verified-against-Cxbx-Reloaded-semantics forward to existing Wine/ntdll
 * functionality instead of living here.
 */

#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ntstatus.h"
#include "wine/asm.h"
#include "wine/debug.h"

/* debug channel retained for future stubs */
/* WINE_DEFAULT_DEBUG_CHANNEL(xboxkrnl); */

DEFINE_FASTCALL_WRAPPER(XBOXKRNL_ExInterlockedAddLargeStatistic,8)
void FASTCALL XBOXKRNL_ExInterlockedAddLargeStatistic( void *a0, LONG a1 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_ExInterlockedCompareExchange64,12)
LONG FASTCALL XBOXKRNL_ExInterlockedCompareExchange64( void *a0, void *a1, void *a2 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_ExfInterlockedInsertHeadList,8)
LONG FASTCALL XBOXKRNL_ExfInterlockedInsertHeadList( void *a0, void *a1 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_ExfInterlockedInsertTailList,8)
LONG FASTCALL XBOXKRNL_ExfInterlockedInsertTailList( void *a0, void *a1 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_ExfInterlockedRemoveHeadList,4)
LONG FASTCALL XBOXKRNL_ExfInterlockedRemoveHeadList( void *a0 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_HalClearSoftwareInterrupt,4)
void FASTCALL XBOXKRNL_HalClearSoftwareInterrupt( LONG a0 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_HalRequestSoftwareInterrupt,4)
void FASTCALL XBOXKRNL_HalRequestSoftwareInterrupt( LONG a0 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_IofCallDriver,8)
LONG FASTCALL XBOXKRNL_IofCallDriver( void *a0, void *a1 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_IofCompleteRequest,8)
void FASTCALL XBOXKRNL_IofCompleteRequest( void *a0, LONG a1 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_KfRaiseIrql,4)
LONG FASTCALL XBOXKRNL_KfRaiseIrql( LONG a0 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_KfLowerIrql,4)
void FASTCALL XBOXKRNL_KfLowerIrql( LONG a0 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_KiUnlockDispatcherDatabase,4)
void FASTCALL XBOXKRNL_KiUnlockDispatcherDatabase( LONG a0 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_ObfDereferenceObject,4)
void FASTCALL XBOXKRNL_ObfDereferenceObject( void *a0 );
DEFINE_FASTCALL_WRAPPER(XBOXKRNL_ObfReferenceObject,4)
void FASTCALL XBOXKRNL_ObfReferenceObject( void *a0 );

















































































































































































































