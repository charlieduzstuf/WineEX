/*
 * xboxkrnl.exe conformance tests.
 *
 * Covers the ordinals with honest usermode implementations (see
 * dlls/xboxkrnl/main.c, sync_io.c, misc.c, keirql_misc.c, xc_crypto.c,
 * hal_ob_stubs.c): memory/string helpers, 64-bit arithmetic, SHA-1/RC4/
 * HMAC/DES/3DES, portable modular exponentiation, the XcUpdateCrypto
 * dispatch vector, live time-keeping data exports, statistics, and
 * object-manager identity mappings. Ordinals are
 * resolved by number because the real xboxkrnl.exe exports by ordinal only
 * (Cxbx-Reloaded KernelThunk.cpp; same table Xemu/Xemi use for HLE).
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <windows.h>
#include <stdio.h>

#include "winternl.h"
#include "ntstatus.h"
#include "wine/test.h"

/* ordinal -> prototype (all stdcall; see dlls/xboxkrnl/xboxkrnl.exe.spec) */
static void * (WINAPI *pExAllocatePool)(SIZE_T);
static void (WINAPI *pExFreePool)(void *);
static ULONGLONG (WINAPI *pKeQueryPerformanceCounter)(void);
static ULONGLONG (WINAPI *pKeQueryPerformanceFrequency)(void);
static void * (WINAPI *pMmAllocateSystemMemory)(ULONG, ULONG);
static ULONG (WINAPI *pMmFreeSystemMemory)(void *, ULONG);
static BOOLEAN (WINAPI *pMmIsAddressValid)(void *);
static ULONG (WINAPI *pMmQueryAllocationSize)(void *);
static NTSTATUS (WINAPI *pMmQueryStatistics)(void *);
static SIZE_T (WINAPI *pRtlCompareMemory)(const void *, const void *, SIZE_T);
static void (WINAPI *pRtlFillMemory)(void *, ULONG, BYTE);
static void (WINAPI *pRtlZeroMemory)(void *, SIZE_T);
static INT64 (WINAPI *pRtlExtendedIntegerMultiply)(INT64, LONG);
static INT64 (WINAPI *pRtlExtendedLargeIntegerDivide)(INT64, ULONG, ULONG *);
static INT64 (WINAPI *pRtlExtendedMagicDivide)(INT64, INT64, CHAR);
static void (WINAPI *pXcSHAInit)(void *);
static void (WINAPI *pXcSHAUpdate)(void *, void *, ULONG);
static void (WINAPI *pXcSHAFinal)(void *, BYTE *);
static void (WINAPI *pXcRC4Key)(void *, ULONG, const BYTE *);
static void (WINAPI *pXcRC4Crypt)(void *, ULONG, BYTE *);
static void (WINAPI *pXcHMAC)(const BYTE *, ULONG, const BYTE *, ULONG,
                              const BYTE *, ULONG, BYTE *);
static void (WINAPI *pXcDESKeyParity)(BYTE *, ULONG);
static void (WINAPI *pXcKeyTable)(ULONG, void *, void *);
static void (WINAPI *pXcBlockCrypt)(ULONG, void *, void *, void *, ULONG);
static NTSTATUS (WINAPI *pPsQueryStatistics)(void *);
static NTSTATUS (WINAPI *pPsSetCreateThreadNotifyRoutine)(void *);
static NTSTATUS (WINAPI *pObCreateObject)(void *, void *, ULONG, void **);
static NTSTATUS (WINAPI *pObInsertObject)(void *, void *, ULONG, void *);
static NTSTATUS (WINAPI *pObOpenObjectByPointer)(void *, void *, void **);
static NTSTATUS (WINAPI *pXeLoadSection)(void *);
static NTSTATUS (WINAPI *pXeUnloadSection)(void *);
static LONG (WINAPI *pXcModExp)(void *, void *, void *, void *, ULONG);
static void (WINAPI *pXcUpdateCrypto)(void *, void *);

#define LOAD(ord, name) \
    p##name = (void *)GetProcAddress( hkrnl, (LPCSTR)(ULONG_PTR)ord ); \
    ok( p##name != NULL, "ordinal %u (" #name ") missing\n", ord )

static void test_ex_pool(void)
{
    void *p = pExAllocatePool( 64 );
    ok( p != NULL, "ExAllocatePool failed\n" );
    if (p)
    {
        memset( p, 0xcc, 64 );
        pExFreePool( p );
    }
}

static void test_ke_query(void)
{
    ULONGLONG c = pKeQueryPerformanceCounter();
    ULONGLONG f = pKeQueryPerformanceFrequency();
    ok( c != 0, "KeQueryPerformanceCounter returned 0\n" );
    ok( f != 0, "KeQueryPerformanceFrequency returned 0\n" );
}

static void test_mm_basic(void)
{
    void *p = pMmAllocateSystemMemory( 4096, PAGE_READWRITE );
    ok( p != NULL, "MmAllocateSystemMemory failed\n" );
    if (p)
    {
        ULONG freed;
        ok( pMmIsAddressValid( p ), "MmIsAddressValid false for own allocation\n" );
        ok( !pMmIsAddressValid( NULL ), "MmIsAddressValid true for NULL\n" );
        ok( pMmQueryAllocationSize( p ) >= 4096, "MmQueryAllocationSize too small\n" );
        freed = pMmFreeSystemMemory( p, 4096 );
        ok( freed == 4096, "MmFreeSystemMemory returned %lu\n", freed );
    }
}

static void test_mm_ps_statistics(void)
{
    BYTE stats[64];
    BYTE ps[32];
    NTSTATUS st = pMmQueryStatistics( stats );
    ok( !st, "MmQueryStatistics failed: %#lx\n", st );
    if (!st)
    {
        ULONG total = *(ULONG *)stats, avail = *(ULONG *)(stats + 4);
        ok( total > 0, "MmQueryStatistics total pages == 0\n" );
        ok( avail <= total, "MmQueryStatistics avail %lu > total %lu\n", avail, total );
    }
    st = pPsQueryStatistics( ps );
    ok( !st, "PsQueryStatistics failed: %#lx\n", st );
    st = pPsSetCreateThreadNotifyRoutine( NULL );
    ok( !st, "PsSetCreateThreadNotifyRoutine failed: %#lx\n", st );
}

static void test_rtl_mem(void)
{
    BYTE buf[16], buf2[16];
    memset( buf2, 0, sizeof(buf2) );
    pRtlZeroMemory( buf, sizeof(buf) );
    ok( !memcmp( buf, buf2, sizeof(buf) ), "RtlZeroMemory did not zero\n" );
    pRtlFillMemory( buf, sizeof(buf), 0xab );
    memset( buf2, 0xab, sizeof(buf2) );
    ok( !memcmp( buf, buf2, sizeof(buf) ), "RtlFillMemory mismatch\n" );
    ok( pRtlCompareMemory( buf, buf2, sizeof(buf) ) == sizeof(buf),
        "RtlCompareMemory full match wrong\n" );
    buf2[0] ^= 0xff;
    ok( pRtlCompareMemory( buf, buf2, sizeof(buf) ) == 0,
        "RtlCompareMemory mismatch offset wrong\n" );
}

static void test_rtl_arithmetic(void)
{
    INT64 prod = pRtlExtendedIntegerMultiply( 1000000, 1000000 );
    ULONG rem = 0xdeadbeef;
    INT64 quot = pRtlExtendedLargeIntegerDivide( 10000000000LL, 1000, &rem );
    INT64 magic;
    ok( prod == 1000000000000LL, "RtlExtendedIntegerMultiply got %I64d\n", prod );
    ok( quot == 10000000LL && rem == 0, "RtlExtendedLargeIntegerDivide got %I64d rem %lu\n",
        quot, rem );
    /* magic divide by 1: (x * 2^64) >> 64 == x */
    magic = pRtlExtendedMagicDivide( 12345, (INT64)0x8000000000000000LL, 63 );
    ok( magic == 12345, "RtlExtendedMagicDivide identity got %I64d\n", magic );
}

/* FIPS 180-1 test vector: SHA-1("abc") = a9993e36... */
static void test_xc_sha(void)
{
    BYTE ctx[128], digest[20];
    static const BYTE expect[20] = { 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,
                                     0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,
                                     0x9c,0xd0,0xd8,0x9d };
    memset( ctx, 0, sizeof(ctx) );
    pXcSHAInit( ctx );
    pXcSHAUpdate( ctx, (void *)"abc", 3 );
    pXcSHAFinal( ctx, digest );
    ok( !memcmp( digest, expect, 20 ), "XcSHA wrong digest for \"abc\"\n" );
}

static void test_xc_rc4_hmac(void)
{
    BYTE ctx[512], data[16], tmp[16];
    BYTE mac1[20], mac2[20];
    static const BYTE key[] = "key";
    static const BYTE msg[] = "The quick brown fox";
    int i;
    memset( ctx, 0, sizeof(ctx) );
    memcpy( data, "0123456789abcdef", 16 );
    memcpy( tmp, data, 16 );
    pXcRC4Key( ctx, 4, (const BYTE *)"test" );
    pXcRC4Crypt( ctx, 16, data );
    ok( memcmp( data, tmp, 16 ), "XcRC4Crypt left data unchanged\n" );
    /* RC4 is symmetric: re-key and crypt again restores */
    pXcRC4Key( ctx, 4, (const BYTE *)"test" );
    pXcRC4Crypt( ctx, 16, data );
    ok( !memcmp( data, tmp, 16 ), "XcRC4Crypt not symmetric\n" );
    pXcHMAC( key, 3, msg, sizeof(msg) - 1, NULL, 0, mac1 );
    pXcHMAC( key, 3, msg, sizeof(msg) - 1, NULL, 0, mac2 );
    ok( !memcmp( mac1, mac2, 20 ), "XcHMAC not deterministic\n" );
    for (i = 0; i < 20; i++) if (mac1[i]) break;
    ok( i < 20, "XcHMAC returned all zeros\n" );
}

static void test_xc_des(void)
{
    BYTE key[8] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };
    BYTE key16[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                       0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
    BYTE table[64], in[8] = "ABCDEFGH", out[8], back[8];
    int i;
    memset( table, 0, sizeof(table) );
    pXcDESKeyParity( key, 8 );
    /* odd parity per byte: popcount of each byte must be odd */
    for (i = 0; i < 8; i++)
    {
        BYTE b = key[i];
        int bits = 0, k;
        for (k = 0; k < 8; k++) bits += (b >> k) & 1;
        ok( bits & 1, "XcDESKeyParity byte %d even parity\n", i );
    }
    pXcKeyTable( 0, table, key );
    ok( *(void **)table != NULL, "XcKeyTable stored NULL key handle\n" );
    if (*(void **)table)
    {
        pXcBlockCrypt( 0, out, in, table, 1 );
        ok( memcmp( out, in, 8 ), "XcBlockCrypt encrypt identity\n" );
        pXcBlockCrypt( 0, back, out, table, 0 );
        ok( !memcmp( back, in, 8 ), "XcBlockCrypt decrypt roundtrip failed\n" );
    }
    /* 2-key 3DES (Type 1, 16-byte K1|K2 key per Cxbx JumpedKeyTable) */
    memset( table, 0, sizeof(table) );
    pXcKeyTable( 1, table, key16 );
    ok( *(void **)table != NULL, "XcKeyTable(3DES) stored NULL key handle\n" );
    if (*(void **)table)
    {
        pXcBlockCrypt( 1, out, in, table, 1 );
        ok( memcmp( out, in, 8 ), "XcBlockCrypt(3DES) encrypt identity\n" );
        pXcBlockCrypt( 1, back, out, table, 0 );
        ok( !memcmp( back, in, 8 ), "XcBlockCrypt(3DES) decrypt roundtrip failed\n" );
    }
}

/* Little-endian DWORD buffers: result = base^exp mod mod (Cxbx
 * xbox_exp_mod mp_import order -1). All values written out in full. */
static void test_xc_modexp_one( ULONG base, ULONG exp, ULONG mod, ULONG expect )
{
    ULONG r = 0xdeadbeef;
    LONG ret = pXcModExp( &r, &base, &exp, &mod, 4 );
    ok( ret == 1, "XcModExp returned %ld, expected 1\n", ret );
    ok( r == expect, "XcModExp(%lu^%lu mod %lu) = %lu, expected %lu\n",
        base, exp, mod, r, expect );
}

static void test_xc_modexp(void)
{
    test_xc_modexp_one( 5, 3, 7, 6 );          /* 125 mod 7 */
    test_xc_modexp_one( 2, 10, 1000, 24 );     /* 1024 mod 1000 */
    test_xc_modexp_one( 7, 5, 13, 11 );        /* 16807 mod 13 */
    test_xc_modexp_one( 0x12345678, 1, 0xFFFFFFFF, 0x12345678 );
    test_xc_modexp_one( 0x1234, 0, 0xFFFF, 1 ); /* x^0 == 1 */
    /* 2-limb: 0x100000001^2 mod 0xFFFFFFFFFFFFFFFF = 0x200000002 */
    {
        ULONG base[2] = { 1, 1 }, exp[2] = { 2, 0 };
        ULONG mod[2] = { 0xFFFFFFFF, 0xFFFFFFFF }, r[2] = { 0, 0 };
        LONG ret = pXcModExp( r, base, exp, mod, 8 );
        ok( ret == 1, "XcModExp(2-limb) returned %ld\n", ret );
        ok( r[0] == 2 && r[1] == 2, "XcModExp(2-limb) = %#lx%08lx, expected 0x200000002\n",
            r[1], r[0] );
    }
    /* bad inputs fail cleanly */
    {
        ULONG r = 0xdeadbeef, v = 5;
        ok( pXcModExp( &r, &v, &v, &v, 3 ) == 0, "XcModExp accepted odd length\n" );
        ok( pXcModExp( &r, &v, &v, &v, 0 ) == 0, "XcModExp accepted zero length\n" );
    }
}

/* CRYPTO_VECTOR layout (see xc_crypto.c): 16 entries, ModExp at index 10. */
static LONG WINAPI test_modexp_42( void *a, void *b, void *c, void *d, ULONG n )
{
    (void)a; (void)b; (void)c; (void)d; (void)n;
    return 42;
}

static void test_xc_updatecrypto(void)
{
    void *zero[16] = { 0 };
    void *rom[16] = { 0 };
    void *custom[16] = { 0 };
    /* ROM vector: defaults for real impls, NULL for Cxbx-parity stubs. */
    pXcUpdateCrypto( zero, rom );
    ok( rom[0] && rom[1] && rom[2] && rom[3] && rom[4] && rom[5],
        "ROM vector missing SHA/RC4/HMAC entries\n" );
    ok( rom[6] == NULL && rom[7] == NULL && rom[8] == NULL && rom[9] == NULL,
        "ROM vector should have NULL PK entries\n" );
    ok( rom[10] != NULL, "ROM vector missing ModExp\n" );
    ok( rom[11] && rom[12] && rom[13] && rom[14], "ROM vector missing DES entries\n" );
    ok( rom[15] == NULL, "ROM vector CryptService should be NULL\n" );
    /* Install an override, observe it, restore from the ROM vector. */
    custom[10] = test_modexp_42;
    pXcUpdateCrypto( custom, NULL );
    {
        ULONG r = 0, v = 5;
        ok( pXcModExp( &r, &v, &v, &v, 4 ) == 42, "override ModExp not installed\n" );
    }
    custom[10] = rom[10];
    pXcUpdateCrypto( custom, NULL );
    test_xc_modexp_one( 5, 3, 7, 6 );
}

static void test_ob_identity(void)
{
    void *obj = NULL, *handle = NULL;
    NTSTATUS st = pObCreateObject( NULL, NULL, 32, &obj );
    ok( !st && obj, "ObCreateObject failed: %#lx\n", st );
    if (obj)
    {
        void *h = NULL;
        st = pObInsertObject( obj, NULL, 0, &h );
        ok( !st && h == obj, "ObInsertObject identity failed: %#lx h=%p obj=%p\n",
            st, h, obj );
        st = pObOpenObjectByPointer( obj, NULL, &handle );
        ok( !st && handle == obj, "ObOpenObjectByPointer identity failed\n" );
    }
}

static void test_xe_sections(void)
{
    NTSTATUS st = pXeLoadSection( NULL );
    ok( !st, "XeLoadSection failed: %#lx\n", st );
    st = pXeUnloadSection( NULL );
    ok( !st, "XeUnloadSection failed: %#lx\n", st );
}

/* Data exports: KeTickCount (156) must advance (ticker thread), and
 * XboxKrnlVersion (324) must report the final retail kernel 1.00.5960.01. */
static void test_data_exports( HMODULE hkrnl )
{
    volatile ULONG *tick = (volatile ULONG *)GetProcAddress( hkrnl, (LPCSTR)(ULONG_PTR)156 );
    USHORT *ver = (USHORT *)GetProcAddress( hkrnl, (LPCSTR)(ULONG_PTR)324 );
    ok( tick != NULL, "KeTickCount data export missing\n" );
    ok( ver != NULL, "XboxKrnlVersion data export missing\n" );
    if (tick)
    {
        ULONG before = *tick;
        Sleep( 60 );
        ok( *tick > before, "KeTickCount did not advance (%lu -> %lu)\n", before, *tick );
    }
    if (ver)
        ok( ver[0] == 1 && ver[1] == 0 && ver[2] == 5960 && ver[3] == 1,
            "XboxKrnlVersion is %u.%u.%u.%u, expected 1.0.5960.1\n",
            ver[0], ver[1], ver[2], ver[3] );
}

START_TEST(xboxkrnl)
{
    HMODULE hkrnl = LoadLibraryA( "xboxkrnl.exe" );
    ok( hkrnl != NULL, "cannot load xboxkrnl.exe\n" );
    if (!hkrnl) return;

    LOAD( 14, ExAllocatePool );
    LOAD( 17, ExFreePool );
    LOAD( 126, KeQueryPerformanceCounter );
    LOAD( 127, KeQueryPerformanceFrequency );
    LOAD( 167, MmAllocateSystemMemory );
    LOAD( 172, MmFreeSystemMemory );
    LOAD( 174, MmIsAddressValid );
    LOAD( 180, MmQueryAllocationSize );
    LOAD( 181, MmQueryStatistics );
    LOAD( 268, RtlCompareMemory );
    LOAD( 284, RtlFillMemory );
    LOAD( 320, RtlZeroMemory );
    LOAD( 281, RtlExtendedIntegerMultiply );
    LOAD( 282, RtlExtendedLargeIntegerDivide );
    LOAD( 283, RtlExtendedMagicDivide );
    LOAD( 335, XcSHAInit );
    LOAD( 336, XcSHAUpdate );
    LOAD( 337, XcSHAFinal );
    LOAD( 338, XcRC4Key );
    LOAD( 339, XcRC4Crypt );
    LOAD( 340, XcHMAC );
    LOAD( 346, XcDESKeyParity );
    LOAD( 347, XcKeyTable );
    LOAD( 348, XcBlockCrypt );
    LOAD( 345, XcModExp );
    LOAD( 351, XcUpdateCrypto );
    LOAD( 256, PsQueryStatistics );
    LOAD( 257, PsSetCreateThreadNotifyRoutine );
    LOAD( 239, ObCreateObject );
    LOAD( 241, ObInsertObject );
    LOAD( 244, ObOpenObjectByPointer );
    LOAD( 327, XeLoadSection );
    LOAD( 328, XeUnloadSection );

    test_ex_pool();
    test_ke_query();
    test_mm_basic();
    test_mm_ps_statistics();
    test_rtl_mem();
    test_rtl_arithmetic();
    test_xc_sha();
    test_xc_rc4_hmac();
    test_xc_des();
    test_xc_modexp();
    test_xc_updatecrypto();
    test_ob_identity();
    test_xe_sections();
    test_data_exports( hkrnl );

    FreeLibrary( hkrnl );
}
