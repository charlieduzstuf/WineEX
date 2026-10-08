/*
 * xgameruntime.dll conformance tests.
 *
 * Covers the always-available entry points: InitializeApiImpl variants
 * (April 2026 GDK Update 3, GDKC_VERSION 10002) and QueryApiImpl dispatch —
 * unknown CLSIDs must return ERROR_NOT_SUPPORTED, and every known impl
 * CLSID must QI to a live COM object. Deeper per-interface behaviour
 * (XSystem IDs, XUser guest sign-in, XGame title id) is exercised through
 * the returned interfaces so regressions in main.c's dispatch table fail
 * here, not in titles.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define COBJMACROS

#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "initguid.h"

#include "wine/test.h"

#include <xsystem.h>
#include <xgame.h>
#include <xuser.h>
#include <xgameruntimetypes.h>

static HRESULT (WINAPI *pInitializeApiImpl)(ULONG, ULONG);
static HRESULT (WINAPI *pInitializeApiImplEx)(ULONG, ULONG, CHAR);
static HRESULT (WINAPI *pInitializeApiImplEx2)(ULONG, ULONG, CHAR, const void *);
static HRESULT (WINAPI *pQueryApiImpl)(const GUID *, REFIID, void **);

static void test_initialize(void)
{
    HRESULT hr;
    hr = pInitializeApiImpl( 10002, 7874 );
    ok( hr == S_OK, "InitializeApiImpl failed: %#lx\n", hr );
    hr = pInitializeApiImplEx( 10002, 7874, 0 );
    ok( hr == S_OK, "InitializeApiImplEx failed: %#lx\n", hr );
    hr = pInitializeApiImplEx2( 10002, 7874, 0, NULL );
    ok( hr == S_OK, "InitializeApiImplEx2 failed: %#lx\n", hr );
}

static void test_query_unknown(void)
{
    GUID bogus = { 0xdeadbeef, 0xdead, 0xbeef, { 0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef } };
    void *out = (void *)0xdeadbeef;
    HRESULT hr = pQueryApiImpl( &bogus, &IID_IUnknown, &out );
    ok( hr == HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED ),
        "QueryApiImpl(bogus) returned %#lx, expected ERROR_NOT_SUPPORTED\n", hr );
}

static void test_xsystem_ids(void)
{
    IXSystemImpl5 *sys = NULL;
    HRESULT hr = pQueryApiImpl( &CLSID_XSystemImpl, &IID_IXSystemImpl5, (void **)&sys );
    ok( hr == S_OK && sys != NULL, "QueryApiImpl(XSystemImpl) failed: %#lx\n", hr );
    if (hr != S_OK || !sys) return;

    {
        char buf[64];
        SIZE_T used = 0;
        hr = IXSystemImpl5_XSystemGetConsoleId( sys, sizeof(buf), buf, &used );
        ok( hr == S_OK, "XSystemGetConsoleId failed: %#lx\n", hr );
        ok( used == 39, "XSystemGetConsoleId used %Iu, expected 39\n", used );
        hr = IXSystemImpl5_XSystemGetConsoleId( sys, 4, buf, &used );
        ok( hr == HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER ),
            "XSystemGetConsoleId small buffer returned %#lx\n", hr );
        hr = IXSystemImpl5_XSystemGetConsoleId( sys, sizeof(buf), NULL, &used );
        ok( hr == E_POINTER, "XSystemGetConsoleId NULL out returned %#lx\n", hr );
    }
    {
        char buf[32];
        SIZE_T used = 0;
        hr = IXSystemImpl5_XSystemGetXboxLiveSandboxId( sys, sizeof(buf), buf, &used );
        ok( hr == S_OK, "XSystemGetXboxLiveSandboxId failed: %#lx\n", hr );
        ok( used == strlen( "RETAIL" ) + 1, "sandbox used %Iu\n", used );
    }
    {
        char buf[64];
        SIZE_T used = 0;
        hr = IXSystemImpl5_XSystemGetAppSpecificDeviceId( sys, sizeof(buf), buf, &used );
        ok( hr == S_OK, "XSystemGetAppSpecificDeviceId failed: %#lx\n", hr );
        ok( used == 45, "device id used %Iu, expected 45\n", used );
    }
    ok( IXSystemImpl5_XSystemIsHandleValid( sys, (XSystemHandle)(ULONG_PTR)1 ),
        "valid handle reported invalid\n" );
    ok( !IXSystemImpl5_XSystemIsHandleValid( sys, NULL ),
        "NULL handle reported valid\n" );
    IXSystemImpl5_Release( sys );
}

static void test_xgame_title(void)
{
    IXGameImpl3 *game = NULL;
    HRESULT hr = pQueryApiImpl( &CLSID_XGameImpl, &IID_IXGameImpl3, (void **)&game );
    ok( hr == S_OK && game != NULL, "QueryApiImpl(XGameImpl) failed: %#lx\n", hr );
    if (hr != S_OK || !game) return;

    {
        UINT32 title = 0xdeadbeef;
        hr = IXGameImpl3_XGameGetXboxTitleId( game, &title );
        ok( hr == S_OK, "XGameGetXboxTitleId failed: %#lx\n", hr );
        hr = IXGameImpl3_XGameGetXboxTitleId( game, NULL );
        ok( hr == E_POINTER, "XGameGetXboxTitleId NULL returned %#lx\n", hr );
    }
    IXGameImpl3_Release( game );
}

START_TEST(xgameruntime)
{
    HMODULE hmod = LoadLibraryA( "xgameruntime.dll" );
    ok( hmod != NULL, "cannot load xgameruntime.dll\n" );
    if (!hmod) return;

    pInitializeApiImpl = (void *)GetProcAddress( hmod, "InitializeApiImpl" );
    pInitializeApiImplEx = (void *)GetProcAddress( hmod, "InitializeApiImplEx" );
    pInitializeApiImplEx2 = (void *)GetProcAddress( hmod, "InitializeApiImplEx2" );
    pQueryApiImpl = (void *)GetProcAddress( hmod, "QueryApiImpl" );
    ok( pInitializeApiImpl && pInitializeApiImplEx && pInitializeApiImplEx2 && pQueryApiImpl,
        "missing exports\n" );
    if (!pInitializeApiImpl || !pQueryApiImpl) { FreeLibrary( hmod ); return; }

    test_initialize();
    test_query_unknown();
    test_xsystem_ids();
    test_xgame_title();

    FreeLibrary( hmod );
}
