/* WinRT Windows.Xbox.* namespace stubs
 *
 * Provides stub activation factories for Xbox One ERA WinRT namespaces.
 * Based on interface definitions from WinDurango/WinDurango (MIT).
 *
 * Namespaces covered:
 *   Windows.Xbox.Input
 *   Windows.Xbox.System
 *   Windows.Xbox.ApplicationModel
 *   Windows.Xbox.UI
 *   Windows.Xbox.Networking
 *   Windows.Xbox.Multiplayer
 *   Windows.Xbox.Chat
 *   Windows.Xbox.Storage
 *   Windows.Xbox.Achievements
 *   Windows.Xbox.Speech.Recognition
 *   Windows.Xbox.Management.Deployment
 *   Windows.Xbox.Media.GameTransportControls
 *   Windows.Xbox.Services
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "winstring.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(xbox);

HRESULT WINAPI DllGetClassObject( REFCLSID clsid, REFIID riid, void **out )
{
    FIXME( "clsid %s, riid %s, out %p stub!\n", debugstr_guid(clsid), debugstr_guid(riid), out );
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllCanUnloadNow(void)
{
    return S_FALSE;
}

HRESULT WINAPI DllGetActivationFactory( HSTRING classid, IActivationFactory **factory )
{
    const WCHAR *name = WindowsGetStringRawBuffer( classid, NULL );

    TRACE( "class %s, factory %p\n", debugstr_hstring(classid), factory );

    *factory = NULL;

    /* All Windows.Xbox.* classes are stubbed - games can load and see
     * we exist, but functionality is not implemented yet. */
    FIXME("class %s not implemented!\n", debugstr_hstring(classid));
    return CLASS_E_CLASSNOTAVAILABLE;
}
