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

/* RuntimeClass names for all known Windows.Xbox.* classes */
#define RC_XBOX_INPUT_CONTROLLER            L"Windows.Xbox.Input.Controller"
#define RC_XBOX_INPUT_GAMEPAD               L"Windows.Xbox.Input.Gamepad"
#define RC_XBOX_INPUT_NAVCONTROLLER         L"Windows.Xbox.Input.NavigationController"
#define RC_XBOX_INPUT_BODYCONTROLLER        L"Windows.Xbox.Input.BodyController"

#define RC_XBOX_SYSTEM_USER                 L"Windows.Xbox.System.User"
#define RC_XBOX_SYSTEM_USERDISPLAYINFO      L"Windows.Xbox.System.UserDisplayInfo"
#define RC_XBOX_SYSTEM_AUDIODEVICEINFO      L"Windows.Xbox.System.AudioDeviceInfo"

#define RC_XBOX_APPMODEL_PACKAGE            L"Windows.Xbox.ApplicationModel.Package"
#define RC_XBOX_APPMODEL_CURRENT            L"Windows.Xbox.ApplicationModel.Package.Current"

#define RC_XBOX_UI_SYSTEMUI                 L"Windows.Xbox.UI.SystemUI"

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

    /* Windows.Xbox.Input — gamepad/controller input */
    if (!wcscmp( name, RC_XBOX_INPUT_GAMEPAD ) ||
        !wcscmp( name, RC_XBOX_INPUT_CONTROLLER ) ||
        !wcscmp( name, RC_XBOX_INPUT_NAVCONTROLLER ) ||
        !wcscmp( name, RC_XBOX_INPUT_BODYCONTROLLER ))
    {
        FIXME("Windows.Xbox.Input class %s not implemented, "
              "see windows.gaming.input for PC equivalent\n",
              debugstr_w(name));
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    /* Windows.Xbox.System — user management */
    if (!wcscmp( name, RC_XBOX_SYSTEM_USER ) ||
        !wcscmp( name, RC_XBOX_SYSTEM_USERDISPLAYINFO ) ||
        !wcscmp( name, RC_XBOX_SYSTEM_AUDIODEVICEINFO ))
    {
        FIXME("Windows.Xbox.System class %s not implemented\n", debugstr_w(name));
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    /* Everything else — generic stub */
    FIXME("Xbox WinRT class %s not implemented!\n", debugstr_hstring(classid));
    return CLASS_E_CLASSNOTAVAILABLE;
}

