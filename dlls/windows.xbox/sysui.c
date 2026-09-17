/* WinRT Windows.Xbox.UI.SystemUI implementation
 *
 * Stub factory: all system UI methods return S_OK so ERA games can proceed
 * past UI-availability checks.  Based on WinDurango Windows.Xbox.UI.idl (MIT).
 */

#include "private.h"

WINE_DEFAULT_DEBUG_CHANNEL(xbox);

static const WCHAR RuntimeClass_SystemUI[] = L"Windows.Xbox.UI.SystemUI";

/* ======================================================================
 * ISystemUIStatics — all show-* methods stub as FIXME
 * ====================================================================== */
typedef struct ISystemUIStatics ISystemUIStatics;
typedef struct ISystemUIStaticsVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ISystemUIStatics*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ISystemUIStatics*);
    ULONG   (STDMETHODCALLTYPE *Release)(ISystemUIStatics*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(ISystemUIStatics*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(ISystemUIStatics*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(ISystemUIStatics*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *ShowProfileCardAsync)(ISystemUIStatics*, void* user, void** async_op);
    HRESULT (STDMETHODCALLTYPE *ShowChangeFriendRelationshipAsync)(ISystemUIStatics*, void* user, void** async_op);
    HRESULT (STDMETHODCALLTYPE *ShowTitleAchievementsAsync)(ISystemUIStatics*, UINT32 title_id, void** async_op);
    HRESULT (STDMETHODCALLTYPE *HasSyncOccurred)(ISystemUIStatics*, boolean*);
    HRESULT (STDMETHODCALLTYPE *ShowSendGameInvitesAsync)(ISystemUIStatics*, void* user, void* session_ref, void** async_op);
    HRESULT (STDMETHODCALLTYPE *ShowAchievementNotificationAsync)(ISystemUIStatics*, void* user, UINT32 title_id, HSTRING achievement_id, void** async_op);
} ISystemUIStaticsVtbl;
struct ISystemUIStatics { CONST_VTBL ISystemUIStaticsVtbl *lpVtbl; };

static const GUID IID_ISystemUIStatics =
    {0x7c2d4cf7, 0x1e8f, 0x5dd7, {0xa3, 0xb4, 0x62, 0x13, 0xd0, 0xb4, 0xde, 0x62}};

struct sysui_statics {
    IActivationFactory IActivationFactory_iface;
    ISystemUIStatics   ISystemUIStatics_iface;
    LONG ref;
};

static inline struct sysui_statics *impl_af_from_su(IActivationFactory *iface)
{ return CONTAINING_RECORD(iface, struct sysui_statics, IActivationFactory_iface); }

static inline struct sysui_statics *impl_su_from_su(ISystemUIStatics *iface)
{ return CONTAINING_RECORD(iface, struct sysui_statics, ISystemUIStatics_iface); }

/* ---- IActivationFactory ---- */
static HRESULT STDMETHODCALLTYPE su_af_QI(IActivationFactory *iface, REFIID iid, void **out)
{
    struct sysui_statics *impl = impl_af_from_su(iface);
    if (IsEqualGUID(iid, &IID_IUnknown)        ||
        IsEqualGUID(iid, &IID_IInspectable)    ||
        IsEqualGUID(iid, &IID_IActivationFactory))
    { *out = &impl->IActivationFactory_iface; IUnknown_AddRef((IUnknown *)*out); return S_OK; }
    if (IsEqualGUID(iid, &IID_ISystemUIStatics))
    { *out = &impl->ISystemUIStatics_iface; IUnknown_AddRef((IUnknown *)*out); return S_OK; }
    FIXME("%s not implemented\n", debugstr_guid(iid));
    *out = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE su_af_AddRef(IActivationFactory *iface)
{ return InterlockedIncrement(&impl_af_from_su(iface)->ref); }
static ULONG STDMETHODCALLTYPE su_af_Release(IActivationFactory *iface)
{ return InterlockedDecrement(&impl_af_from_su(iface)->ref); }
static HRESULT STDMETHODCALLTYPE su_af_GetIids(IActivationFactory *iface, ULONG *n, IID **ids)
{ *n = 0; *ids = NULL; return S_OK; }
static HRESULT STDMETHODCALLTYPE su_af_GetRTCN(IActivationFactory *iface, HSTRING *cn)
{ return WindowsCreateString(RuntimeClass_SystemUI, wcslen(RuntimeClass_SystemUI), cn); }
static HRESULT STDMETHODCALLTYPE su_af_GetTL(IActivationFactory *iface, TrustLevel *tl)
{ *tl = BaseTrust; return S_OK; }
static HRESULT STDMETHODCALLTYPE su_af_Activate(IActivationFactory *iface, IInspectable **inst)
{ *inst = NULL; return E_NOTIMPL; }

static const IActivationFactoryVtbl su_af_vtbl =
{
    su_af_QI, su_af_AddRef, su_af_Release,
    su_af_GetIids, su_af_GetRTCN, su_af_GetTL,
    su_af_Activate,
};

/* ---- ISystemUIStatics methods ---- */
static HRESULT STDMETHODCALLTYPE su_QI(ISystemUIStatics *iface, REFIID iid, void **out)
{ return IActivationFactory_QueryInterface(&impl_su_from_su(iface)->IActivationFactory_iface, iid, out); }
static ULONG STDMETHODCALLTYPE su_AddRef(ISystemUIStatics *iface)
{ return IActivationFactory_AddRef(&impl_su_from_su(iface)->IActivationFactory_iface); }
static ULONG STDMETHODCALLTYPE su_Release(ISystemUIStatics *iface)
{ return IActivationFactory_Release(&impl_su_from_su(iface)->IActivationFactory_iface); }
static HRESULT STDMETHODCALLTYPE su_GetIids(ISystemUIStatics *iface, ULONG *n, IID **ids)
{ *n = 0; *ids = NULL; return S_OK; }
static HRESULT STDMETHODCALLTYPE su_GetRTCN(ISystemUIStatics *iface, HSTRING *cn)
{ return WindowsCreateString(RuntimeClass_SystemUI, wcslen(RuntimeClass_SystemUI), cn); }
static HRESULT STDMETHODCALLTYPE su_GetTL(ISystemUIStatics *iface, TrustLevel *tl)
{ *tl = BaseTrust; return S_OK; }

/* Minimal completed IAsyncOperation returning NULL result, used for all show ops */
typedef struct su_async su_async;
typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(su_async*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(su_async*);
    ULONG   (STDMETHODCALLTYPE *Release)(su_async*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(su_async*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(su_async*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(su_async*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *get_Id)(su_async*, UINT32*);
    HRESULT (STDMETHODCALLTYPE *get_Status)(su_async*, AsyncStatus*);
    HRESULT (STDMETHODCALLTYPE *get_ErrorCode)(su_async*, HRESULT*);
    HRESULT (STDMETHODCALLTYPE *Cancel)(su_async*);
    HRESULT (STDMETHODCALLTYPE *Close)(su_async*);
    HRESULT (STDMETHODCALLTYPE *put_Completed)(su_async*, void*);
    HRESULT (STDMETHODCALLTYPE *get_Completed)(su_async*, void**);
    HRESULT (STDMETHODCALLTYPE *GetResults)(su_async*, void**);
} su_async_vtbl;
struct su_async { CONST_VTBL su_async_vtbl *lpVtbl; LONG ref; };

typedef struct { HRESULT (STDMETHODCALLTYPE *QI)(void*,REFIID,void**);
                 ULONG   (STDMETHODCALLTYPE *AddRef)(void*);
                 ULONG   (STDMETHODCALLTYPE *Release)(void*);
                 HRESULT (STDMETHODCALLTYPE *Invoke)(void*,su_async*,AsyncStatus); } su_handler_vtbl;

static HRESULT STDMETHODCALLTYPE sa_QI(su_async *a, REFIID iid, void **out)
{ if (IsEqualGUID(iid,&IID_IUnknown)||IsEqualGUID(iid,&IID_IInspectable)||IsEqualGUID(iid,&IID_IAsyncInfo))
  { InterlockedIncrement(&a->ref); *out=a; return S_OK; } *out=NULL; return E_NOINTERFACE; }
static ULONG STDMETHODCALLTYPE sa_AddRef(su_async *a)  { return InterlockedIncrement(&a->ref); }
static ULONG STDMETHODCALLTYPE sa_Release(su_async *a)
{ ULONG r=InterlockedDecrement(&a->ref); if(!r) HeapFree(GetProcessHeap(),0,a); return r; }
static HRESULT STDMETHODCALLTYPE sa_GetIids(su_async *a,ULONG *n,IID **ids){*n=0;*ids=NULL;return S_OK;}
static HRESULT STDMETHODCALLTYPE sa_GetRTCN(su_async *a,HSTRING *cn){*cn=NULL;return S_OK;}
static HRESULT STDMETHODCALLTYPE sa_GetTL(su_async *a,TrustLevel *tl){*tl=BaseTrust;return S_OK;}
static HRESULT STDMETHODCALLTYPE sa_get_Id(su_async *a,UINT32 *id){*id=1;return S_OK;}
static HRESULT STDMETHODCALLTYPE sa_get_Status(su_async *a,AsyncStatus *s){*s=Completed;return S_OK;}
static HRESULT STDMETHODCALLTYPE sa_get_ErrorCode(su_async *a,HRESULT *hr){*hr=S_OK;return S_OK;}
static HRESULT STDMETHODCALLTYPE sa_Cancel(su_async *a){return S_OK;}
static HRESULT STDMETHODCALLTYPE sa_Close(su_async *a){return S_OK;}
static HRESULT STDMETHODCALLTYPE sa_put_Completed(su_async *a, void *handler)
{
    if (handler) {
        su_handler_vtbl **h = (su_handler_vtbl **)handler;
        (*h)->Invoke(handler, a, Completed);
    }
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE sa_get_Completed(su_async *a,void **h){*h=NULL;return S_OK;}
static HRESULT STDMETHODCALLTYPE sa_GetResults(su_async *a,void **out){*out=NULL;return S_OK;}

static const su_async_vtbl sa_vtbl = {
    sa_QI, sa_AddRef, sa_Release, sa_GetIids, sa_GetRTCN, sa_GetTL,
    sa_get_Id, sa_get_Status, sa_get_ErrorCode, sa_Cancel, sa_Close,
    sa_put_Completed, sa_get_Completed, sa_GetResults,
};

static HRESULT make_null_async(void **out)
{
    su_async *a = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*a));
    if (!a) return E_OUTOFMEMORY;
    a->lpVtbl = &sa_vtbl;
    a->ref = 1;
    *out = a;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE su_ShowProfileCard(ISystemUIStatics *iface, void *user, void **out)
{ TRACE("(%p, %p, %p)\n", iface, user, out); return make_null_async(out); }

static HRESULT STDMETHODCALLTYPE su_ShowChangeFriendRelationship(ISystemUIStatics *iface, void *user, void **out)
{ TRACE("(%p, %p, %p)\n", iface, user, out); return make_null_async(out); }

static HRESULT STDMETHODCALLTYPE su_ShowTitleAchievements(ISystemUIStatics *iface, UINT32 tid, void **out)
{ TRACE("(%p, %u, %p)\n", iface, tid, out); return make_null_async(out); }

static HRESULT STDMETHODCALLTYPE su_HasSyncOccurred(ISystemUIStatics *iface, boolean *value)
{ TRACE("(%p, %p)\n", iface, value); *value = TRUE; return S_OK; }

static HRESULT STDMETHODCALLTYPE su_ShowSendGameInvites(ISystemUIStatics *iface, void *user,
    void *session_ref, void **out)
{ TRACE("(%p, %p, %p, %p)\n", iface, user, session_ref, out); return make_null_async(out); }

static HRESULT STDMETHODCALLTYPE su_ShowAchievementNotification(ISystemUIStatics *iface,
    void *user, UINT32 tid, HSTRING achievement_id, void **out)
{ TRACE("(%p, %p, %u, %p, %p)\n", iface, user, tid, achievement_id, out); return make_null_async(out); }

static const ISystemUIStaticsVtbl su_vtbl =
{
    su_QI, su_AddRef, su_Release,
    su_GetIids, su_GetRTCN, su_GetTL,
    su_ShowProfileCard,
    su_ShowChangeFriendRelationship,
    su_ShowTitleAchievements,
    su_HasSyncOccurred,
    su_ShowSendGameInvites,
    su_ShowAchievementNotification,
};

static struct sysui_statics sysui_statics_instance =
{
    {&su_af_vtbl},
    {&su_vtbl},
    1
};

IActivationFactory *xbox_sysui_factory = &sysui_statics_instance.IActivationFactory_iface;
