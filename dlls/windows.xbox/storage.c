/* WinRT Windows.Xbox.Storage.ConnectedStorageSpace implementation
 *
 * Provides save-container support backed by the local filesystem under
 * %LOCALAPPDATA%\WineEX\ConnectedStorage\.  Async operations complete
 * synchronously: the Completed handler is invoked during put_Completed,
 * which is safe because ERA games always call put_Completed before waiting.
 *
 * Interface GUIDs from WinDurango Windows.Xbox.Storage.idl (MIT).
 */

#include "private.h"
#include "asyncinfo.h"
#include "shellapi.h"
#include "shlobj.h"

/* ======================================================================
 * Local IVectorView<HSTRING> / IIterable<HSTRING> / IIterator<HSTRING>
 * Used to return blob-name lists from GetNamesAsync.
 * ====================================================================== */

struct hstr_iter;
struct hstr_view;

struct hstr_iter {
    IIterator_HSTRING IIterator_HSTRING_iface;
    LONG ref;
    IVectorView_HSTRING *view;
    UINT32 index;
    UINT32 size;
};

static inline struct hstr_iter *impl_from_hstr_iter(IIterator_HSTRING *iface)
{ return CONTAINING_RECORD(iface, struct hstr_iter, IIterator_HSTRING_iface); }

static HRESULT STDMETHODCALLTYPE hstr_iter_QI(IIterator_HSTRING *iface, REFIID iid, void **out)
{
    struct hstr_iter *impl = impl_from_hstr_iter(iface);
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IIterator_HSTRING))
    { IInspectable_AddRef((*out = &impl->IIterator_HSTRING_iface)); return S_OK; }
    *out = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE hstr_iter_AddRef(IIterator_HSTRING *iface)
{ return InterlockedIncrement(&impl_from_hstr_iter(iface)->ref); }
static ULONG STDMETHODCALLTYPE hstr_iter_Release(IIterator_HSTRING *iface)
{
    struct hstr_iter *impl = impl_from_hstr_iter(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    if (!ref) { IVectorView_HSTRING_Release(impl->view); HeapFree(GetProcessHeap(), 0, impl); }
    return ref;
}
static HRESULT STDMETHODCALLTYPE hstr_iter_GetIids(IIterator_HSTRING *iface, ULONG *n, IID **ids)
{ *n = 0; *ids = NULL; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_iter_GetRTCN(IIterator_HSTRING *iface, HSTRING *cn)
{ *cn = NULL; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_iter_GetTL(IIterator_HSTRING *iface, TrustLevel *tl)
{ *tl = BaseTrust; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_iter_get_Current(IIterator_HSTRING *iface, HSTRING *val)
{ return IVectorView_HSTRING_GetAt(impl_from_hstr_iter(iface)->view, impl_from_hstr_iter(iface)->index, val); }
static HRESULT STDMETHODCALLTYPE hstr_iter_get_HasCurrent(IIterator_HSTRING *iface, boolean *val)
{ *val = impl_from_hstr_iter(iface)->index < impl_from_hstr_iter(iface)->size; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_iter_MoveNext(IIterator_HSTRING *iface, boolean *val)
{
    struct hstr_iter *impl = impl_from_hstr_iter(iface);
    if (impl->index < impl->size) impl->index++;
    return hstr_iter_get_HasCurrent(iface, val);
}
static HRESULT STDMETHODCALLTYPE hstr_iter_GetMany(IIterator_HSTRING *iface, UINT32 n,
    HSTRING *items, UINT *count)
{ return IVectorView_HSTRING_GetMany(impl_from_hstr_iter(iface)->view,
      impl_from_hstr_iter(iface)->index, n, items, count); }

static const IIterator_HSTRINGVtbl hstr_iter_vtbl = {
    hstr_iter_QI, hstr_iter_AddRef, hstr_iter_Release,
    hstr_iter_GetIids, hstr_iter_GetRTCN, hstr_iter_GetTL,
    hstr_iter_get_Current, hstr_iter_get_HasCurrent, hstr_iter_MoveNext, hstr_iter_GetMany,
};

struct hstr_view {
    IVectorView_HSTRING IVectorView_HSTRING_iface;
    IIterable_HSTRING   IIterable_HSTRING_iface;
    LONG ref;
    UINT32 count;
    HSTRING names[1];
};

static inline struct hstr_view *impl_from_hstr_view(IVectorView_HSTRING *iface)
{ return CONTAINING_RECORD(iface, struct hstr_view, IVectorView_HSTRING_iface); }
static inline struct hstr_view *impl_from_hstr_iterable(IIterable_HSTRING *iface)
{ return CONTAINING_RECORD(iface, struct hstr_view, IIterable_HSTRING_iface); }

static void hstr_view_destroy(struct hstr_view *impl)
{
    UINT32 i;
    for (i = 0; i < impl->count; i++) WindowsDeleteString(impl->names[i]);
    HeapFree(GetProcessHeap(), 0, impl);
}

static HRESULT STDMETHODCALLTYPE hstr_view_QI(IVectorView_HSTRING *iface, REFIID iid, void **out)
{
    struct hstr_view *impl = impl_from_hstr_view(iface);
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IVectorView_HSTRING))
    { IInspectable_AddRef((*out = &impl->IVectorView_HSTRING_iface)); return S_OK; }
    if (IsEqualGUID(iid, &IID_IIterable_HSTRING))
    { IInspectable_AddRef((*out = &impl->IIterable_HSTRING_iface)); return S_OK; }
    *out = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE hstr_view_AddRef(IVectorView_HSTRING *iface)
{ return InterlockedIncrement(&impl_from_hstr_view(iface)->ref); }
static ULONG STDMETHODCALLTYPE hstr_view_Release(IVectorView_HSTRING *iface)
{
    struct hstr_view *impl = impl_from_hstr_view(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    if (!ref) hstr_view_destroy(impl);
    return ref;
}
static HRESULT STDMETHODCALLTYPE hstr_view_GetIids(IVectorView_HSTRING *iface, ULONG *n, IID **ids)
{ *n = 0; *ids = NULL; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_view_GetRTCN(IVectorView_HSTRING *iface, HSTRING *cn)
{ *cn = NULL; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_view_GetTL(IVectorView_HSTRING *iface, TrustLevel *tl)
{ *tl = BaseTrust; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_view_GetAt(IVectorView_HSTRING *iface, UINT32 idx, HSTRING *val)
{
    struct hstr_view *impl = impl_from_hstr_view(iface);
    if (idx >= impl->count) { *val = NULL; return E_BOUNDS; }
    return WindowsDuplicateString(impl->names[idx], val);
}
static HRESULT STDMETHODCALLTYPE hstr_view_get_Size(IVectorView_HSTRING *iface, UINT32 *val)
{ *val = impl_from_hstr_view(iface)->count; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_view_IndexOf(IVectorView_HSTRING *iface, HSTRING elem,
    UINT32 *idx, BOOLEAN *found)
{
    struct hstr_view *impl = impl_from_hstr_view(iface);
    UINT32 i;
    for (i = 0; i < impl->count; i++)
        if (WindowsIsStringEmpty(elem) ? WindowsIsStringEmpty(impl->names[i])
            : CompareStringOrdinal(WindowsGetStringRawBuffer(impl->names[i], NULL), -1,
                                   WindowsGetStringRawBuffer(elem, NULL), -1, FALSE) == CSTR_EQUAL)
            break;
    if ((*found = i < impl->count)) *idx = i; else *idx = 0;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE hstr_view_GetMany(IVectorView_HSTRING *iface, UINT32 start,
    UINT32 n, HSTRING *items, UINT *count)
{
    struct hstr_view *impl = impl_from_hstr_view(iface);
    UINT32 i; HRESULT hr;
    if (start >= impl->count) { *count = 0; return E_BOUNDS; }
    for (i = start; i < impl->count && i - start < n; i++)
        if (FAILED(hr = WindowsDuplicateString(impl->names[i], &items[i - start])))
        { *count = 0; return hr; }
    *count = i - start;
    return S_OK;
}

static const IVectorView_HSTRINGVtbl hstr_view_vtbl = {
    hstr_view_QI, hstr_view_AddRef, hstr_view_Release,
    hstr_view_GetIids, hstr_view_GetRTCN, hstr_view_GetTL,
    hstr_view_GetAt, hstr_view_get_Size, hstr_view_IndexOf, hstr_view_GetMany,
};

/* IIterable<HSTRING> face of hstr_view */
static HRESULT STDMETHODCALLTYPE hstr_itbl_QI(IIterable_HSTRING *iface, REFIID iid, void **out)
{ return hstr_view_QI(&impl_from_hstr_iterable(iface)->IVectorView_HSTRING_iface, iid, out); }
static ULONG STDMETHODCALLTYPE hstr_itbl_AddRef(IIterable_HSTRING *iface)
{ return hstr_view_AddRef(&impl_from_hstr_iterable(iface)->IVectorView_HSTRING_iface); }
static ULONG STDMETHODCALLTYPE hstr_itbl_Release(IIterable_HSTRING *iface)
{ return hstr_view_Release(&impl_from_hstr_iterable(iface)->IVectorView_HSTRING_iface); }
static HRESULT STDMETHODCALLTYPE hstr_itbl_GetIids(IIterable_HSTRING *iface, ULONG *n, IID **ids)
{ *n = 0; *ids = NULL; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_itbl_GetRTCN(IIterable_HSTRING *iface, HSTRING *cn)
{ *cn = NULL; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_itbl_GetTL(IIterable_HSTRING *iface, TrustLevel *tl)
{ *tl = BaseTrust; return S_OK; }
static HRESULT STDMETHODCALLTYPE hstr_itbl_First(IIterable_HSTRING *iface, IIterator_HSTRING **out)
{
    struct hstr_view *vimpl = impl_from_hstr_iterable(iface);
    struct hstr_iter *iter = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*iter));
    if (!iter) return E_OUTOFMEMORY;
    iter->IIterator_HSTRING_iface.lpVtbl = &hstr_iter_vtbl;
    iter->ref = 1;
    IVectorView_HSTRING_AddRef((iter->view = &vimpl->IVectorView_HSTRING_iface));
    iter->size = vimpl->count;
    *out = &iter->IIterator_HSTRING_iface;
    return S_OK;
}
static const IIterable_HSTRINGVtbl hstr_itbl_vtbl = {
    hstr_itbl_QI, hstr_itbl_AddRef, hstr_itbl_Release,
    hstr_itbl_GetIids, hstr_itbl_GetRTCN, hstr_itbl_GetTL,
    hstr_itbl_First,
};

static HRESULT hstr_view_create(const WCHAR **names_w, UINT32 count, IVectorView_HSTRING **out)
{
    struct hstr_view *impl;
    UINT32 i;
    HRESULT hr;

    impl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        offsetof(struct hstr_view, names[count ? count : 1]));
    if (!impl) return E_OUTOFMEMORY;
    impl->IVectorView_HSTRING_iface.lpVtbl = &hstr_view_vtbl;
    impl->IIterable_HSTRING_iface.lpVtbl  = &hstr_itbl_vtbl;
    impl->ref   = 1;
    impl->count = count;
    for (i = 0; i < count; i++)
    {
        if (FAILED(hr = WindowsCreateString(names_w[i], lstrlenW(names_w[i]), &impl->names[i])))
        { impl->count = i; hstr_view_destroy(impl); return hr; }
    }
    *out = &impl->IVectorView_HSTRING_iface;
    return S_OK;
}

WINE_DEFAULT_DEBUG_CHANNEL(xbox);

static const WCHAR RuntimeClass_ConnectedStorageSpace[] =
    L"Windows.Xbox.Storage.ConnectedStorageSpace";
static const WCHAR RuntimeClass_ConnectedStorageContainer[] =
    L"Windows.Xbox.Storage.ConnectedStorageContainer";

/* ======================================================================
 * Forward declarations
 * ====================================================================== */
typedef struct IConnectedStorageSpace IConnectedStorageSpace;
typedef struct IConnectedStorageSpaceStatics IConnectedStorageSpaceStatics;
typedef struct IConnectedStorageContainer IConnectedStorageContainer;

/* ======================================================================
 * Generic immediately-completed IAsyncOperation<IInspectable*>
 *
 * Vtbl layout matches the WinRT IAsyncOperation<T> vtable exactly:
 *   IInspectable (QI/AddRef/Release/GetIids/GetRTCN/GetTL)
 *   IAsyncInfo   (get_Id/get_Status/get_ErrorCode/Cancel/Close)
 *   IAsyncOperation<T> (put_Completed/get_Completed/GetResults)
 *
 * We use the same struct for every result type; callers receive it as
 * void** and only call the methods through their own strongly-typed vtbl
 * pointer, so the opaque IInspectable* result slot works for any T.
 * ====================================================================== */
typedef struct async_op async_op;
typedef struct async_op_vtbl {
    /* IUnknown / IInspectable */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(async_op*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(async_op*);
    ULONG   (STDMETHODCALLTYPE *Release)(async_op*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(async_op*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(async_op*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(async_op*, TrustLevel*);
    /* IAsyncInfo */
    HRESULT (STDMETHODCALLTYPE *get_Id)(async_op*, UINT32*);
    HRESULT (STDMETHODCALLTYPE *get_Status)(async_op*, AsyncStatus*);
    HRESULT (STDMETHODCALLTYPE *get_ErrorCode)(async_op*, HRESULT*);
    HRESULT (STDMETHODCALLTYPE *Cancel)(async_op*);
    HRESULT (STDMETHODCALLTYPE *Close)(async_op*);
    /* IAsyncOperation<T> */
    HRESULT (STDMETHODCALLTYPE *put_Completed)(async_op*, void* handler);
    HRESULT (STDMETHODCALLTYPE *get_Completed)(async_op*, void** handler);
    HRESULT (STDMETHODCALLTYPE *GetResults)(async_op*, void** out);
} async_op_vtbl;

struct async_op {
    CONST_VTBL async_op_vtbl *lpVtbl;
    LONG ref;
    IInspectable *result;   /* NULL for void operations */
    const GUID *iid_result; /* IID of result interface (for QI on caller side) */
};

/* Completed-handler typedef: matches IAsyncOperationCompletedHandler<T>::Invoke */
typedef struct async_handler_iface async_handler_iface;
typedef struct async_handler_vtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(async_handler_iface*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(async_handler_iface*);
    ULONG   (STDMETHODCALLTYPE *Release)(async_handler_iface*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(async_handler_iface*, async_op*, AsyncStatus);
} async_handler_vtbl;
struct async_handler_iface { CONST_VTBL async_handler_vtbl *lpVtbl; };

static HRESULT STDMETHODCALLTYPE aop_QI(async_op *op, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IUnknown) ||
        IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAsyncInfo))
    {
        *out = op;
        InterlockedIncrement(&op->ref);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE aop_AddRef(async_op *op)
{
    return InterlockedIncrement(&op->ref);
}

static ULONG STDMETHODCALLTYPE aop_Release(async_op *op)
{
    ULONG ref = InterlockedDecrement(&op->ref);
    if (!ref)
    {
        if (op->result) IInspectable_Release(op->result);
        HeapFree(GetProcessHeap(), 0, op);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE aop_GetIids(async_op *op, ULONG *n, IID **ids)
{ *n = 0; *ids = NULL; return S_OK; }

static HRESULT STDMETHODCALLTYPE aop_GetRTCN(async_op *op, HSTRING *cn)
{ return WindowsCreateString(L"Windows.Foundation.IAsyncOperation`1", 37, cn); }

static HRESULT STDMETHODCALLTYPE aop_GetTL(async_op *op, TrustLevel *tl)
{ *tl = BaseTrust; return S_OK; }

static HRESULT STDMETHODCALLTYPE aop_get_Id(async_op *op, UINT32 *id)
{ *id = 1; return S_OK; }

static HRESULT STDMETHODCALLTYPE aop_get_Status(async_op *op, AsyncStatus *s)
{ *s = Completed; return S_OK; }

static HRESULT STDMETHODCALLTYPE aop_get_ErrorCode(async_op *op, HRESULT *hr)
{ *hr = S_OK; return S_OK; }

static HRESULT STDMETHODCALLTYPE aop_Cancel(async_op *op) { return S_OK; }
static HRESULT STDMETHODCALLTYPE aop_Close(async_op *op) { return S_OK; }

static HRESULT STDMETHODCALLTYPE aop_put_Completed(async_op *op, void *handler)
{
    /* Fire immediately — we're already in Completed state */
    if (handler)
    {
        async_handler_iface *h = (async_handler_iface *)handler;
        h->lpVtbl->Invoke(h, op, Completed);
    }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE aop_get_Completed(async_op *op, void **handler)
{ *handler = NULL; return S_OK; }

static HRESULT STDMETHODCALLTYPE aop_GetResults(async_op *op, void **out)
{
    if (op->result)
    {
        IInspectable_AddRef(op->result);
        *out = op->result;
    }
    else
        *out = NULL;
    return S_OK;
}

static const async_op_vtbl async_op_impl_vtbl =
{
    aop_QI, aop_AddRef, aop_Release,
    aop_GetIids, aop_GetRTCN, aop_GetTL,
    aop_get_Id, aop_get_Status, aop_get_ErrorCode, aop_Cancel, aop_Close,
    aop_put_Completed, aop_get_Completed, aop_GetResults,
};

static HRESULT async_op_create(IInspectable *result, async_op **out)
{
    async_op *op = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*op));
    if (!op) return E_OUTOFMEMORY;
    op->lpVtbl = &async_op_impl_vtbl;
    op->ref = 1;
    op->result = result;
    if (result) IInspectable_AddRef(result);
    *out = op;
    return S_OK;
}

/* ======================================================================
 * IConnectedStorageContainer
 * ====================================================================== */
typedef struct IConnectedStorageContainerVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IConnectedStorageContainer*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IConnectedStorageContainer*);
    ULONG   (STDMETHODCALLTYPE *Release)(IConnectedStorageContainer*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IConnectedStorageContainer*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IConnectedStorageContainer*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IConnectedStorageContainer*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *SubmitUpdatesAsync)(IConnectedStorageContainer*, void* updates, void* deletes, void** async_op);
    HRESULT (STDMETHODCALLTYPE *ReadAsync)(IConnectedStorageContainer*, void* reads, void** async_op);
    HRESULT (STDMETHODCALLTYPE *GetNamesAsync)(IConnectedStorageContainer*, void** async_op);
    HRESULT (STDMETHODCALLTYPE *DeleteAsync)(IConnectedStorageContainer*, void* names, void** async_op);
} IConnectedStorageContainerVtbl;
struct IConnectedStorageContainer { CONST_VTBL IConnectedStorageContainerVtbl *lpVtbl; };

static const GUID IID_IConnectedStorageContainer =
    {0x3c4a3b6c, 0x8a62, 0x5f90, {0xa7, 0x32, 0x89, 0xa3, 0x1b, 0x3c, 0x91, 0x22}};

struct container_obj {
    IConnectedStorageContainer IConnectedStorageContainer_iface;
    LONG ref;
    WCHAR path[MAX_PATH]; /* backing directory */
};

static inline struct container_obj *impl_from_container(IConnectedStorageContainer *iface)
{
    return CONTAINING_RECORD(iface, struct container_obj, IConnectedStorageContainer_iface);
}

static HRESULT STDMETHODCALLTYPE container_QI(IConnectedStorageContainer *iface, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IUnknown) ||
        IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IConnectedStorageContainer))
    {
        *out = iface;
        IUnknown_AddRef((IUnknown *)*out);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE container_AddRef(IConnectedStorageContainer *iface)
{
    struct container_obj *impl = impl_from_container(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG STDMETHODCALLTYPE container_Release(IConnectedStorageContainer *iface)
{
    struct container_obj *impl = impl_from_container(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    if (!ref) HeapFree(GetProcessHeap(), 0, impl);
    return ref;
}

static HRESULT STDMETHODCALLTYPE container_GetIids(IConnectedStorageContainer *iface, ULONG *n, IID **ids)
{ *n = 0; *ids = NULL; return S_OK; }

static HRESULT STDMETHODCALLTYPE container_GetRTCN(IConnectedStorageContainer *iface, HSTRING *cn)
{ return WindowsCreateString(RuntimeClass_ConnectedStorageContainer,
      wcslen(RuntimeClass_ConnectedStorageContainer), cn); }

static HRESULT STDMETHODCALLTYPE container_GetTL(IConnectedStorageContainer *iface, TrustLevel *tl)
{ *tl = BaseTrust; return S_OK; }

static HRESULT STDMETHODCALLTYPE container_SubmitUpdatesAsync(IConnectedStorageContainer *iface,
    void *updates, void *deletes, void **out)
{
    struct container_obj *impl = impl_from_container(iface);
    async_op *op;
    HRESULT hr;

    TRACE("(%p, updates %p, deletes %p, %p)\n", iface, updates, deletes, out);

    /* Delete blobs named in the deletes IVectorView<HSTRING> */
    if (deletes)
    {
        IIterable_HSTRING *iterable = NULL;
        if (SUCCEEDED(IUnknown_QueryInterface((IUnknown *)deletes, &IID_IIterable_HSTRING,
            (void **)&iterable)))
        {
            IIterator_HSTRING *iter = NULL;
            boolean has;
            if (SUCCEEDED(IIterable_HSTRING_First(iterable, &iter)))
            {
                IIterator_HSTRING_get_HasCurrent(iter, &has);
                while (has)
                {
                    HSTRING name = NULL;
                    WCHAR path[MAX_PATH];
                    IIterator_HSTRING_get_Current(iter, &name);
                    lstrcpyW(path, impl->path);
                    lstrcatW(path, L"\\");
                    lstrcatW(path, WindowsGetStringRawBuffer(name, NULL));
                    DeleteFileW(path);
                    WindowsDeleteString(name);
                    IIterator_HSTRING_MoveNext(iter, &has);
                }
                IIterator_HSTRING_Release(iter);
            }
            IIterable_HSTRING_Release(iterable);
        }
    }

    /* updates is IMapView<HSTRING, IBuffer> — iterating requires parameterised IID;
     * log FIXME only when non-NULL so games that pass NULL updates don't spam. */
    if (updates)
        FIXME("(%p): updates IMapView<HSTRING,IBuffer> iteration not yet implemented\n", iface);

    hr = async_op_create(NULL, &op);
    if (SUCCEEDED(hr)) *out = op;
    return hr;
}

static HRESULT STDMETHODCALLTYPE container_ReadAsync(IConnectedStorageContainer *iface,
    void *reads, void **out)
{
    async_op *op;
    HRESULT hr;
    /* reads is IMapView<HSTRING,IBuffer> — filling IBuffer requires parameterised IID */
    FIXME("(%p, %p, %p): reads IMapView<HSTRING,IBuffer> not yet implemented\n", iface, reads, out);
    hr = async_op_create(NULL, &op);
    if (SUCCEEDED(hr)) *out = op;
    return hr;
}

static HRESULT STDMETHODCALLTYPE container_GetNamesAsync(IConnectedStorageContainer *iface, void **out)
{
    struct container_obj *impl = impl_from_container(iface);
    WIN32_FIND_DATAW data;
    HANDLE hfind;
    WCHAR pattern[MAX_PATH];
    const WCHAR **names_buf = NULL;
    UINT32 count = 0, cap = 0;
    async_op *op;
    IVectorView_HSTRING *view;
    HRESULT hr;

    TRACE("(%p, %p)\n", iface, out);

    lstrcpyW(pattern, impl->path);
    lstrcatW(pattern, L"\\*");

    hfind = FindFirstFileW(pattern, &data);
    if (hfind != INVALID_HANDLE_VALUE)
    {
        do {
            WCHAR *copy;
            if (!lstrcmpW(data.cFileName, L".") || !lstrcmpW(data.cFileName, L"..")) continue;
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (count >= cap)
            {
                UINT32 newcap = cap ? cap * 2 : 16;
                const WCHAR **tmp = HeapReAlloc(GetProcessHeap(), 0, names_buf,
                    newcap * sizeof(*names_buf));
                if (!tmp) { hr = E_OUTOFMEMORY; FindClose(hfind); goto cleanup; }
                names_buf = tmp; cap = newcap;
            }
            copy = HeapAlloc(GetProcessHeap(), 0, (lstrlenW(data.cFileName) + 1) * sizeof(WCHAR));
            if (!copy) { hr = E_OUTOFMEMORY; FindClose(hfind); goto cleanup; }
            lstrcpyW(copy, data.cFileName);
            names_buf[count++] = copy;
        } while (FindNextFileW(hfind, &data));
        FindClose(hfind);
    }

    hr = hstr_view_create(names_buf, count, &view);
    /* free the per-entry copies */
    { UINT32 i; for (i = 0; i < count; i++) HeapFree(GetProcessHeap(), 0, (void *)names_buf[i]); }
    HeapFree(GetProcessHeap(), 0, names_buf);
    if (FAILED(hr)) return hr;

    hr = async_op_create((IInspectable *)view, &op);
    IVectorView_HSTRING_Release(view);
    if (SUCCEEDED(hr)) *out = op;
    return hr;

cleanup:
    { UINT32 i; for (i = 0; i < count; i++) HeapFree(GetProcessHeap(), 0, (void *)names_buf[i]); }
    HeapFree(GetProcessHeap(), 0, names_buf);
    return hr;
}

static HRESULT STDMETHODCALLTYPE container_DeleteAsync(IConnectedStorageContainer *iface,
    void *names, void **out)
{
    struct container_obj *impl = impl_from_container(iface);
    async_op *op;
    HRESULT hr;

    TRACE("(%p, names %p, %p)\n", iface, names, out);

    if (names)
    {
        IIterable_HSTRING *iterable = NULL;
        if (SUCCEEDED(IUnknown_QueryInterface((IUnknown *)names, &IID_IIterable_HSTRING,
            (void **)&iterable)))
        {
            IIterator_HSTRING *iter = NULL;
            boolean has;
            if (SUCCEEDED(IIterable_HSTRING_First(iterable, &iter)))
            {
                IIterator_HSTRING_get_HasCurrent(iter, &has);
                while (has)
                {
                    HSTRING name = NULL;
                    WCHAR path[MAX_PATH];
                    IIterator_HSTRING_get_Current(iter, &name);
                    lstrcpyW(path, impl->path);
                    lstrcatW(path, L"\\");
                    lstrcatW(path, WindowsGetStringRawBuffer(name, NULL));
                    DeleteFileW(path);
                    WindowsDeleteString(name);
                    IIterator_HSTRING_MoveNext(iter, &has);
                }
                IIterator_HSTRING_Release(iter);
            }
            IIterable_HSTRING_Release(iterable);
        }
    }

    hr = async_op_create(NULL, &op);
    if (SUCCEEDED(hr)) *out = op;
    return hr;
}

static const IConnectedStorageContainerVtbl container_vtbl =
{
    container_QI,
    container_AddRef,
    container_Release,
    container_GetIids,
    container_GetRTCN,
    container_GetTL,
    container_SubmitUpdatesAsync,
    container_ReadAsync,
    container_GetNamesAsync,
    container_DeleteAsync,
};

static HRESULT container_create(const WCHAR *path, IConnectedStorageContainer **out)
{
    struct container_obj *impl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*impl));
    if (!impl) return E_OUTOFMEMORY;
    impl->IConnectedStorageContainer_iface.lpVtbl = &container_vtbl;
    impl->ref = 1;
    lstrcpynW(impl->path, path, MAX_PATH);
    CreateDirectoryW(path, NULL); /* create if not present */
    *out = &impl->IConnectedStorageContainer_iface;
    return S_OK;
}

/* ======================================================================
 * IConnectedStorageSpace
 * ====================================================================== */
typedef struct IConnectedStorageSpaceVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IConnectedStorageSpace*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IConnectedStorageSpace*);
    ULONG   (STDMETHODCALLTYPE *Release)(IConnectedStorageSpace*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IConnectedStorageSpace*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IConnectedStorageSpace*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IConnectedStorageSpace*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *CreateContainer)(IConnectedStorageSpace*, HSTRING name, IConnectedStorageContainer**);
    HRESULT (STDMETHODCALLTYPE *DeleteContainerAsync)(IConnectedStorageSpace*, HSTRING name, void** async_op);
    HRESULT (STDMETHODCALLTYPE *GetContainerNames)(IConnectedStorageSpace*, void** view);
} IConnectedStorageSpaceVtbl;
struct IConnectedStorageSpace { CONST_VTBL IConnectedStorageSpaceVtbl *lpVtbl; };

static const GUID IID_IConnectedStorageSpace =
    {0x40f52f87, 0x9c5e, 0x4f57, {0xb7, 0xf2, 0x4c, 0x3a, 0x3a, 0x4c, 0x5e, 0xa7}};

struct space_obj {
    IConnectedStorageSpace IConnectedStorageSpace_iface;
    LONG ref;
    WCHAR root[MAX_PATH]; /* %LOCALAPPDATA%\WineEX\ConnectedStorage\ */
};

static inline struct space_obj *impl_from_space(IConnectedStorageSpace *iface)
{
    return CONTAINING_RECORD(iface, struct space_obj, IConnectedStorageSpace_iface);
}

static HRESULT STDMETHODCALLTYPE space_QI(IConnectedStorageSpace *iface, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IUnknown) ||
        IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IConnectedStorageSpace))
    {
        *out = iface;
        IUnknown_AddRef((IUnknown *)*out);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE space_AddRef(IConnectedStorageSpace *iface)
{
    struct space_obj *impl = impl_from_space(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG STDMETHODCALLTYPE space_Release(IConnectedStorageSpace *iface)
{
    struct space_obj *impl = impl_from_space(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    if (!ref) HeapFree(GetProcessHeap(), 0, impl);
    return ref;
}

static HRESULT STDMETHODCALLTYPE space_GetIids(IConnectedStorageSpace *iface, ULONG *n, IID **ids)
{ *n = 0; *ids = NULL; return S_OK; }

static HRESULT STDMETHODCALLTYPE space_GetRTCN(IConnectedStorageSpace *iface, HSTRING *cn)
{ return WindowsCreateString(RuntimeClass_ConnectedStorageSpace,
      wcslen(RuntimeClass_ConnectedStorageSpace), cn); }

static HRESULT STDMETHODCALLTYPE space_GetTL(IConnectedStorageSpace *iface, TrustLevel *tl)
{ *tl = BaseTrust; return S_OK; }

static HRESULT STDMETHODCALLTYPE space_CreateContainer(IConnectedStorageSpace *iface,
    HSTRING name, IConnectedStorageContainer **out)
{
    struct space_obj *impl = impl_from_space(iface);
    WCHAR path[MAX_PATH];
    const WCHAR *name_str = WindowsGetStringRawBuffer(name, NULL);

    TRACE("(%p, %s, %p)\n", iface, debugstr_hstring(name), out);

    lstrcpyW(path, impl->root);
    lstrcatW(path, name_str);
    return container_create(path, out);
}

static HRESULT STDMETHODCALLTYPE space_DeleteContainerAsync(IConnectedStorageSpace *iface,
    HSTRING name, void **out)
{
    struct space_obj *impl = impl_from_space(iface);
    WCHAR path[MAX_PATH];
    SHFILEOPSTRUCTW op_struct = {0};
    async_op *op;
    HRESULT hr;

    TRACE("(%p, %s, %p)\n", iface, debugstr_hstring(name), out);

    lstrcpyW(path, impl->root);
    lstrcatW(path, WindowsGetStringRawBuffer(name, NULL));
    /* SHFileOperation needs double-null terminated path */
    path[lstrlenW(path) + 1] = 0;
    op_struct.wFunc = FO_DELETE;
    op_struct.pFrom = path;
    op_struct.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    SHFileOperationW(&op_struct);

    hr = async_op_create(NULL, &op);
    if (SUCCEEDED(hr)) *out = op;
    return hr;
}

static HRESULT STDMETHODCALLTYPE space_GetContainerNames(IConnectedStorageSpace *iface, void **out)
{
    FIXME("(%p, %p): stub\n", iface, out);
    *out = NULL;
    return E_NOTIMPL;
}

static const IConnectedStorageSpaceVtbl space_vtbl =
{
    space_QI,
    space_AddRef,
    space_Release,
    space_GetIids,
    space_GetRTCN,
    space_GetTL,
    space_CreateContainer,
    space_DeleteContainerAsync,
    space_GetContainerNames,
};

static HRESULT space_create(IConnectedStorageSpace **out)
{
    struct space_obj *impl;
    WCHAR appdata[MAX_PATH];

    impl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*impl));
    if (!impl) return E_OUTOFMEMORY;

    /* Build root path: %LOCALAPPDATA%\WineEX\ConnectedStorage\ */
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata);
    lstrcpyW(impl->root, appdata);
    lstrcatW(impl->root, L"\\WineEX\\ConnectedStorage\\");
    CreateDirectoryW(impl->root, NULL);

    impl->IConnectedStorageSpace_iface.lpVtbl = &space_vtbl;
    impl->ref = 1;
    *out = &impl->IConnectedStorageSpace_iface;
    return S_OK;
}

/* ======================================================================
 * IConnectedStorageSpaceStatics — activation factory
 * ====================================================================== */
typedef struct IConnectedStorageSpaceStaticsVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IConnectedStorageSpaceStatics*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IConnectedStorageSpaceStatics*);
    ULONG   (STDMETHODCALLTYPE *Release)(IConnectedStorageSpaceStatics*);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IConnectedStorageSpaceStatics*, ULONG*, IID**);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IConnectedStorageSpaceStatics*, HSTRING*);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IConnectedStorageSpaceStatics*, TrustLevel*);
    HRESULT (STDMETHODCALLTYPE *GetForUserAsync)(IConnectedStorageSpaceStatics*, void* user, HSTRING scid, void** async_op);
    HRESULT (STDMETHODCALLTYPE *GetSyncOnDemandForUserAsync)(IConnectedStorageSpaceStatics*, void* user, HSTRING scid, void** async_op);
} IConnectedStorageSpaceStaticsVtbl;
struct IConnectedStorageSpaceStatics { CONST_VTBL IConnectedStorageSpaceStaticsVtbl *lpVtbl; };

static const GUID IID_IConnectedStorageSpaceStatics =
    {0xe3c07ebb, 0x8f63, 0x5cec, {0xa8, 0x3a, 0x47, 0x2d, 0x06, 0x37, 0xf4, 0xc8}};

struct storage_statics {
    IActivationFactory           IActivationFactory_iface;
    IConnectedStorageSpaceStatics IConnectedStorageSpaceStatics_iface;
    LONG ref;
};

static inline struct storage_statics *impl_af_from_storage(IActivationFactory *iface)
{ return CONTAINING_RECORD(iface, struct storage_statics, IActivationFactory_iface); }

static inline struct storage_statics *impl_ss_from_storage(IConnectedStorageSpaceStatics *iface)
{ return CONTAINING_RECORD(iface, struct storage_statics, IConnectedStorageSpaceStatics_iface); }

static HRESULT STDMETHODCALLTYPE storage_af_QI(IActivationFactory *iface, REFIID iid, void **out)
{
    struct storage_statics *impl = impl_af_from_storage(iface);
    if (IsEqualGUID(iid, &IID_IUnknown)        ||
        IsEqualGUID(iid, &IID_IInspectable)    ||
        IsEqualGUID(iid, &IID_IActivationFactory))
    {
        *out = &impl->IActivationFactory_iface;
        IUnknown_AddRef((IUnknown *)*out);
        return S_OK;
    }
    if (IsEqualGUID(iid, &IID_IConnectedStorageSpaceStatics))
    {
        *out = &impl->IConnectedStorageSpaceStatics_iface;
        IUnknown_AddRef((IUnknown *)*out);
        return S_OK;
    }
    FIXME("%s not implemented\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE storage_af_AddRef(IActivationFactory *iface)
{ return InterlockedIncrement(&impl_af_from_storage(iface)->ref); }

static ULONG STDMETHODCALLTYPE storage_af_Release(IActivationFactory *iface)
{ return InterlockedDecrement(&impl_af_from_storage(iface)->ref); }

static HRESULT STDMETHODCALLTYPE storage_af_GetIids(IActivationFactory *iface, ULONG *n, IID **ids)
{ *n = 0; *ids = NULL; return S_OK; }

static HRESULT STDMETHODCALLTYPE storage_af_GetRTCN(IActivationFactory *iface, HSTRING *cn)
{ return WindowsCreateString(RuntimeClass_ConnectedStorageSpace,
      wcslen(RuntimeClass_ConnectedStorageSpace), cn); }

static HRESULT STDMETHODCALLTYPE storage_af_GetTL(IActivationFactory *iface, TrustLevel *tl)
{ *tl = BaseTrust; return S_OK; }

static HRESULT STDMETHODCALLTYPE storage_af_Activate(IActivationFactory *iface, IInspectable **inst)
{ *inst = NULL; return E_NOTIMPL; }

static const IActivationFactoryVtbl storage_af_vtbl =
{
    storage_af_QI, storage_af_AddRef, storage_af_Release,
    storage_af_GetIids, storage_af_GetRTCN, storage_af_GetTL,
    storage_af_Activate,
};

/* IConnectedStorageSpaceStatics methods */
static HRESULT STDMETHODCALLTYPE ss_QI(IConnectedStorageSpaceStatics *iface, REFIID iid, void **out)
{
    struct storage_statics *impl = impl_ss_from_storage(iface);
    return IActivationFactory_QueryInterface(&impl->IActivationFactory_iface, iid, out);
}
static ULONG STDMETHODCALLTYPE ss_AddRef(IConnectedStorageSpaceStatics *iface)
{ return IActivationFactory_AddRef(&impl_ss_from_storage(iface)->IActivationFactory_iface); }
static ULONG STDMETHODCALLTYPE ss_Release(IConnectedStorageSpaceStatics *iface)
{ return IActivationFactory_Release(&impl_ss_from_storage(iface)->IActivationFactory_iface); }
static HRESULT STDMETHODCALLTYPE ss_GetIids(IConnectedStorageSpaceStatics *iface, ULONG *n, IID **ids)
{ *n = 0; *ids = NULL; return S_OK; }
static HRESULT STDMETHODCALLTYPE ss_GetRTCN(IConnectedStorageSpaceStatics *iface, HSTRING *cn)
{ return WindowsCreateString(RuntimeClass_ConnectedStorageSpace,
      wcslen(RuntimeClass_ConnectedStorageSpace), cn); }
static HRESULT STDMETHODCALLTYPE ss_GetTL(IConnectedStorageSpaceStatics *iface, TrustLevel *tl)
{ *tl = BaseTrust; return S_OK; }

static HRESULT STDMETHODCALLTYPE ss_GetForUserAsync(IConnectedStorageSpaceStatics *iface,
    void *user, HSTRING scid, void **out)
{
    IConnectedStorageSpace *space;
    async_op *op;
    HRESULT hr;

    TRACE("(%p, %p, %s, %p)\n", iface, user, debugstr_hstring(scid), out);

    hr = space_create(&space);
    if (FAILED(hr)) return hr;

    hr = async_op_create((IInspectable *)space, &op);
    IUnknown_Release((IUnknown *)space);
    if (SUCCEEDED(hr)) *out = op;
    return hr;
}

static HRESULT STDMETHODCALLTYPE ss_GetSyncOnDemandForUserAsync(IConnectedStorageSpaceStatics *iface,
    void *user, HSTRING scid, void **out)
{
    TRACE("(%p, %p, %s, %p) — same as GetForUserAsync\n", iface, user, debugstr_hstring(scid), out);
    return ss_GetForUserAsync(iface, user, scid, out);
}

static const IConnectedStorageSpaceStaticsVtbl storage_statics_vtbl =
{
    ss_QI, ss_AddRef, ss_Release,
    ss_GetIids, ss_GetRTCN, ss_GetTL,
    ss_GetForUserAsync,
    ss_GetSyncOnDemandForUserAsync,
};

static struct storage_statics storage_statics_instance =
{
    {&storage_af_vtbl},
    {&storage_statics_vtbl},
    1
};

IActivationFactory *xbox_storage_factory = &storage_statics_instance.IActivationFactory_iface;
