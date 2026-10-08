/*
 * winexbe.exe - Original Xbox XBE executable loader for Wine.
 *
 * Usage: winexbe.exe <path-to-xbe> [args...]
 *
 * XBE format reference: Cxbx-Reloaded src/common/xbe/Xbe.h + Xbe.cpp.
 * Kernel thunk resolution: each DWORD in the thunk table holds an ordinal
 * (bit 31 set) pointing into xboxkrnl.exe's by-ordinal export table.
 * We resolve each thunk to the real function address at load time.
 * Non-kernel imports (Xdk libraries linked as extra DLLs, e.g. xbdm) use a
 * standard PE IMAGE_IMPORT_DESCRIPTOR array at nonkernel_import_dir_addr;
 * those are resolved with LoadLibraryA/GetProcAddress like Cxbx-Reloaded's
 * Xbe::ResolveNonKernelImports / Xemu's HLE library mapping does.
 *
 * TLS: the XBE TLS directory (Xbe::Tls in Cxbx) holds a data template plus
 * an optional callback. We allocate a host TLS slot, copy the template into
 * freshly committed memory and invoke the callback on the new thread before
 * jumping to the entry point — matching Cxbx-Reloaded's EmuTLS handling.
 *
 * Section mapping: XBE sections live at absolute 32-bit virtual addresses.
 * We use VirtualAlloc with MEM_RESERVE at base_addr for the full image, then
 * commit + populate each section individually. Page protections are set per
 * section flags after data is copied (including HEAD/TAIL_PAGE_READONLY
 * first/last-page downgrades). Shared-page refcounts are initialised to 1.
 */

#include <stdarg.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winternl.h"
#include "ntstatus.h"

/* ======================================================================
 * XBE header layout (Xbe.h)
 * ====================================================================== */
#define XBE_MAGIC  0x48454258u  /* "XBEH" */

#define XBE_KSEG0_BASE               0x80000000u
#define XBE_WRITE_COMBINED_BASE      0xF0000000u
#define XBE_SEGABOOT_EP_XOR          0x40000000u

enum xbe_type { XBE_RETAIL, XBE_DEBUG, XBE_CHIHIRO };
static const UINT32 xbe_xor_ep[3] = { 0xA8FC57AB, 0x94859D4B, 0x40B5C16E };
static const UINT32 xbe_xor_kt[3] = { 0x5B6D40B6, 0xEFB1F152, 0x2290059D };

#pragma pack(push,1)
struct xbe_header {
    UINT32 magic;               /* 0x0000 */
    BYTE   signature[256];      /* 0x0004 */
    UINT32 base_addr;           /* 0x0104 */
    UINT32 sizeof_headers;      /* 0x0108 */
    UINT32 sizeof_image;        /* 0x010C */
    UINT32 sizeof_image_header; /* 0x0110 */
    UINT32 timedate;            /* 0x0114 */
    UINT32 certificate_addr;    /* 0x0118 */
    UINT32 sections;            /* 0x011C */
    UINT32 section_headers_addr;/* 0x0120 */
    UINT32 init_flags;          /* 0x0124 */
    UINT32 entry_addr;          /* 0x0128 — XOR-encoded */
    UINT32 tls_addr;            /* 0x012C */
    UINT32 pe_stack_commit;     /* 0x0130 */
    UINT32 pe_heap_reserve;     /* 0x0134 */
    UINT32 pe_heap_commit;      /* 0x0138 */
    UINT32 pe_base_addr;        /* 0x013C */
    UINT32 pe_sizeof_image;     /* 0x0140 */
    UINT32 pe_checksum;         /* 0x0144 */
    UINT32 pe_timedate;         /* 0x0148 */
    UINT32 debug_pathname_addr; /* 0x014C */
    UINT32 debug_filename_addr; /* 0x0150 */
    UINT32 debug_unicode_filename_addr; /* 0x0154 */
    UINT32 kernel_image_thunk_addr;     /* 0x0158 — XOR-encoded */
    UINT32 nonkernel_import_dir_addr;   /* 0x015C */
    UINT32 library_versions;            /* 0x0160 */
    UINT32 library_versions_addr;       /* 0x0164 */
    UINT32 kernel_library_version_addr; /* 0x0168 */
    UINT32 xapi_library_version_addr;   /* 0x016C */
    UINT32 logo_bitmap_addr;            /* 0x0170 */
    UINT32 logo_bitmap_size;            /* 0x0174 */
};

struct xbe_section_header {
    UINT32 flags;
    UINT32 virtual_addr;
    UINT32 virtual_size;
    UINT32 raw_addr;
    UINT32 sizeof_raw;
    UINT32 section_name_addr;
    UINT32 section_name_ref_count;
    UINT32 head_shared_page_ref_count_addr;
    UINT32 tail_shared_page_ref_count_addr;
    BYTE   sha1_digest[20];
};
#pragma pack(pop)

#define XBEIMAGE_SECTION_WRITEABLE  0x00000001
#define XBEIMAGE_SECTION_EXECUTABLE 0x00000004
#define XBEIMAGE_SECTION_HEAD_PAGE_READONLY 0x00000010
#define XBEIMAGE_SECTION_TAIL_PAGE_READONLY 0x00000020

#define XBE_THUNK_ORDINAL_MASK 0x7FFFFFFFu

#define XBE_LOAD_BUFFER 0x10000

/* XBE TLS directory (Cxbx-Reloaded Xbe::Tls, 6 ULONG fields). */
struct xbe_tls_dir {
    UINT32 data_start_addr;
    UINT32 data_end_addr;
    UINT32 tls_index_addr;
    UINT32 tls_callback_addr;
    UINT32 zero_fill_size;
    UINT32 characteristics;
};

/* PE import descriptor for non-kernel imports (IMAGE_IMPORT_DESCRIPTOR). */
struct xbe_import_desc {
    UINT32 original_first_thunk;
    UINT32 timedate;
    UINT32 forwarder_chain;
    UINT32 name_addr;
    UINT32 first_thunk;
};

struct xbe_library_version {
    char   name[8];
    UINT16 major_version;
    UINT16 minor_version;
    UINT16 build_version;
    UINT16 flags;
};

/* ======================================================================
 * Helpers
 * ====================================================================== */
static void xbe_fatal( const char *msg )
{
    DWORD n;
    WriteFile( GetStdHandle(STD_ERROR_HANDLE), msg, strlen(msg), &n, NULL );
    WriteFile( GetStdHandle(STD_ERROR_HANDLE), "\n", 1, &n, NULL );
    ExitProcess( 1 );
}

/* Map a virtual address in the XBE header region to a pointer in 'buf'. */
static const void *xbe_va( const BYTE *buf, UINT32 bufsz, UINT32 base, UINT32 va, UINT32 need )
{
    UINT32 off;
    if (va < base) return NULL;
    off = va - base;
    if (off > bufsz || need > bufsz - off) return NULL;
    return buf + off;
}

/* ======================================================================
 * Kernel thunk table resolver
 *
 * Thunk table is an array of UINT32 at kernel_thunk_addr (absolute VA).
 * Each non-zero entry: bit 31 set, low 15 bits = xboxkrnl.exe ordinal
 * (Cxbx-Reloaded KernelThunk.cpp; Xemu/Xemi use the same ordinal table).
 * We replace each entry with GetProcAddress(hXboxKrnl, ordinal).
 * Unlike the old silent leave-it-fault behaviour, an unresolvable ordinal
 * is fatal with the ordinal printed: silent faults are undebuggable and
 * Xemu/Xemi both fail load here too.
 * ====================================================================== */
static DWORD xbe_unresolved_ordinal; /* set on failure for the fatal message */
static BOOL resolve_kernel_thunks( UINT32 *thunk_table, HMODULE hKrnl )
{
    UINT32 i;
    for (i = 0; thunk_table[i]; i++)
    {
        UINT32 raw = thunk_table[i];
        UINT32 ordinal = raw & XBE_THUNK_ORDINAL_MASK;
        FARPROC fn = GetProcAddress( hKrnl, (LPCSTR)(ULONG_PTR)ordinal );
        if (fn)
            thunk_table[i] = (UINT32)(ULONG_PTR)fn;
        else
        {
            xbe_unresolved_ordinal = ordinal;
            return FALSE;
        }
    }
    return TRUE;
}

/* Resolve non-kernel imports: IMAGE_IMPORT_DESCRIPTOR array at the mapped
 * nonkernel_import_dir_addr (Cxbx-Reloaded Xbe::ResolveNonKernelImports).
 * Each entry names a DLL (e.g. xbdm.dll on devkit titles); we LoadLibraryA
 * it and patch OriginalFirstThunk->FirstThunk. Missing DLL => fatal since
 * the title cannot run without it. */
static BOOL resolve_nonkernel_imports( UINT32 import_dir_addr )
{
    const struct xbe_import_desc *desc = (const struct xbe_import_desc *)(ULONG_PTR)import_dir_addr;
    for (; desc->name_addr; desc++)
    {
        const char *dll = (const char *)(ULONG_PTR)desc->name_addr;
        HMODULE mod;
        UINT32 *oft, *ft;
        if (!desc->original_first_thunk || !desc->first_thunk) return FALSE;
        mod = LoadLibraryA( dll );
        if (!mod) return FALSE;
        oft = (UINT32 *)(ULONG_PTR)desc->original_first_thunk;
        ft  = (UINT32 *)(ULONG_PTR)desc->first_thunk;
        for (; *oft; oft++, ft++)
        {
            FARPROC fn;
            if (*oft & 0x80000000u)
                fn = GetProcAddress( mod, (LPCSTR)(ULONG_PTR)(*oft & 0xffff) );
            else
                fn = GetProcAddress( mod, (LPCSTR)(ULONG_PTR)(*oft + 2) ); /* skip hint */
            if (!fn) return FALSE;
            *ft = (UINT32)(ULONG_PTR)fn;
        }
    }
    return TRUE;
}

/* ======================================================================
 * Section mapper: VirtualAlloc at absolute XBE VAs
 *
 * HEAD/TAIL_PAGE_READONLY downgrade the first/last 4K page of the section
 * (Cxbx-Reloaded Xbe::MapSections). Shared-page refcounts are initialised
 * to 1 so title code observing them sees a mapped section, like Xemu does.
 * ====================================================================== */
static BOOL map_xbe_sections( HANDLE file, UINT32 base_addr, UINT32 sizeof_image,
                               const struct xbe_section_header *sections, UINT32 nsec )
{
    UINT32 i;
    void *region;
    DWORD old_prot;

    /* Reserve entire image range; ignore failure — sections commit individually */
    region = VirtualAlloc( (void *)(ULONG_PTR)base_addr, sizeof_image,
                           MEM_RESERVE, PAGE_NOACCESS );
    (void)region;

    for (i = 0; i < nsec; i++)
    {
        const struct xbe_section_header *s = &sections[i];
        BYTE *dest;
        DWORD read;

        if (!s->virtual_addr || !s->virtual_size) continue;

        dest = VirtualAlloc( (void *)(ULONG_PTR)s->virtual_addr, s->virtual_size,
                              MEM_COMMIT, PAGE_READWRITE );
        if (!dest) return FALSE;

        memset( dest, 0, s->virtual_size );

        if (s->sizeof_raw && s->raw_addr)
        {
            LONG hi = 0;
            SetFilePointer( file, s->raw_addr, &hi, FILE_BEGIN );
            ReadFile( file, dest, min(s->sizeof_raw, s->virtual_size), &read, NULL );
        }

        /* Apply page protection after writing */
        if (s->flags & XBEIMAGE_SECTION_EXECUTABLE)
            VirtualProtect( dest, s->virtual_size, PAGE_EXECUTE_READ, &old_prot );
        else if (!(s->flags & XBEIMAGE_SECTION_WRITEABLE))
            VirtualProtect( dest, s->virtual_size, PAGE_READONLY, &old_prot );
        /* else leave PAGE_READWRITE */

        /* HEAD/TAIL_PAGE_READONLY: downgrade first/last 4K page (Cxbx Xbe::MapSections) */
        if ((s->flags & XBEIMAGE_SECTION_HEAD_PAGE_READONLY) && s->virtual_size > 4096)
            VirtualProtect( dest, 4096, PAGE_READONLY, &old_prot );
        if ((s->flags & XBEIMAGE_SECTION_TAIL_PAGE_READONLY) && s->virtual_size > 4096)
            VirtualProtect( dest + s->virtual_size - 4096, 4096, PAGE_READONLY, &old_prot );

        /* Shared-page refcounts: mark mapped (Xemu initialises these to 1) */
        if (s->head_shared_page_ref_count_addr)
            *(volatile ULONG *)(ULONG_PTR)s->head_shared_page_ref_count_addr = 1;
        if (s->tail_shared_page_ref_count_addr)
            *(volatile ULONG *)(ULONG_PTR)s->tail_shared_page_ref_count_addr = 1;
    }
    return TRUE;
}

/* Initialise XBE TLS: allocate a host TLS slot, publish its index through
 * tls_index_addr, and zero-fill/reserve per the template (Cxbx EmuTLS). The
 * optional callback runs on the new thread before the entry point. */
static DWORD xbe_tls_index = TLS_OUT_OF_INDEXES;
static void (WINAPI *xbe_tls_callback)( void *dll_base, DWORD reason, void *reserved );

static void init_xbe_tls( UINT32 tls_dir_addr )
{
    const struct xbe_tls_dir *tls = (const struct xbe_tls_dir *)(ULONG_PTR)tls_dir_addr;
    UINT32 data_size, total;
    BYTE *tls_data;
    if (!tls_dir_addr || !tls->data_start_addr) return;
    data_size = tls->data_end_addr > tls->data_start_addr
              ? tls->data_end_addr - tls->data_start_addr : 0;
    total = data_size + tls->zero_fill_size;
    if (!total) total = 4;
    tls_data = VirtualAlloc( NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if (!tls_data) return;
    if (data_size)
        memcpy( tls_data, (void *)(ULONG_PTR)tls->data_start_addr, data_size );
    xbe_tls_index = TlsAlloc();
    if (xbe_tls_index != TLS_OUT_OF_INDEXES)
    {
        TlsSetValue( xbe_tls_index, tls_data );
        if (tls->tls_index_addr)
            *(volatile DWORD *)(ULONG_PTR)tls->tls_index_addr = xbe_tls_index;
    }
    if (tls->tls_callback_addr)
        xbe_tls_callback = (void (WINAPI *)(void*,DWORD,void*))(ULONG_PTR)tls->tls_callback_addr;
}

/* Publish the XBE path through xboxkrnl's XeImageFileName export
 * (ordinal 326). Dashboards and homebrew (e.g. MXM, XBMC) read it to
 * locate their data files; Xemu fills it from the loaded path the same
 * way. Resolved by ordinal since xboxkrnl.exe exports by ordinal only. */
static void publish_image_file_name( HMODULE hKrnl, const WCHAR *xbe_path )
{
    STRING *img = (STRING *)GetProcAddress( hKrnl, (LPCSTR)(ULONG_PTR)326 );
    char *ansi;
    int len;
    if (!img) return;
    len = WideCharToMultiByte( CP_ACP, 0, xbe_path, -1, NULL, 0, NULL, NULL );
    if (len <= 1) return;
    ansi = HeapAlloc( GetProcessHeap(), 0, len );
    if (!ansi) return;
    WideCharToMultiByte( CP_ACP, 0, xbe_path, -1, ansi, len, NULL, NULL );
    img->Buffer = ansi;
    img->Length = (USHORT)(len - 1);
    img->MaximumLength = (USHORT)len;
}

/* ======================================================================
 * Thread entry: jump to XBE entry point
 * The XBE entry point signature is void __cdecl start(void).
 * ====================================================================== */
typedef void (__cdecl *XBE_ENTRY)(void);

static DWORD WINAPI xbe_thread_entry( void *param )
{
    /* Run the XBE TLS callback first (DLL_THREAD_ATTACH), like Cxbx does
     * before jumping to the title entry point. */
    if (xbe_tls_callback)
        xbe_tls_callback( NULL, 1 /* DLL_THREAD_ATTACH */, NULL );
    {
        XBE_ENTRY entry = (XBE_ENTRY)(ULONG_PTR)param;
        entry();
    }
    return 0;
}

/* ======================================================================
 * wmain
 * ====================================================================== */
int __cdecl wmain( int argc, WCHAR **argv )
{
    HANDLE file;
    BYTE *hdr_buf;
    DWORD read;
    const struct xbe_header *hdr;
    const struct xbe_section_header *sections;
    enum xbe_type type;
    UINT32 entry_point, kernel_thunk_addr;
    HMODULE hKrnl;
    HANDLE thread;
    DWORD exit_code;
    char msgbuf[128];

    if (argc < 2) xbe_fatal( "usage: winexbe.exe <file.xbe> [args...]\n"
                             "  Extra args are forwarded to the title via the command line." );

    file = CreateFileW( argv[1], GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, 0 );
    if (file == INVALID_HANDLE_VALUE) xbe_fatal( "cannot open XBE file" );

    hdr_buf = HeapAlloc( GetProcessHeap(), 0, XBE_LOAD_BUFFER );
    if (!hdr_buf) xbe_fatal( "out of memory" );

    if (!ReadFile( file, hdr_buf, XBE_LOAD_BUFFER, &read, NULL ) || read < sizeof(*hdr) )
        xbe_fatal( "cannot read XBE header" );

    hdr = (const struct xbe_header *)hdr_buf;
    if (hdr->magic != XBE_MAGIC) xbe_fatal( "not an XBE file (bad magic)" );

    /* Decode image type (Cxbx-Reloaded algorithm: XOR candidate then range-check) */
    if ((hdr->entry_addr ^ xbe_xor_ep[XBE_DEBUG]) < 0x01000000u)
        type = XBE_DEBUG;
    else if ((hdr->entry_addr ^ xbe_xor_ep[XBE_CHIHIRO]) < 0x01000000u)
        type = XBE_CHIHIRO;
    else
        type = XBE_RETAIL;

    entry_point        = hdr->entry_addr              ^ xbe_xor_ep[type];
    kernel_thunk_addr  = hdr->kernel_image_thunk_addr ^ xbe_xor_kt[type];

    /* Validate section count */
    if (!hdr->sections || hdr->sections > 256) xbe_fatal( "implausible section count" );

    sections = (const struct xbe_section_header *)
        xbe_va( hdr_buf, read, hdr->base_addr, hdr->section_headers_addr,
                hdr->sections * sizeof(struct xbe_section_header) );
    if (!sections) xbe_fatal( "section header table out of range" );

    /* Map sections at absolute VAs */
    if (!map_xbe_sections( file, hdr->base_addr, hdr->sizeof_image, sections, hdr->sections ))
        xbe_fatal( "failed to map XBE sections" );

    /* Library versions (informational, Cxbx logs these at load) */
    {
        const struct xbe_library_version *libs = (const struct xbe_library_version *)
            xbe_va( hdr_buf, read, hdr->base_addr, hdr->library_versions_addr,
                    hdr->library_versions * sizeof(struct xbe_library_version) );
        DWORD n;
        char libmsg[64];
        UINT32 i;
        if (libs)
        {
            for (i = 0; i < hdr->library_versions; i++)
            {
                int k;
                for (k = 0; k < 8 && libs[i].name[k]; k++) libmsg[k] = libs[i].name[k];
                libmsg[k] = 0;
                /* keep it to stderr diagnostics; titles must not depend on this */
                WriteFile( GetStdHandle(STD_ERROR_HANDLE), "winexbe: lib ", 12, &n, NULL );
                WriteFile( GetStdHandle(STD_ERROR_HANDLE), libmsg, k, &n, NULL );
                WriteFile( GetStdHandle(STD_ERROR_HANDLE), "\n", 1, &n, NULL );
            }
        }
    }

    CloseHandle( file );

    /* Initialise TLS before any title code runs (needs mapped image) */
    if (hdr->tls_addr)
        init_xbe_tls( hdr->tls_addr );

    HeapFree( GetProcessHeap(), 0, hdr_buf );

    /* Load xboxkrnl.exe and resolve kernel thunks */
    hKrnl = LoadLibraryW( L"xboxkrnl.exe" );
    if (!hKrnl) xbe_fatal( "cannot load xboxkrnl.exe" );

    /* Publish the image path for titles that read XeImageFileName */
    publish_image_file_name( hKrnl, argv[1] );

    if (kernel_thunk_addr)
    {
        if (!resolve_kernel_thunks( (UINT32 *)(ULONG_PTR)kernel_thunk_addr, hKrnl ))
        {
            wsprintfA( msgbuf, "winexbe: unresolvable xboxkrnl ordinal %u; "
                       "title needs a kernel export WineEX does not implement yet",
                       xbe_unresolved_ordinal );
            xbe_fatal( msgbuf );
        }
    }

    /* Non-kernel imports (xbdm etc. on devkit titles) */
    if (hdr->nonkernel_import_dir_addr)
    {
        if (!resolve_nonkernel_imports( hdr->nonkernel_import_dir_addr ))
            xbe_fatal( "winexbe: failed to resolve non-kernel imports "
                       "(missing title DLL, e.g. xbdm.dll?)" );
    }

    /* Launch the XBE entry point on a new thread */
    thread = CreateThread( NULL, hdr->pe_stack_commit ? hdr->pe_stack_commit : 0x10000,
                           xbe_thread_entry, (void *)(ULONG_PTR)entry_point,
                           0, NULL );
    if (!thread) xbe_fatal( "cannot create XBE thread" );

    WaitForSingleObject( thread, INFINITE );
    GetExitCodeThread( thread, &exit_code );
    CloseHandle( thread );
    FreeLibrary( hKrnl );
    return (int)exit_code;
}
